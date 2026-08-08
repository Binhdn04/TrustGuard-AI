from __future__ import annotations

import asyncio
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Header, Request

from src.agents.graph import build_openai_graph
from src.config import get_settings
from src.core.auth import ConfiguredAuthenticator, Principal, UserRole
from src.core.errors import PlatformError
from src.core.rate_limit import MemoryRateLimiter, RedisRateLimiter
from src.models import ErrorCode
from src.repositories import PostgresPlatformRepository, SQLiteBlacklistRepository
from src.services.analysis import AnalysisService
from src.services.durable_worker import DurableAnalysisWorker, OutboxPublisher
from src.services.processor import LangGraphAnalysisProcessor
from src.services.realtime import MemoryTicketStore, RedisTicketStore, WebSocketTicketManager

_worker: DurableAnalysisWorker | None = None
_worker_task = None
_outbox: OutboxPublisher | None = None
_outbox_task = None


@lru_cache
def get_analysis_service() -> AnalysisService:
    settings = get_settings()
    postgres = settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://"))
    blacklist = (
        PostgresPlatformRepository(settings.database_url, settings.database_encryption_key)
        if postgres
        else SQLiteBlacklistRepository(settings.security_database_path)
    )
    graph = build_openai_graph(blacklist=blacklist)
    processor = LangGraphAnalysisProcessor(graph)
    return AnalysisService(blacklist=blacklist, processor=processor, durable_jobs=postgres)


async def resolve_analysis_service(request: Request) -> AnalysisService:
    override = request.app.dependency_overrides.get(get_analysis_service)
    if override is None:
        return get_analysis_service()
    service = override()
    if hasattr(service, "__await__"):
        return await service
    return service


async def close_analysis_service() -> None:
    if get_analysis_service.cache_info().currsize == 0:
        return
    service = get_analysis_service()
    get_analysis_service.cache_clear()
    await service.aclose()


async def start_durable_worker() -> None:
    global _outbox, _outbox_task, _worker, _worker_task
    service = get_analysis_service()
    if not isinstance(service.repository, PostgresPlatformRepository):
        return
    settings = get_settings()
    _worker = DurableAnalysisWorker(service.repository, service, lease_seconds=settings.job_lease_seconds)
    _worker_task = asyncio.create_task(_worker.run(), name="durable-analysis-worker")
    _outbox = OutboxPublisher(service.repository, settings.redis_url)
    _outbox_task = asyncio.create_task(_outbox.run(), name="transactional-outbox-publisher")


async def stop_durable_worker() -> None:
    global _outbox, _outbox_task, _worker, _worker_task
    if _worker is not None:
        _worker.stop()
    if _worker_task is not None:
        await _worker_task
    if _outbox is not None:
        _outbox.stop()
    if _outbox_task is not None:
        await _outbox_task
    if _outbox is not None:
        await _outbox.close()
    _worker = None
    _worker_task = None
    _outbox = None
    _outbox_task = None


@lru_cache
def get_ticket_manager() -> WebSocketTicketManager:
    settings = get_settings()
    # Redis is required for shared production tickets. Tests/development stay
    # offline unless the application is configured for PostgreSQL runtime.
    store = None
    if settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://")):
        try:
            store = RedisTicketStore(settings.redis_url)
        except (ImportError, RuntimeError):
            if settings.app_env == "production":
                raise
    store = store or MemoryTicketStore()
    return WebSocketTicketManager(store, settings.websocket_ticket_ttl_seconds)


async def close_ticket_manager() -> None:
    if get_ticket_manager.cache_info().currsize:
        manager = get_ticket_manager()
        get_ticket_manager.cache_clear()
        await manager.close()


async def get_principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
    settings = get_settings()
    principal = await get_authenticator().authenticate_async(authorization)
    limit = (
        settings.admin_rate_limit_per_minute
        if principal.role is UserRole.SECURITY_ADMIN
        else settings.user_rate_limit_per_minute
    )
    if not await get_rate_limiter().allow(f"{principal.role.value}:{principal.user_id}", limit):
        raise PlatformError(
            status_code=429,
            code=ErrorCode.RATE_LIMITED,
            message="Request rate limit exceeded.",
            retryable=True,
        )
    return principal


@lru_cache
def get_authenticator() -> ConfiguredAuthenticator:
    return ConfiguredAuthenticator(get_settings())


@lru_cache
def get_rate_limiter():
    settings = get_settings()
    if settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://")):
        try:
            return RedisRateLimiter(settings.redis_url)
        except (ImportError, RuntimeError):
            if settings.app_env == "production":
                raise
    return MemoryRateLimiter()


async def close_rate_limiter() -> None:
    if get_rate_limiter.cache_info().currsize:
        limiter = get_rate_limiter()
        get_rate_limiter.cache_clear()
        await limiter.close()


AnalysisServiceDependency = Annotated[AnalysisService, Depends(resolve_analysis_service)]
PrincipalDependency = Annotated[Principal, Depends(get_principal)]
TicketManagerDependency = Annotated[WebSocketTicketManager, Depends(get_ticket_manager)]
