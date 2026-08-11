from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Annotated

if TYPE_CHECKING:
    from src.services.durable_worker import DurableAnalysisWorker, OutboxPublisher, RetentionWorker

from fastapi import Depends, Header, Request

from src.agents.campaign import (
    ConfigurableCampaignDetector,
    InMemoryCampaignObservationStore,
    RepositoryCampaignObservationStore,
)
from src.agents.graph import build_openai_graph
from src.agents.tools.advanced import OpenAIEmbeddingProvider
from src.config import get_settings
from src.core.auth import ConfiguredAuthenticator, Principal, UserRole
from src.core.errors import PlatformError
from src.core.rate_limit import MemoryRateLimiter, RedisRateLimiter
from src.models import ErrorCode
from src.repositories import PostgresPlatformRepository, SQLiteBlacklistRepository
from src.services.analysis import AnalysisService
from src.services.platform_wave2 import (
    ArtifactSigner,
    MemoryWave2Repository,
    VersionedSourceRegistry,
    Wave2PlatformService,
    default_source_policies,
)
from src.services.processor import LangGraphAnalysisProcessor
from src.services.realtime import (
    MemoryEventNotifier,
    MemoryTicketStore,
    RedisEventNotifier,
    RedisTicketStore,
    WebSocketTicketManager,
)
from src.services.screenshot import ScreenshotCaptureCoordinator

_worker: DurableAnalysisWorker | None = None
_worker_task = None
_outbox: OutboxPublisher | None = None
_outbox_task = None
_retention: RetentionWorker | None = None
_retention_task = None
_memory_wave2_repository = MemoryWave2Repository()
_source_registry = VersionedSourceRegistry(default_source_policies())


@lru_cache
def get_analysis_service() -> AnalysisService:
    settings = get_settings()
    postgres = settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://"))
    blacklist = (
        PostgresPlatformRepository(
            settings.database_url,
            settings.database_encryption_key,
            content_retention_days=settings.artifact_retention_days,
        )
        if postgres
        else SQLiteBlacklistRepository(settings.security_database_path)
    )
    processor = None
    if not postgres or settings.run_durable_worker:
        campaign_store = (
            RepositoryCampaignObservationStore(blacklist) if postgres else InMemoryCampaignObservationStore()
        )
        graph = build_openai_graph(
            blacklist=blacklist,
            source_registry=_source_registry,
            campaign_detector=ConfigurableCampaignDetector(campaign_store),
        )
        processor = LangGraphAnalysisProcessor(
            graph,
            deadline_seconds=settings.analysis_deadline_seconds,
            max_tool_cost_usd=settings.max_provider_cost_usd,
        )
    artifact_repository = blacklist if postgres else _memory_wave2_repository
    screenshot_capture = ScreenshotCaptureCoordinator(
        artifact_repository,
        settings.artifact_storage_dir,
        retention_days=settings.artifact_retention_days,
        timeout_seconds=settings.provider_timeout_seconds,
    )
    return AnalysisService(
        blacklist=blacklist,
        processor=processor,
        durable_jobs=postgres,
        screenshot_capture=screenshot_capture,
    )


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
    global _outbox, _outbox_task, _retention, _retention_task, _worker, _worker_task
    service = get_analysis_service()
    if not isinstance(service.repository, PostgresPlatformRepository):
        return
    try:
        from src.services.durable_worker import (  # noqa: PLC0415
            DurableAnalysisWorker,
            OutboxPublisher,
            ReembeddingJobHandler,
            RetentionWorker,
        )
    except ImportError:
        if get_settings().app_env == "production":
            raise
        return
    settings = get_settings()
    policies = await service.repository.load_source_policies(datetime.now(UTC))
    _source_registry.replace(policies or default_source_policies())

    async def refresh_source_registry() -> None:
        active = await service.repository.load_source_policies(datetime.now(UTC))
        _source_registry.replace(active or default_source_policies())
    handlers = {}
    if settings.openai_api_key:
        embedding_provider = OpenAIEmbeddingProvider(
            settings.openai_api_key,
            timeout=settings.provider_timeout_seconds,
        )
        handlers["reembed_fact_check_result"] = ReembeddingJobHandler(service.repository, embedding_provider)
    _worker = DurableAnalysisWorker(
        service.repository,
        service,
        lease_seconds=settings.job_lease_seconds,
        job_handlers=handlers,
        before_analysis=refresh_source_registry,
    )
    _worker_task = asyncio.create_task(_worker.run(), name="durable-analysis-worker")
    _retention = RetentionWorker(service.repository)
    _retention_task = asyncio.create_task(_retention.run(), name="retention-worker")
    try:
        _outbox = OutboxPublisher(service.repository, settings.redis_url)
        _outbox_task = asyncio.create_task(_outbox.run(), name="transactional-outbox-publisher")
    except Exception:
        import logging

        if settings.app_env == "production":
            raise
        logging.getLogger(__name__).warning("OutboxPublisher skipped: redis not available")


async def stop_durable_worker() -> None:
    global _outbox, _outbox_task, _retention, _retention_task, _worker, _worker_task
    if _worker is not None:
        _worker.stop()
    if _worker_task is not None:
        await _worker_task
    if _worker is not None:
        await _worker.close()
    if _outbox is not None:
        _outbox.stop()
    if _outbox_task is not None:
        await _outbox_task
    if _outbox is not None:
        await _outbox.close()
    if _retention is not None:
        _retention.stop()
    if _retention_task is not None:
        await _retention_task
    _worker = None
    _worker_task = None
    _outbox = None
    _outbox_task = None
    _retention = None
    _retention_task = None


@lru_cache
def get_ticket_manager() -> WebSocketTicketManager:
    settings = get_settings()
    # Redis is required for shared production tickets. Tests/development use
    # the single-process store so local PostgreSQL does not require Redis.
    store = None
    if settings.app_env == "production":
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


@lru_cache
def get_event_notifier():
    settings = get_settings()
    if settings.app_env == "production":
        try:
            return RedisEventNotifier(settings.redis_url)
        except (ImportError, RuntimeError):
            if settings.app_env == "production":
                raise
    return MemoryEventNotifier()


async def close_event_notifier() -> None:
    if get_event_notifier.cache_info().currsize:
        notifier = get_event_notifier()
        get_event_notifier.cache_clear()
        await notifier.close()


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
    if settings.app_env == "production":
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


@lru_cache
def get_wave2_service() -> Wave2PlatformService:
    settings = get_settings()
    analysis_service = get_analysis_service()
    repository = analysis_service.repository
    if not isinstance(repository, PostgresPlatformRepository):
        repository = _memory_wave2_repository
    signer = ArtifactSigner(settings.artifact_signing_key, settings.artifact_access_ttl_seconds)
    return Wave2PlatformService(repository, signer, _source_registry)


async def resolve_wave2_service(request: Request) -> Wave2PlatformService:
    override = request.app.dependency_overrides.get(get_wave2_service)
    if override is None:
        return get_wave2_service()
    service = override()
    if hasattr(service, "__await__"):
        return await service
    return service


AnalysisServiceDependency = Annotated[AnalysisService, Depends(resolve_analysis_service)]
PrincipalDependency = Annotated[Principal, Depends(get_principal)]
TicketManagerDependency = Annotated[WebSocketTicketManager, Depends(get_ticket_manager)]
Wave2ServiceDependency = Annotated[Wave2PlatformService, Depends(resolve_wave2_service)]
