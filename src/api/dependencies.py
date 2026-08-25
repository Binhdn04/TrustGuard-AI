from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Annotated

if TYPE_CHECKING:
    from src.services.durable_worker import (
        OutboxPublisher,
        RetentionWorker,
        SecurityV4DurableWorker,
    )

from fastapi import Depends, Header, Request

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_trust import SecurityTrustService
from src.agents.tools import (
    CloudflareRadarDomainFamiliarityProvider,
    DomainRegistrationProvider,
    GuardedRedirectResolver,
    ProductionUrlReputationCascade,
    SafeDnsEvidenceResolver,
    VirusTotalUrlProvider,
)
from src.agents.tools.security_memory import SecurityMemoryLookupTool
from src.config import get_settings
from src.core.auth import ConfiguredAuthenticator, Principal, UserRole
from src.core.errors import PlatformError
from src.core.rate_limit import MemoryRateLimiter, RedisRateLimiter
from src.models import ErrorCode
from src.repositories import PostgresPlatformRepository, SQLiteBlacklistRepository
from src.security_ai import (
    ModelTokenPricing,
    OpenAISecurityAssistant,
    SecurityAssistantRuntime,
    TurnBudget,
    TurnExecutionContext,
)
from src.services.official_verification_coordinator import OfficialLinkVerificationCoordinator
from src.services.official_verification_rollout import (
    OfficialVerificationMode,
    OfficialVerificationRolloutStage,
)
from src.services.official_verification_transport import (
    GuardedHtmlFetcher,
    build_official_verification_providers,
)
from src.services.page_capture import PageCaptureService
from src.services.platform_wave2 import (
    MemoryWave2Repository,
    VersionedSourceRegistry,
    Wave2PlatformService,
    default_source_policies,
)
from src.services.realtime import (
    MemoryEventNotifier,
    MemoryTicketStore,
    RedisEventNotifier,
    RedisTicketStore,
    WebSocketTicketManager,
)
from src.services.security_admin_copilot import SecurityAdminCopilotService
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_blacklist import SecurityBlacklistAdminService
from src.services.security_memory import SecurityMemoryService
from src.services.security_pipeline import SecurityTriagePipeline
from src.services.security_response import GroundedSecurityResponseService
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_trust import SecurityTrustAdminService
from src.services.security_understanding import SecuritySemanticUnderstandingService

_outbox: OutboxPublisher | None = None
_outbox_task = None
_retention: RetentionWorker | None = None
_retention_task = None
_security_worker: SecurityV4DurableWorker | None = None
_security_worker_task = None
_memory_wave2_repository = MemoryWave2Repository()
_source_registry = VersionedSourceRegistry(default_source_policies())


@lru_cache
def get_official_verification_rollout_stage() -> OfficialVerificationRolloutStage | None:
    settings = get_settings()
    mode = OfficialVerificationMode(settings.security_official_verification_mode)
    if mode is OfficialVerificationMode.OFF:
        return None
    providers = build_official_verification_providers(settings)
    fetcher = GuardedHtmlFetcher(timeout=settings.provider_timeout_seconds)
    coordinator = OfficialLinkVerificationCoordinator(
        get_security_trust_repository(),
        search=providers.search,
        extract=providers.extract,
        fetcher=fetcher,
        source_registry=_source_registry,
    )
    closers = [item for item in (providers.search, providers.extract, fetcher) if item is not None]
    return OfficialVerificationRolloutStage(
        coordinator,
        mode=mode,
        closers=closers,
    )


async def close_official_verification_rollout_stage() -> None:
    if get_official_verification_rollout_stage.cache_info().currsize:
        stage = get_official_verification_rollout_stage()
        get_official_verification_rollout_stage.cache_clear()
        if stage is not None:
            await stage.aclose()


@lru_cache
def get_page_capture_service() -> PageCaptureService:
    settings = get_settings()
    return PageCaptureService(
        timeout_seconds=settings.security_page_capture_timeout_seconds,
        max_image_bytes=settings.security_page_capture_max_image_bytes,
        max_concurrency=settings.security_page_capture_max_concurrency,
        viewport_width=settings.security_page_capture_viewport_width,
        viewport_height=settings.security_page_capture_viewport_height,
        jpeg_quality=settings.security_page_capture_jpeg_quality,
    )


async def close_page_capture_service() -> None:
    if get_page_capture_service.cache_info().currsize:
        service = get_page_capture_service()
        get_page_capture_service.cache_clear()
        await service.aclose()


@lru_cache
def get_security_assistant_model():
    """Construct the provider only when at least one AI operation is enabled."""
    settings = get_settings()
    ai_operation_enabled = any(
        (
            settings.security_ai_understanding_enabled,
            settings.security_ai_planning_enabled,
            settings.security_ai_explanation_enabled,
            settings.security_admin_copilot_enabled,
        )
    )
    if not ai_operation_enabled or not settings.security_ai_provider_configuration_valid():
        return None
    return OpenAISecurityAssistant(
        api_key=settings.openai_api_key,
        small_model=settings.security_ai_small_model,
        synthesis_model=settings.security_ai_synthesis_model,
        timeout=settings.security_ai_timeout_seconds,
        small_pricing=ModelTokenPricing(
            settings.security_ai_small_input_cost_per_million_usd,
            settings.security_ai_small_output_cost_per_million_usd,
        ),
        synthesis_pricing=ModelTokenPricing(
            settings.security_ai_synthesis_input_cost_per_million_usd,
            settings.security_ai_synthesis_output_cost_per_million_usd,
        ),
    )


def new_security_turn_execution_context() -> TurnExecutionContext:
    settings = get_settings()
    return TurnExecutionContext(
        deadline_seconds=settings.analysis_deadline_seconds,
        max_estimated_cost_usd=settings.max_provider_cost_usd,
        ai_budget=TurnBudget(max_calls=settings.security_ai_max_calls_per_turn),
    )


def new_security_assistant_runtime(
    execution_context: TurnExecutionContext | None = None,
) -> SecurityAssistantRuntime:
    """Budgets are per turn, so this dependency must never be cached."""
    settings = get_settings()
    context = execution_context or new_security_turn_execution_context()
    return SecurityAssistantRuntime(
        timeout_seconds=settings.security_ai_timeout_seconds,
        turn_deadline_seconds=settings.security_ai_turn_deadline_seconds,
        max_retries=settings.security_ai_max_retries,
        budget=context.ai_budget,
        turn_started_at=context.started_at,
        execution_context=context,
    )


async def get_security_turn_execution_context() -> TurnExecutionContext:
    """Create the end-to-end execution boundary once for this request."""
    return new_security_turn_execution_context()


SecurityTurnExecutionContextDependency = Annotated[
    TurnExecutionContext,
    Depends(get_security_turn_execution_context),
]


async def get_security_turn_runtime(
    execution_context: SecurityTurnExecutionContextDependency,
) -> SecurityAssistantRuntime:
    """One shared AI budget/deadline for the complete v4 turn.

    FastAPI caches dependency results for the lifetime of a request, so every
    AI stage receives this exact instance while different turns remain
    isolated.
    """
    return new_security_assistant_runtime(execution_context)


SecurityAssistantRuntimeDependency = Annotated[
    SecurityAssistantRuntime,
    Depends(get_security_turn_runtime),
]


async def get_security_understanding_service(
    runtime: SecurityAssistantRuntimeDependency,
) -> SecuritySemanticUnderstandingService:
    settings = get_settings()

    async def load_gazetteer_brands():
        return await get_security_trust_repository().list_active_brands(datetime.now(UTC))

    return SecuritySemanticUnderstandingService(
        enabled=settings.security_ai_understanding_enabled,
        model=get_security_assistant_model(),
        runtime=runtime,
        gazetteer_loader=load_gazetteer_brands,
    )


async def get_grounded_security_response_service(
    runtime: SecurityAssistantRuntimeDependency,
) -> GroundedSecurityResponseService:
    settings = get_settings()
    return GroundedSecurityResponseService(
        ai_enabled=settings.security_ai_explanation_enabled,
        model=get_security_assistant_model(),
        runtime=runtime,
    )


@lru_cache
def get_security_triage_scope_service() -> SecurityTriageScopeService:
    return SecurityTriageScopeService()


@lru_cache
def get_security_analysis_service() -> SecurityAnalysisService:
    settings = get_settings()
    repository = (
        PostgresPlatformRepository(
            settings.database_url,
            settings.database_encryption_key,
            content_retention_days=settings.content_retention_days,
        )
        if settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://"))
        else SQLiteBlacklistRepository(settings.security_database_path)
    )
    return SecurityAnalysisService(
        repository,
        conversation_retention_days=settings.security_conversation_retention_days,
    )


@lru_cache
def get_security_trust_repository():
    settings = get_settings()
    if settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://")):
        return PostgresPlatformRepository(
            settings.database_url,
            settings.database_encryption_key,
            content_retention_days=settings.content_retention_days,
        )
    return SQLiteBlacklistRepository(settings.security_database_path)


@lru_cache
def get_security_trust_service() -> SecurityTrustService:
    settings = get_settings()
    return SecurityTrustService(
        get_security_trust_repository(),
        source_registry=_source_registry,
        domain_familiarity_enabled=settings.security_domain_familiarity_mode != "off",
    )


@lru_cache
def get_security_trust_admin_service() -> SecurityTrustAdminService:
    return SecurityTrustAdminService(get_security_trust_repository())


@lru_cache
def get_security_memory_service() -> SecurityMemoryService:
    return SecurityMemoryService(get_security_trust_repository())


async def get_security_admin_copilot_service(
    runtime: SecurityAssistantRuntimeDependency,
) -> SecurityAdminCopilotService:
    settings = get_settings()
    return SecurityAdminCopilotService(
        get_security_analysis_service(),
        get_security_memory_service(),
        get_security_trust_repository(),
        get_security_assistant_model(),
        runtime,
        enabled=settings.security_admin_copilot_enabled,
    )


async def resolve_security_trust_service(request: Request) -> SecurityTrustService:
    override = request.app.dependency_overrides.get(get_security_trust_service)
    service = get_security_trust_service() if override is None else override()
    if hasattr(service, "__await__"):
        return await service
    return service


async def resolve_security_trust_admin_service(request: Request) -> SecurityTrustAdminService:
    override = request.app.dependency_overrides.get(get_security_trust_admin_service)
    service = get_security_trust_admin_service() if override is None else override()
    if hasattr(service, "__await__"):
        return await service
    return service


async def resolve_security_memory_service(request: Request) -> SecurityMemoryService:
    override = request.app.dependency_overrides.get(get_security_memory_service)
    service = get_security_memory_service() if override is None else override()
    if hasattr(service, "__await__"):
        return await service
    return service


async def resolve_security_analysis_service(request: Request) -> SecurityAnalysisService:
    override = request.app.dependency_overrides.get(get_security_analysis_service)
    service = get_security_analysis_service() if override is None else override()
    if hasattr(service, "__await__"):
        return await service
    return service


async def resolve_security_triage_scope_service(request: Request) -> SecurityTriageScopeService:
    override = request.app.dependency_overrides.get(get_security_triage_scope_service)
    service = get_security_triage_scope_service() if override is None else override()
    if hasattr(service, "__await__"):
        return await service
    return service


@lru_cache
def get_security_investigation_service() -> SecurityInvestigationService:
    settings = get_settings()
    postgres = settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://"))
    blacklist = (
        PostgresPlatformRepository(
            settings.database_url,
            settings.database_encryption_key,
            content_retention_days=settings.content_retention_days,
        )
        if postgres
        else SQLiteBlacklistRepository(settings.security_database_path)
    )
    reputation = None
    domain_familiarity = None
    if settings.virustotal_api_key:
        primary = VirusTotalUrlProvider(
            settings.virustotal_api_key,
            timeout=settings.provider_timeout_seconds,
        )
        reputation = ProductionUrlReputationCascade(
            primary,
            allow_secondary=False,
            max_network_calls=settings.reputation_max_network_calls,
        )
    if settings.security_domain_familiarity_mode != "off" and settings.cloudflare_radar_api_token:
        domain_familiarity = CloudflareRadarDomainFamiliarityProvider(
            settings.cloudflare_radar_api_token,
            timeout=min(settings.provider_timeout_seconds, 3.0),
        )
    return SecurityInvestigationService(
        blacklist=blacklist,
        dns=SafeDnsEvidenceResolver(),
        redirect=GuardedRedirectResolver(timeout=min(settings.provider_timeout_seconds, 5.0)),
        rdap=DomainRegistrationProvider(
            settings.bkns_whois_api_key,
            timeout=min(settings.provider_timeout_seconds, 5.0),
        ),
        reputation=reputation,
        domain_familiarity=domain_familiarity,
        domain_familiarity_enabled=settings.security_domain_familiarity_mode != "off",
        execution_ledger=blacklist,
        planning_enabled=settings.security_ai_planning_enabled,
        assistant_model=get_security_assistant_model(),
        runtime_factory=new_security_assistant_runtime,
        max_external_calls=settings.security_investigation_max_external_calls,
        max_retries=settings.security_investigation_max_retries,
        deadline_seconds=settings.security_investigation_deadline_seconds,
    )


async def close_security_investigation_service() -> None:
    if get_security_investigation_service.cache_info().currsize == 0:
        return
    service = get_security_investigation_service()
    get_security_investigation_service.cache_clear()
    await service.aclose()


async def close_security_analysis_service() -> None:
    if get_security_analysis_service.cache_info().currsize == 0:
        return
    service = get_security_analysis_service()
    get_security_analysis_service.cache_clear()
    await service.aclose()


async def close_security_trust_services() -> None:
    if get_security_trust_service.cache_info().currsize:
        service = get_security_trust_service()
        get_security_trust_service.cache_clear()
        await service.aclose()
    get_security_trust_admin_service.cache_clear()
    get_security_memory_service.cache_clear()
    get_security_blacklist_admin_service.cache_clear()
    if get_security_trust_repository.cache_info().currsize:
        repository = get_security_trust_repository()
        get_security_trust_repository.cache_clear()
        close = getattr(repository, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result


async def resolve_security_investigation_service(request: Request) -> SecurityInvestigationService:
    override = request.app.dependency_overrides.get(get_security_investigation_service)
    if override is None:
        return get_security_investigation_service()
    service = override()
    if hasattr(service, "__await__"):
        return await service
    return service


async def start_durable_worker() -> None:
    global _outbox, _outbox_task, _retention, _retention_task, _security_worker, _security_worker_task
    security_analyses = get_security_analysis_service()
    if not isinstance(security_analyses.repository, PostgresPlatformRepository):
        return
    try:
        from src.services.durable_worker import (  # noqa: PLC0415
            OutboxPublisher,
            RetentionWorker,
            SecurityV4DurableWorker,
            SecurityV4JobHandler,
        )
    except ImportError:
        if get_settings().app_env == "production":
            raise
        return
    settings = get_settings()
    if settings.security_async_execution_enabled:

        def security_pipeline_factory(runtime: SecurityAssistantRuntime) -> SecurityTriagePipeline:
            async def load_gazetteer_brands():
                return await get_security_trust_repository().list_active_brands(datetime.now(UTC))

            memory_lookup = (
                SecurityMemoryLookupTool(get_security_memory_service(), enabled=True)
                if settings.security_memory_retrieval_enabled
                else None
            )
            return SecurityTriagePipeline(
                understanding=SecuritySemanticUnderstandingService(
                    enabled=settings.security_ai_understanding_enabled,
                    model=get_security_assistant_model(),
                    runtime=runtime,
                    gazetteer_loader=load_gazetteer_brands,
                ),
                investigation=get_security_investigation_service(),
                trust=get_security_trust_service(),
                responses=GroundedSecurityResponseService(
                    ai_enabled=settings.security_ai_explanation_enabled,
                    model=get_security_assistant_model(),
                    runtime=runtime,
                ),
                official_verification_rollout=get_official_verification_rollout_stage(),
                memory_lookup=memory_lookup,
                familiarity_enforced=settings.security_domain_familiarity_mode == "enforced",
            )

        security_handler = SecurityV4JobHandler(
            security_analyses.repository,
            security_analyses,
            pipeline_factory=security_pipeline_factory,
            runtime_factory=new_security_assistant_runtime,
            memory=get_security_memory_service(),
            propose_actions=get_wave2_service().propose_security_admin_actions,
        )
        _security_worker = SecurityV4DurableWorker(
            security_analyses.repository,
            security_handler,
            lease_seconds=settings.job_lease_seconds,
        )
        _security_worker_task = asyncio.create_task(_security_worker.run(), name="security-v4-durable-worker")
    _retention = RetentionWorker(security_analyses.repository)
    _retention_task = asyncio.create_task(_retention.run(), name="retention-worker")
    try:
        _outbox = OutboxPublisher(security_analyses.repository, settings.redis_url)
        _outbox_task = asyncio.create_task(_outbox.run(), name="transactional-outbox-publisher")
    except Exception:
        import logging

        if settings.app_env == "production":
            raise
        logging.getLogger(__name__).warning("OutboxPublisher skipped: redis not available")


async def stop_durable_worker() -> None:
    global _outbox, _outbox_task, _retention, _retention_task, _security_worker, _security_worker_task
    if _security_worker is not None:
        _security_worker.stop()
    if _security_worker_task is not None:
        await _security_worker_task
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
    _outbox = None
    _outbox_task = None
    _retention = None
    _retention_task = None
    _security_worker = None
    _security_worker_task = None


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


async def resolve_ticket_manager(request: Request) -> WebSocketTicketManager:
    override = request.app.dependency_overrides.get(get_ticket_manager)
    manager = get_ticket_manager() if override is None else override()
    if hasattr(manager, "__await__"):
        return await manager
    return manager


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
    repository = get_security_analysis_service().repository
    if not isinstance(repository, PostgresPlatformRepository):
        _memory_wave2_repository.action_sink = repository
        repository = _memory_wave2_repository
    return Wave2PlatformService(repository, _source_registry)


@lru_cache
def get_security_blacklist_admin_service() -> SecurityBlacklistAdminService:
    return SecurityBlacklistAdminService(get_wave2_service())


async def resolve_wave2_service(request: Request) -> Wave2PlatformService:
    override = request.app.dependency_overrides.get(get_wave2_service)
    if override is None:
        return get_wave2_service()
    service = override()
    if hasattr(service, "__await__"):
        return await service
    return service


async def resolve_security_blacklist_admin_service(request: Request) -> SecurityBlacklistAdminService:
    override = request.app.dependency_overrides.get(get_security_blacklist_admin_service)
    service = get_security_blacklist_admin_service() if override is None else override()
    if hasattr(service, "__await__"):
        return await service
    return service


PrincipalDependency = Annotated[Principal, Depends(get_principal)]
PageCaptureServiceDependency = Annotated[PageCaptureService, Depends(get_page_capture_service)]
TicketManagerDependency = Annotated[WebSocketTicketManager, Depends(resolve_ticket_manager)]
Wave2ServiceDependency = Annotated[Wave2PlatformService, Depends(resolve_wave2_service)]
SecurityBlacklistAdminServiceDependency = Annotated[
    SecurityBlacklistAdminService, Depends(resolve_security_blacklist_admin_service)
]
SecurityTriageScopeServiceDependency = Annotated[
    SecurityTriageScopeService,
    Depends(resolve_security_triage_scope_service),
]
SecurityMemoryServiceDependency = Annotated[SecurityMemoryService, Depends(resolve_security_memory_service)]
SecurityAnalysisServiceDependency = Annotated[SecurityAnalysisService, Depends(resolve_security_analysis_service)]
SecurityAdminCopilotServiceDependency = Annotated[
    SecurityAdminCopilotService, Depends(get_security_admin_copilot_service)
]
SecurityUnderstandingServiceDependency = Annotated[
    SecuritySemanticUnderstandingService,
    Depends(get_security_understanding_service),
]
SecurityResponseServiceDependency = Annotated[
    GroundedSecurityResponseService,
    Depends(get_grounded_security_response_service),
]
SecurityTrustServiceDependency = Annotated[SecurityTrustService, Depends(resolve_security_trust_service)]
SecurityTrustAdminServiceDependency = Annotated[
    SecurityTrustAdminService, Depends(resolve_security_trust_admin_service)
]
