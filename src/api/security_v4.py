from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request, WebSocket
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketDisconnect

from src.agents.security_risk import assess_security_risk
from src.agents.tools.security_memory import SecurityMemoryLookupTool
from src.api.dependencies import (
    PrincipalDependency,
    SecurityAdminCopilotServiceDependency,
    SecurityAnalysisServiceDependency,
    SecurityAssistantRuntimeDependency,
    SecurityMemoryServiceDependency,
    SecurityResponseServiceDependency,
    SecurityTriageScopeServiceDependency,
    SecurityTrustAdminServiceDependency,
    SecurityTrustServiceDependency,
    SecurityUnderstandingServiceDependency,
    TicketManagerDependency,
    get_event_notifier,
    get_rate_limiter,
    get_security_analysis_service,
    get_ticket_manager,
    resolve_security_investigation_service,
    resolve_security_memory_service,
    resolve_wave2_service,
)
from src.config import get_settings
from src.core.auth import require_security_admin
from src.core.errors import PlatformError
from src.models import (
    AnalysisStatus,
    AppealStatus,
    BrandCreateRequestV4,
    BrandPageV4,
    BrandRecordV4,
    ErrorCode,
    ErrorEnvelope,
    PotentialThreatV4,
    ReportStatus,
    ScopeDecisionV4,
    SecurityAdminAuditPageV4,
    SecurityAdminCopilotRequestV4,
    SecurityAdminCopilotResponseV4,
    SecurityAnalysisAcceptedResponseV4,
    SecurityAnalysisEventPageV4,
    SecurityAnalysisPageV4,
    SecurityAppealAdminRecordV4,
    SecurityAppealCreateRequestV4,
    SecurityAppealDecisionRequestV4,
    SecurityAppealPageV4,
    SecurityAppealRecordV4,
    SecurityAuditResourceV4,
    SecurityCampaignAuditRecordV4,
    SecurityCampaignDecisionRequestV4,
    SecurityCampaignPageV4,
    SecurityCampaignRecordV4,
    SecurityCampaignReviewerStatusV4,
    SecurityCapabilitiesResponseV4,
    SecurityConversationPageV4,
    SecurityConversationV4,
    SecurityDomainIntelligencePageV4,
    SecurityExecutionModeV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryAuditRecordV4,
    SecurityMemoryCorrectionRequestV4,
    SecurityMemoryPageV4,
    SecurityMemoryRecordV4,
    SecurityReportAdminRecordV4,
    SecurityReportCreateRequestV4,
    SecurityReportDecisionRequestV4,
    SecurityReportPageV4,
    SecurityReportRecordV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
    SecurityThreatIntelligencePageV4,
    SecurityTriageCreateRequestV4,
    SecurityWebSocketTicketRequestV4,
    SecurityWebSocketTicketResponseV4,
    TrustLifecycleV4,
    WhitelistCreateRequestV4,
    WhitelistPageV4,
    WhitelistRecordV4,
)
from src.services.security_conversation_policy import is_incident_exposure

router = APIRouter(tags=["security-triage-v4"])

_COMMON_ERRORS = {
    403: {"model": ErrorEnvelope},
    404: {"model": ErrorEnvelope},
    409: {"model": ErrorEnvelope},
    422: {"model": ErrorEnvelope},
    429: {"model": ErrorEnvelope},
}


def _encode_cursor(sequence: int) -> str:
    return base64.urlsafe_b64encode(str(sequence).encode()).decode().rstrip("=")


def _decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        return int(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode())
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise PlatformError(
            status_code=422,
            code=ErrorCode.VALIDATION_ERROR,
            message="The event cursor is invalid.",
            retryable=False,
        ) from exc


def _page(items: list, limit: int, offset: int) -> tuple[list, int]:
    return items[offset : offset + limit], len(items)


@router.get(
    "/capabilities",
    response_model=SecurityCapabilitiesResponseV4,
    response_model_exclude_none=True,
)
async def security_capabilities_v4() -> SecurityCapabilitiesResponseV4:
    settings = get_settings()
    configured = settings.enabled_security_capabilities() if hasattr(settings, "enabled_security_capabilities") else {}
    capabilities = {name: True for name, enabled in configured.items() if enabled}
    return SecurityCapabilitiesResponseV4(
        release_profile=settings.security_release_profile,
        **capabilities,
    )


@router.post(
    "/analyses",
    response_model=SecurityScopeResponseV4,
    responses={202: {"model": SecurityAnalysisAcceptedResponseV4}, **_COMMON_ERRORS},
)
async def create_security_analysis_v4(
    request: SecurityTriageCreateRequestV4,
    service: SecurityTriageScopeServiceDependency,
    analyses: SecurityAnalysisServiceDependency,
    trust: SecurityTrustServiceDependency,
    understanding: SecurityUnderstandingServiceDependency,
    responses: SecurityResponseServiceDependency,
    ai_runtime: SecurityAssistantRuntimeDependency,
    principal: PrincipalDependency,
    http_request: Request,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=200)] = None,
) -> SecurityScopeResponseV4 | JSONResponse:
    scoped = service.assess(request)
    if request.execution_mode is SecurityExecutionModeV4.ASYNC:
        settings = get_settings()
        if not settings.security_async_execution_enabled:
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONFLICT,
                message="Async Security v4 execution is not enabled.",
                retryable=False,
            )
        if idempotency_key is None or not idempotency_key.strip():
            raise PlatformError(
                status_code=422,
                code=ErrorCode.VALIDATION_ERROR,
                message="Idempotency-Key is required for async Security v4 turns.",
                retryable=False,
            )
        accepted = await analyses.enqueue_turn(request, scoped, principal, idempotency_key.strip())
        return JSONResponse(status_code=202, content=jsonable_encoder(accepted))

    scoped = await analyses.begin_turn(request, scoped, principal)
    settings = get_settings()
    memory = None
    try:
        scoped = await understanding.enrich(request, scoped)
        if scoped.scope_decision is ScopeDecisionV4.IN_SCOPE:
            exposure = scoped.assistant_context.exposure_state if scoped.assistant_context else None
            if exposure is not None and is_incident_exposure(exposure):
                if settings.security_memory_retrieval_enabled:
                    memory = await resolve_security_memory_service(http_request)
                    scoped = await SecurityMemoryLookupTool(memory, enabled=True).enrich(
                        scoped,
                        owner_id=principal.user_id,
                    )
                scoped = assess_security_risk(
                    scoped,
                    memory_enabled=settings.security_memory_retrieval_enabled,
                )
            else:
                investigation = await resolve_security_investigation_service(http_request)
                scoped = await investigation.investigate(request, scoped, runtime=ai_runtime)
                scoped = await trust.enrich(request, scoped)
                if settings.security_memory_retrieval_enabled:
                    memory = await resolve_security_memory_service(http_request)
                    scoped = await SecurityMemoryLookupTool(memory, enabled=True).enrich(
                        scoped,
                        owner_id=principal.user_id,
                    )
                scoped = assess_security_risk(
                    scoped,
                    memory_enabled=settings.security_memory_retrieval_enabled,
                )
            scoped = await responses.enrich(scoped)
        else:
            scoped = scoped.model_copy(update={"status": AnalysisStatus.COMPLETED, "completed_at": datetime.now(UTC)})
    except Exception as exc:
        failed = scoped.model_copy(update={"status": AnalysisStatus.FAILED, "completed_at": datetime.now(UTC)})
        await analyses.persist_failed(failed, principal)
        raise PlatformError(
            status_code=500,
            code=ErrorCode.INTERNAL_ERROR,
            message="Security analysis failed.",
            retryable=True,
            details={"analysis_id": str(scoped.analysis_id)},
        ) from exc
    await analyses.persist_completed(scoped, principal)
    if scoped.risk is not None:
        try:
            memory = memory or await resolve_security_memory_service(http_request)
            await memory.record(scoped, principal.user_id)
        except Exception:
            limitations = list(dict.fromkeys([*scoped.limitations, "Không thể cập nhật Security Memory."]))
            scoped = scoped.model_copy(update={"limitations": limitations})
            await analyses.persist_completed(scoped, principal)
        try:
            wave2 = await resolve_wave2_service(http_request)
            await wave2.propose_security_admin_actions(scoped)
        except Exception:
            limitations = list(dict.fromkeys([*scoped.limitations, "Không thể tạo đề xuất HITL cho Security Admin."]))
            scoped = scoped.model_copy(update={"limitations": limitations})
            await analyses.persist_completed(scoped, principal)
    return scoped


@router.get("/admin/security-memory", response_model=list[SecurityMemoryRecordV4], responses=_COMMON_ERRORS)
async def list_security_memory_v4(
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityMemoryRecordV4]:
    return await memory.list_memory(principal)


@router.get("/admin/security-memory/page", response_model=SecurityMemoryPageV4, responses=_COMMON_ERRORS)
async def page_security_memory_v4(
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
    q: str | None = Query(default=None, max_length=253),
    risk: SecurityRiskV4 | None = None,
    verdict: SecurityMemoryAdminVerdictV4 | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityMemoryPageV4:
    records = await memory.list_memory(principal)
    if q:
        needle = q.casefold()
        records = [
            item
            for item in records
            if needle in (item.claimed_brand or "").casefold()
            or any(needle in domain.casefold() for domain in item.canonical_domains)
        ]
    if risk is not None:
        records = [item for item in records if item.risk is risk]
    if verdict is not None:
        records = [item for item in records if item.admin_verdict is verdict]
    items, total = _page(records, limit, offset)
    return SecurityMemoryPageV4(items=items, total=total, limit=limit, offset=offset)


@router.post(
    "/admin/security-memory/{memory_id}/corrections",
    response_model=SecurityMemoryRecordV4,
    responses=_COMMON_ERRORS,
)
async def correct_security_memory_v4(
    memory_id: UUID,
    request: SecurityMemoryCorrectionRequestV4,
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
) -> SecurityMemoryRecordV4:
    return await memory.correct_memory(memory_id, request.verdict, request.note, principal)


@router.get(
    "/admin/security-memory/{memory_id}/audit",
    response_model=list[SecurityMemoryAuditRecordV4],
    responses=_COMMON_ERRORS,
)
async def security_memory_audit_v4(
    memory_id: UUID,
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityMemoryAuditRecordV4]:
    return await memory.memory_audit(memory_id, principal)


@router.get(
    "/admin/security-campaigns",
    response_model=list[SecurityCampaignRecordV4],
    responses=_COMMON_ERRORS,
)
async def list_security_campaigns_v4(
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityCampaignRecordV4]:
    return await memory.list_campaigns(principal)


@router.get("/admin/security-campaigns/page", response_model=SecurityCampaignPageV4, responses=_COMMON_ERRORS)
async def page_security_campaigns_v4(
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
    status: SecurityCampaignReviewerStatusV4 | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityCampaignPageV4:
    records = await memory.list_campaigns(principal)
    if status is not None:
        records = [item for item in records if item.reviewer_status is status]
    if q:
        needle = q.casefold()
        records = [item for item in records if needle in item.hypothesis.casefold()]
    items, total = _page(records, limit, offset)
    return SecurityCampaignPageV4(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/admin/security-campaigns/{campaign_id}",
    response_model=SecurityCampaignRecordV4,
    responses=_COMMON_ERRORS,
)
async def get_security_campaign_v4(
    campaign_id: UUID,
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
) -> SecurityCampaignRecordV4:
    return await memory.get_campaign(campaign_id, principal)


@router.post(
    "/admin/security-campaigns/{campaign_id}/decision",
    response_model=SecurityCampaignRecordV4,
    responses=_COMMON_ERRORS,
)
async def review_security_campaign_v4(
    campaign_id: UUID,
    request: SecurityCampaignDecisionRequestV4,
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
) -> SecurityCampaignRecordV4:
    return await memory.review_campaign(campaign_id, request.decision, request.note, principal)


@router.get(
    "/admin/security-campaigns/{campaign_id}/audit",
    response_model=list[SecurityCampaignAuditRecordV4],
    responses=_COMMON_ERRORS,
)
async def security_campaign_audit_v4(
    campaign_id: UUID,
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityCampaignAuditRecordV4]:
    return await memory.campaign_audit(campaign_id, principal)


@router.get(
    "/admin/intelligence/domains",
    response_model=SecurityDomainIntelligencePageV4,
    responses=_COMMON_ERRORS,
)
async def list_security_domain_intelligence_v4(
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
    q: str | None = Query(default=None, max_length=253),
    risk: SecurityRiskV4 | None = None,
    threat_type: PotentialThreatV4 | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityDomainIntelligencePageV4:
    records = await memory.domain_intelligence(principal)
    if q:
        needle = q.casefold()
        records = [item for item in records if needle in item.domain.casefold()]
    if risk is not None:
        records = [item for item in records if item.risk_distribution.get(risk, 0) > 0]
    if threat_type is not None:
        records = [item for item in records if item.threat_distribution.get(threat_type, 0) > 0]
    items, total = _page(records, limit, offset)
    return SecurityDomainIntelligencePageV4(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/admin/intelligence/threats",
    response_model=SecurityThreatIntelligencePageV4,
    responses=_COMMON_ERRORS,
)
async def list_security_threat_intelligence_v4(
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
    risk: SecurityRiskV4 | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityThreatIntelligencePageV4:
    records = await memory.threat_intelligence(principal)
    if risk is not None:
        records = [item for item in records if item.risk_distribution.get(risk, 0) > 0]
    items, total = _page(records, limit, offset)
    return SecurityThreatIntelligencePageV4(items=items, total=total, limit=limit, offset=offset)


@router.get("/admin/audit", response_model=SecurityAdminAuditPageV4, responses=_COMMON_ERRORS)
async def list_security_admin_audit_v4(
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
    resource_type: SecurityAuditResourceV4 | None = None,
    action: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityAdminAuditPageV4:
    records = await analyses.list_admin_audit(principal)
    if resource_type is not None:
        records = [item for item in records if item.resource_type is resource_type]
    if action:
        records = [item for item in records if item.action == action]
    items, total = _page(records, limit, offset)
    return SecurityAdminAuditPageV4(items=items, total=total, limit=limit, offset=offset)


@router.get("/conversations", response_model=SecurityConversationPageV4, responses=_COMMON_ERRORS)
async def list_security_conversations_v4(
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityConversationPageV4:
    records = await analyses.list_conversations_for(principal)
    items, total = _page(records, limit, offset)
    return SecurityConversationPageV4(items=items, total=total, limit=limit, offset=offset)


@router.get("/conversations/{conversation_id}", response_model=SecurityConversationV4, responses=_COMMON_ERRORS)
async def get_security_conversation_v4(
    conversation_id: UUID,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> SecurityConversationV4:
    return await analyses.get_conversation_for(conversation_id, principal)


@router.post("/admin/brands", response_model=BrandRecordV4, status_code=201, responses=_COMMON_ERRORS)
async def create_brand_v4(
    request: BrandCreateRequestV4,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> BrandRecordV4:
    return await admin.create_brand(request, principal)


@router.get("/admin/brands", response_model=list[BrandRecordV4], responses=_COMMON_ERRORS)
async def list_brands_v4(
    admin: SecurityTrustAdminServiceDependency, principal: PrincipalDependency
) -> list[BrandRecordV4]:
    return await admin.list_brands(principal)


@router.get("/admin/brands/page", response_model=BrandPageV4, responses=_COMMON_ERRORS)
async def page_brands_v4(
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
    lifecycle: TrustLifecycleV4 | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> BrandPageV4:
    records = await admin.list_brands(principal)
    if lifecycle is not None:
        records = [item for item in records if item.lifecycle is lifecycle]
    if q:
        needle = q.casefold()
        records = [
            item
            for item in records
            if needle in item.name.casefold()
            or any(needle in alias.casefold() for alias in item.aliases)
            or any(needle in domain.casefold() for domain in item.official_domains)
        ]
    items, total = _page(records, limit, offset)
    return BrandPageV4(items=items, total=total, limit=limit, offset=offset)


@router.post("/admin/brands/{brand_id}/disable", response_model=BrandRecordV4, responses=_COMMON_ERRORS)
async def disable_brand_v4(
    brand_id: UUID,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> BrandRecordV4:
    return await admin.disable_brand(str(brand_id), principal)


@router.post("/admin/whitelist", response_model=WhitelistRecordV4, status_code=201, responses=_COMMON_ERRORS)
async def create_whitelist_v4(
    request: WhitelistCreateRequestV4,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> WhitelistRecordV4:
    return await admin.create_whitelist(request, principal)


@router.get("/admin/whitelist", response_model=list[WhitelistRecordV4], responses=_COMMON_ERRORS)
async def list_whitelist_v4(
    admin: SecurityTrustAdminServiceDependency, principal: PrincipalDependency
) -> list[WhitelistRecordV4]:
    return await admin.list_whitelist(principal)


@router.get("/admin/whitelist/page", response_model=WhitelistPageV4, responses=_COMMON_ERRORS)
async def page_whitelist_v4(
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
    lifecycle: TrustLifecycleV4 | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> WhitelistPageV4:
    records = await admin.list_whitelist(principal)
    if lifecycle is not None:
        records = [item for item in records if item.lifecycle is lifecycle]
    if q:
        needle = q.casefold()
        records = [item for item in records if needle in item.indicator.casefold()]
    items, total = _page(records, limit, offset)
    return WhitelistPageV4(items=items, total=total, limit=limit, offset=offset)


@router.post("/admin/whitelist/{whitelist_id}/disable", response_model=WhitelistRecordV4, responses=_COMMON_ERRORS)
async def disable_whitelist_v4(
    whitelist_id: UUID,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> WhitelistRecordV4:
    return await admin.disable_whitelist(str(whitelist_id), principal)


@router.get("/analyses/page", response_model=SecurityAnalysisPageV4, responses=_COMMON_ERRORS)
async def page_security_analyses_v4(
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
    scope_decision: ScopeDecisionV4 | None = None,
    risk: SecurityRiskV4 | None = None,
    threat_type: PotentialThreatV4 | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityAnalysisPageV4:
    records = await analyses.list_for(principal)
    if scope_decision is not None:
        records = [item for item in records if item.scope_decision is scope_decision]
    if risk is not None:
        records = [item for item in records if item.risk is risk]
    if threat_type is not None:
        records = [item for item in records if item.threat_type is threat_type]
    if q:
        needle = q.casefold()
        records = [
            item
            for item in records
            if item.security_context is not None
            and (
                needle in (item.security_context.claimed_entity or "").casefold()
                or any(needle in url.casefold() for url in item.security_context.urls)
            )
        ]
    items, total = _page(records, limit, offset)
    return SecurityAnalysisPageV4(items=items, total=total, limit=limit, offset=offset)


@router.get("/admin/reports", response_model=SecurityReportPageV4, responses=_COMMON_ERRORS)
async def list_security_reports_admin_v4(
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
    status: ReportStatus | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityReportPageV4:
    records = await analyses.list_reports_admin(principal, status=status)
    if q:
        needle = q.casefold()
        records = [
            item
            for item in records
            if needle in item.owner_id.casefold()
            or needle in item.reason.casefold()
            or needle in (item.comment or "").casefold()
            or needle in str(item.analysis_id)
        ]
    items, total = _page(records, limit, offset)
    return SecurityReportPageV4(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/admin/analyses/{analysis_id}",
    response_model=SecurityScopeResponseV4,
    responses=_COMMON_ERRORS,
)
async def get_security_analysis_admin_v4(
    analysis_id: UUID,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> SecurityScopeResponseV4:
    return await analyses.get_for_admin(analysis_id, principal)


@router.post(
    "/admin/analyses/{analysis_id}/copilot",
    response_model=SecurityAdminCopilotResponseV4,
    responses=_COMMON_ERRORS,
)
async def draft_security_admin_copilot_v4(
    analysis_id: UUID,
    request: SecurityAdminCopilotRequestV4,
    copilot: SecurityAdminCopilotServiceDependency,
    principal: PrincipalDependency,
) -> SecurityAdminCopilotResponseV4:
    require_security_admin(principal)
    settings = get_settings()
    if not await get_rate_limiter().allow(
        f"security-admin-copilot:{principal.user_id}:{analysis_id}",
        settings.security_admin_copilot_rate_limit_per_minute,
    ):
        raise PlatformError(
            status_code=429,
            code=ErrorCode.RATE_LIMITED,
            message="Security Admin Copilot refresh rate limit exceeded.",
            retryable=True,
        )
    return await copilot.suggest(analysis_id, principal, refresh=request.refresh)


@router.post(
    "/admin/reports/{report_id}/decision",
    response_model=SecurityReportAdminRecordV4,
    responses=_COMMON_ERRORS,
)
async def decide_security_report_admin_v4(
    report_id: UUID,
    request: SecurityReportDecisionRequestV4,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> SecurityReportAdminRecordV4:
    return await analyses.decide_report(report_id, request.decision, request.note, principal)


@router.get("/admin/appeals", response_model=SecurityAppealPageV4, responses=_COMMON_ERRORS)
async def list_security_appeals_admin_v4(
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
    status: AppealStatus | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityAppealPageV4:
    records = await analyses.list_appeals_admin(principal, status=status)
    if q:
        needle = q.casefold()
        records = [
            item
            for item in records
            if needle in item.owner_id.casefold()
            or needle in item.reason.casefold()
            or needle in (item.comment or "").casefold()
            or needle in str(item.analysis_id)
        ]
    items, total = _page(records, limit, offset)
    return SecurityAppealPageV4(items=items, total=total, limit=limit, offset=offset)


@router.post(
    "/admin/appeals/{appeal_id}/decision",
    response_model=SecurityAppealAdminRecordV4,
    responses=_COMMON_ERRORS,
)
async def decide_security_appeal_admin_v4(
    appeal_id: UUID,
    request: SecurityAppealDecisionRequestV4,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> SecurityAppealAdminRecordV4:
    return await analyses.decide_appeal(appeal_id, request.outcome, request.note, principal)


@router.get("/analyses/{analysis_id}", response_model=SecurityScopeResponseV4, responses=_COMMON_ERRORS)
async def get_security_analysis_v4(
    analysis_id: UUID,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> SecurityScopeResponseV4:
    return await analyses.get_for(analysis_id, principal)


@router.get("/analyses", response_model=list[SecurityScopeResponseV4], responses=_COMMON_ERRORS)
async def list_security_analyses_v4(
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityScopeResponseV4]:
    return await analyses.list_for(principal)


@router.post(
    "/analyses/{analysis_id}/reports",
    response_model=SecurityReportRecordV4,
    status_code=201,
    responses=_COMMON_ERRORS,
)
async def create_security_report_v4(
    analysis_id: UUID,
    request: SecurityReportCreateRequestV4,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> SecurityReportRecordV4:
    return await analyses.create_report(analysis_id, request, principal)


@router.get(
    "/analyses/{analysis_id}/reports",
    response_model=list[SecurityReportRecordV4],
    responses=_COMMON_ERRORS,
)
async def list_security_reports_v4(
    analysis_id: UUID,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityReportRecordV4]:
    return await analyses.list_reports_for(analysis_id, principal)


@router.post(
    "/analyses/{analysis_id}/appeals",
    response_model=SecurityAppealRecordV4,
    status_code=201,
    responses=_COMMON_ERRORS,
)
async def create_security_appeal_v4(
    analysis_id: UUID,
    request: SecurityAppealCreateRequestV4,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> SecurityAppealRecordV4:
    return await analyses.create_appeal(analysis_id, request, principal)


@router.get(
    "/analyses/{analysis_id}/appeals",
    response_model=list[SecurityAppealRecordV4],
    responses=_COMMON_ERRORS,
)
async def list_security_appeals_v4(
    analysis_id: UUID,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityAppealRecordV4]:
    return await analyses.list_appeals_for(analysis_id, principal)


@router.get("/analyses/{analysis_id}/events", response_model=SecurityAnalysisEventPageV4, responses=_COMMON_ERRORS)
async def security_analysis_events_v4(
    analysis_id: UUID,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
    cursor: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
) -> SecurityAnalysisEventPageV4:
    after = _decode_cursor(cursor)
    events = [event for event in await analyses.events_for(analysis_id, principal) if event.sequence > after][:limit]
    return SecurityAnalysisEventPageV4(
        events=events,
        next_cursor=_encode_cursor(events[-1].sequence) if events else cursor,
    )


@router.post("/ws-tickets", response_model=SecurityWebSocketTicketResponseV4, status_code=201, responses=_COMMON_ERRORS)
async def create_security_websocket_ticket_v4(
    request: SecurityWebSocketTicketRequestV4,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
    tickets: TicketManagerDependency,
) -> SecurityWebSocketTicketResponseV4:
    await analyses.get_for(request.analysis_id, principal)
    ticket, expires_at = await tickets.issue(request.analysis_id, principal)
    return SecurityWebSocketTicketResponseV4(
        ticket=ticket,
        analysis_id=request.analysis_id,
        expires_at=expires_at,
        stream_path=f"/api/v4/analyses/{request.analysis_id}/stream",
    )


@router.websocket("/analyses/{analysis_id}/stream")
async def security_analysis_stream_v4(
    websocket: WebSocket,
    analysis_id: UUID,
    ticket: str = Query(max_length=256),
    cursor: str | None = Query(default=None, max_length=128),
) -> None:
    ticket_factory = websocket.app.dependency_overrides.get(get_ticket_manager, get_ticket_manager)
    tickets = ticket_factory()
    if hasattr(tickets, "__await__"):
        tickets = await tickets
    principal = await tickets.consume(ticket, analysis_id)
    if principal is None:
        await websocket.close(code=4403, reason="Invalid or expired WebSocket ticket.")
        return
    service_factory = websocket.app.dependency_overrides.get(
        get_security_analysis_service, get_security_analysis_service
    )
    analyses = service_factory()
    if hasattr(analyses, "__await__"):
        analyses = await analyses
    try:
        after = _decode_cursor(cursor)
        await analyses.get_for(analysis_id, principal)
    except PlatformError:
        await websocket.close(code=4403, reason="Security analysis access denied.")
        return
    await websocket.accept()
    notifier_factory = websocket.app.dependency_overrides.get(get_event_notifier, get_event_notifier)
    notifier = notifier_factory()
    if hasattr(notifier, "__await__"):
        notifier = await notifier
    listener = await notifier.listen(analysis_id)
    try:
        while True:
            fresh = [event for event in await analyses.events_for(analysis_id, principal) if event.sequence > after]
            for event in fresh:
                await websocket.send_json(jsonable_encoder(event))
                after = event.sequence
            if fresh and fresh[-1].status in {AnalysisStatus.COMPLETED, AnalysisStatus.FAILED}:
                await websocket.close(code=1000, reason="Security analysis reached a terminal state.")
                return
            await listener.wait(15.0)
    except (WebSocketDisconnect, RuntimeError):
        return
    finally:
        await listener.close()


__all__ = ["router"]
