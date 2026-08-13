from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Query, Request, WebSocket
from fastapi.encoders import jsonable_encoder
from starlette.websockets import WebSocketDisconnect

from src.agents.security_risk import assess_security_risk
from src.api.dependencies import (
    PrincipalDependency,
    SecurityAnalysisServiceDependency,
    SecurityMemoryServiceDependency,
    SecurityTriageScopeServiceDependency,
    SecurityTrustAdminServiceDependency,
    SecurityTrustServiceDependency,
    TicketManagerDependency,
    get_security_analysis_service,
    get_ticket_manager,
    resolve_security_investigation_service,
    resolve_security_memory_service,
    resolve_wave2_service,
)
from src.core.errors import PlatformError
from src.models import (
    AnalysisStatus,
    BrandCreateRequestV4,
    BrandRecordV4,
    ErrorCode,
    ErrorEnvelope,
    ScopeDecisionV4,
    SecurityAnalysisEventPageV4,
    SecurityAppealCreateRequestV4,
    SecurityAppealRecordV4,
    SecurityCampaignAuditRecordV4,
    SecurityCampaignDecisionRequestV4,
    SecurityCampaignRecordV4,
    SecurityConversationV4,
    SecurityMemoryAuditRecordV4,
    SecurityMemoryCorrectionRequestV4,
    SecurityMemoryRecordV4,
    SecurityReportCreateRequestV4,
    SecurityReportRecordV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    SecurityWebSocketTicketRequestV4,
    SecurityWebSocketTicketResponseV4,
    WhitelistCreateRequestV4,
    WhitelistRecordV4,
)

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


@router.post("/analyses", response_model=SecurityScopeResponseV4, responses=_COMMON_ERRORS)
async def create_security_analysis_v4(
    request: SecurityTriageCreateRequestV4,
    service: SecurityTriageScopeServiceDependency,
    analyses: SecurityAnalysisServiceDependency,
    trust: SecurityTrustServiceDependency,
    principal: PrincipalDependency,
    http_request: Request,
) -> SecurityScopeResponseV4:
    scoped = service.assess(request)
    scoped = await analyses.begin_turn(request, scoped, principal)
    try:
        if scoped.scope_decision is ScopeDecisionV4.IN_SCOPE:
            investigation = await resolve_security_investigation_service(http_request)
            scoped = await investigation.investigate(request, scoped)
            scoped = assess_security_risk(await trust.enrich(request, scoped))
        else:
            scoped = scoped.model_copy(
                update={"status": AnalysisStatus.COMPLETED, "completed_at": datetime.now(UTC)}
            )
    except Exception as exc:
        failed = scoped.model_copy(
            update={"status": AnalysisStatus.FAILED, "completed_at": datetime.now(UTC)}
        )
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
            memory = await resolve_security_memory_service(http_request)
            await memory.record(scoped)
        except Exception:
            limitations = list(
                dict.fromkeys([*scoped.limitations, "Không thể cập nhật Security Memory."])
            )
            scoped = scoped.model_copy(update={"limitations": limitations})
            await analyses.persist_completed(scoped, principal)
        try:
            wave2 = await resolve_wave2_service(http_request)
            await wave2.propose_security_admin_actions(scoped)
        except Exception:
            limitations = list(
                dict.fromkeys([*scoped.limitations, "Không thể tạo đề xuất HITL cho Security Admin."])
            )
            scoped = scoped.model_copy(update={"limitations": limitations})
            await analyses.persist_completed(scoped, principal)
    return scoped


@router.get("/admin/security-memory", response_model=list[SecurityMemoryRecordV4], responses=_COMMON_ERRORS)
async def list_security_memory_v4(
    memory: SecurityMemoryServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityMemoryRecordV4]:
    return await memory.list_memory(principal)


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
    "/conversations/{conversation_id}", response_model=SecurityConversationV4, responses=_COMMON_ERRORS
)
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


@router.post("/admin/brands/{brand_id}/disable", response_model=BrandRecordV4, responses=_COMMON_ERRORS)
async def disable_brand_v4(
    brand_id: UUID,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> BrandRecordV4:
    return await admin.disable_brand(str(brand_id), principal)


@router.post(
    "/admin/whitelist", response_model=WhitelistRecordV4, status_code=201, responses=_COMMON_ERRORS
)
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


@router.post(
    "/admin/whitelist/{whitelist_id}/disable", response_model=WhitelistRecordV4, responses=_COMMON_ERRORS
)
async def disable_whitelist_v4(
    whitelist_id: UUID,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> WhitelistRecordV4:
    return await admin.disable_whitelist(str(whitelist_id), principal)


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


@router.get(
    "/analyses/{analysis_id}/events", response_model=SecurityAnalysisEventPageV4, responses=_COMMON_ERRORS
)
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


@router.post(
    "/ws-tickets", response_model=SecurityWebSocketTicketResponseV4, status_code=201, responses=_COMMON_ERRORS
)
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
    try:
        for event in await analyses.events_for(analysis_id, principal):
            if event.sequence > after:
                await websocket.send_json(jsonable_encoder(event))
        await websocket.close(code=1000, reason="Security analysis reached a terminal state.")
    except (WebSocketDisconnect, RuntimeError):
        return


__all__ = ["router"]
