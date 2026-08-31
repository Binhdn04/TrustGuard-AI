from __future__ import annotations

import base64
import binascii
import json
import unicodedata
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request, WebSocket
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response
from starlette.websockets import WebSocketDisconnect

from src.agents.tools.security_memory import SecurityMemoryLookupTool
from src.api.dependencies import (
    PageCaptureServiceDependency,
    PrincipalDependency,
    SecurityAdminCopilotServiceDependency,
    SecurityAnalysisServiceDependency,
    SecurityAssistantRuntimeDependency,
    SecurityBlacklistAdminServiceDependency,
    SecurityMemoryServiceDependency,
    SecurityResponseServiceDependency,
    SecurityTriageScopeServiceDependency,
    SecurityTrustAdminServiceDependency,
    SecurityTrustServiceDependency,
    SecurityUnderstandingServiceDependency,
    TicketManagerDependency,
    get_event_notifier,
    get_official_verification_rollout_stage,
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
    AdminActionAuditRecordV3,
    AdminActionDecisionRequestV3,
    AdminActionDecisionResponseV3,
    AdminActionPageV3,
    AdminActionRecordV3,
    AdminActionStatus,
    AnalysisStatus,
    AppealStatus,
    BrandCreateRequestV4,
    BrandPageV4,
    BrandRecordV4,
    ErrorCode,
    ErrorEnvelope,
    IdentityAssociationAssuranceV4,
    IdentityCandidateDecisionRequestV4,
    IdentityCandidatePageV4,
    IdentityCandidateV4,
    IdentityRelationshipV4,
    ManualIdentityCandidateCreateRequestV4,
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
    SecurityBlacklistActionProposalV4,
    SecurityBlacklistActionStatusV4,
    SecurityBlacklistAuditRecordV4,
    SecurityBlacklistDecisionRequestV4,
    SecurityBlacklistDecisionResponseV4,
    SecurityBlacklistDisableRequestV4,
    SecurityBlacklistLifecycleV4,
    SecurityBlacklistPageV4,
    SecurityBlacklistProposalRequestV4,
    SecurityBlacklistRecordV4,
    SecurityCampaignAuditRecordV4,
    SecurityCampaignDecisionRequestV4,
    SecurityCampaignPageV4,
    SecurityCampaignRecordV4,
    SecurityCampaignReviewerStatusV4,
    SecurityCapabilitiesResponseV4,
    SecurityChatRequestV4,
    SecurityChatResponseV4,
    SecurityChatRouteV4,
    SecurityConversationPageV4,
    SecurityConversationV4,
    SecurityDomainIntelligencePageV4,
    SecurityExecutionModeV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryAuditRecordV4,
    SecurityMemoryCorrectionRequestV4,
    SecurityMemoryPageV4,
    SecurityMemoryRecordV4,
    SecurityPageCaptureRequestV4,
    SecurityReportAdminRecordV4,
    SecurityReportCreateRequestV4,
    SecurityReportDecisionRequestV4,
    SecurityReportPageV4,
    SecurityReportRecordV4,
    SecurityReportRemediationActionV4,
    SecurityReportRemediationReferenceV4,
    SecurityReportRemediationStatusV4,
    SecurityReportRemediationUpdateV4,
    SecurityReportResolutionV4,
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
from src.observability.langfuse import get_langfuse_observability
from src.services.page_capture import PageCaptureError
from src.services.security_pipeline import SecurityTriagePipeline

router = APIRouter(tags=["security-triage-v4"])

_COMMON_ERRORS = {
    403: {"model": ErrorEnvelope},
    404: {"model": ErrorEnvelope},
    409: {"model": ErrorEnvelope},
    422: {"model": ErrorEnvelope},
    429: {"model": ErrorEnvelope},
}


async def _complete_report_for_admin_action(action_id, status, execution_error, analyses, principal) -> None:
    report = await analyses.report_for_admin_action(action_id, principal)
    if report is None or report.remediation_status is not SecurityReportRemediationStatusV4.PENDING:
        return
    executed = status.value == SecurityBlacklistActionStatusV4.EXECUTED.value
    await analyses.record_report_remediation(
        report.report_id,
        SecurityReportRemediationUpdateV4(
            status=(
                SecurityReportRemediationStatusV4.EXECUTED if executed else SecurityReportRemediationStatusV4.FAILED
            ),
            # Keep the reviewed-action linkage even when review rejects the
            # proposal or execution fails. Operators still need to trace the
            # terminal report remediation back to its immutable action audit.
            reference=SecurityReportRemediationReferenceV4(admin_action_id=action_id),
            note=("Reviewed blacklist action executed." if executed else execution_error or "Action rejected."),
            evidence_refs=[],
        ),
        principal,
    )


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


_HISTORY_ACTION_SEARCH_ALIASES = {
    "login": "đăng nhập liên kết",
    "share_otp": "chia sẻ mã otp",
    "share_credentials": "cung cấp thông tin đăng nhập mật khẩu",
    "transfer_money": "chuyển tiền",
    "pay_fee": "thanh toán phí",
    "provide_personal_information": "cung cấp thông tin cá nhân",
    "open_link": "kiểm tra mở liên kết website",
    "install_app": "cài đặt ứng dụng",
    "share_screen": "chia sẻ màn hình",
    "scan_qr": "quét mã qr",
    "submit_form": "điền biểu mẫu",
    "register_or_apply": "đăng ký nộp đơn trực tuyến",
    "download_file": "tải xuống tệp",
}

_HISTORY_SCENARIO_SEARCH_ALIASES = {
    "recruitment": "tuyển dụng việc làm",
    "promotion_prize": "khuyến mãi trúng thưởng",
    "charity": "từ thiện",
    "investment": "đầu tư",
    "online_task": "nhiệm vụ trực tuyến",
    "account_verification": "xác minh tài khoản",
    "payment": "thanh toán",
    "refund": "hoàn tiền",
}


def _fold_history_search(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    folded = "".join(character for character in decomposed if not unicodedata.combining(character))
    return " ".join(folded.replace("đ", "d").replace("_", " ").replace("-", " ").split())


def _history_search_document(item: SecurityScopeResponseV4) -> str:
    values: list[str] = []
    context = item.security_context
    if context is not None:
        action = context.requested_action.value if context.requested_action is not None else None
        scenario = context.scenario.value
        values.extend(
            value
            for value in (
                context.claimed_entity,
                *context.urls,
                action,
                _HISTORY_ACTION_SEARCH_ALIASES.get(action or ""),
                scenario,
                _HISTORY_SCENARIO_SEARCH_ALIASES.get(scenario),
                context.potential_threat.value,
            )
            if value
        )
    verification = item.official_verification
    if verification is not None:
        intent = verification.intent
        values.extend(
            value
            for value in (
                intent.organization_name,
                *intent.derived_organization_names,
                intent.claim_summary,
                intent.topic.value if intent.topic is not None else None,
                intent.requested_action.value if intent.requested_action is not None else None,
            )
            if value
        )
    if item.assistant_response is not None:
        values.append(item.assistant_response.summary)
    return _fold_history_search(" ".join(values))


def _chat_context_document(
    conversation: SecurityConversationV4,
    active: SecurityScopeResponseV4,
) -> str:
    context = conversation.summary.security_context
    assistant = conversation.summary.assistant_context
    structured_context = None
    if context is not None:
        structured_context = {
            "claimed_entity": context.claimed_entity,
            "scenario": context.scenario.value,
            "requested_action": context.requested_action.value if context.requested_action is not None else None,
            "amount": context.amount,
            "urgency": context.urgency,
            "urls": context.urls,
            "credential_request": context.credential_request,
            "otp_request": context.otp_request,
            "payment_request": context.payment_request,
            "personal_information_request": context.personal_information_request,
            "impersonation_signals": context.impersonation_signals,
            "potential_threat": context.potential_threat.value,
        }
    assistant_context = None
    if assistant is not None:
        assistant_context = {
            "exposure_state": assistant.exposure_state.value,
            "missing_information": assistant.missing_information,
        }
    assessment = {
        "risk": active.risk.value if active.risk is not None else None,
        "threat_type": active.threat_type.value if active.threat_type is not None else None,
        "recommended_actions": [item.value for item in active.recommended_actions],
        "assistant_summary": active.assistant_response.summary if active.assistant_response is not None else None,
    }
    return json.dumps(
        {
            "schema": "security-chat-context-v1",
            "conversation_version": conversation.context_version,
            "security_context": structured_context,
            "assistant_context": assistant_context,
            "current_assessment": assessment,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


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


@router.get("/admin/actions", response_model=AdminActionPageV3, responses=_COMMON_ERRORS)
async def list_admin_actions_v4(
    principal: PrincipalDependency,
    http_request: Request,
    action_status: AdminActionStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> AdminActionPageV3:
    require_security_admin(principal)
    wave2 = await resolve_wave2_service(http_request)
    return await wave2.list_admin_actions(action_status, limit, offset)


@router.get("/admin/actions/{action_id}", response_model=AdminActionRecordV3, responses=_COMMON_ERRORS)
async def get_admin_action_v4(
    action_id: UUID,
    principal: PrincipalDependency,
    http_request: Request,
) -> AdminActionRecordV3:
    require_security_admin(principal)
    wave2 = await resolve_wave2_service(http_request)
    return await wave2.get_admin_action(action_id)


@router.post(
    "/admin/actions/{action_id}/decision",
    response_model=AdminActionDecisionResponseV3,
    responses=_COMMON_ERRORS,
)
async def decide_admin_action_v4(
    action_id: UUID,
    request: AdminActionDecisionRequestV3,
    principal: PrincipalDependency,
    analyses: SecurityAnalysisServiceDependency,
    http_request: Request,
) -> AdminActionDecisionResponseV3:
    require_security_admin(principal)
    wave2 = await resolve_wave2_service(http_request)
    result = await wave2.decide_admin_action(action_id, request.decision, request.note, principal.user_id)
    await _complete_report_for_admin_action(action_id, result.status, result.execution_error, analyses, principal)
    return result


@router.get(
    "/admin/actions/{action_id}/audit",
    response_model=list[AdminActionAuditRecordV3],
    responses=_COMMON_ERRORS,
)
async def list_admin_action_audit_v4(
    action_id: UUID,
    principal: PrincipalDependency,
    http_request: Request,
) -> list[AdminActionAuditRecordV3]:
    require_security_admin(principal)
    wave2 = await resolve_wave2_service(http_request)
    return await wave2.list_admin_action_audit(action_id)


@router.get(
    "/admin/blacklist/page",
    response_model=SecurityBlacklistPageV4,
    responses=_COMMON_ERRORS,
)
async def list_security_blacklist_admin_v4(
    blacklist: SecurityBlacklistAdminServiceDependency,
    principal: PrincipalDependency,
    q: str | None = Query(default=None, max_length=200),
    lifecycle: SecurityBlacklistLifecycleV4 | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> SecurityBlacklistPageV4:
    return await blacklist.list_records(principal, q=q, lifecycle=lifecycle, limit=limit, offset=offset)


@router.post(
    "/admin/blacklist/proposals",
    response_model=SecurityBlacklistActionProposalV4,
    status_code=201,
    responses=_COMMON_ERRORS,
)
async def propose_security_blacklist_admin_v4(
    request: SecurityBlacklistProposalRequestV4,
    blacklist: SecurityBlacklistAdminServiceDependency,
    principal: PrincipalDependency,
) -> SecurityBlacklistActionProposalV4:
    return await blacklist.propose_add(request, principal)


@router.post(
    "/admin/blacklist/actions/{action_id}/decision",
    response_model=SecurityBlacklistDecisionResponseV4,
    responses=_COMMON_ERRORS,
)
async def decide_security_blacklist_action_admin_v4(
    action_id: UUID,
    request: SecurityBlacklistDecisionRequestV4,
    blacklist: SecurityBlacklistAdminServiceDependency,
    analyses: SecurityAnalysisServiceDependency,
    principal: PrincipalDependency,
) -> SecurityBlacklistDecisionResponseV4:
    result = await blacklist.decide(action_id, request.decision, request.note, principal)
    await _complete_report_for_admin_action(action_id, result.status, result.execution_error, analyses, principal)
    return result


@router.get(
    "/admin/blacklist/{blacklist_id}",
    response_model=SecurityBlacklistRecordV4,
    responses=_COMMON_ERRORS,
)
async def get_security_blacklist_admin_v4(
    blacklist_id: UUID,
    blacklist: SecurityBlacklistAdminServiceDependency,
    principal: PrincipalDependency,
) -> SecurityBlacklistRecordV4:
    return await blacklist.get_record(blacklist_id, principal)


@router.post(
    "/admin/blacklist/{blacklist_id}/disable-proposals",
    response_model=SecurityBlacklistActionProposalV4,
    status_code=201,
    responses=_COMMON_ERRORS,
)
async def propose_disable_security_blacklist_admin_v4(
    blacklist_id: UUID,
    request: SecurityBlacklistDisableRequestV4,
    blacklist: SecurityBlacklistAdminServiceDependency,
    principal: PrincipalDependency,
) -> SecurityBlacklistActionProposalV4:
    return await blacklist.propose_disable(blacklist_id, request, principal)


@router.get(
    "/admin/blacklist/{blacklist_id}/audit",
    response_model=list[SecurityBlacklistAuditRecordV4],
    responses=_COMMON_ERRORS,
)
async def list_security_blacklist_audit_admin_v4(
    blacklist_id: UUID,
    blacklist: SecurityBlacklistAdminServiceDependency,
    principal: PrincipalDependency,
) -> list[SecurityBlacklistAuditRecordV4]:
    return await blacklist.list_audit(blacklist_id, principal)


@router.post("/chat", response_model=SecurityChatResponseV4, responses=_COMMON_ERRORS)
async def security_chat_v4(
    request: SecurityChatRequestV4,
    principal: PrincipalDependency,
    service: SecurityTriageScopeServiceDependency,
    analyses: SecurityAnalysisServiceDependency,
    responses: SecurityResponseServiceDependency,
) -> SecurityChatResponseV4:
    """Route a follow-up through the bounded chatbot before opening another analysis turn."""
    retained_context = ""
    if request.conversation_id is not None:
        conversation = await analyses.get_conversation_for(request.conversation_id, principal)
        if conversation.context_version != request.conversation_version:
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONVERSATION_VERSION_STALE,
                message="The security conversation version is stale.",
                retryable=True,
                details={"current_version": conversation.context_version},
            )
        active = await analyses.get_for(conversation.active_analysis_id, principal)
        retained_context = _chat_context_document(conversation, active)
    local = service.assess(SecurityTriageCreateRequestV4(message=request.message))
    if set(local.scope_reasons) & {"assistant_capabilities", "assistant_greeting"}:
        local = await responses.enrich_terminal(local)
        assert local.boundary_message is not None
        return SecurityChatResponseV4(
            route=SecurityChatRouteV4.CONVERSATION,
            response=local.boundary_message,
        )
    from src.agents.graph import agent as chatbot_agent  # noqa: PLC0415

    try:
        observability = get_langfuse_observability()
        with observability.trace(
            "security-chat",
            feature="chat",
            user_id=principal.user_id,
            session_id=str(request.conversation_id) if request.conversation_id else None,
            input={"message": request.message},
        ) as trace:
            agent_input = {"query": request.message, "context": retained_context}
            if observability.enabled:
                result = await chatbot_agent.ainvoke(
                    agent_input,
                    config=observability.langchain_config("security-chat-agent"),
                )
            else:
                result = await chatbot_agent.ainvoke(agent_input)
            if trace is not None:
                trace.update(output={"status": "ok", "response": result.get("response", "")})
    except Exception as exc:
        raise PlatformError(
            status_code=503,
            code=ErrorCode.INTERNAL_ERROR,
            message="Security assistant chat is temporarily unavailable.",
            retryable=True,
        ) from exc
    try:
        metadata = json.loads(result.get("analysis", ""))
    except (TypeError, json.JSONDecodeError):
        metadata = {}
    tools_called = metadata.get("tools_called", []) if isinstance(metadata, dict) else []
    route = (
        SecurityChatRouteV4.SECURITY_ANALYSIS
        if isinstance(tools_called, list) and "check_scam" in tools_called
        else SecurityChatRouteV4.CONVERSATION
    )
    return SecurityChatResponseV4(route=route, response=result.get("response", ""))


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

    async def resolve_investigation():
        return await resolve_security_investigation_service(http_request)

    async def resolve_memory_lookup() -> SecurityMemoryLookupTool:
        nonlocal memory
        memory = memory or await resolve_security_memory_service(http_request)
        return SecurityMemoryLookupTool(memory, enabled=True)

    pipeline = SecurityTriagePipeline(
        understanding=understanding,
        investigation_resolver=resolve_investigation,
        trust=trust,
        responses=responses,
        official_verification_rollout=get_official_verification_rollout_stage(),
        memory_lookup_resolver=resolve_memory_lookup if settings.security_memory_retrieval_enabled else None,
        familiarity_enforced=settings.security_domain_familiarity_mode == "enforced",
    )
    try:
        observability = get_langfuse_observability()
        with observability.trace(
            "security-analysis",
            feature="analysis",
            user_id=principal.user_id,
            session_id=str(scoped.conversation_id),
            input={"message": request.message},
        ) as trace:
            scoped = await pipeline.process(
                request,
                scoped,
                runtime=ai_runtime,
                owner_id=principal.user_id,
            )
            if trace is not None:
                trace.update(
                    output={
                        "status": scoped.status.value,
                        "scope": scoped.scope_decision.value,
                        "risk": scoped.risk.value if scoped.risk else None,
                        "score": scoped.score,
                        "confidence": scoped.confidence,
                        "threat_type": scoped.threat_type.value if scoped.threat_type else None,
                        "investigation_status": scoped.investigation_status.value,
                        "tool_calls_used": scoped.tool_calls_used,
                        "errors": [
                            {
                                "tool": error.tool.value,
                                "code": error.code,
                                "provider": error.provider,
                                "retryable": error.retryable,
                            }
                            for error in scoped.errors
                        ],
                        "assistant_response": (
                            scoped.assistant_response.model_dump(mode="json")
                            if scoped.assistant_response is not None
                            else None
                        ),
                    }
                )
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
            or any(
                needle in identity.canonical_value.casefold()
                or needle in identity.display_value.casefold()
                or needle in identity.entity_name.casefold()
                for identity in item.official_identities
            )
        ]
    items, total = _page(records, limit, offset)
    return BrandPageV4(items=items, total=total, limit=limit, offset=offset)


@router.post(
    "/admin/brands/{brand_id}/versions",
    response_model=BrandRecordV4,
    status_code=201,
    responses=_COMMON_ERRORS,
)
async def create_brand_version_v4(
    brand_id: UUID,
    request: BrandCreateRequestV4,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> BrandRecordV4:
    return await admin.create_brand_version(str(brand_id), request, principal)


@router.post("/admin/brands/{brand_id}/disable", response_model=BrandRecordV4, responses=_COMMON_ERRORS)
async def disable_brand_v4(
    brand_id: UUID,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> BrandRecordV4:
    return await admin.disable_brand(str(brand_id), principal)


@router.get(
    "/admin/identity-candidates/page",
    response_model=IdentityCandidatePageV4,
    responses=_COMMON_ERRORS,
)
async def page_identity_candidates_v4(
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
    status: IdentityAssociationAssuranceV4 | None = None,
    relationship: IdentityRelationshipV4 | None = None,
    entity: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> IdentityCandidatePageV4:
    records = await admin.list_identity_candidates(principal)
    if status is not None:
        records = [item for item in records if item.assurance is status]
    if relationship is not None:
        records = [item for item in records if item.relationship is relationship]
    if entity:
        needle = entity.casefold()
        records = [item for item in records if needle in item.entity_name.casefold()]
    items, total = _page(records, limit, offset)
    return IdentityCandidatePageV4(items=items, total=total, limit=limit, offset=offset)


@router.post(
    "/admin/identity-candidates",
    response_model=IdentityCandidateV4,
    status_code=201,
    responses=_COMMON_ERRORS,
)
async def create_manual_identity_candidate_v4(
    request: ManualIdentityCandidateCreateRequestV4,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> IdentityCandidateV4:
    return await admin.create_manual_identity_candidate(request, principal)


@router.post(
    "/admin/identity-candidates/{candidate_id}/decisions",
    response_model=IdentityCandidateV4,
    responses=_COMMON_ERRORS,
)
async def decide_identity_candidate_v4(
    candidate_id: UUID,
    request: IdentityCandidateDecisionRequestV4,
    admin: SecurityTrustAdminServiceDependency,
    principal: PrincipalDependency,
) -> IdentityCandidateV4:
    return await admin.decide_identity_candidate(str(candidate_id), request, principal)


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
        needle = _fold_history_search(q)
        if needle:
            records = [item for item in records if needle in _history_search_document(item)]
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
    memory: SecurityMemoryServiceDependency,
    trust: SecurityTrustAdminServiceDependency,
    blacklist: SecurityBlacklistAdminServiceDependency,
    principal: PrincipalDependency,
) -> SecurityReportAdminRecordV4:
    record = await analyses.decide_report(report_id, request, principal)
    if request.remediation_action is SecurityReportRemediationActionV4.NONE:
        return record
    try:
        if request.remediation_action is SecurityReportRemediationActionV4.UPDATE_MEMORY:
            memory_record = await memory.memory_for_analysis(record.analysis_id, principal)
            if memory_record is None:
                raise RuntimeError("SECURITY_MEMORY_NOT_FOUND")
            verdict = {
                SecurityReportResolutionV4.CONFIRM_SAFE: SecurityMemoryAdminVerdictV4.SAFE,
                SecurityReportResolutionV4.MARK_FALSE_POSITIVE: SecurityMemoryAdminVerdictV4.FALSE_POSITIVE,
                SecurityReportResolutionV4.CONFIRM_MALICIOUS: SecurityMemoryAdminVerdictV4.MALICIOUS,
            }[request.resolution]
            updated_memory = await memory.correct_memory(memory_record.memory_id, verdict, request.note, principal)
            return await analyses.record_report_remediation(
                report_id,
                SecurityReportRemediationUpdateV4(
                    status=SecurityReportRemediationStatusV4.EXECUTED,
                    reference=SecurityReportRemediationReferenceV4(memory_id=updated_memory.memory_id),
                    note=request.note,
                    evidence_refs=request.evidence_refs,
                ),
                principal,
            )
        if request.remediation_action is SecurityReportRemediationActionV4.ADD_TO_WHITELIST:
            whitelist_request = request.whitelist_entry
            if whitelist_request is None:
                raise RuntimeError("WHITELIST_INPUT_MISSING")
            provenance = (f"report:{report_id};analysis:{record.analysis_id};{whitelist_request.provenance}")[:1000]
            whitelist_record = await trust.create_whitelist(
                whitelist_request.model_copy(update={"provenance": provenance}), principal
            )
            return await analyses.record_report_remediation(
                report_id,
                SecurityReportRemediationUpdateV4(
                    status=SecurityReportRemediationStatusV4.EXECUTED,
                    reference=SecurityReportRemediationReferenceV4(whitelist_id=whitelist_record.whitelist_id),
                    note=request.note,
                    evidence_refs=request.evidence_refs,
                ),
                principal,
            )
        proposal_input = request.blacklist_proposal
        if proposal_input is None:
            raise RuntimeError("BLACKLIST_PROPOSAL_INPUT_MISSING")
        proposal = await blacklist.propose_add(
            SecurityBlacklistProposalRequestV4(
                canonical_domain=proposal_input.canonical_domain,
                reason=proposal_input.reason,
                evidence_refs=proposal_input.evidence_refs,
                provenance=proposal_input.provenance,
                source_analysis_id=record.analysis_id,
                source_report_id=report_id,
            ),
            principal,
        )
        return await analyses.link_report_remediation(
            report_id,
            SecurityReportRemediationReferenceV4(admin_action_id=proposal.action_id),
            request.note,
            request.audit_evidence_refs(),
            principal,
        )
    except Exception as exc:
        return await analyses.record_report_remediation(
            report_id,
            SecurityReportRemediationUpdateV4(
                status=SecurityReportRemediationStatusV4.FAILED,
                note=f"Remediation failed: {type(exc).__name__}",
                evidence_refs=request.audit_evidence_refs(),
            ),
            principal,
        )


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


@router.post(
    "/analyses/{analysis_id}/page-capture",
    response_class=Response,
    responses={
        200: {"content": {"image/jpeg": {}}},
        **_COMMON_ERRORS,
    },
)
async def capture_security_analysis_page_v4(
    analysis_id: UUID,
    request: SecurityPageCaptureRequestV4,
    analyses: SecurityAnalysisServiceDependency,
    capture: PageCaptureServiceDependency,
    principal: PrincipalDependency,
) -> Response:
    settings = get_settings()
    if not settings.security_page_capture_enabled:
        raise PlatformError(
            status_code=409,
            code=ErrorCode.CONFLICT,
            message="Page capture is not enabled.",
            retryable=False,
        )
    analysis = await analyses.get_for(analysis_id, principal)
    context = analysis.security_context
    if context is None or request.url_index >= len(context.urls):
        raise PlatformError(
            status_code=422,
            code=ErrorCode.VALIDATION_ERROR,
            message="The requested URL does not belong to this analysis.",
            retryable=False,
        )
    try:
        result = await capture.capture(context.urls[request.url_index])
    except PageCaptureError as exc:
        blocked = exc.code in {"SSRF_BLOCKED", "INVALID_TARGET", "RESPONSE_TOO_LARGE"}
        timeout = exc.code == "PROVIDER_TIMEOUT"
        raise PlatformError(
            status_code=422 if blocked else 504 if timeout else 503,
            code=(
                ErrorCode.VALIDATION_ERROR
                if blocked
                else ErrorCode.PROVIDER_TIMEOUT
                if timeout
                else ErrorCode.INTERNAL_ERROR
            ),
            message=exc.message,
            retryable=exc.retryable,
            details={"capture_code": exc.code},
        ) from exc
    except Exception as exc:
        raise PlatformError(
            status_code=503,
            code=ErrorCode.INTERNAL_ERROR,
            message="Page capture is temporarily unavailable.",
            retryable=True,
            details={"capture_code": "CAPTURE_FAILED"},
        ) from exc
    return Response(
        content=result.content,
        media_type=result.media_type,
        headers={
            "Cache-Control": "private, no-store, max-age=0",
            "Content-Disposition": 'inline; filename="page-capture.jpg"',
            "X-Content-Type-Options": "nosniff",
        },
    )


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
