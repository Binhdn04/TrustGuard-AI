from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Query, WebSocket, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from starlette.websockets import WebSocketDisconnect

from src.api.dependencies import (
    AnalysisServiceDependency,
    PrincipalDependency,
    TicketManagerDependency,
    Wave2ServiceDependency,
    get_analysis_service,
    get_event_notifier,
    get_ticket_manager,
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
    AnalysisAcceptedResponseV3,
    AnalysisCreateRequestV3,
    AnalysisEventPageV3,
    AnalysisReportRequest,
    AnalysisReportResponseV3,
    AnalysisResponseV3,
    AnalysisStatus,
    AnalysisStatusEventPayload,
    AnalysisStatusEventV3,
    AppealCreateRequestV3,
    AppealDecisionRequestV3,
    AppealDecisionResponseV3,
    AppealPageV3,
    AppealReceiptV3,
    AppealResponseV3,
    AppealStatus,
    CampaignDecisionRequestV3,
    CampaignDetailV3,
    CampaignPageV3,
    CampaignReviewerStatus,
    CapabilitiesResponseV3,
    CaseStatus,
    CaseUpdateEventPayload,
    CaseUpdateEventV3,
    ErrorCode,
    ErrorEnvelope,
    FinalResultEventPayload,
    FinalResultEventV3,
    InvestigationTool,
    OperationsMetricsResponseV3,
    ProvisionalWarningEventPayload,
    ProvisionalWarningEventV3,
    ReportStatus,
    ReviewQueueDecisionRequest,
    ReviewQueueItem,
    ScreenshotStatusResponseV3,
    SourceDiscoveryDecisionRequestV3,
    SourceDiscoveryRecordV3,
    SourcePolicyCreateRequestV3,
    SourcePolicyRecordV3,
    StepTransitionEventPayload,
    StepTransitionEventV3,
    WebSocketTicketRequestV3,
    WebSocketTicketResponseV3,
)
from src.services.platform_wave2 import SourceRegistryEntry, SourceTier

router = APIRouter(tags=["contract-v3"])

_COMMON_ERRORS = {
    403: {"model": ErrorEnvelope},
    404: {"model": ErrorEnvelope},
    409: {"model": ErrorEnvelope},
    429: {"model": ErrorEnvelope},
    422: {"model": ErrorEnvelope},
}
_PLANNED_ERRORS = _COMMON_ERRORS
_MAX_ARTIFACT_BYTES = 5 * 1024 * 1024


@router.get("/capabilities", response_model=CapabilitiesResponseV3, responses=_COMMON_ERRORS)
async def capabilities_v3(principal: PrincipalDependency) -> CapabilitiesResponseV3:
    del principal
    settings = get_settings()
    configured = {
        "openai": bool(settings.openai_api_key),
        "google_fact_check": bool(settings.google_fact_check_api_key),
        "tavily": bool(settings.tavily_api_key),
        "web_risk": bool(settings.google_web_risk_api_key),
        "virustotal": bool(settings.virustotal_api_key),
        "postgresql": settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://")),
        "redis": bool(settings.redis_url),
        "screenshot": True,
    }
    ready_count = sum(configured.values())
    profile = "live" if ready_count == len(configured) else "partial" if ready_count else "offline"
    return CapabilitiesResponseV3(
        profile=profile,
        capabilities={name: "ready" if ready else "not_configured" for name, ready in configured.items()},
    )


def _as_v3(response) -> AnalysisResponseV3:
    return AnalysisResponseV3.model_validate(response.model_dump(exclude={"contract_version"}))


def _encode_cursor(sequence: int) -> str:
    raw = str(sequence).encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        sequence = int(base64.urlsafe_b64decode(padded).decode("ascii"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise PlatformError(
            status_code=422,
            code=ErrorCode.VALIDATION_ERROR,
            message="The event cursor is invalid.",
            retryable=False,
        ) from exc
    if sequence < 0:
        raise PlatformError(
            status_code=422,
            code=ErrorCode.VALIDATION_ERROR,
            message="The event cursor is invalid.",
            retryable=False,
        )
    return sequence


def _event_id(analysis_id: UUID, sequence: int, occurred_at: datetime, step: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"trustguard:{analysis_id}:{sequence}:{occurred_at.isoformat()}:{step}")


@router.post(
    "/analyses",
    response_model=AnalysisAcceptedResponseV3,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_COMMON_ERRORS,
)
async def create_analysis_v3(
    request: AnalysisCreateRequestV3,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> AnalysisAcceptedResponseV3:
    accepted = await service.create(request, principal)
    return AnalysisAcceptedResponseV3.model_validate(accepted.model_dump(exclude={"contract_version"}))


@router.get("/analyses", response_model=list[AnalysisResponseV3], responses=_COMMON_ERRORS)
async def list_analyses_v3(
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[AnalysisResponseV3]:
    return [_as_v3(item) for item in await service.list_for(principal)]


@router.get("/analyses/{analysis_id}", response_model=AnalysisResponseV3, responses=_COMMON_ERRORS)
async def get_analysis_v3(
    analysis_id: UUID,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> AnalysisResponseV3:
    return _as_v3(await service.get_for(analysis_id, principal))


@router.get(
    "/analyses/{analysis_id}/events",
    response_model=AnalysisEventPageV3,
    responses=_COMMON_ERRORS,
)
async def analysis_events_v3(
    analysis_id: UUID,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
    cursor: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
) -> AnalysisEventPageV3:
    after_sequence = _decode_cursor(cursor)
    return await _build_event_page(analysis_id, service, principal, after_sequence, cursor, limit)


async def _build_event_page(
    analysis_id: UUID,
    service,
    principal,
    after_sequence: int,
    cursor: str | None,
    limit: int,
) -> AnalysisEventPageV3:
    response = await service.get_for(analysis_id, principal)
    plan_by_id = {step.step_id: step for step in response.investigation_plan}
    # events_for() returns append order. Persisted records enforce that order
    # with their monotonic event_id; the in-memory implementation uses its
    # append-only list. Sequence numbers must be assigned from that stable
    # order rather than from timestamps, which are not necessarily unique.
    legacy_events = await service.events_for(analysis_id, principal)
    converted = []

    for sequence, event in enumerate(legacy_events, start=1):
        if sequence <= after_sequence:
            continue
        common = {
            "event_id": _event_id(analysis_id, sequence, event.occurred_at, event.step),
            "analysis_id": analysis_id,
            "sequence": sequence,
            "occurred_at": event.occurred_at,
        }
        if event.step_id is not None and event.step_status is not None:
            step = plan_by_id.get(event.step_id)
            converted.append(
                StepTransitionEventV3(
                    **common,
                    payload=StepTransitionEventPayload(
                        step_id=event.step_id,
                        tool=step.tool if step is not None else InvestigationTool(event.step),
                        target=step.target if step is not None else event.target or "unavailable",
                        reason_code=step.reason_code if step is not None else event.reason_code or "runtime_transition",
                        depends_on=step.depends_on if step is not None else event.depends_on,
                        status=event.step_status,
                    ),
                )
            )
        elif event.is_provisional and event.provisional_risk_level and event.provisional_summary:
            converted.append(
                ProvisionalWarningEventV3(
                    **common,
                    payload=ProvisionalWarningEventPayload(
                        risk_level=event.provisional_risk_level,
                        summary=event.provisional_summary,
                        evidence_refs=event.evidence_refs,
                        is_provisional=True,
                    ),
                )
            )
        elif event.step.startswith("review_"):
            converted.append(
                CaseUpdateEventV3(
                    **common,
                    payload=CaseUpdateEventPayload(case_status=CaseStatus(event.step.removeprefix("review_"))),
                )
            )
        elif event.status is AnalysisStatus.COMPLETED:
            converted.append(
                FinalResultEventV3(
                    **common,
                    payload=FinalResultEventPayload(result_ref=f"analysis:{analysis_id}:result"),
                )
            )
        else:
            converted.append(
                AnalysisStatusEventV3(
                    **common,
                    payload=AnalysisStatusEventPayload(status=event.status),
                )
            )
        if len(converted) == limit:
            break

    # This is a polling checkpoint, not an end-of-collection marker. On an
    # empty poll the caller must retain the same checkpoint so a later event
    # can be requested without replaying already-seen events.
    next_cursor = _encode_cursor(converted[-1].sequence) if converted else cursor
    return AnalysisEventPageV3(events=converted, next_cursor=next_cursor)


@router.post(
    "/analyses/{analysis_id}/reports",
    response_model=AnalysisReportResponseV3,
    status_code=status.HTTP_201_CREATED,
    responses=_COMMON_ERRORS,
)
async def report_analysis_v3(
    analysis_id: UUID,
    request: AnalysisReportRequest,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> AnalysisReportResponseV3:
    receipt = await service.report(analysis_id, request, principal)
    return AnalysisReportResponseV3.model_validate(receipt.model_dump())


@router.get(
    "/analyses/{analysis_id}/reports",
    response_model=list[AnalysisReportResponseV3],
    responses=_COMMON_ERRORS,
)
async def list_reports_v3(
    analysis_id: UUID,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[AnalysisReportResponseV3]:
    reports = await service.list_reports_by_analysis(analysis_id, principal)
    return [AnalysisReportResponseV3.model_validate(r.model_dump()) for r in reports]


@router.get(
    "/analyses/{analysis_id}/appeals",
    response_model=list[AppealResponseV3],
    responses=_COMMON_ERRORS,
)
async def list_analysis_appeals_v3(
    analysis_id: UUID,
    service: AnalysisServiceDependency,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> list[AppealResponseV3]:
    await service.get_for(analysis_id, principal)
    return await wave2.list_user_appeals(analysis_id, principal)


@router.get(
    "/analyses/{analysis_id}/screenshot",
    response_model=ScreenshotStatusResponseV3,
    responses=_COMMON_ERRORS,
)
async def get_analysis_screenshot_v3(
    analysis_id: UUID,
    service: AnalysisServiceDependency,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> ScreenshotStatusResponseV3:
    analysis = await service.get_for(analysis_id, principal)
    request = await service.get_request_for(analysis_id, principal)
    return await wave2.screenshot_status(
        analysis_id,
        consented=bool(getattr(request, "consent_to_capture_screenshot", False)),
        analysis_status=analysis.status,
        principal=principal,
    )


@router.get("/artifacts/{artifact_id}", response_class=Response, responses=_COMMON_ERRORS)
async def get_artifact_v3(
    artifact_id: UUID,
    wave2: Wave2ServiceDependency,
    token: str = Query(max_length=1024),
) -> Response:
    artifact = await wave2.artifact_for_download(artifact_id, token)
    settings = get_settings()
    storage_root = Path(settings.artifact_storage_dir).resolve()
    artifact_path = (storage_root / artifact.storage_key).resolve()
    if not artifact_path.is_relative_to(storage_root):
        raise PlatformError(
            status_code=404,
            code=ErrorCode.NOT_FOUND,
            message="Artifact was not found.",
            retryable=False,
        )
    # Keep the download boundary independently capped even if storage or
    # metadata was populated outside the capture coordinator.
    content = _read_verified_artifact(artifact_path, artifact.size_bytes, artifact.sha256)
    if content is None:
        raise PlatformError(
            status_code=404,
            code=ErrorCode.NOT_FOUND,
            message="Artifact was not found.",
            retryable=False,
        )
    return Response(
        content=content,
        media_type=artifact.media_type,
        headers={
            "Cache-Control": "private, no-store",
            "Content-Disposition": "inline",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _read_verified_artifact(path: Path, expected_size: int, expected_sha256: str) -> bytes | None:
    if not 0 <= expected_size <= _MAX_ARTIFACT_BYTES:
        return None
    try:
        with path.open("rb") as handle:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size != expected_size:
                return None
            # The extra byte detects growth after fstat without ever allocating
            # more than the configured limit plus one byte.
            content = handle.read(expected_size + 1)
    except (OSError, ValueError):
        return None
    if len(content) != expected_size or hashlib.sha256(content).hexdigest() != expected_sha256:
        return None
    return content


@router.post(
    "/ws-tickets",
    response_model=WebSocketTicketResponseV3,
    status_code=status.HTTP_201_CREATED,
    responses=_COMMON_ERRORS,
)
async def create_websocket_ticket_v3(
    request: WebSocketTicketRequestV3,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
    tickets: TicketManagerDependency,
) -> WebSocketTicketResponseV3:
    await service.get_for(request.analysis_id, principal)
    ticket, expires_at = await tickets.issue(request.analysis_id, principal)
    return WebSocketTicketResponseV3(
        ticket=ticket,
        analysis_id=request.analysis_id,
        expires_at=expires_at,
        stream_path=f"/api/v3/analyses/{request.analysis_id}/stream",
    )


@router.websocket("/analyses/{analysis_id}/stream")
async def analysis_stream_v3(
    websocket: WebSocket,
    analysis_id: UUID,
    ticket: str = Query(max_length=256),
    cursor: str | None = Query(default=None, max_length=128),
) -> None:
    """Replay persisted events and then tail them without owning the job.

    Closing this socket only ends delivery; analysis processing is deliberately
    independent of the connection lifecycle.
    """
    ticket_factory = websocket.app.dependency_overrides.get(get_ticket_manager, get_ticket_manager)
    tickets = ticket_factory()
    if hasattr(tickets, "__await__"):
        tickets = await tickets
    principal = await tickets.consume(ticket, analysis_id)
    if principal is None:
        await websocket.close(code=4403, reason="Invalid or expired WebSocket ticket.")
        return

    service_factory = websocket.app.dependency_overrides.get(get_analysis_service, get_analysis_service)
    service = service_factory()
    if hasattr(service, "__await__"):
        service = await service
    try:
        await service.get_for(analysis_id, principal)
    except PlatformError:
        await websocket.close(code=4403, reason="Analysis access denied.")
        return

    try:
        after_sequence = _decode_cursor(cursor)
    except PlatformError:
        await websocket.close(code=4400, reason="Invalid event cursor.")
        return
    await websocket.accept()
    checkpoint = cursor
    notifier_factory = websocket.app.dependency_overrides.get(get_event_notifier, get_event_notifier)
    notifier = notifier_factory()
    if hasattr(notifier, "__await__"):
        notifier = await notifier
    try:
        listener = await notifier.listen(analysis_id)
    except Exception:
        await websocket.close(code=1013, reason="Realtime delivery is temporarily unavailable.")
        return
    try:
        while True:
            page = await _build_event_page(analysis_id, service, principal, after_sequence, checkpoint, 500)
            terminal = False
            for event in page.events:
                await websocket.send_json(jsonable_encoder(event))
                after_sequence = event.sequence
                terminal = (
                    terminal
                    or event.event_type.value == "final_result"
                    or (event.event_type.value == "analysis_status" and event.payload.status is AnalysisStatus.FAILED)
                )
            checkpoint = page.next_cursor
            if terminal:
                await websocket.close(code=1000, reason="Analysis reached a terminal state.")
                return
            # Redis outbox delivery wakes production streams. The timeout is a
            # low-frequency correctness fallback if a notification is missed.
            await listener.wait(timeout_seconds=10)
    except (WebSocketDisconnect, RuntimeError):
        return
    finally:
        with suppress(Exception):
            await listener.close()


@router.post(
    "/analyses/{analysis_id}/appeals",
    response_model=AppealReceiptV3,
    status_code=status.HTTP_201_CREATED,
    responses=_PLANNED_ERRORS,
)
async def create_appeal_v3(
    analysis_id: UUID,
    request: AppealCreateRequestV3,
    service: AnalysisServiceDependency,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> AppealReceiptV3:
    analysis = await service.get_for(analysis_id, principal)
    return await wave2.create_appeal(analysis_id, principal.user_id, request, analysis.evidence or [])


@router.get("/appeals/{appeal_id}", response_model=AppealResponseV3, responses=_PLANNED_ERRORS)
async def get_appeal_v3(
    appeal_id: UUID,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> AppealResponseV3:
    return await wave2.get_appeal(appeal_id, principal)


@router.get("/admin/appeals", response_model=AppealPageV3, responses=_PLANNED_ERRORS)
async def list_admin_appeals_v3(
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
    appeal_status: AppealStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> AppealPageV3:
    require_security_admin(principal)
    return await wave2.list_appeals(appeal_status, limit, offset)


@router.post(
    "/admin/appeals/{appeal_id}/decision",
    response_model=AppealDecisionResponseV3,
    responses=_PLANNED_ERRORS,
)
async def decide_appeal_v3(
    appeal_id: UUID,
    request: AppealDecisionRequestV3,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> AppealDecisionResponseV3:
    require_security_admin(principal)
    return await wave2.decide_appeal(appeal_id, request, principal.user_id)


@router.post(
    "/admin/actions/{action_id}/decision",
    response_model=AdminActionDecisionResponseV3,
    responses=_PLANNED_ERRORS,
)
async def decide_admin_action_v3(
    action_id: UUID,
    request: AdminActionDecisionRequestV3,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> AdminActionDecisionResponseV3:
    require_security_admin(principal)
    return await wave2.decide_admin_action(action_id, request.decision, request.note, principal.user_id)


@router.get("/admin/actions", response_model=AdminActionPageV3, responses=_PLANNED_ERRORS)
async def list_admin_actions_v3(
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
    action_status: AdminActionStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> AdminActionPageV3:
    require_security_admin(principal)
    return await wave2.list_admin_actions(action_status, limit, offset)


@router.get("/admin/actions/{action_id}", response_model=AdminActionRecordV3, responses=_PLANNED_ERRORS)
async def get_admin_action_v3(
    action_id: UUID,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> AdminActionRecordV3:
    require_security_admin(principal)
    return await wave2.get_admin_action(action_id)


@router.get(
    "/admin/actions/{action_id}/audit",
    response_model=list[AdminActionAuditRecordV3],
    responses=_PLANNED_ERRORS,
)
async def list_admin_action_audit_v3(
    action_id: UUID,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> list[AdminActionAuditRecordV3]:
    require_security_admin(principal)
    return await wave2.list_admin_action_audit(action_id)


@router.get("/admin/campaigns", response_model=CampaignPageV3, responses=_PLANNED_ERRORS)
async def list_campaigns_v3(
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
    reviewer_status: CampaignReviewerStatus | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> CampaignPageV3:
    require_security_admin(principal)
    return await wave2.list_campaigns(reviewer_status, limit, offset)


@router.get("/admin/campaigns/{campaign_id}", response_model=CampaignDetailV3, responses=_PLANNED_ERRORS)
async def get_campaign_v3(
    campaign_id: UUID,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> CampaignDetailV3:
    require_security_admin(principal)
    return await wave2.get_campaign(campaign_id)


@router.post(
    "/admin/campaigns/{campaign_id}/decision",
    response_model=CampaignDetailV3,
    responses=_PLANNED_ERRORS,
)
async def review_campaign_v3(
    campaign_id: UUID,
    request: CampaignDecisionRequestV3,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> CampaignDetailV3:
    require_security_admin(principal)
    return await wave2.review_campaign(campaign_id, request.decision, request.note, principal.user_id)


@router.get("/admin/sources", response_model=list[SourcePolicyRecordV3], responses=_PLANNED_ERRORS)
async def list_source_policies_v3(
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> list[SourcePolicyRecordV3]:
    require_security_admin(principal)
    return [SourcePolicyRecordV3.model_validate(item.model_dump()) for item in await wave2.list_sources()]


@router.post(
    "/admin/sources",
    response_model=SourcePolicyRecordV3,
    status_code=status.HTTP_201_CREATED,
    responses=_PLANNED_ERRORS,
)
async def create_source_policy_v3(
    request: SourcePolicyCreateRequestV3,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> SourcePolicyRecordV3:
    require_security_admin(principal)
    now = datetime.now(UTC)
    entry = SourceRegistryEntry(
        **request.model_dump(exclude={"tier"}),
        tier=SourceTier(request.tier.value),
        reviewer_id=principal.user_id,
        reviewed_at=now,
    )
    await wave2.register_source(entry)
    return SourcePolicyRecordV3.model_validate(entry.model_dump())


@router.get(
    "/admin/source-discoveries",
    response_model=list[SourceDiscoveryRecordV3],
    responses=_PLANNED_ERRORS,
)
async def list_source_discoveries_v3(
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> list[SourceDiscoveryRecordV3]:
    require_security_admin(principal)
    return [SourceDiscoveryRecordV3.model_validate(item.model_dump()) for item in await wave2.list_source_discoveries()]


@router.post(
    "/admin/source-discoveries/{domain}/decision",
    response_model=SourceDiscoveryRecordV3,
    responses=_PLANNED_ERRORS,
)
async def decide_source_discovery_v3(
    domain: str,
    request: SourceDiscoveryDecisionRequestV3,
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
) -> SourceDiscoveryRecordV3:
    require_security_admin(principal)
    result = await wave2.decide_source_discovery(domain, request.decision, request.note, principal.user_id)
    return SourceDiscoveryRecordV3.model_validate(result.model_dump())


@router.get("/admin/metrics", response_model=OperationsMetricsResponseV3, responses=_PLANNED_ERRORS)
async def get_operations_metrics_v3(
    wave2: Wave2ServiceDependency,
    principal: PrincipalDependency,
    from_: datetime = Query(alias="from"),
    to: datetime = Query(),
) -> OperationsMetricsResponseV3:
    require_security_admin(principal)
    return await wave2.operations_metrics(from_, to)


@router.get("/admin/review-queue", response_model=list[ReviewQueueItem], responses=_PLANNED_ERRORS)
async def list_review_queue_items_v3(
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[ReviewQueueItem]:
    require_security_admin(principal)
    return await service.list_review_queue_items()


@router.post(
    "/admin/review-queue/{item_id}/start-review",
    responses=_PLANNED_ERRORS,
    status_code=status.HTTP_204_NO_CONTENT,
)
async def start_review_v3(
    item_id: UUID,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> None:
    require_security_admin(principal)
    item_key = str(item_id)
    item = await service.get_review_queue_item(item_key)
    if not item:
        raise PlatformError(status_code=404, code=ErrorCode.NOT_FOUND, message="Item not found", retryable=False)
    if item.status is not ReportStatus.SUBMITTED:
        raise PlatformError(
            status_code=409,
            code=ErrorCode.INTERNAL_ERROR,
            message="Report is no longer awaiting review.",
            retryable=False,
        )
    if not await service.start_review_queue_item(item_key, principal.user_id):
        raise PlatformError(
            status_code=409,
            code=ErrorCode.INTERNAL_ERROR,
            message="Report review state changed. Refresh and try again.",
            retryable=False,
        )


@router.post(
    "/admin/review-queue/{item_id}/decision",
    responses=_PLANNED_ERRORS,
    status_code=status.HTTP_204_NO_CONTENT,
)
async def decide_review_queue_item_v3(
    item_id: UUID,
    request: ReviewQueueDecisionRequest,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> None:
    require_security_admin(principal)
    item_key = str(item_id)
    item = await service.get_review_queue_item(item_key)
    if not item:
        raise PlatformError(status_code=404, code=ErrorCode.NOT_FOUND, message="Item not found", retryable=False)
    if item.status is not ReportStatus.REVIEWING:
        raise PlatformError(
            status_code=409,
            code=ErrorCode.INTERNAL_ERROR,
            message="Report must be in reviewing state before a decision.",
            retryable=False,
        )
    if not await service.decide_review_queue_item(
        item_key,
        decision=request.decision,
        reviewer_id=principal.user_id,
        note=request.note,
    ):
        raise PlatformError(
            status_code=409,
            code=ErrorCode.INTERNAL_ERROR,
            message="Report review state changed. Refresh and try again.",
            retryable=False,
        )
