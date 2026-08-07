from __future__ import annotations

import base64
import binascii
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Query, WebSocket, status

from src.api.dependencies import AnalysisServiceDependency, PrincipalDependency
from src.core.auth import require_security_admin
from src.core.errors import PlatformError
from src.models import (
    AdminActionDecisionRequestV3,
    AdminActionDecisionResponseV3,
    AdminActionPageV3,
    AdminActionRecordV3,
    AdminActionStatus,
    AnalysisAcceptedResponseV3,
    AnalysisCreateRequest,
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
    CampaignDetailV3,
    CampaignPageV3,
    CampaignReviewerStatus,
    CaseStatus,
    CaseUpdateEventPayload,
    CaseUpdateEventV3,
    ErrorCode,
    ErrorEnvelope,
    FinalResultEventPayload,
    FinalResultEventV3,
    InvestigationTool,
    OperationsMetricsResponseV3,
    StepTransitionEventPayload,
    StepTransitionEventV3,
    WebSocketTicketRequestV3,
    WebSocketTicketResponseV3,
)

router = APIRouter(tags=["contract-v3"])

_COMMON_ERRORS = {
    403: {"model": ErrorEnvelope},
    404: {"model": ErrorEnvelope},
    422: {"model": ErrorEnvelope},
}
_PLANNED_ERRORS = {**_COMMON_ERRORS, 501: {"model": ErrorEnvelope}}


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


def _planned_feature() -> None:
    raise PlatformError(
        status_code=501,
        code=ErrorCode.INTERNAL_ERROR,
        message="This v3 capability is frozen but is not implemented in Wave 0.",
        retryable=False,
    )


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
    accepted = await service.create(AnalysisCreateRequest.model_validate(request.model_dump()), principal)
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
                        target=step.target if step is not None else "unavailable",
                        reason_code=step.reason_code if step is not None else "legacy_event",
                        depends_on=step.depends_on if step is not None else [],
                        status=event.step_status,
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


@router.post(
    "/ws-tickets",
    response_model=WebSocketTicketResponseV3,
    status_code=status.HTTP_201_CREATED,
    responses=_PLANNED_ERRORS,
)
async def create_websocket_ticket_v3(
    request: WebSocketTicketRequestV3,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> WebSocketTicketResponseV3:
    await service.get_for(request.analysis_id, principal)
    _planned_feature()


@router.websocket("/analyses/{analysis_id}/stream")
async def analysis_stream_v3(websocket: WebSocket, analysis_id: UUID, ticket: str = Query()) -> None:
    # The route is reserved in Wave 0; ticket issue/consume and replay arrive with
    # the durable event store in Wave 1.
    del analysis_id, ticket
    await websocket.close(code=1013, reason="WebSocket streaming is not implemented in Wave 0.")


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
    principal: PrincipalDependency,
) -> AppealReceiptV3:
    del request
    await service.get_for(analysis_id, principal)
    _planned_feature()


@router.get("/appeals/{appeal_id}", response_model=AppealResponseV3, responses=_PLANNED_ERRORS)
async def get_appeal_v3(appeal_id: UUID, principal: PrincipalDependency) -> AppealResponseV3:
    del appeal_id, principal
    _planned_feature()


@router.get("/admin/appeals", response_model=AppealPageV3, responses=_PLANNED_ERRORS)
async def list_admin_appeals_v3(
    principal: PrincipalDependency,
    appeal_status: AppealStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> AppealPageV3:
    del appeal_status, limit, offset
    require_security_admin(principal)
    _planned_feature()


@router.post(
    "/admin/appeals/{appeal_id}/decision",
    response_model=AppealDecisionResponseV3,
    responses=_PLANNED_ERRORS,
)
async def decide_appeal_v3(
    appeal_id: UUID,
    request: AppealDecisionRequestV3,
    principal: PrincipalDependency,
) -> AppealDecisionResponseV3:
    del appeal_id, request
    require_security_admin(principal)
    _planned_feature()


@router.post(
    "/admin/actions/{action_id}/decision",
    response_model=AdminActionDecisionResponseV3,
    responses=_PLANNED_ERRORS,
)
async def decide_admin_action_v3(
    action_id: UUID,
    request: AdminActionDecisionRequestV3,
    principal: PrincipalDependency,
) -> AdminActionDecisionResponseV3:
    del action_id, request
    require_security_admin(principal)
    _planned_feature()


@router.get("/admin/actions", response_model=AdminActionPageV3, responses=_PLANNED_ERRORS)
async def list_admin_actions_v3(
    principal: PrincipalDependency,
    action_status: AdminActionStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> AdminActionPageV3:
    del action_status, limit, offset
    require_security_admin(principal)
    _planned_feature()


@router.get("/admin/actions/{action_id}", response_model=AdminActionRecordV3, responses=_PLANNED_ERRORS)
async def get_admin_action_v3(action_id: UUID, principal: PrincipalDependency) -> AdminActionRecordV3:
    del action_id
    require_security_admin(principal)
    _planned_feature()


@router.get("/admin/campaigns", response_model=CampaignPageV3, responses=_PLANNED_ERRORS)
async def list_campaigns_v3(
    principal: PrincipalDependency,
    reviewer_status: CampaignReviewerStatus | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> CampaignPageV3:
    del reviewer_status, limit, offset
    require_security_admin(principal)
    _planned_feature()


@router.get("/admin/campaigns/{campaign_id}", response_model=CampaignDetailV3, responses=_PLANNED_ERRORS)
async def get_campaign_v3(campaign_id: UUID, principal: PrincipalDependency) -> CampaignDetailV3:
    del campaign_id
    require_security_admin(principal)
    _planned_feature()


@router.get("/admin/metrics", response_model=OperationsMetricsResponseV3, responses=_PLANNED_ERRORS)
async def get_operations_metrics_v3(
    principal: PrincipalDependency,
    from_: datetime = Query(alias="from"),
    to: datetime = Query(),
) -> OperationsMetricsResponseV3:
    del from_, to
    require_security_admin(principal)
    _planned_feature()
