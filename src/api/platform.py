from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Query, status

from src.api.dependencies import AnalysisServiceDependency, PrincipalDependency
from src.core.auth import require_security_admin
from src.models import (
    AdminDecisionRequest,
    AdminDecisionAudit,
    AdminDecisionResponse,
    AnalysisAcceptedResponse,
    AnalysisCreateRequest,
    AnalysisEvent,
    AnalysisReportRequest,
    AnalysisReportRecord,
    AnalysisReportResponse,
    AnalysisResponse,
    BlacklistEntry,
    ErrorEnvelope,
)

router = APIRouter()


@router.post(
    "/analyses",
    response_model=AnalysisAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={403: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope}},
)
async def create_analysis(
    request: AnalysisCreateRequest,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> AnalysisAcceptedResponse:
    return await service.create(request, principal)


@router.get("/analyses", response_model=list[AnalysisResponse])
async def list_analyses(
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[AnalysisResponse]:
    return await service.list_for(principal)


@router.get(
    "/analyses/{analysis_id}",
    response_model=AnalysisResponse,
    responses={403: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
async def get_analysis(
    analysis_id: UUID,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> AnalysisResponse:
    return await service.get_for(analysis_id, principal)


@router.post(
    "/analyses/{analysis_id}/reports",
    response_model=AnalysisReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def report_analysis(
    analysis_id: UUID,
    request: AnalysisReportRequest,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> AnalysisReportResponse:
    return await service.report(analysis_id, request, principal)


@router.get("/analyses/{analysis_id}/events", response_model=list[AnalysisEvent])
async def analysis_events(
    analysis_id: UUID,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[AnalysisEvent]:
    return await service.events_for(analysis_id, principal)


@router.get("/admin/cases", response_model=list[AnalysisResponse])
async def list_admin_cases(
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> list[AnalysisResponse]:
    require_security_admin(principal)
    return await service.list_review_cases()


@router.get("/admin/reports", response_model=list[AnalysisReportRecord])
async def list_admin_reports(
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[AnalysisReportRecord]:
    require_security_admin(principal)
    return await service.list_reports(limit=limit, offset=offset)


@router.get("/admin/decisions", response_model=list[AdminDecisionAudit])
async def list_admin_decisions(
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[AdminDecisionAudit]:
    require_security_admin(principal)
    return await service.list_decisions(limit=limit, offset=offset)


@router.get("/admin/blacklist", response_model=list[BlacklistEntry])
async def list_admin_blacklist(
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
    query: str | None = Query(default=None, max_length=253),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[BlacklistEntry]:
    require_security_admin(principal)
    return await service.list_blacklist(query=query, limit=limit, offset=offset)


@router.post(
    "/admin/cases/{analysis_id}/decision",
    response_model=AdminDecisionResponse,
)
async def decide_admin_case(
    analysis_id: UUID,
    request: AdminDecisionRequest,
    service: AnalysisServiceDependency,
    principal: PrincipalDependency,
) -> AdminDecisionResponse:
    require_security_admin(principal)
    return await service.decide(analysis_id, request, principal)
