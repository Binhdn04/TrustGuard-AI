from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status

from src.api.dependencies import AnalysisServiceDependency, PrincipalDependency
from src.core.auth import require_security_admin
from src.models import (
    AdminDecisionRequest,
    AdminDecisionResponse,
    AnalysisAcceptedResponse,
    AnalysisCreateRequest,
    AnalysisEvent,
    AnalysisReportRequest,
    AnalysisReportResponse,
    AnalysisResponse,
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
