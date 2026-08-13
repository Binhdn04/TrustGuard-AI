from fastapi import APIRouter, Request

from src.api.dependencies import (
    PrincipalDependency,
    SecurityTriageScopeServiceDependency,
    resolve_security_investigation_service,
)
from src.models import ErrorEnvelope, ScopeDecisionV4, SecurityScopeResponseV4, SecurityTriageCreateRequestV4

router = APIRouter(tags=["security-triage-v4"])

_COMMON_ERRORS = {
    403: {"model": ErrorEnvelope},
    422: {"model": ErrorEnvelope},
    429: {"model": ErrorEnvelope},
}


@router.post("/analyses", response_model=SecurityScopeResponseV4, responses=_COMMON_ERRORS)
async def scope_security_analysis_v4(
    request: SecurityTriageCreateRequestV4,
    service: SecurityTriageScopeServiceDependency,
    principal: PrincipalDependency,
    http_request: Request,
) -> SecurityScopeResponseV4:
    del principal
    scoped = service.assess(request)
    if scoped.scope_decision is not ScopeDecisionV4.IN_SCOPE:
        return scoped
    investigation = await resolve_security_investigation_service(http_request)
    return await investigation.investigate(request, scoped)


__all__ = ["router"]
