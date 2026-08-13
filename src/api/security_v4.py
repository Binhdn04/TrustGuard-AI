from fastapi import APIRouter

from src.api.dependencies import PrincipalDependency, SecurityTriageScopeServiceDependency
from src.models import ErrorEnvelope, SecurityScopeResponseV4, SecurityTriageCreateRequestV4

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
) -> SecurityScopeResponseV4:
    del principal
    return service.assess(request)


__all__ = ["router"]
