import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.dependencies import (
    close_event_notifier,
    close_official_verification_rollout_stage,
    close_page_capture_service,
    close_rate_limiter,
    close_security_analysis_service,
    close_security_investigation_service,
    close_security_trust_services,
    close_ticket_manager,
    get_security_analysis_service,
    start_durable_worker,
    stop_durable_worker,
)
from src.api.middleware import StructuredRequestLogMiddleware
from src.api.security_v4 import router as security_v4_router
from src.config import get_settings
from src.core.errors import PlatformError
from src.core.logging import configure_structured_logging
from src.core.product_boundary import SECURITY_TRIAGE_API_PREFIX
from src.models import ErrorCode
from src.observability.langfuse import close_langfuse_observability, get_langfuse_observability

logger = logging.getLogger("trustguard.official_verification")


def documentation_urls(app_env: str) -> dict[str, str | None]:
    """Expose interactive API documentation only outside production."""
    if app_env == "production":
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_structured_logging(settings.log_level)
    logger.info(
        "official_verification_runtime_mode",
        extra={
            "official_verification": {
                "rollout_mode": settings.security_official_verification_mode,
                "risk_policy_enforced": settings.security_official_verification_mode == "enforced",
            }
        },
    )
    get_langfuse_observability()
    if not settings.demo_auth_enabled and (not settings.oidc_issuer or not settings.oidc_audience):
        raise RuntimeError("OIDC_ISSUER and OIDC_AUDIENCE are required when demo auth is disabled")
    print(f"Starting {settings.app_name} in {settings.app_env} mode")
    if settings.run_durable_worker:
        await start_durable_worker()
    try:
        yield
    finally:
        if settings.run_durable_worker:
            await stop_durable_worker()
        await close_security_analysis_service()
        await close_security_trust_services()
        await close_security_investigation_service()
        await close_official_verification_rollout_stage()
        await close_page_capture_service()
        await close_ticket_manager()
        await close_event_notifier()
        await close_rate_limiter()
        close_langfuse_observability()
        print("Shutting down...")


app = FastAPI(
    title="TrustGuard AI",
    description="Evidence-grounded risk analysis API",
    version="3.0.0",
    lifespan=lifespan,
    **documentation_urls(get_settings().app_env),
)

settings = get_settings()
app.add_middleware(StructuredRequestLogMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(security_v4_router, prefix=SECURITY_TRIAGE_API_PREFIX)


@app.exception_handler(PlatformError)
async def platform_error_handler(request, exc: PlatformError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code.value,
                "message": exc.message,
                "retryable": exc.retryable,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": ErrorCode.VALIDATION_ERROR.value,
                "message": "Request validation failed.",
                "retryable": False,
                "details": {"errors": jsonable_encoder(exc.errors())},
            }
        },
    )


@app.get("/health")
async def health():
    return {"status": "ok", "env": settings.app_env}


@app.get("/health/ready")
async def readiness():
    checks = {"database": True, "redis": True, "providers": True}
    service = get_security_analysis_service()
    healthcheck = getattr(service.repository, "healthcheck", None)
    if healthcheck is not None:
        try:
            checks["database"] = bool(await healthcheck())
        except Exception:
            checks["database"] = False
    if settings.app_env == "production":
        try:
            from redis.asyncio import Redis

            client = Redis.from_url(settings.redis_url)
            try:
                checks["redis"] = bool(await client.ping())
            finally:
                await client.aclose()
        except Exception:
            checks["redis"] = False
    if settings.live_providers_required:
        checks["providers"] = all(settings.security_live_provider_requirements().values())
    status_code = 200 if all(checks.values()) else 503
    return JSONResponse(
        status_code=status_code, content={"status": "ready" if status_code == 200 else "degraded", "checks": checks}
    )
