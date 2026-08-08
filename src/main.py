from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.dependencies import (
    close_analysis_service,
    close_event_notifier,
    close_rate_limiter,
    close_ticket_manager,
    start_durable_worker,
    stop_durable_worker,
)
from src.api.middleware import StructuredRequestLogMiddleware
from src.api.platform_v3 import router as platform_v3_router
from src.api.routes import router
from src.config import get_settings
from src.core.errors import PlatformError
from src.core.logging import configure_structured_logging
from src.models import ErrorCode


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_structured_logging(settings.log_level)
    if not settings.demo_auth_enabled and (not settings.oidc_issuer or not settings.oidc_audience):
        raise RuntimeError("OIDC_ISSUER and OIDC_AUDIENCE are required when demo auth is disabled")
    if settings.app_env == "production" and settings.database_encryption_key == "development-only-change-me":
        raise RuntimeError("DATABASE_ENCRYPTION_KEY must be changed in production")
    print(f"Starting {settings.app_name} in {settings.app_env} mode")
    await start_durable_worker()
    try:
        yield
    finally:
        await stop_durable_worker()
        await close_analysis_service()
        await close_ticket_manager()
        await close_event_notifier()
        await close_rate_limiter()
        print("Shutting down...")


app = FastAPI(
    title="TrustGuard AI",
    description="Evidence-grounded risk analysis API",
    version="3.0.0",
    lifespan=lifespan,
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

app.include_router(router, prefix="/api/v2")
app.include_router(platform_v3_router, prefix="/api/v3")


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
