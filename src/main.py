from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.routes import router
from src.agents.graph import analysis_agent, close_graph_resources
from src.config import get_settings
from src.core.errors import PlatformError
from src.models import ErrorBody, ErrorCode, ErrorEnvelope


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    print(f"Starting {settings.app_name} in {settings.app_env} mode")
    try:
        yield
    finally:
        await close_graph_resources(analysis_agent)
        print("Shutting down...")


app = FastAPI(
    title="AI20K Agent",
    description="AI Agent built with LangGraph",
    version="1.0.0",
    lifespan=lifespan,
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.exception_handler(PlatformError)
async def platform_error_handler(request: Request, exc: PlatformError) -> JSONResponse:
    envelope = ErrorEnvelope(
        error=ErrorBody(
            code=exc.code,
            message=exc.message,
            retryable=exc.retryable,
            details=exc.details,
        )
    )
    return JSONResponse(status_code=exc.status_code, content=envelope.model_dump(mode="json"))


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI/Starlette versions expose slightly different errors() keyword
    # arguments. Keep only stable, non-sensitive fields instead of returning
    # the rejected user input or provider context.
    details = {"errors": [{key: item[key] for key in ("type", "loc", "msg") if key in item} for item in exc.errors()]}
    envelope = ErrorEnvelope(
        error=ErrorBody(
            code=ErrorCode.VALIDATION_ERROR,
            message="Request validation failed.",
            retryable=False,
            details=details,
        )
    )
    return JSONResponse(status_code=422, content=envelope.model_dump(mode="json"))


@app.get("/health")
async def health():
    return {"status": "ok", "env": settings.app_env}
