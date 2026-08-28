from __future__ import annotations

import hmac
import logging
import time
from hashlib import sha256
from ipaddress import ip_address, ip_network
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.config import Settings, get_settings
from src.core.product_boundary import product_route_metadata
from src.models import ErrorCode

logger = logging.getLogger("trustguard.http")


def client_ip_for_request(request, settings: Settings) -> str | None:
    """Return the peer IP, accepting X-Forwarded-For only from a trusted proxy."""
    if request.client is None:
        return None
    try:
        peer_ip = ip_address(request.client.host)
    except ValueError:
        return None

    trusted_networks = tuple(
        ip_network(value, strict=False) for value in settings.trusted_proxy_ips.split(",") if value
    )
    if not any(peer_ip in network for network in trusted_networks):
        return peer_ip.compressed

    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        try:
            return ip_address(forwarded_for.split(",", maxsplit=1)[0].strip()).compressed
        except ValueError:
            pass
    return peer_ip.compressed


def ip_rate_limit_key(client_ip: str, settings: Settings) -> str:
    """Avoid retaining a raw source IP in the limiter's in-memory or Redis key."""
    digest = hmac.new(
        settings.database_encryption_key.encode("utf-8"),
        client_ip.encode("utf-8"),
        sha256,
    ).hexdigest()
    return f"ip:{digest}"


class StructuredRequestLogMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)

    async def dispatch(self, request, call_next):
        request_id = request.headers.get("x-request-id", str(uuid4()))[:128]
        started = time.monotonic()
        product_route = product_route_metadata(request.url.path, request.method)
        settings = get_settings()
        if request.url.path.startswith("/api/"):
            # Import lazily: dependencies construct application services and
            # share this cached limiter with the authenticated user buckets.
            from src.api.dependencies import get_rate_limiter

            source_ip = client_ip_for_request(request, settings) or "unknown"
            allowed = await get_rate_limiter().allow(
                ip_rate_limit_key(source_ip, settings), settings.ip_rate_limit_per_minute
            )
            if not allowed:
                product_fields = (
                    {
                        "api_contract": product_route.api_contract,
                        "product_profile": product_route.product_profile,
                    }
                    if product_route is not None
                    else {}
                )
                logger.warning(
                    "http_ip_rate_limited",
                    extra={
                        "request_id": request_id,
                        "method": request.method,
                        "route": request.url.path,
                        "status_code": 429,
                        **product_fields,
                    },
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": ErrorCode.RATE_LIMITED.value,
                            "message": "Request rate limit exceeded.",
                            "retryable": True,
                            "details": {},
                        }
                    },
                    headers={"x-request-id": request_id},
                )
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        product_fields = (
            {
                "api_contract": product_route.api_contract,
                "product_profile": product_route.product_profile,
            }
            if product_route is not None
            else {}
        )
        logger.info(
            "http_request_completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                # Route only: never query strings, request bodies, or credentials.
                "route": request.url.path,
                "status_code": response.status_code,
                "latency_ms": round((time.monotonic() - started) * 1000),
                **product_fields,
            },
        )
        return response
