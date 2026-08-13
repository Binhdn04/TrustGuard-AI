from __future__ import annotations

import logging
import time
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware

from src.core.product_boundary import product_route_metadata

logger = logging.getLogger("trustguard.http")


class StructuredRequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = request.headers.get("x-request-id", str(uuid4()))[:128]
        started = time.monotonic()
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        product_route = product_route_metadata(request.url.path, request.method)
        product_fields = (
            {
                "api_contract": product_route.api_contract,
                "product_profile": product_route.product_profile,
                "compatibility_usage": product_route.compatibility_usage,
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
