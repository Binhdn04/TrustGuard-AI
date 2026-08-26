from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

_SECRET_KEY = re.compile(r"(authorization|token|secret|password|otp|message|prompt|comment)", re.I)


def redact(value):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SECRET_KEY.search(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class RedactingJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for name in (
            "request_id",
            "method",
            "route",
            "status_code",
            "latency_ms",
            "job_id",
            "failure_code",
            "failure_type",
            "api_contract",
            "product_profile",
            "official_verification",
            "tracing_enabled",
            "observability_enabled",
            "environment",
            "base_url_host",
            "sample_rate",
            "sdk_debug",
            "capture_sanitized_content",
            "feature",
            "trace_name",
            "operation",
            "field_name",
            "attempts",
        ):
            if hasattr(record, name):
                payload[name] = getattr(record, name)
        return json.dumps(redact(payload), separators=(",", ":"), ensure_ascii=False)


def configure_structured_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingJsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
