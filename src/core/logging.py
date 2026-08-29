from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

_SECRET_KEY = re.compile(
    r"(authorization|token|secret|password|otp|message|prompt|comment|raw[_-]?capture)",
    re.I,
)
_BEARER_TOKEN = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.I)
_OPENAI_API_KEY = re.compile(r"\bsk(?:-proj)?-[A-Za-z0-9_-]+\b", re.I)
_ASSIGNMENT_SECRET = re.compile(
    r"\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*([=:])\s*[^\s,;]+",
    re.I,
)
_SENSITIVE_QUERY_VALUE = re.compile(
    r"([?&](?:access_token|api[_-]?key|authorization|password|secret|ticket|token)=)[^&#\s]+",
    re.I,
)
_NETWORK_URL = re.compile(r"(?:https?|wss?)://[^\s\"'<>]+", re.I)


def _strip_url_query_and_fragment(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.query and not parsed.fragment:
        return value
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _redact_string(value: str) -> str:
    value = _BEARER_TOKEN.sub("Bearer [REDACTED]", value)
    value = _OPENAI_API_KEY.sub("[REDACTED]", value)
    value = _ASSIGNMENT_SECRET.sub(r"\1\2[REDACTED]", value)
    value = _SENSITIVE_QUERY_VALUE.sub(r"\1[REDACTED]", value)
    return _NETWORK_URL.sub(_strip_url_query_and_fragment, value)


def redact(value):
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, dict):
        return {
            redact(str(key)): "[REDACTED]" if _SECRET_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


class RedactingJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": redact(record.getMessage()),
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
            "failure_location",
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
                payload[name] = redact(getattr(record, name))
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def configure_structured_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingJsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
