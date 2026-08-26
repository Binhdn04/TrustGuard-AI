from __future__ import annotations

import hashlib
import hmac
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

from src.config import Settings, get_settings

_PRIVATE_ATTRIBUTE_KEYS = {
    "langfuse.trace.input",
    "langfuse.trace.output",
    "langfuse.observation.input",
    "langfuse.observation.output",
    "langfuse.observation.status_message",
}
_PRIVATE_ATTRIBUTE_PARTS = (
    ".content",
    ".contents",
    ".message",
    ".messages",
    ".prompt",
    ".prompts",
    ".completion",
    ".completions",
    ".tool.arguments",
)
_SAFE_METADATA_KEYS = {"feature", "operation", "privacy"}
_REDACTED = "[REDACTED_PRIVATE_CONTENT]"
_SAFE_STRUCTURED = "safe-structured"
_SANITIZED_CONTENT = "sanitized-content"
_CONTENT_REDACTED = "content-redacted"
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
_LABELED_SECRET_RE = re.compile(
    r"(?i)\b(?:otp|one[- ]time(?:\s+password)?|password|passcode|mật\s*khẩu|mat\s*khau|"
    r"pin|token|secret|api[_ -]?key|credential|authorization)\s*[:=]?\s*\S+"
)
_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}(?:\.[a-zA-Z0-9_-]{10,})?\b")
_LONG_TOKEN_RE = re.compile(
    r"\b(?=[a-zA-Z0-9_-]{20,}\b)(?=[a-zA-Z0-9_-]*[a-zA-Z])(?=[a-zA-Z0-9_-]*\d)[a-zA-Z0-9_-]+\b"
)

logger = logging.getLogger("trustguard.observability")


def sanitize_trace_content(value: Any) -> Any:
    """Keep debug context while removing secrets, PII, and URL query data."""
    if isinstance(value, dict):
        return {str(key): sanitize_trace_content(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_trace_content(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_trace_content(item) for item in value]
    if not isinstance(value, str):
        return value

    def scrub_url(match: re.Match[str]) -> str:
        parsed = urlsplit(match.group(0))
        if parsed.username or parsed.password:
            return "[REDACTED_URL]"
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

    sanitized = _URL_RE.sub(scrub_url, value)
    sanitized = _EMAIL_RE.sub("[REDACTED_EMAIL]", sanitized)
    sanitized = _LABELED_SECRET_RE.sub("[REDACTED_SECRET]", sanitized)
    sanitized = _JWT_RE.sub("[REDACTED_TOKEN]", sanitized)
    return _LONG_TOKEN_RE.sub("[REDACTED_TOKEN]", sanitized)


def mask_private_trace_data(*, params, allow_sanitized_content: bool = False):
    """Remove private/provider payloads immediately before export to Langfuse."""
    from langfuse.types import MaskOtelSpansResult, OtelSpanPatch

    patches = {}
    for identifier, span in params.spans.items():
        delete_attributes: list[str] = []
        set_attributes: dict[str, str | bool] = {}
        privacy = str(span.attributes.get("langfuse.observation.metadata.privacy", "")).strip('"')
        for key in span.attributes:
            lowered = key.casefold()
            # Keep approved structured policy outputs useful for debugging,
            # while continuing to mask framework/provider I/O.
            if lowered.startswith(("gen_ai.", "llm.")) and any(part in lowered for part in _PRIVATE_ATTRIBUTE_PARTS):
                delete_attributes.append(key)
            elif key in _PRIVATE_ATTRIBUTE_KEYS:
                if privacy == _SAFE_STRUCTURED and lowered.endswith(".output"):
                    continue
                if allow_sanitized_content and privacy == _SANITIZED_CONTENT:
                    sanitized = sanitize_trace_content(span.attributes[key])
                    if sanitized != span.attributes[key]:
                        set_attributes[key] = sanitized
                else:
                    set_attributes[key] = _REDACTED
            elif lowered.startswith("langfuse.observation.metadata."):
                metadata_key = lowered.rsplit(".", 1)[-1]
                if metadata_key not in _SAFE_METADATA_KEYS:
                    delete_attributes.append(key)
        set_attributes["trustguard.private_content_redacted"] = True
        patches[identifier] = OtelSpanPatch(
            delete_attributes=tuple(delete_attributes),
            set_attributes=set_attributes,
        )
    return MaskOtelSpansResult(span_patches=patches)


class LangfuseObservability:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = None
        if not settings.langfuse_configuration_valid():
            logger.info(
                "langfuse_observability_disabled",
                extra=self._diagnostic_context(),
            )
            return

        # Import only after Settings has loaded configuration. Explicit
        # constructor arguments avoid relying on import-time environment state.
        try:
            from langfuse import Langfuse

            self._client = Langfuse(
                public_key=settings.langfuse_public_key,
                secret_key=settings.langfuse_secret_key,
                base_url=settings.langfuse_base_url,
                tracing_enabled=settings.langfuse_tracing_enabled,
                environment=settings.app_env,
                sample_rate=settings.langfuse_sample_rate,
                debug=settings.langfuse_debug,
                mask_otel_spans=lambda *, params: mask_private_trace_data(
                    params=params,
                    allow_sanitized_content=settings.langfuse_capture_sanitized_content,
                ),
            )
            logger.info(
                "langfuse_observability_initialized",
                extra=self._diagnostic_context(observability_enabled=True),
            )
        except Exception as exc:  # noqa: BLE001 - optional telemetry must fail open
            logger.warning(
                "langfuse_observability_disabled",
                extra={
                    **self._diagnostic_context(),
                    "failure_code": "initialization_error",
                    "failure_type": type(exc).__name__,
                },
            )

    def _diagnostic_context(self, *, observability_enabled: bool = False) -> dict[str, Any]:
        """Return non-secret deployment diagnostics safe for Railway logs."""
        return {
            "tracing_enabled": self._settings.langfuse_tracing_enabled,
            "observability_enabled": observability_enabled,
            "environment": self._settings.app_env,
            "base_url_host": urlparse(self._settings.langfuse_base_url).hostname or "invalid",
            "sample_rate": self._settings.langfuse_sample_rate,
            "sdk_debug": self._settings.langfuse_debug,
            "capture_sanitized_content": self._settings.langfuse_capture_sanitized_content,
        }

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def pseudonymous_user_id(self, user_id: str) -> str:
        digest = hmac.new(
            self._settings.database_encryption_key.encode(),
            f"langfuse-user:{user_id}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"tg_{digest[:24]}"

    @contextmanager
    def trace(
        self,
        name: str,
        *,
        feature: str,
        user_id: str | None = None,
        session_id: str | None = None,
        input: dict[str, Any] | None = None,
    ) -> Iterator[Any | None]:
        if self._client is None:
            with nullcontext(None) as span:
                yield span
            return

        from langfuse import propagate_attributes

        log_context = {"trace_name": name, "feature": feature}
        logger.info("langfuse_trace_started", extra=log_context)
        with self._client.start_as_current_observation(
            name=name,
            as_type="span",
            input=(sanitize_trace_content(input) if self._settings.langfuse_capture_sanitized_content else _REDACTED),
            metadata={
                "feature": feature,
                "privacy": _SANITIZED_CONTENT if self._settings.langfuse_capture_sanitized_content else _CONTENT_REDACTED,
            },
        ) as span:
            failure: tuple[BaseException, Any] | None = None
            try:
                with propagate_attributes(
                    trace_name=name,
                    user_id=self.pseudonymous_user_id(user_id) if user_id else None,
                    session_id=session_id,
                    tags=["security-triage", feature],
                    metadata={"feature": feature, "privacy": _SAFE_STRUCTURED},
                ):
                    yield span
            except BaseException as exc:
                # Normalize before the Langfuse context manager observes the
                # failure; provider exception text may contain response data.
                span.update(
                    output={"status": "error"},
                    level="ERROR",
                    status_message="operation_failed",
                )
                failure = (exc, exc.__traceback__)
        if failure is not None:
            logger.warning(
                "langfuse_trace_failed",
                extra={**log_context, "failure_type": type(failure[0]).__name__},
            )
            raise failure[0].with_traceback(failure[1])
        logger.info("langfuse_trace_completed", extra=log_context)

    @contextmanager
    def observation(
        self,
        name: str,
        *,
        as_type: str = "span",
        input: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Iterator[Any | None]:
        """Create a nested observation containing sanitized structured data only."""
        if self._client is None:
            with nullcontext(None) as span:
                yield span
            return

        safe_metadata = {**(metadata or {}), "privacy": _SAFE_STRUCTURED}
        with self._client.start_as_current_observation(
            name=name,
            as_type=as_type,
            input=input,
            metadata=safe_metadata,
        ) as span:
            try:
                yield span
            except BaseException as exc:
                span.update(
                    output={"status": "error", "failure_type": type(exc).__name__},
                    level="ERROR",
                    status_message="operation_failed",
                )
                raise

    def generation(self, operation: str):
        if self._client is None:
            return nullcontext(None)
        return self._client.start_as_current_observation(
            name=f"security-ai-{operation}",
            as_type="generation",
            input=_REDACTED,
            metadata={
                "feature": "security-ai",
                "operation": operation,
                "privacy": _CONTENT_REDACTED,
            },
        )

    def langchain_config(self, operation: str) -> dict[str, Any]:
        if self._client is None:
            return {"run_name": operation}
        from langfuse.langchain import CallbackHandler

        return {
            "callbacks": [CallbackHandler(public_key=self._settings.langfuse_public_key)],
            "run_name": operation,
            "metadata": {
                "langfuse_trace_name": operation,
                "langfuse_tags": ["security-triage", "chat"],
                "feature": "chat",
                "operation": operation,
                "privacy": _CONTENT_REDACTED,
            },
        }

    def flush(self) -> None:
        if self._client is not None:
            try:
                self._client.flush()
                logger.info("langfuse_flush_completed")
            except Exception as exc:  # noqa: BLE001 - optional telemetry must fail open
                logger.warning(
                    "langfuse_flush_failed",
                    extra={"failure_code": "flush_error", "failure_type": type(exc).__name__},
                )

    def shutdown(self) -> None:
        if self._client is not None:
            try:
                self._client.shutdown()
                logger.info("langfuse_shutdown_completed")
            except Exception as exc:  # noqa: BLE001 - optional telemetry must fail open
                logger.warning(
                    "langfuse_shutdown_failed",
                    extra={"failure_code": "shutdown_error", "failure_type": type(exc).__name__},
                )


@lru_cache
def get_langfuse_observability() -> LangfuseObservability:
    return LangfuseObservability(get_settings())


def close_langfuse_observability() -> None:
    if get_langfuse_observability.cache_info().currsize:
        observability = get_langfuse_observability()
        get_langfuse_observability.cache_clear()
        observability.shutdown()


__all__ = [
    "LangfuseObservability",
    "close_langfuse_observability",
    "get_langfuse_observability",
    "mask_private_trace_data",
    "sanitize_trace_content",
]
