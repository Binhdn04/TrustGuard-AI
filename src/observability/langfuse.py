from __future__ import annotations

import hashlib
import hmac
import logging
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from functools import lru_cache
from typing import Any

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

logger = logging.getLogger("trustguard.observability")


def mask_private_trace_data(*, params):
    """Remove private message/provider payloads immediately before export."""
    from langfuse.types import MaskOtelSpansResult, OtelSpanPatch

    patches = {}
    for identifier, span in params.spans.items():
        delete_attributes: list[str] = []
        set_attributes: dict[str, str | bool] = {}
        privacy = str(span.attributes.get("langfuse.observation.metadata.privacy", "")).strip('"')
        for key in span.attributes:
            lowered = key.casefold()
            # Application-owned observations only contain policy outputs,
            # counts, enums, and normalized failure codes. Keep those useful
            # for debugging while continuing to mask framework/provider I/O.
            if key in _PRIVATE_ATTRIBUTE_KEYS and not (privacy == _SAFE_STRUCTURED and lowered.endswith(".output")):
                set_attributes[key] = _REDACTED
            elif lowered.startswith(("gen_ai.", "llm.")) and any(part in lowered for part in _PRIVATE_ATTRIBUTE_PARTS):
                delete_attributes.append(key)
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
                mask_otel_spans=mask_private_trace_data,
            )
        except Exception:  # noqa: BLE001 - optional telemetry must fail open
            logger.warning(
                "langfuse_observability_disabled",
                extra={"failure_code": "initialization_error"},
            )

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
    ) -> Iterator[Any | None]:
        if self._client is None:
            with nullcontext(None) as span:
                yield span
            return

        from langfuse import propagate_attributes

        with self._client.start_as_current_observation(
            name=name,
            as_type="span",
            input=_REDACTED,
            metadata={"feature": feature, "privacy": _SAFE_STRUCTURED},
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
            raise failure[0].with_traceback(failure[1])

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
                "privacy": "content-redacted",
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
                "privacy": "content-redacted",
            },
        }

    def flush(self) -> None:
        if self._client is not None:
            self._client.flush()

    def shutdown(self) -> None:
        if self._client is not None:
            self._client.shutdown()


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
]
