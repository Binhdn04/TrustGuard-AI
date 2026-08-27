from types import MappingProxyType, SimpleNamespace

import pytest
from pydantic import ValidationError

from src.config import Settings
from src.observability.langfuse import LangfuseObservability, mask_private_trace_data, sanitize_trace_content


class _FakeLangfuse:
    latest_kwargs = None

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.shutdown_calls = 0
        type(self).latest_kwargs = kwargs

    def shutdown(self) -> None:
        self.shutdown_calls += 1


def test_langfuse_gate_requires_complete_configuration() -> None:
    with pytest.raises(ValidationError, match="LANGFUSE_PUBLIC_KEY"):
        Settings(
            langfuse_tracing_enabled=True,
            langfuse_public_key="",
            langfuse_secret_key="",
            _env_file=None,
        )


def test_langfuse_is_disabled_by_default() -> None:
    observability = LangfuseObservability(Settings(_env_file=None))

    assert observability.enabled is False
    assert observability.langchain_config("security-chat") == {"run_name": "security-chat"}


def test_langfuse_startup_log_contains_only_safe_diagnostics(monkeypatch, caplog) -> None:
    import langfuse

    monkeypatch.setattr(langfuse, "Langfuse", _FakeLangfuse)
    settings = Settings(
        langfuse_tracing_enabled=True,
        langfuse_public_key="pk-private-value",
        langfuse_secret_key="sk-private-value",
        langfuse_base_url="https://cloud.langfuse.com",
        langfuse_sample_rate=0.5,
        langfuse_debug=True,
        _env_file=None,
    )

    with caplog.at_level("INFO", logger="trustguard.observability"):
        observability = LangfuseObservability(settings)

    assert observability.enabled is True
    assert _FakeLangfuse.latest_kwargs["debug"] is True
    record = next(record for record in caplog.records if record.message == "langfuse_observability_initialized")
    assert record.tracing_enabled is True
    assert record.observability_enabled is True
    assert record.environment == "test"
    assert record.base_url_host == "cloud.langfuse.com"
    assert record.sample_rate == 0.5
    assert record.sdk_debug is True
    assert "pk-private-value" not in caplog.text
    assert "sk-private-value" not in caplog.text


def test_langfuse_user_ids_are_stable_and_pseudonymous() -> None:
    settings = Settings(database_encryption_key="test-key", _env_file=None)
    observability = LangfuseObservability(settings)

    first = observability.pseudonymous_user_id("auth0|private-user")

    assert first == observability.pseudonymous_user_id("auth0|private-user")
    assert first != observability.pseudonymous_user_id("auth0|another-user")
    assert "private-user" not in first


def test_export_mask_removes_private_content_and_unapproved_metadata() -> None:
    identifier = object()
    params = SimpleNamespace(
        spans=MappingProxyType(
            {
                identifier: SimpleNamespace(
                    attributes=MappingProxyType(
                        {
                            "langfuse.observation.input": "private OTP 123456",
                            "langfuse.observation.output": "provider response",
                            "langfuse.observation.status_message": "raw provider error",
                            "langfuse.observation.metadata.feature": "chat",
                            "langfuse.observation.metadata.secret": "credential",
                            "gen_ai.prompt.0.content": "private message",
                            "langfuse.observation.model.name": "gpt-test",
                        }
                    )
                )
            }
        )
    )

    patch = mask_private_trace_data(params=params).span_patches[identifier]

    assert patch.set_attributes["langfuse.observation.input"] == "[REDACTED_PRIVATE_CONTENT]"
    assert patch.set_attributes["langfuse.observation.output"] == "[REDACTED_PRIVATE_CONTENT]"
    assert patch.set_attributes["langfuse.observation.status_message"] == "[REDACTED_PRIVATE_CONTENT]"
    assert "gen_ai.prompt.0.content" in patch.delete_attributes
    assert "langfuse.observation.metadata.secret" in patch.delete_attributes
    assert "langfuse.observation.metadata.feature" not in patch.delete_attributes
    assert "langfuse.observation.model.name" not in patch.delete_attributes


def test_export_mask_preserves_application_owned_safe_structured_output() -> None:
    identifier = object()
    params = SimpleNamespace(
        spans=MappingProxyType(
            {
                identifier: SimpleNamespace(
                    attributes=MappingProxyType(
                        {
                            "langfuse.observation.input": '{"message":"private OTP 123456"}',
                            "langfuse.observation.output": '{"status":"failed","code":"TIMEOUT"}',
                            "langfuse.observation.metadata.privacy": "safe-structured",
                        }
                    )
                )
            }
        )
    )

    patch = mask_private_trace_data(params=params).span_patches[identifier]

    assert patch.set_attributes["langfuse.observation.input"] == "[REDACTED_PRIVATE_CONTENT]"
    assert "langfuse.observation.output" not in patch.set_attributes


def test_sanitized_content_capture_keeps_debug_text_without_sensitive_values() -> None:
    identifier = object()
    params = SimpleNamespace(
        spans=MappingProxyType(
            {
                identifier: SimpleNamespace(
                    attributes=MappingProxyType(
                        {
                            "langfuse.observation.input": (
                                "Mã OTP: 123456; email user@example.com; https://example.com/login?token=super-secret"
                            ),
                            "langfuse.observation.output": "Đừng chia sẻ token=abc123",
                            "langfuse.observation.metadata.privacy": "sanitized-content",
                        }
                    )
                )
            }
        )
    )

    patch = mask_private_trace_data(params=params, allow_sanitized_content=True).span_patches[identifier]

    assert patch.set_attributes["langfuse.observation.input"] == (
        "Mã [REDACTED_SECRET] email [REDACTED_EMAIL]; https://example.com/login"
    )
    assert patch.set_attributes["langfuse.observation.output"] == "Đừng chia sẻ [REDACTED_SECRET]"
    assert patch.set_attributes["trustguard.private_content_redacted"] is True


def test_sanitize_trace_content_handles_nested_payloads_and_bearer_tokens() -> None:
    sanitized = sanitize_trace_content(
        {"request": ["Authorization: Bearer eyJheader123456.payload123456.signature123456"]}
    )

    assert sanitized == {"request": ["[REDACTED_SECRET] [REDACTED_TOKEN]"]}
