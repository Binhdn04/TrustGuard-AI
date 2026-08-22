from types import MappingProxyType, SimpleNamespace

import pytest
from pydantic import ValidationError

from src.config import Settings
from src.observability.langfuse import LangfuseObservability, mask_private_trace_data


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
