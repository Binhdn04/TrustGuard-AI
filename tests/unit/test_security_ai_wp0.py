import asyncio
from time import perf_counter
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from src.config import Settings
from src.security_ai.contracts import (
    AssistantOperation,
    AssistantSynthesis,
    ModelResponse,
    Understanding,
)
from src.security_ai.fake import DeterministicFakeSecurityAssistant
from src.security_ai.openai import ModelTokenPricing, OpenAISecurityAssistant
from src.security_ai.runtime import SecurityAssistantRuntime, TurnBudget


def test_security_ai_structured_outputs_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Understanding.model_validate({"sender_intent": "payment", "invented": True})


@pytest.mark.asyncio
async def test_fake_adapter_passes_typed_schema_and_accounts_budget() -> None:
    fake = DeterministicFakeSecurityAssistant()
    runtime = SecurityAssistantRuntime(max_retries=0)
    result = await runtime.invoke(
        AssistantOperation.UNDERSTAND,
        lambda: fake.understand("Share an OTP", None),
        Understanding,
    )

    assert result.status == "ok"
    assert isinstance(result.output, Understanding)
    assert runtime.budget.calls == 1
    assert runtime.metrics[0].provider == "fake"
    assert runtime.metrics[0].status == "ok"


@pytest.mark.asyncio
async def test_runtime_timeout_is_normalized_to_fallback() -> None:
    async def slow():
        await asyncio.sleep(0.05)

    runtime = SecurityAssistantRuntime(timeout_seconds=0.001, max_retries=0)
    result = await runtime.invoke(AssistantOperation.UNDERSTAND, slow, Understanding)

    assert result.status == "fallback"
    assert result.error == "timeout"
    assert runtime.metrics[0].error == "timeout"


@pytest.mark.asyncio
async def test_runtime_retries_malformed_output_then_falls_back() -> None:
    calls = 0

    async def malformed():
        nonlocal calls
        calls += 1
        return {"output": {"unknown": True}, "provider": "fake", "model": "bad"}

    runtime = SecurityAssistantRuntime(max_retries=1)
    result = await runtime.invoke(AssistantOperation.UNDERSTAND, malformed, Understanding)

    assert result.status == "fallback"
    assert result.error == "invalid_structured_output"
    assert calls == 2
    assert runtime.budget.calls == 2
    assert len(runtime.metrics) == 2


@pytest.mark.asyncio
async def test_runtime_enforces_four_calls_and_single_synthesis() -> None:
    response = ModelResponse(output=Understanding(sender_intent="unknown"), provider="fake", model="v1")

    async def valid():
        return response

    runtime = SecurityAssistantRuntime(max_retries=0, budget=TurnBudget(max_calls=4))
    for _ in range(4):
        assert (await runtime.invoke(AssistantOperation.UNDERSTAND, valid, Understanding)).status == "ok"
    exhausted = await runtime.invoke(AssistantOperation.UNDERSTAND, valid, Understanding)
    assert exhausted.status == "fallback"
    assert exhausted.error == "turn_call_budget_exhausted"


@pytest.mark.asyncio
async def test_runtime_enforces_exactly_one_synthesis_call() -> None:
    response = ModelResponse(output=AssistantSynthesis(summary="Done"), provider="fake", model="v1")

    async def valid():
        return response

    runtime = SecurityAssistantRuntime(max_retries=0)
    first = await runtime.invoke(AssistantOperation.SYNTHESIZE, valid, AssistantSynthesis)
    second = await runtime.invoke(AssistantOperation.SYNTHESIZE, valid, AssistantSynthesis)

    assert first.status == "ok"
    assert second.status == "fallback"
    assert second.error == "turn_synthesis_budget_exhausted"
    assert runtime.budget.synthesis_calls == 1


@pytest.mark.asyncio
async def test_runtime_enforces_hard_turn_deadline() -> None:
    async def must_not_run():
        raise AssertionError("provider call started after the turn deadline")

    runtime = SecurityAssistantRuntime(
        turn_deadline_seconds=0.01,
        turn_started_at=perf_counter() - 1,
    )
    result = await runtime.invoke(AssistantOperation.UNDERSTAND, must_not_run, Understanding)

    assert result.status == "fallback"
    assert result.error == "turn_deadline_exceeded"
    assert runtime.budget.calls == 0


@pytest.mark.asyncio
async def test_runtime_cancels_inflight_call_at_turn_deadline() -> None:
    async def slow():
        await asyncio.sleep(0.05)

    runtime = SecurityAssistantRuntime(
        timeout_seconds=1,
        turn_deadline_seconds=0.001,
        max_retries=0,
    )
    result = await runtime.invoke(AssistantOperation.UNDERSTAND, slow, Understanding)

    assert result.status == "fallback"
    assert result.error == "turn_deadline_exceeded"


@pytest.mark.asyncio
async def test_openai_adapter_accounts_configured_token_cost() -> None:
    class StructuredClient:
        def with_structured_output(self, schema, include_raw):
            assert schema is Understanding
            assert include_raw is True
            return self

        async def ainvoke(self, payload):
            assert "security_message_understanding" in payload
            return {
                "parsed": {"sender_intent": "credential_theft"},
                "raw": SimpleNamespace(
                    usage_metadata={"input_tokens": 1_000, "output_tokens": 250},
                    response_metadata={"model_name": "priced-model-2026-08-01"},
                ),
            }

    adapter = object.__new__(OpenAISecurityAssistant)
    response = await adapter._call(
        StructuredClient(),
        "priced-model",
        ModelTokenPricing(input_per_million_usd=2.0, output_per_million_usd=8.0),
        Understanding,
        {"operation": "security_message_understanding"},
    )

    assert response.usage.input_tokens == 1_000
    assert response.usage.output_tokens == 250
    assert response.usage.cost_usd == pytest.approx(0.004)
    assert response.model == "priced-model-2026-08-01"


def test_production_rejects_enabled_ai_without_provider_configuration() -> None:
    from tests.unit.test_config import production_settings

    with pytest.raises(ValidationError, match="OPENAI_API_KEY"):
        production_settings(security_ai_understanding_enabled=True, openai_api_key="")


def test_security_ai_rejects_blank_model_configuration() -> None:
    with pytest.raises(ValidationError, match="model names must not be blank"):
        Settings(security_ai_small_model="   ", _env_file=None)


def test_security_ai_rejects_invalid_pricing_configuration() -> None:
    with pytest.raises(ValidationError):
        Settings(
            security_ai_small_input_cost_per_million_usd=0,
            _env_file=None,
        )


def test_all_security_ai_flags_default_off() -> None:
    settings = Settings(_env_file=None)
    assert not any(settings.enabled_security_capabilities().values())
