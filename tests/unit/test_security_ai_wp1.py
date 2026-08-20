from __future__ import annotations

import json

import pytest

from src.agents.security_risk import assess_security_risk
from src.agents.security_scope import extract_security_context
from src.models import (
    AssistantProcessingModeV4,
    ExposureStateV4,
    MissingInformationSlotV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityConversationSummaryV4,
    SecurityInvestigationStatusV4,
    SecurityScenarioV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import ModelResponse, SemanticSecuritySignal, Understanding, UnderstandingSourceSpan
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_understanding import (
    SecuritySemanticUnderstandingService,
    merge_semantic_understanding,
)


def _understanding(message: str, **values) -> Understanding:
    output = Understanding(**values)
    grounded_fields: list[str] = []
    for field_name in (
        "scope_decision",
        "sender_intent",
        "social_engineering_techniques",
        "claimed_entity",
        "scenario",
        "requested_action",
        "exposure_state",
    ):
        value = getattr(output, field_name)
        if value not in (None, [], ExposureStateV4.UNKNOWN):
            grounded_fields.append(field_name)
    grounded_fields.extend(signal.value for signal in output.security_signals)
    return output.model_copy(
        update={
            "field_confidences": {field: 0.9 for field in grounded_fields},
            "source_spans": [
                UnderstandingSourceSpan(field_name=field, start=0, end=len(message)) for field in grounded_fields
            ],
        }
    )


def _scope(message: str):
    return SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))


def test_grounded_ai_signals_are_merged_and_change_deterministic_score() -> None:
    message = "ck lẹ 2 củ để giữ suất"
    scoped = _scope(message)
    output = _understanding(
        message,
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        sender_intent="coerce_payment",
        scenario=SecurityScenarioV4.PAYMENT,
        requested_action=RequestedActionV4.TRANSFER_MONEY,
        security_signals=[SemanticSecuritySignal.PAYMENT_REQUEST, SemanticSecuritySignal.URGENCY],
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")
    # Risk consumes context evidence in production. A minimal empty evidence list
    # still demonstrates that AI-added booleans feed the deterministic score.
    completed = assess_security_risk(
        merged.model_copy(
            update={
                "next_step": "RISK_ASSESSMENT",
                "investigation_status": SecurityInvestigationStatusV4.COMPLETED,
            }
        )
    )

    assert merged.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert merged.security_context.payment_request is True
    assert merged.security_context.urgency is True
    assert merged.security_context.urls == []
    assert completed.score == 70
    assert completed.risk.value == "HIGH_RISK"


def test_rule_true_signals_are_sticky_and_conflicts_are_retained_as_limitations() -> None:
    message = "HR tuyển dụng yêu cầu đóng phí hồ sơ ngay"
    scoped = _scope(message)
    assert scoped.security_context.payment_request is True
    output = _understanding(
        message,
        scenario=SecurityScenarioV4.PAYMENT,
        requested_action=RequestedActionV4.TRANSFER_MONEY,
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")
    completed = assess_security_risk(
        merged.model_copy(
            update={
                "next_step": "RISK_ASSESSMENT",
                "investigation_status": SecurityInvestigationStatusV4.COMPLETED,
            }
        )
    )

    assert merged.security_context.payment_request is True
    assert merged.security_context.scenario is SecurityScenarioV4.RECRUITMENT
    assert merged.security_context.requested_action is RequestedActionV4.PAY_FEE
    assert any("xung đột" in item for item in merged.limitations)
    assert completed.confidence <= 0.65


def test_ungrounded_or_low_confidence_signals_are_discarded() -> None:
    message = "Tin nhắn này hơi kỳ"
    scoped = _scope(message)
    output = Understanding(
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        scenario=SecurityScenarioV4.PAYMENT,
        security_signals=[SemanticSecuritySignal.PAYMENT_REQUEST],
        field_confidences={
            "scope_decision": 0.79,
            "scenario": 0.99,
            "payment_request": 0.99,
        },
        source_spans=[],
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.scope_decision is ScopeDecisionV4.NEED_MORE_INFO
    assert merged.security_context is None
    assert any("source span" in item for item in merged.limitations)


def test_ai_cannot_replace_locally_extracted_urls() -> None:
    message = "Mở https://local.example/login"
    scoped = _scope(message)
    output = _understanding(
        message,
        requested_action=RequestedActionV4.OPEN_LINK,
        security_signals=[SemanticSecuritySignal.CREDENTIAL_REQUEST],
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.security_context.urls == ["https://local.example/login"]


@pytest.mark.asyncio
async def test_explicit_general_fact_check_is_terminal_without_model_call() -> None:
    class MustNotRun:
        async def understand(self, message, conversation_summary):
            raise AssertionError("explicit boundary invoked AI")

    message = "Ai vô địch World Cup?"
    service = SecuritySemanticUnderstandingService(
        enabled=True,
        model=MustNotRun(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    )
    result = await service.enrich(SecurityTriageCreateRequestV4(message=message), _scope(message))

    assert result.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
    assert result.assistant_context.processing_mode is AssistantProcessingModeV4.RULES_ONLY


@pytest.mark.asyncio
@pytest.mark.parametrize("message", ["Xin chào", "Bạn có thể làm gì?"])
async def test_local_conversation_intents_are_terminal_without_model_call(message: str) -> None:
    class MustNotRun:
        async def understand(self, message, conversation_summary):
            raise AssertionError("local conversation intent invoked AI")

    service = SecuritySemanticUnderstandingService(
        enabled=True,
        model=MustNotRun(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    )
    result = await service.enrich(SecurityTriageCreateRequestV4(message=message), _scope(message))

    assert result.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
    assert result.assistant_context.processing_mode is AssistantProcessingModeV4.RULES_ONLY
    assert result.boundary_message is not None
    assert result.risk is None


@pytest.mark.asyncio
async def test_first_vague_security_turn_gives_llm_the_policy_selected_follow_up_slot() -> None:
    message = "Tôi nhận được tin nhắn lạ"

    class FollowUpModel:
        received_summary: dict | None = None

        async def understand(self, message: str, conversation_summary: str | None):
            assert conversation_summary is not None
            self.received_summary = json.loads(conversation_summary)
            return ModelResponse(
                output=_understanding(
                    message,
                    scope_decision=ScopeDecisionV4.NEED_MORE_INFO,
                    follow_up_slot=MissingInformationSlotV4.ACTION_TAKEN,
                    follow_up_question="Bạn đã thực hiện hành động nào theo tin nhắn đó chưa?",
                ),
                provider="fake",
                model="understanding-v1",
            )

    model = FollowUpModel()
    service = SecuritySemanticUnderstandingService(
        enabled=True,
        model=model,
        runtime=SecurityAssistantRuntime(max_retries=0),
    )

    result = await service.enrich(SecurityTriageCreateRequestV4(message=message), _scope(message))

    assert model.received_summary == {
        "security_context": None,
        "exposure_state": "UNKNOWN",
        "policy_selected_follow_up_slot": "action_taken",
    }
    assert result.scope_decision is ScopeDecisionV4.NEED_MORE_INFO
    assert result.follow_up_slot is MissingInformationSlotV4.ACTION_TAKEN
    assert result.follow_up_question == "Bạn đã thực hiện hành động nào theo tin nhắn đó chưa?"


@pytest.mark.asyncio
async def test_provider_malformed_output_falls_back_without_api_error() -> None:
    class Malformed:
        async def understand(self, message, conversation_summary):
            return {
                "output": {"security_signals": ["safe"], "urls": ["https://invented.example"]},
                "provider": "fake",
                "model": "malformed",
            }

    message = "Ngân hàng yêu cầu gửi OTP"
    service = SecuritySemanticUnderstandingService(
        enabled=True,
        model=Malformed(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    )
    result = await service.enrich(SecurityTriageCreateRequestV4(message=message), _scope(message))

    assert result.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert result.security_context.otp_request is True
    assert result.assistant_context.processing_mode is AssistantProcessingModeV4.FALLBACK
    assert result.security_context.urls == []


def test_boundary_conflict_returns_need_more_info() -> None:
    message = "Ngân hàng yêu cầu gửi OTP"
    scoped = _scope(message)
    output = _understanding(
        message,
        scope_decision=ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK,
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.scope_decision is ScopeDecisionV4.NEED_MORE_INFO
    assert merged.terminal is True
    assert any("phạm vi" in item for item in merged.limitations)


def test_assistant_context_stores_offsets_but_no_raw_excerpt() -> None:
    message = "Đã bấm link rồi"
    scoped = _scope(message)
    output = _understanding(
        message,
        exposure_state=ExposureStateV4.LINK_OPENED,
        sender_intent="credential_capture",
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")
    serialized = merged.assistant_context.model_dump_json()

    assert merged.assistant_context.exposure_state is ExposureStateV4.LINK_OPENED
    assert merged.assistant_context.source_spans
    assert "Đã bấm link rồi" not in serialized


def test_rule_extractor_remains_available_for_rules_only_regression() -> None:
    context = extract_security_context("Ngân hàng yêu cầu gửi OTP ngay")
    assert context.otp_request is True


def test_optional_assistant_context_is_omitted_when_ai_is_disabled() -> None:
    scoped = _scope("Ngân hàng yêu cầu gửi OTP")

    assert "assistant_context" not in scoped.model_dump()
    assert "assistant_context" not in SecurityConversationSummaryV4().model_dump()
