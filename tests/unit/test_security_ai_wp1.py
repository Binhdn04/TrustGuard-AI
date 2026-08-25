from __future__ import annotations

import json

import pytest

from src.agents.security_risk import assess_security_risk
from src.agents.security_scope import extract_security_context
from src.models import (
    AssistantProcessingModeV4,
    EntityUrlRelationshipV4,
    ExposureStateV4,
    MissingInformationSlotV4,
    PotentialThreatV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityConversationSummaryV4,
    SecurityInvestigationStatusV4,
    SecurityScenarioV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import (
    EntityUrlClaimCandidate,
    ModelResponse,
    SemanticSecuritySignal,
    Understanding,
    UnderstandingSourceSpan,
)
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_entity_mentions import EntityMentionCandidate
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
    if output.entity_url_claims:
        grounded_fields.append("entity_url_claims")
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


def test_hosted_understanding_schema_requires_grounding_collections() -> None:
    schema = Understanding.model_json_schema()

    assert {"field_confidences", "span_selections"} <= set(schema["required"])


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
    assert any("low_confidence" in item and "scope_decision" in item for item in merged.limitations)
    assert any(
        "missing_source_span" in item and "payment_request, scenario, scope_decision" in item
        for item in merged.limitations
    )


def test_semantic_grounding_reports_missing_confidence_and_invalid_span_separately(caplog) -> None:
    message = "Tin nhắn này hơi kỳ"
    scoped = _scope(message)
    output = Understanding(
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        scenario=SecurityScenarioV4.PAYMENT,
        field_confidences={"scenario": 0.99},
        source_spans=[
            UnderstandingSourceSpan(field_name="scope_decision", start=0, end=len(message)),
            UnderstandingSourceSpan(field_name="scenario", start=len(message), end=len(message) + 5),
        ],
    )

    with caplog.at_level("WARNING", logger="trustguard.security_ai"):
        merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert any("missing_confidence" in item and "scope_decision" in item for item in merged.limitations)
    assert any("invalid_source_span" in item and "scenario" in item for item in merged.limitations)
    rejected = [record for record in caplog.records if record.getMessage() == "security_ai_semantic_field_rejected"]
    assert {(record.field_name, record.failure_code) for record in rejected} == {
        ("scope_decision", "missing_confidence"),
        ("scenario", "invalid_source_span"),
    }
    assert {record.operation for record in rejected} == {"understand"}
    assert all(message not in record.getMessage() for record in rejected)


def test_literal_claimed_entity_is_grounded_when_model_omits_metadata() -> None:
    message = "Bệnh viện Đại học Y yêu cầu đăng ký tại https://bachmai.gov.vn/"
    scoped = _scope(message)
    output = Understanding(claimed_entity="Bệnh viện Đại học Y")

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.security_context.claimed_entity == "Bệnh viện Đại học Y"
    assert merged.assistant_context.field_confidences["claimed_entity"] == 1
    span = next(item for item in merged.assistant_context.source_spans if item.field_name == "claimed_entity")
    assert message[span.start : span.end] == "Bệnh viện Đại học Y"
    assert all("claimed_entity" not in item for item in merged.limitations)


def test_arbitrary_literal_is_not_promoted_to_claimed_entity_without_grounding() -> None:
    message = "Hãy mở link ngay https://example.com"
    scoped = _scope(message)
    output = Understanding(claimed_entity="ngay")

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.security_context.claimed_entity is None
    assert any("claimed_entity" in item for item in merged.limitations)


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


def test_ai_cannot_turn_a_url_inspection_into_a_sender_open_link_request() -> None:
    message = "Check https://arbitrary.example"
    scoped = _scope(message)
    output = _understanding(message, requested_action=RequestedActionV4.OPEN_LINK)

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.security_context.requested_action is None
    assert any("requested_action" in item for item in merged.limitations)
    assert "requested_action" not in merged.assistant_context.field_confidences


def test_local_entity_candidate_is_not_an_impersonation_signal() -> None:
    message = "Check Google at https://arbitrary.example"
    scoped = _scope(message)

    merged = SecuritySemanticUnderstandingService._merge_local_candidates(
        message,
        scoped,
        [EntityMentionCandidate(mention_id="entity_0", text="Google", start=6, end=12)],
    )

    assert merged.security_context.claimed_entity == "Google"
    assert merged.security_context.impersonation_signals == []
    assert merged.security_context.potential_threat is PotentialThreatV4.UNDETERMINED_SECURITY_THREAT


def test_grounded_entity_url_claim_uses_only_a_local_url_index() -> None:
    message = "Bệnh viện Đại học Y thông báo web của bệnh viện là https://bachmai.gov.vn/"
    scoped = _scope(message)
    output = _understanding(
        message,
        claimed_entity="Bệnh viện Đại học Y",
        entity_url_claims=[
            EntityUrlClaimCandidate(
                entity_name="Bệnh viện Đại học Y",
                url_index=0,
                relationship=EntityUrlRelationshipV4.CLAIMED_OFFICIAL_SITE,
            )
        ],
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.security_context.entity_url_claims[0].url_index == 0
    assert merged.security_context.entity_url_claims[0].entity_name == "Bệnh viện Đại học Y"


def test_backend_stable_entity_id_creates_exact_spans_without_model_offsets() -> None:
    message = (
        "Mọi người nên đăng ký trước. Hôm nay tôi đi Bệnh viện Đại học Y vào phòng khám. "
        "Web của bệnh viện đây nhé: https://bachmai.gov.vn/"
    )
    scoped = _scope(message)
    output = Understanding(
        claimed_entity_id="entity_0",
        entity_url_claims=[
            EntityUrlClaimCandidate(
                entity_mention_id="entity_0",
                url_index=0,
                relationship=EntityUrlRelationshipV4.CLAIMED_OFFICIAL_SITE,
            )
        ],
        field_confidences={"claimed_entity_id": 0.95, "entity_url_claims": 0.95},
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.assistant_context.processing_mode is AssistantProcessingModeV4.HYBRID
    entity_span = next(item for item in merged.assistant_context.source_spans if item.field_name == "claimed_entity")
    relation_span = next(
        item for item in merged.assistant_context.source_spans if item.field_name == "entity_url_claims"
    )
    assert message[entity_span.start : entity_span.end] == "Bệnh viện Đại học Y"
    assert "Bệnh viện Đại học Y" in message[relation_span.start : relation_span.end]
    assert "bachmai.gov.vn" in message[relation_span.start : relation_span.end]
    assert merged.security_context.entity_url_claims[0].entity_name == "Bệnh viện Đại học Y"


def test_entity_url_claim_with_an_unknown_url_index_is_rejected() -> None:
    message = "Bệnh viện Đại học Y thông báo web của bệnh viện là https://bachmai.gov.vn/"
    scoped = _scope(message)
    output = _understanding(
        message,
        claimed_entity="Bệnh viện Đại học Y",
        entity_url_claims=[
            EntityUrlClaimCandidate(
                entity_name="Bệnh viện Đại học Y",
                url_index=1,
                relationship=EntityUrlRelationshipV4.CLAIMED_OFFICIAL_SITE,
            )
        ],
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    # The invalid AI claim is rejected, while the independently grounded local
    # ownership rule remains sticky.
    assert len(merged.security_context.entity_url_claims) == 1
    assert merged.security_context.entity_url_claims[0].url_index == 0
    assert any("entity_url_claims" in item for item in merged.limitations)


@pytest.mark.asyncio
@pytest.mark.parametrize(("start", "end"), [(83, 83), (90, 83)])
async def test_invalid_provider_span_drops_only_affected_semantic_field(start: int, end: int) -> None:
    message = "Bệnh viện Đại học Y giới thiệu một cổng đăng ký tại https://bachmai.gov.vn/"

    class InvalidSpanModel:
        async def understand(self, message, conversation_summary):
            del conversation_summary
            return ModelResponse(
                output=Understanding(
                    claimed_entity="Bệnh viện Đại học Y",
                    entity_url_claims=[
                        EntityUrlClaimCandidate(
                            entity_name="Bệnh viện Đại học Y",
                            url_index=0,
                            relationship=EntityUrlRelationshipV4.REFERENCE_ONLY,
                        )
                    ],
                    field_confidences={"claimed_entity": 0.95, "entity_url_claims": 0.9},
                    source_spans=[
                        UnderstandingSourceSpan(field_name="claimed_entity", start=0, end=21),
                        UnderstandingSourceSpan(field_name="entity_url_claims", start=start, end=end),
                    ],
                ),
                provider="fake",
                model="understanding-v1",
            )

    result = await SecuritySemanticUnderstandingService(
        enabled=True,
        model=InvalidSpanModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(SecurityTriageCreateRequestV4(message=message), _scope(message))

    assert result.assistant_context.processing_mode is AssistantProcessingModeV4.HYBRID
    assert result.security_context.claimed_entity == "Bệnh viện Đại học Y"
    assert result.security_context.entity_url_claims == []
    assert any("entity_url_claims" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_explicit_general_fact_check_is_confirmed_by_model_before_terminal() -> None:
    class GeneralFactModel:
        called = False

        async def understand(self, message, conversation_summary):
            self.called = True
            return ModelResponse(
                output=_understanding(
                    message,
                    scope_decision=ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK,
                ),
                provider="fake",
                model="understanding-v1",
            )

    message = "Ai vô địch World Cup?"
    service = SecuritySemanticUnderstandingService(
        enabled=True,
        model=(model := GeneralFactModel()),
        runtime=SecurityAssistantRuntime(max_retries=0),
    )
    result = await service.enrich(SecurityTriageCreateRequestV4(message=message), _scope(message))

    assert result.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
    assert model.called is True
    assert result.assistant_context.processing_mode is AssistantProcessingModeV4.HYBRID


@pytest.mark.asyncio
async def test_grounded_ai_can_recover_a_rule_scope_false_negative() -> None:
    message = "Họ bảo tôi xác nhận hồ sơ qua cổng nội bộ"
    scoped = _scope(message)
    assert scoped.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK

    class SecurityModel:
        async def understand(self, message, conversation_summary):
            del conversation_summary
            return ModelResponse(
                output=_understanding(
                    message,
                    scope_decision=ScopeDecisionV4.IN_SCOPE,
                    requested_action=RequestedActionV4.PROVIDE_PERSONAL_INFORMATION,
                    security_signals=[SemanticSecuritySignal.PERSONAL_INFORMATION_REQUEST],
                ),
                provider="fake",
                model="understanding-v1",
            )

    result = await SecuritySemanticUnderstandingService(
        enabled=True,
        model=SecurityModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(SecurityTriageCreateRequestV4(message=message), scoped)

    assert result.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert result.terminal is False
    assert result.security_context.personal_information_request is True


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

    assert model.received_summary is not None
    assert model.received_summary["security_context"] is None
    assert model.received_summary["exposure_state"] == "UNKNOWN"
    assert model.received_summary["policy_selected_follow_up_slot"] == "action_taken"
    assert model.received_summary["span_candidates"]
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


def test_ai_cannot_downgrade_a_rule_positive_security_scope() -> None:
    message = "Ngân hàng yêu cầu gửi OTP"
    scoped = _scope(message)
    output = _understanding(
        message,
        scope_decision=ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK,
    )

    merged = merge_semantic_understanding(message, scoped, output, model_version="fake-semantic-v1")

    assert merged.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert merged.terminal is False
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
