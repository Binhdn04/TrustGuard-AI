from src.models import RequestedActionV4, ScopeDecisionV4, SecurityTriageCreateRequestV4
from src.security_ai.contracts import Understanding, UnderstandingSpanSelection
from src.security_ai.openai import _OpenAIUnderstanding
from src.services.security_span_candidates import generate_semantic_span_candidates
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_understanding import merge_semantic_understanding


def test_candidates_cover_url_phrase_clause_and_full_message_with_stable_preference() -> None:
    message = "Cán bộ phường hướng dẫn tôi vào\nhttps://example.test/passport để làm hộ chiếu"
    first = generate_semantic_span_candidates(message)
    second = generate_semantic_span_candidates(message)

    assert first == second
    assert {item.kind for item in first} >= {"url", "phrase", "clause", "full_message"}
    assert any(message[item.start : item.end] == "https://example.test/passport" for item in first)
    assert first[-1].kind == "full_message"


def test_hosted_understanding_wire_selects_ids_and_has_no_offset_fields() -> None:
    schema = _OpenAIUnderstanding.model_json_schema()

    assert "span_selections" in schema["properties"]
    assert "source_spans" not in schema["properties"]
    assert '"start"' not in str(schema)
    assert '"end"' not in str(schema)


def test_retired_scalar_action_is_ignored_when_spans_are_valid() -> None:
    message = "Vào https://example.test để làm hộ chiếu"
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))
    spans = generate_semantic_span_candidates(message)
    phrase = next(item for item in spans if "làm hộ chiếu" in message[item.start : item.end])
    output = Understanding(
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        requested_action=RequestedActionV4.APPLY_FOR_PASSPORT,
        field_confidences={"scope_decision": 0.95, "requested_action": 0.95},
        span_selections=[
            UnderstandingSpanSelection(field_name="scope_decision", span_ids=["missing_span"]),
            UnderstandingSpanSelection(field_name="requested_action", span_ids=[phrase.span_id]),
        ],
    )

    merged = merge_semantic_understanding(message, scope, output, model_version="span-id-test", span_candidates=spans)

    assert merged.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert merged.security_context is not None
    assert merged.security_context.requested_action is None
    assert not any("invalid_source_span" in item and "scope_decision" in item for item in merged.limitations)
