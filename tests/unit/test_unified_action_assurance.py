from src.agents.security_risk import assess_security_risk
from src.models import RequestedActionV4, SecurityRiskV4, SecurityTriageCreateRequestV4
from src.security_ai.contracts import (
    SemanticActionKind,
    SemanticActionMention,
    SemanticDirection,
    SemanticInteractionType,
    SemanticModality,
    SemanticParticipant,
    SemanticSensitiveObject,
    SemanticStance,
    Understanding,
)
from src.services.security_span_candidates import generate_semantic_span_candidates
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_understanding import merge_semantic_understanding


def _requested(action: SemanticActionKind, sensitive: SemanticSensitiveObject, span_id: str) -> SemanticActionMention:
    return SemanticActionMention(
        action_kind=action,
        sensitive_object=sensitive,
        actor=SemanticParticipant.SENDER,
        recipient=SemanticParticipant.USER,
        direction=SemanticDirection.TO_USER,
        modality=SemanticModality.REQUESTED,
        stance=SemanticStance.ASSERTED,
        interaction_type=SemanticInteractionType.DISCLOSURE
        if action is SemanticActionKind.DISCLOSE
        else SemanticInteractionType.ROUTINE_WORKFLOW,
        span_ids=[span_id],
        confidence=0.95,
    )


def test_registration_and_id_card_mention_is_not_personal_information_disclosure() -> None:
    message = "Họ yêu cầu tôi đăng ký hồ sơ và mang thẻ căn cước."
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))
    candidates = generate_semantic_span_candidates(message)
    merged = merge_semantic_understanding(
        message,
        scope,
        Understanding(
            action_mentions=[
                _requested(
                    SemanticActionKind.REGISTER_OR_APPLY,
                    SemanticSensitiveObject.PERSONAL_INFORMATION,
                    candidates[0].span_id,
                )
            ]
        ),
        model_version="test",
        span_candidates=candidates,
    )
    assert merged.security_context is not None
    assert merged.security_context.requested_action is RequestedActionV4.REGISTER_OR_APPLY
    assert not merged.security_context.personal_information_request
    assert merged.assistant_context is not None
    assert len(merged.assistant_context.grounded_actions) == 1


def test_retired_scalar_action_cannot_erase_literal_rule_action() -> None:
    message = "Mở link https://example.com ngay"
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))
    merged = merge_semantic_understanding(
        message, scope, Understanding(requested_action=RequestedActionV4.OPEN_LINK), model_version="test"
    )
    decision = assess_security_risk(merged, familiarity_enforced=True)
    assert decision.security_context is not None
    assert decision.security_context.requested_action is RequestedActionV4.OPEN_LINK
    assert decision.risk is not SecurityRiskV4.SAFE
    assert decision.policy_version == "security-risk-v7"
    assert decision.policy_metadata is not None
    assert decision.policy_metadata.decision_assurance == "action_intent_unavailable"
