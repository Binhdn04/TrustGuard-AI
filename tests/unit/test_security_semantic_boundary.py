from src.agents.security_scope import extract_security_context
from src.models import ExposureStateV4, RequestedActionV4, SecurityTriageCreateRequestV4
from src.security_ai.contracts import (
    SemanticActionKind,
    SemanticActionMention,
    SemanticCompletionStatus,
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
from src.services.official_verification_intent import build_grounded_verification_intent
from src.services.security_understanding import merge_semantic_understanding


def test_fallback_distinguishes_form_authentication_from_otp_disclosure() -> None:
    authentication = extract_security_context("Nhập OTP vào form này")
    disclosure = extract_security_context("Gửi OTP cho tôi")

    assert authentication.otp_request is False
    assert authentication.requested_action is RequestedActionV4.SUBMIT_FORM
    assert disclosure.otp_request is True
    assert disclosure.requested_action is RequestedActionV4.SHARE_OTP


def test_fallback_does_not_promote_login_support_problem() -> None:
    context = extract_security_context("Tôi không đăng nhập được Google")

    assert context.requested_action is None
    assert context.credential_request is False


def test_semantic_mentions_project_only_active_sender_disclosure() -> None:
    message = 'Họ viết "gửi mật khẩu" nhưng tôi chỉ đăng nhập trong ứng dụng'
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))
    candidates = generate_semantic_span_candidates(message)
    anchor = candidates[-1].span_id
    output = Understanding(
        action_mentions=[
            SemanticActionMention(
                action_kind=SemanticActionKind.DISCLOSE,
                sensitive_object=SemanticSensitiveObject.CREDENTIALS,
                actor=SemanticParticipant.SENDER,
                recipient=SemanticParticipant.USER,
                direction=SemanticDirection.TO_USER,
                modality=SemanticModality.REQUESTED,
                stance=SemanticStance.QUOTED,
                interaction_type=SemanticInteractionType.DISCLOSURE,
                span_ids=[anchor],
                confidence=0.96,
            ),
            SemanticActionMention(
                action_kind=SemanticActionKind.LOGIN,
                sensitive_object=SemanticSensitiveObject.CREDENTIALS,
                actor=SemanticParticipant.USER,
                recipient=SemanticParticipant.FORM_OR_SERVICE,
                direction=SemanticDirection.USER_TO_FORM_OR_SERVICE,
                modality=SemanticModality.PERFORMED,
                stance=SemanticStance.ASSERTED,
                interaction_type=SemanticInteractionType.AUTHENTICATION,
                exposure_event=False,
                completion_status=SemanticCompletionStatus.COMPLETED,
                span_ids=[anchor],
                confidence=0.95,
            ),
        ]
    )

    merged = merge_semantic_understanding(
        message, scope, output, model_version="semantic-test", span_candidates=candidates
    )

    assert merged.security_context is not None
    assert merged.security_context.credential_request is False
    assert merged.security_context.requested_action is None
    assert merged.assistant_context is not None
    assert merged.assistant_context.exposure_state is ExposureStateV4.UNKNOWN


def test_invalid_mention_is_dropped_without_discarding_valid_sibling() -> None:
    message = "Gửi OTP cho tôi"
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))
    candidates = generate_semantic_span_candidates(message)
    valid = SemanticActionMention(
        action_kind=SemanticActionKind.DISCLOSE,
        sensitive_object=SemanticSensitiveObject.OTP,
        actor=SemanticParticipant.SENDER,
        recipient=SemanticParticipant.USER,
        direction=SemanticDirection.TO_USER,
        modality=SemanticModality.REQUESTED,
        stance=SemanticStance.ASSERTED,
        interaction_type=SemanticInteractionType.DISCLOSURE,
        span_ids=[candidates[-1].span_id],
        confidence=0.95,
    )
    invalid = valid.model_copy(update={"span_ids": ["span_missing"]})

    merged = merge_semantic_understanding(
        message,
        scope,
        Understanding(action_mentions=[invalid, valid]),
        model_version="semantic-test",
        span_candidates=candidates,
    )

    assert merged.security_context is not None
    assert merged.security_context.otp_request is True
    assert merged.security_context.requested_action is RequestedActionV4.SHARE_OTP


def test_literal_apply_action_survives_semantic_omission_and_binds_its_url() -> None:
    message = "Please visit https://forms.example/apply to apply."
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))

    merged = merge_semantic_understanding(message, scope, Understanding(), model_version="semantic-test")

    assert merged.security_context is not None
    assert merged.security_context.requested_action is RequestedActionV4.REGISTER_OR_APPLY
    intent = build_grounded_verification_intent(message, merged.security_context, merged.assistant_context)
    assert intent is not None
    assert intent.contract.action_url_indices == [0]


def test_requested_user_to_service_action_projects_and_binds_its_url() -> None:
    message = "Please visit https://forms.example/apply to apply."
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))
    candidates = generate_semantic_span_candidates(message)
    action_span = next(item for item in candidates if message[item.start : item.end] == "apply")
    output = Understanding(
        action_mentions=[
            SemanticActionMention(
                action_kind=SemanticActionKind.REGISTER_OR_APPLY,
                sensitive_object=SemanticSensitiveObject.NONE,
                actor=SemanticParticipant.USER,
                recipient=SemanticParticipant.FORM_OR_SERVICE,
                direction=SemanticDirection.USER_TO_FORM_OR_SERVICE,
                modality=SemanticModality.REQUESTED,
                stance=SemanticStance.ASSERTED,
                interaction_type=SemanticInteractionType.ROUTINE_WORKFLOW,
                span_ids=[action_span.span_id],
                url_indices=[0],
                confidence=0.95,
            )
        ]
    )

    merged = merge_semantic_understanding(message, scope, output, model_version="semantic-test")

    assert merged.security_context is not None
    assert merged.security_context.requested_action is RequestedActionV4.REGISTER_OR_APPLY
    intent = build_grounded_verification_intent(message, merged.security_context, merged.assistant_context)
    assert intent is not None
    assert intent.contract.action_url_indices == [0]


def test_reference_only_url_does_not_become_an_action_url() -> None:
    message = "Reference material: https://docs.example/overview."
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))

    merged = merge_semantic_understanding(message, scope, Understanding(), model_version="semantic-test")

    assert merged.security_context is not None
    assert merged.security_context.requested_action is None
    intent = build_grounded_verification_intent(message, merged.security_context, merged.assistant_context)
    assert intent is None or intent.contract.action_url_indices == []


def test_action_binds_only_the_url_in_its_clause() -> None:
    message = "Reference: https://docs.example/overview. Please visit https://forms.example/apply to apply."
    scope = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))
    assert scope.security_context is not None

    intent = build_grounded_verification_intent(message, scope.security_context)

    assert intent is not None
    assert intent.contract.action_url_indices == [1]
