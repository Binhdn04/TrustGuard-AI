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
