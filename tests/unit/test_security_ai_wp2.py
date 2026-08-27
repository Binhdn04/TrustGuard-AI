from __future__ import annotations

from src.agents.security_risk import assess_security_risk
from src.models import (
    AssistantContextV4,
    AssistantProcessingModeV4,
    ExposureStateV4,
    MissingInformationSlotV4,
    SecurityRecommendedActionV4,
    SecurityTriageCreateRequestV4,
)
from src.services.security_conversation_policy import (
    apply_adaptive_conversation_policy,
    detect_local_exposure,
    highest_exposure,
    unresolved_slots,
)
from src.services.security_triage import SecurityTriageScopeService


def _scope(message: str):
    return SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message=message))


def _assistant(exposure: ExposureStateV4) -> AssistantContextV4:
    return AssistantContextV4(
        processing_mode=AssistantProcessingModeV4.RULES_ONLY,
        exposure_state=exposure,
        model_version="rules-only-v1",
    )


def test_missing_slot_policy_is_ordered_and_asks_exactly_one_question() -> None:
    scoped = _scope("Tôi nhận được tin nhắn lạ")

    result = apply_adaptive_conversation_policy("Tôi nhận được tin nhắn lạ", scoped)

    assert result.follow_up_slot is MissingInformationSlotV4.ACTION_TAKEN
    # Policy selects the only allowed slot; the response composer supplies
    # user-facing wording after that selection.
    assert result.follow_up_question is None
    assert result.assistant_context.missing_information == [slot.value for slot in MissingInformationSlotV4]


def test_policy_advances_to_requested_action_after_user_says_no_action_taken() -> None:
    scoped = _scope("Tôi nhận được tin nhắn lạ")

    result = apply_adaptive_conversation_policy("Tôi chưa làm gì", scoped)

    assert result.assistant_context.exposure_state is ExposureStateV4.PRE_ACTION
    assert result.follow_up_slot is MissingInformationSlotV4.REQUESTED_SENSITIVE_ACTION


def test_llm_can_only_phrase_the_policy_selected_slot() -> None:
    scoped = _scope("Tôi nhận được tin nhắn lạ")

    result = apply_adaptive_conversation_policy(
        "Tôi nhận được tin nhắn lạ",
        scoped,
        drafted_slot=MissingInformationSlotV4.URL_OR_CONTACT,
        drafted_question="Mã OTP 123456 của bạn là gì?",
    )

    assert result.follow_up_slot is MissingInformationSlotV4.ACTION_TAKEN
    assert result.follow_up_question is None


def test_exposure_is_local_and_monotonic() -> None:
    assert detect_local_exposure("Tôi đã gửi OTP cho họ") is ExposureStateV4.OTP_SHARED
    assert highest_exposure(ExposureStateV4.OTP_SHARED, ExposureStateV4.PRE_ACTION) is ExposureStateV4.OTP_SHARED


def test_incident_exposure_has_immediate_deterministic_recovery_actions() -> None:
    scoped = _scope("Ngân hàng yêu cầu gửi OTP")
    scoped = scoped.model_copy(update={"assistant_context": _assistant(ExposureStateV4.OTP_SHARED)})

    result = assess_security_risk(scoped)

    assert result.risk.value != "SAFE"
    assert SecurityRecommendedActionV4.REVOKE_ACTIVE_SESSIONS in result.recommended_actions
    assert SecurityRecommendedActionV4.CONTACT_BANK_OR_PAYMENT_PROVIDER in result.recommended_actions
    assert SecurityRecommendedActionV4.PRESERVE_MESSAGE_FOR_REPORTING in result.recommended_actions


def test_each_incident_exposure_maps_to_its_policy_recovery_actions() -> None:
    expected = {
        ExposureStateV4.LINK_OPENED: {SecurityRecommendedActionV4.CLOSE_PAGE_AND_DO_NOT_RETURN},
        ExposureStateV4.CREDENTIAL_SHARED: {
            SecurityRecommendedActionV4.CHANGE_PASSWORD_FROM_TRUSTED_DEVICE,
            SecurityRecommendedActionV4.REVOKE_ACTIVE_SESSIONS,
        },
        ExposureStateV4.OTP_SHARED: {
            SecurityRecommendedActionV4.REVOKE_ACTIVE_SESSIONS,
            SecurityRecommendedActionV4.CONTACT_BANK_OR_PAYMENT_PROVIDER,
        },
        ExposureStateV4.PAYMENT_SENT: {SecurityRecommendedActionV4.CONTACT_BANK_OR_PAYMENT_PROVIDER},
    }
    scoped = _scope("Ngân hàng yêu cầu gửi OTP")

    for exposure, required in expected.items():
        result = assess_security_risk(scoped.model_copy(update={"assistant_context": _assistant(exposure)}))
        assert required <= set(result.recommended_actions)
        assert SecurityRecommendedActionV4.PRESERVE_MESSAGE_FOR_REPORTING in result.recommended_actions


def test_amount_or_deadline_resolves_the_last_combined_slot() -> None:
    scoped = _scope("Yêu cầu chuyển tiền 2 triệu ngay")

    slots = unresolved_slots(scoped.security_context, ExposureStateV4.PRE_ACTION)

    assert MissingInformationSlotV4.AMOUNT_DEADLINE_CHANNEL not in slots
