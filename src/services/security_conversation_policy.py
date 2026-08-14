from __future__ import annotations

import re

from src.agents.security_scope import partial_security_context
from src.models import (
    AssistantContextV4,
    AssistantProcessingModeV4,
    ExposureStateV4,
    MissingInformationSlotV4,
    ScopeDecisionV4,
    SecurityContextV4,
    SecurityScopeResponseV4,
)

_EXPOSURE_RANK = {
    ExposureStateV4.UNKNOWN: 0,
    ExposureStateV4.PRE_ACTION: 1,
    ExposureStateV4.LINK_OPENED: 2,
    ExposureStateV4.CREDENTIAL_SHARED: 3,
    ExposureStateV4.OTP_SHARED: 4,
    ExposureStateV4.PAYMENT_SENT: 5,
}
_EXPOSURE_PATTERNS = (
    (
        ExposureStateV4.PAYMENT_SENT,
        (
            "đã chuyển tiền",
            "da chuyen tien",
            "đã chuyển khoản",
            "da chuyen khoan",
            "đã thanh toán",
            "da thanh toan",
            "paid already",
            "sent the money",
        ),
    ),
    (
        ExposureStateV4.OTP_SHARED,
        (
            "đã gửi otp",
            "da gui otp",
            "đã đưa otp",
            "da dua otp",
            "đã gửi mã xác thực",
            "da gui ma xac thuc",
            "shared the otp",
            "sent the verification code",
        ),
    ),
    (
        ExposureStateV4.CREDENTIAL_SHARED,
        (
            "đã nhập mật khẩu",
            "da nhap mat khau",
            "đã gửi mật khẩu",
            "da gui mat khau",
            "đã cung cấp mật khẩu",
            "da cung cap mat khau",
            "shared my password",
            "entered my password",
            "shared credentials",
        ),
    ),
    (
        ExposureStateV4.LINK_OPENED,
        (
            "đã bấm link",
            "da bam link",
            "đã mở link",
            "da mo link",
            "đã nhấn vào",
            "da nhan vao",
            "clicked the link",
            "opened the link",
        ),
    ),
    (
        ExposureStateV4.PRE_ACTION,
        (
            "chưa làm gì",
            "chua lam gi",
            "chưa bấm",
            "chua bam",
            "chưa gửi",
            "chua gui",
            "chưa chuyển",
            "chua chuyen",
            "not yet",
            "haven't done",
            "have not done",
        ),
    ),
)
_QUESTION_TEMPLATES = {
    MissingInformationSlotV4.ACTION_TAKEN: ("Bạn đã bấm link, nhập thông tin, gửi OTP hoặc chuyển tiền chưa?"),
    MissingInformationSlotV4.REQUESTED_SENSITIVE_ACTION: (
        "Người gửi yêu cầu bạn đăng nhập, cung cấp mật khẩu/OTP hay chuyển tiền gì?"
    ),
    MissingInformationSlotV4.URL_OR_CONTACT: (
        "Tin nhắn có đường link, tên miền, số điện thoại hoặc tài khoản liên hệ nào?"
    ),
    MissingInformationSlotV4.CLAIMED_ORGANIZATION: ("Người gửi tự xưng là tổ chức hoặc thương hiệu nào?"),
    MissingInformationSlotV4.AMOUNT_DEADLINE_CHANNEL: ("Họ nêu số tiền, thời hạn hoặc kênh liên hệ nào?"),
}
_UNSAFE_DRAFT = re.compile(r"https?://|www\.|\b\d{4,8}\b|[\w.+-]+@[\w.-]+", re.IGNORECASE)


def highest_exposure(*states: ExposureStateV4) -> ExposureStateV4:
    return max(states, key=_EXPOSURE_RANK.__getitem__, default=ExposureStateV4.UNKNOWN)


def detect_local_exposure(message: str) -> ExposureStateV4:
    text = " ".join(message.casefold().split())
    matches = [state for state, patterns in _EXPOSURE_PATTERNS if any(pattern in text for pattern in patterns)]
    return highest_exposure(*matches) if matches else ExposureStateV4.UNKNOWN


def is_incident_exposure(state: ExposureStateV4) -> bool:
    return _EXPOSURE_RANK[state] >= _EXPOSURE_RANK[ExposureStateV4.LINK_OPENED]


def unresolved_slots(
    context: SecurityContextV4 | None,
    exposure_state: ExposureStateV4,
) -> list[MissingInformationSlotV4]:
    slots: list[MissingInformationSlotV4] = []
    if exposure_state is ExposureStateV4.UNKNOWN:
        slots.append(MissingInformationSlotV4.ACTION_TAKEN)
    if context is None or not (
        context.requested_action
        or context.credential_request
        or context.otp_request
        or context.payment_request
        or context.personal_information_request
    ):
        slots.append(MissingInformationSlotV4.REQUESTED_SENSITIVE_ACTION)
    if context is None or not context.urls:
        slots.append(MissingInformationSlotV4.URL_OR_CONTACT)
    if context is None or not context.claimed_entity:
        slots.append(MissingInformationSlotV4.CLAIMED_ORGANIZATION)
    if context is None or not (context.amount or context.urgency):
        slots.append(MissingInformationSlotV4.AMOUNT_DEADLINE_CHANNEL)
    return slots


def select_missing_slot(
    context: SecurityContextV4 | None,
    exposure_state: ExposureStateV4,
) -> MissingInformationSlotV4 | None:
    slots = unresolved_slots(context, exposure_state)
    return slots[0] if slots else None


def deterministic_question(slot: MissingInformationSlotV4) -> str:
    return _QUESTION_TEMPLATES[slot]


def _safe_drafted_question(
    selected_slot: MissingInformationSlotV4,
    drafted_slot: MissingInformationSlotV4 | None,
    drafted_question: str | None,
) -> str | None:
    if drafted_slot is not selected_slot or drafted_question is None:
        return None
    question = " ".join(drafted_question.split())
    if len(question) > 500 or not question.endswith("?") or question.count("?") != 1 or _UNSAFE_DRAFT.search(question):
        return None
    return question


def apply_adaptive_conversation_policy(
    message: str,
    scope: SecurityScopeResponseV4,
    *,
    drafted_slot: MissingInformationSlotV4 | None = None,
    drafted_question: str | None = None,
) -> SecurityScopeResponseV4:
    """Apply deterministic exposure, missing-slot, and one-question policy."""
    existing_assistant = scope.assistant_context or AssistantContextV4(
        processing_mode=AssistantProcessingModeV4.RULES_ONLY,
        model_version="rules-only-v1",
    )
    exposure = highest_exposure(
        existing_assistant.exposure_state,
        detect_local_exposure(message),
    )
    context = scope.security_context
    update: dict[str, object] = {}
    if is_incident_exposure(exposure) and scope.scope_decision is not ScopeDecisionV4.IN_SCOPE:
        context = context or partial_security_context(message)
        update.update(
            scope_decision=ScopeDecisionV4.IN_SCOPE,
            terminal=False,
            next_step="INVESTIGATION",
            security_context=context,
            follow_up_question=None,
            follow_up_slot=None,
            boundary_message=None,
            scope_reasons=list(dict.fromkeys([*scope.scope_reasons, "incident_exposure_detected"])),
        )

    slots = unresolved_slots(context, exposure)
    assistant_context = existing_assistant.model_copy(
        update={
            "exposure_state": exposure,
            "missing_information": [slot.value for slot in slots],
        }
    )
    update["assistant_context"] = assistant_context
    effective_decision = update.get("scope_decision", scope.scope_decision)
    if effective_decision is ScopeDecisionV4.NEED_MORE_INFO:
        selected = slots[0] if slots else MissingInformationSlotV4.AMOUNT_DEADLINE_CHANNEL
        question = _safe_drafted_question(
            selected,
            drafted_slot,
            drafted_question,
        ) or deterministic_question(selected)
        update.update(
            follow_up_slot=selected,
            follow_up_question=question,
        )
    return scope.model_copy(update=update)


__all__ = [
    "apply_adaptive_conversation_policy",
    "detect_local_exposure",
    "deterministic_question",
    "highest_exposure",
    "is_incident_exposure",
    "select_missing_slot",
    "unresolved_slots",
]
