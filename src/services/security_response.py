from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum

from src.models import (
    SECURITY_ASSISTANT_RESPONSE_VERSION,
    AssistantGenerationModeV4,
    AssistantImmediateStepV4,
    AssistantReasonV4,
    AssistantResponseV4,
    SecurityEvidenceV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
    VerificationStatusV4,
)
from src.security_ai.contracts import AssistantOperation, AssistantSynthesis, SecurityAssistantModel
from src.security_ai.runtime import SecurityAssistantRuntime

_UNSAFE_LINK_TEXT = re.compile(r"(?:https?://|www\.)\S*", re.IGNORECASE)
_TECHNICAL_METRIC_TEXT = re.compile(
    r"(?:\b(?:risk score|confidence|policy|evidence_ref)\b|\bđiểm\s+(?:số|rủi ro)\b|độ tin cậy|"
    r"\b\d+(?:[.,]\d+)?\s*(?:%|/100))",
    re.IGNORECASE,
)
_AI_SYNTHESIS_LIMITATION = (
    "AI diễn đạt không khả dụng; phản hồi vẫn được tạo trực tiếp từ kết quả, bằng chứng và hành động đã kiểm chứng."
)
_AI_FAILURE_REASON_LABELS = {
    "budget_exceeded": "vượt ngân sách lượt gọi",
    "invalid_structured_output": "structured output không hợp lệ",
    "provider_unconfigured": "provider AI chưa được cấu hình",
    "provider_error": "provider trả lỗi",
    "timeout": "provider quá thời gian chờ",
    "turn_deadline_exceeded": "lượt phân tích vượt deadline",
    "grounding_rejected": "phản hồi AI không vượt qua kiểm tra grounding",
    "unknown_evidence_ref": "phản hồi AI trích dẫn bằng chứng không tồn tại",
    "unsafe_url": "phản hồi AI chứa liên kết không được phép tái hiện",
    "technical_metric": "phản hồi AI chứa điểm số hoặc chỉ số kỹ thuật không được phép",
    "missing_top_reasons": "phản hồi AI thiếu lý do có trích dẫn bằng chứng",
    "official_verification_overreach": "phản hồi AI suy rộng kết quả xác minh chính thức",
    "invalid_response_contract": "phản hồi AI không thỏa hợp đồng phản hồi cuối",
}
_FOLLOW_UP_OFFER = (
    "Nếu bạn đã mở liên kết, nhập mật khẩu, gửi OTP hoặc chuyển tiền, hãy nói cho mình biết loại hành động "
    "đã thực hiện — không gửi giá trị mật khẩu hay mã OTP — để mình hướng dẫn bước tiếp theo."
)

_RISK_GUIDANCE: dict[SecurityRiskV4, str] = {
    SecurityRiskV4.SAFE: (
        "Các kiểm tra hiện có chưa phát hiện dấu hiệu nguy hiểm rõ ràng. "
        "Dù vậy, bạn vẫn nên kiểm tra đúng kênh chính thức trước khi cung cấp thông tin nhạy cảm."
    ),
    SecurityRiskV4.LOW_RISK: (
        "Mình chưa thấy bằng chứng mạnh cho thấy đây là lừa đảo, nhưng vẫn có dấu hiệu cần thận trọng."
    ),
    SecurityRiskV4.SUSPICIOUS: (
        "Nội dung này có một số dấu hiệu đáng ngờ. Bạn nên tạm dừng và xác minh lại trước khi làm theo yêu cầu."
    ),
    SecurityRiskV4.HIGH_RISK: (
        "Nội dung này có nguy cơ cao khiến bạn mất tài khoản, thông tin cá nhân hoặc tiền. "
        "Bạn nên dừng lại và chưa làm theo yêu cầu của người gửi."
    ),
    SecurityRiskV4.MALICIOUS: (
        "Mình phát hiện bằng chứng mạnh cho thấy mục tiêu này nguy hiểm. Đừng tiếp tục tương tác với nó."
    ),
    SecurityRiskV4.INSUFFICIENT_EVIDENCE: (
        "Mình chưa có đủ dữ liệu để xác nhận nội dung này an toàn hay nguy hiểm. "
        "Trong lúc chưa rõ, bạn nên coi đây là tình huống cần thận trọng."
    ),
}

_ACTION_GUIDANCE: dict[SecurityRecommendedActionV4, str] = {
    SecurityRecommendedActionV4.DO_NOT_OPEN_LINK: "Đừng mở hoặc quay lại liên kết này.",
    SecurityRecommendedActionV4.DO_NOT_SHARE_CREDENTIALS: "Đừng cung cấp tên đăng nhập hoặc mật khẩu.",
    SecurityRecommendedActionV4.DO_NOT_SHARE_OTP: "Không chia sẻ mã OTP với bất kỳ ai.",
    SecurityRecommendedActionV4.DO_NOT_TRANSFER_MONEY: "Chưa chuyển tiền hoặc thanh toán theo yêu cầu này.",
    SecurityRecommendedActionV4.VERIFY_VIA_OFFICIAL_CHANNEL: (
        "Hãy tự liên hệ tổ chức qua ứng dụng, website hoặc số điện thoại chính thức."
    ),
    SecurityRecommendedActionV4.CHANGE_PASSWORD_IF_ALREADY_SHARED: (
        "Nếu đã cung cấp mật khẩu, hãy đổi ngay trên một thiết bị đáng tin cậy."
    ),
    SecurityRecommendedActionV4.CONTACT_BANK_IF_ALREADY_PAID: (
        "Nếu đã chuyển tiền, hãy liên hệ ngân hàng hoặc đơn vị thanh toán ngay."
    ),
    SecurityRecommendedActionV4.REPORT_AND_BLOCK_SENDER: "Báo cáo và chặn người gửi.",
    SecurityRecommendedActionV4.PROCEED_WITH_CAUTION: "Chỉ tiếp tục sau khi đã xác minh bằng kênh chính thức.",
    SecurityRecommendedActionV4.ALLOW_OPEN: "Bạn có thể mở liên kết đã được xác minh này.",
    SecurityRecommendedActionV4.CLOSE_PAGE_AND_DO_NOT_RETURN: "Đóng trang và không quay lại liên kết đó.",
    SecurityRecommendedActionV4.CHANGE_PASSWORD_FROM_TRUSTED_DEVICE: ("Đổi mật khẩu từ một thiết bị đáng tin cậy."),
    SecurityRecommendedActionV4.REVOKE_ACTIVE_SESSIONS: "Đăng xuất các phiên đang hoạt động trên tài khoản.",
    SecurityRecommendedActionV4.CONTACT_BANK_OR_PAYMENT_PROVIDER: (
        "Liên hệ ngay ngân hàng hoặc đơn vị thanh toán để được hỗ trợ."
    ),
    SecurityRecommendedActionV4.PRESERVE_MESSAGE_FOR_REPORTING: "Giữ lại tin nhắn để làm bằng chứng báo cáo.",
}

_SIGNAL_GUIDANCE: tuple[tuple[frozenset[str], str], ...] = (
    (
        frozenset({"official_domain_verified"}),
        "Tên miền được nêu đã được xác minh thuộc quyền kiểm soát chính thức của tổ chức.",
    ),
    (
        frozenset({"sender_identity_unverified"}),
        "Tin nhắn chưa có đủ bằng chứng xác thực danh tính người gửi.",
    ),
    (
        frozenset({"action_endorsement_unverified"}),
        "Nguồn chính thức chưa xác nhận đúng yêu cầu đăng nhập hoặc hành động trong tin nhắn.",
    ),
    (frozenset({"otp_request", "share_otp"}), "Người gửi yêu cầu mã OTP, là thông tin không nên chia sẻ."),
    (frozenset({"credential_request", "share_credentials"}), "Người gửi yêu cầu bạn cung cấp thông tin đăng nhập."),
    (frozenset({"login"}), "Nội dung đề cập một bước đăng nhập; chỉ tiếp tục qua kênh chính thức."),
    (
        frozenset({"payment_request", "transfer_money", "pay_fee"}),
        "Người gửi yêu cầu bạn chuyển tiền hoặc thanh toán.",
    ),
    (
        frozenset({"approved_blacklist_hit", "malicious", "confirmed_threat", "threat_intelligence_hit"}),
        "Địa chỉ này đã được một nguồn kiểm tra bảo mật ghi nhận là nguy hiểm.",
    ),
    (
        frozenset({"lookalike_domain", "domain_mismatch", "claimed_identity_unverified"}),
        "Địa chỉ quan sát được không khớp rõ ràng với tổ chức được nhắc tới.",
    ),
    (
        frozenset({"approved_whitelist", "official_match", "official_contact_match", "safe"}),
        "Địa chỉ này khớp với một nguồn đã được kiểm duyệt.",
    ),
    (
        frozenset({"new_domain", "recent_registration"}),
        "Tên miền còn mới, nên chưa có nhiều lịch sử để đối chiếu.",
    ),
    (frozenset({"punycode_domain", "promotion_lure_domain"}), "Tên miền có đặc điểm thường cần kiểm tra kỹ."),
)

logger = logging.getLogger("trustguard.security_ai")


class SynthesisGroundingFailure(StrEnum):
    UNKNOWN_EVIDENCE_REF = "unknown_evidence_ref"
    UNSAFE_URL = "unsafe_url"
    TECHNICAL_METRIC = "technical_metric"
    MISSING_TOP_REASONS = "missing_top_reasons"
    INVALID_RESPONSE_CONTRACT = "invalid_response_contract"
    OFFICIAL_VERIFICATION_OVERREACH = "official_verification_overreach"


@dataclass(frozen=True, slots=True)
class SynthesisGroundingCheck:
    response: AssistantResponseV4 | None
    failure: SynthesisGroundingFailure | None = None


def _remove_unsafe_sentences(text: str) -> tuple[str, bool]:
    """Remove a prohibited prose fragment without retaining private/model text."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    retained = [
        sentence
        for sentence in sentences
        if sentence
        and not _UNSAFE_LINK_TEXT.search(sentence)
        and not _TECHNICAL_METRIC_TEXT.search(sentence)
    ]
    return " ".join(retained).strip(), len(retained) != len(sentences)


def _remove_unverified_official_claims(text: str) -> tuple[str, bool]:
    """Drop only sentences that assert official verification without evidence."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    retained = [
        sentence
        for sentence in sentences
        if not (
            ("tên miền chính thức" in sentence.casefold() or "domain chính thức" in sentence.casefold())
            and "đã được xác minh" in sentence.casefold()
        )
        and not re.search(r"người gửi.{0,30}(?:đã được|được) xác minh", sentence, re.IGNORECASE)
    ]
    return " ".join(retained).strip(), len(retained) != len(sentences)


def repair_grounded_ai_response(
    scope: SecurityScopeResponseV4,
    synthesis: AssistantSynthesis,
) -> tuple[AssistantResponseV4 | None, list[str]]:
    """Fail soft: retain valid AI prose/reasons when one component is unsafe.

    The repair never creates facts, verdicts, or actions.  If a required
    component is entirely removed it is supplied by the existing evidence/policy
    renderer, while the remaining safe prose remains model-authored.
    """
    repairs: list[str] = []
    summary, changed = _remove_unsafe_sentences(synthesis.summary)
    if changed:
        repairs.append("removed_unsafe_or_metric_text")
    summary, changed = _remove_unverified_official_claims(summary)
    if changed:
        repairs.append("removed_unverified_official_claim")
    if not summary:
        summary = _friendly_summary(scope)
        repairs.append("replaced_summary_with_policy_grounded_text")

    available_refs = {item.evidence_ref for item in scope.evidence}
    reasons: list[AssistantReasonV4] = []
    for reason in synthesis.top_reasons:
        text, changed = _remove_unsafe_sentences(reason.text)
        text, official_changed = _remove_unverified_official_claims(text)
        if changed or official_changed:
            repairs.append("removed_unsafe_reason_text")
        if not text or set(reason.evidence_refs) - available_refs:
            repairs.append("dropped_invalid_reason")
            continue
        reasons.append(AssistantReasonV4(text=text, evidence_refs=reason.evidence_refs))
    if available_refs and not reasons:
        reasons = _grounded_plain_reasons(scope)
        repairs.append("replaced_reasons_with_evidence_grounded_text")

    repaired = AssistantSynthesis(
        summary=summary,
        top_reasons=[
            {"text": reason.text, "evidence_refs": reason.evidence_refs}
            for reason in reasons
        ],
    )
    checked = check_grounded_ai_response(scope, repaired)
    return checked.response, list(dict.fromkeys(repairs))


def _immediate_steps(scope: SecurityScopeResponseV4) -> list[AssistantImmediateStepV4]:
    assert scope.policy_version is not None
    return [
        AssistantImmediateStepV4(action=action, policy_ref=scope.policy_version) for action in scope.recommended_actions
    ]


def _plain_reason(evidence: SecurityEvidenceV4) -> str:
    signals = set(evidence.signal.casefold().split("+"))
    for expected, guidance in _SIGNAL_GUIDANCE:
        if signals & expected:
            return guidance
    return {
        "redirect": "Liên kết có chuyển hướng; điểm đến cuối cần được xem xét thận trọng.",
        "rdap": "Thông tin đăng ký tên miền chưa đủ để chứng minh địa chỉ này an toàn.",
        "dns": "Tên miền có thể truy cập được, nhưng điều đó không đồng nghĩa với việc nó an toàn.",
        "url_reputation": "Dịch vụ kiểm tra uy tín chưa cung cấp kết luận đủ mạnh về địa chỉ này.",
        "brand_match": "Mối liên hệ giữa địa chỉ và thương hiệu được nhắc tới chưa được xác nhận rõ ràng.",
        "security_context": "Nội dung có yêu cầu hoặc tình huống cần được xử lý thận trọng.",
    }.get(evidence.type.value, "Có một tín hiệu bảo mật cần được xem xét thêm.")


def _grounded_plain_reasons(scope: SecurityScopeResponseV4) -> list[AssistantReasonV4]:
    evidence_by_ref = {item.evidence_ref: item for item in scope.evidence}
    return [
        AssistantReasonV4(text=_plain_reason(evidence_by_ref[ref]), evidence_refs=[ref])
        for ref in scope.explanation_evidence_refs
        if ref in evidence_by_ref
    ][:3]


def _friendly_summary(scope: SecurityScopeResponseV4) -> str:
    assert scope.risk is not None
    summary = _RISK_GUIDANCE[scope.risk]
    evidence_by_signal = {item.signal: item for item in scope.evidence if item.type.value == "official_verification"}
    ownership = evidence_by_signal.get("official_domain_verified")
    sender = evidence_by_signal.get("sender_identity_unverified")
    action = evidence_by_signal.get("action_endorsement_unverified")
    verification_sentences: list[str] = []
    if ownership is not None and ownership.target:
        verification_sentences.append(f"{ownership.target} đã được xác minh là tên miền chính thức.")
    if sender is not None or action is not None:
        verification_sentences.append(
            "Tuy nhiên, chưa đủ bằng chứng xác nhận người gửi và yêu cầu đăng nhập trong tin nhắn."
        )
        verification_sentences.append("Không nhập mật khẩu hoặc OTP chỉ dựa trên tin nhắn này.")
    if verification_sentences:
        summary = " ".join([*verification_sentences, summary])
    if scope.recommended_actions:
        summary = f"{summary} {_ACTION_GUIDANCE[scope.recommended_actions[0]]}"
    return summary


def policy_grounded_assistant_response(scope: SecurityScopeResponseV4) -> AssistantResponseV4:
    """Answer the user in plain language while staying grounded in verified case data."""
    return AssistantResponseV4(
        summary=_friendly_summary(scope),
        top_reasons=_grounded_plain_reasons(scope),
        uncertainties=list(scope.limitations)[:20],
        immediate_steps=_immediate_steps(scope),
        follow_up_offer=_FOLLOW_UP_OFFER,
        generation_mode=AssistantGenerationModeV4.POLICY_GROUNDED,
    )


# Compatibility import for integrations that have not migrated to the new
# name. New responses produced through it are still policy-grounded.
template_assistant_response = policy_grounded_assistant_response


def check_grounded_ai_response(
    scope: SecurityScopeResponseV4,
    synthesis: AssistantSynthesis,
) -> SynthesisGroundingCheck:
    """Return a grounded response or a non-sensitive rejection reason."""
    available_refs = {item.evidence_ref for item in scope.evidence}
    cited_refs = {ref for reason in synthesis.top_reasons for ref in reason.evidence_refs}
    texts = [
        synthesis.summary,
        *(reason.text for reason in synthesis.top_reasons),
        *synthesis.uncertainties,
        *([synthesis.follow_up_offer] if synthesis.follow_up_offer else []),
    ]
    if cited_refs - available_refs:
        return SynthesisGroundingCheck(None, SynthesisGroundingFailure.UNKNOWN_EVIDENCE_REF)
    if any(_UNSAFE_LINK_TEXT.search(text) for text in texts):
        return SynthesisGroundingCheck(None, SynthesisGroundingFailure.UNSAFE_URL)
    if any(
        _TECHNICAL_METRIC_TEXT.search(text)
        for text in [synthesis.summary, *(reason.text for reason in synthesis.top_reasons)]
    ):
        return SynthesisGroundingCheck(None, SynthesisGroundingFailure.TECHNICAL_METRIC)
    combined = " ".join(texts).casefold()
    signals = {item.signal for item in scope.evidence if item.type.value == "official_verification"}
    if (
        ("tên miền chính thức" in combined or "domain chính thức" in combined)
        and "đã được xác minh" in combined
        and "official_domain_verified" not in signals
    ) or (
        re.search(r"người gửi.{0,30}(?:đã được|được) xác minh", combined) is not None
        and scope.official_verification is not None
        and scope.official_verification.sender_verification.status is not VerificationStatusV4.VERIFIED
    ):
        return SynthesisGroundingCheck(None, SynthesisGroundingFailure.OFFICIAL_VERIFICATION_OVERREACH)
    if available_refs and not synthesis.top_reasons:
        return SynthesisGroundingCheck(None, SynthesisGroundingFailure.MISSING_TOP_REASONS)
    try:
        return SynthesisGroundingCheck(
            AssistantResponseV4(
                summary=synthesis.summary,
                top_reasons=[
                    AssistantReasonV4(text=reason.text, evidence_refs=reason.evidence_refs)
                    for reason in synthesis.top_reasons
                ],
                # Uncertainty and procedural fields remain deterministic even when
                # prose synthesis succeeds.
                uncertainties=list(scope.limitations)[:20],
                immediate_steps=_immediate_steps(scope),
                follow_up_offer=_FOLLOW_UP_OFFER,
                response_version=SECURITY_ASSISTANT_RESPONSE_VERSION,
                generation_mode=AssistantGenerationModeV4.AI,
            )
        )
    except ValueError:
        return SynthesisGroundingCheck(None, SynthesisGroundingFailure.INVALID_RESPONSE_CONTRACT)


def grounded_ai_response(
    scope: SecurityScopeResponseV4,
    synthesis: AssistantSynthesis,
) -> AssistantResponseV4 | None:
    """Compatibility wrapper returning only the accepted grounded response."""
    return check_grounded_ai_response(scope, synthesis).response


class GroundedSecurityResponseService:
    def __init__(
        self,
        *,
        ai_enabled: bool,
        model: SecurityAssistantModel | None,
        runtime: SecurityAssistantRuntime,
    ) -> None:
        self._ai_enabled = ai_enabled
        self._model = model
        self._runtime = runtime

    async def enrich(self, scope: SecurityScopeResponseV4) -> SecurityScopeResponseV4:
        if scope.risk is None or scope.policy_version is None:
            return scope
        response = policy_grounded_assistant_response(scope)
        if not self._ai_enabled:
            return scope.model_copy(update={"assistant_response": response})
        if self._model is None:
            return self._with_ai_limitation(scope, response, reason="provider_unconfigured")

        result = await self._runtime.invoke(
            AssistantOperation.SYNTHESIZE,
            lambda: self._model.synthesize(self._synthesis_payload(scope)),
            AssistantSynthesis,
        )
        checked = check_grounded_ai_response(scope, result.output) if result.output is not None else None
        grounded = checked.response if checked is not None else None
        repairs: list[str] = []
        if grounded is None and result.output is not None:
            grounded, repairs = repair_grounded_ai_response(scope, result.output)
            if grounded is not None:
                logger.info(
                    "security_ai_response_repaired",
                    extra={
                        "operation": AssistantOperation.SYNTHESIZE.value,
                        "guard_failure": checked.failure.value if checked and checked.failure else None,
                        "repair_actions": repairs,
                        "final_response_source": "ai_repaired",
                    },
                )
                limitation = "AI diễn đạt đã được làm sạch; kết luận và hành động vẫn do evidence/policy quyết định."
                limitations = list(dict.fromkeys([*scope.limitations, limitation]))
                return scope.model_copy(
                    update={
                        "assistant_response": grounded.model_copy(update={"uncertainties": limitations[:20]}),
                        "limitations": limitations,
                    }
                )
        if grounded is None:
            reason = result.error or (
                checked.failure.value if checked is not None and checked.failure is not None else "grounding_rejected"
            )
            if result.error is None:
                logger.warning(
                    "security_ai_grounding_rejected",
                    extra={
                        "operation": AssistantOperation.SYNTHESIZE.value,
                        "failure_code": reason,
                    },
                )
            return self._with_ai_limitation(scope, response, reason=reason)
        logger.info(
            "security_ai_response_trace",
            extra={
                "operation": AssistantOperation.SYNTHESIZE.value,
                "guard_failure": None,
                "repair_actions": repairs,
                "final_response_source": "ai",
            },
        )
        return scope.model_copy(update={"assistant_response": grounded})

    @staticmethod
    def _with_ai_limitation(
        scope: SecurityScopeResponseV4,
        response: AssistantResponseV4,
        *,
        reason: str,
    ) -> SecurityScopeResponseV4:
        reason_label = _AI_FAILURE_REASON_LABELS.get(reason, "lỗi AI không xác định")
        limitation = f"{_AI_SYNTHESIS_LIMITATION} Nguyên nhân: {reason_label} ({reason})."
        limitations = list(dict.fromkeys([*scope.limitations, limitation]))
        response = response.model_copy(update={"uncertainties": limitations[:20]})
        return scope.model_copy(update={"assistant_response": response, "limitations": limitations})

    @staticmethod
    def _synthesis_payload(scope: SecurityScopeResponseV4) -> dict[str, object]:
        return {
            "risk": scope.risk.value if scope.risk else None,
            "score": scope.score,
            "confidence": scope.confidence,
            "threat_type": scope.threat_type.value if scope.threat_type else None,
            "policy_version": scope.policy_version,
            "policy_metadata": scope.policy_metadata.model_dump(mode="json") if scope.policy_metadata else None,
            "recommended_actions": [action.value for action in scope.recommended_actions],
            "recommended_action_guidance": [_ACTION_GUIDANCE[action] for action in scope.recommended_actions],
            "explanation": scope.explanation,
            "evidence": [
                {
                    "evidence_ref": item.evidence_ref,
                    "type": item.type.value,
                    "source": item.source,
                    "signal": item.signal,
                    "description": item.description,
                }
                for item in scope.evidence
            ],
            "limitations": list(scope.limitations),
            "official_verification": (
                {
                    "domain_ownership_verification": scope.official_verification.domain_ownership_verification.model_dump(
                        mode="json"
                    ),
                    "sender_verification": scope.official_verification.sender_verification.model_dump(mode="json"),
                    "action_endorsement_verification": (
                        scope.official_verification.action_endorsement_verification.model_dump(mode="json")
                    ),
                }
                if scope.official_verification is not None
                else None
            ),
        }


__all__ = [
    "GroundedSecurityResponseService",
    "SynthesisGroundingCheck",
    "SynthesisGroundingFailure",
    "check_grounded_ai_response",
    "grounded_ai_response",
    "policy_grounded_assistant_response",
    "repair_grounded_ai_response",
    "template_assistant_response",
]
