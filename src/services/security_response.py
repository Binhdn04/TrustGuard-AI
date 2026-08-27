from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from src.models import (
    SECURITY_ASSISTANT_RESPONSE_VERSION,
    AssistantGenerationModeV4,
    AssistantImmediateStepV4,
    AssistantReasonV4,
    AssistantResponseV4,
    RequestedActionV4,
    SecurityEvidenceV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
    VerificationStatusV4,
)
from src.security_ai.contracts import AssistantOperation, AssistantSynthesis, SecurityAssistantModel
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.official_verification_coordinator import has_verified_exact_resource_endorsement

_UNSAFE_LINK_TEXT = re.compile(r"(?:https?://|www\.)\S*", re.IGNORECASE)
_TECHNICAL_METRIC_TEXT = re.compile(
    r"(?:\b(?:risk score|confidence|policy|evidence_ref)\b|\bđiểm\s+(?:số|rủi ro)\b|độ tin cậy|"
    r"\b\d+(?:[.,]\d+)?\s*(?:%|/100))",
    re.IGNORECASE,
)
_CAUTIONARY_SAFE_CONTRADICTION = re.compile(
    r"(?:rủi\s+ro\s+thấp|cẩn\s+thận|thận\s+trọng|"
    r"(?:xác\s+minh|kiểm\s+tra).{0,40}(?:kênh|website|trang|nguồn)\s+chính\s+thức)",
    re.IGNORECASE,
)
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
    INVALID_RESPONSE_CONTRACT = "invalid_response_contract"
    OFFICIAL_VERIFICATION_OVERREACH = "official_verification_overreach"
    MISSING_REQUIRED_AFFIRMATION = "missing_required_affirmation"
    CAUTION_CONTRADICTS_VERIFIED_PASSIVE_TARGET = "caution_contradicts_verified_passive_target"
    CONTRADICTS_VERIFIED_EXACT_RESOURCE_ENDORSEMENT = "contradicts_verified_exact_resource_endorsement"


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
        if sentence and not _UNSAFE_LINK_TEXT.search(sentence) and not _TECHNICAL_METRIC_TEXT.search(sentence)
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


def _has_verified_official_allow_open(scope: SecurityScopeResponseV4) -> bool:
    """Whether policy requires an affirmative answer about the submitted action.

    The submitted resource can be third-party hosted.  Its verified, exact
    official endorsement is sufficient here; domain ownership remains a
    separate fact and must not be implied by the affirmative response.
    """
    verification = scope.official_verification
    return bool(
        scope.risk is SecurityRiskV4.SAFE
        and SecurityRecommendedActionV4.ALLOW_OPEN in scope.recommended_actions
        and verification is not None
        and verification.resource_verification.status is VerificationStatusV4.VERIFIED
        and verification.action_endorsement_verification.status is VerificationStatusV4.VERIFIED
    )


def _has_verified_exact_resource_endorsement(scope: SecurityScopeResponseV4) -> bool:
    """Whether accepted provenance endorses this exact submitted resource.

    This is deliberately narrower than publisher/domain ownership and broader
    than a SAFE decision.  It remains true when sender identity, a separate
    requested action, or wider campaign details are unresolved.
    """
    context = scope.security_context
    return has_verified_exact_resource_endorsement(
        scope.official_verification,
        context.urls if context is not None else (),
    )


_NEGATES_OFFICIAL_RESOURCE_EVIDENCE = re.compile(
    r"(?:"
    # Vietnamese: the negative conclusion is about official verification of a
    # campaign/claim/resource, not an independent sender or domain question.
    r"(?:chưa|không|không thể|không có).{0,80}"
    r"(?:xác minh|xác nhận|kiểm chứng|bằng chứng).{0,80}"
    r"(?:nguồn|kênh|trang|website).{0,20}chính thức.{0,100}"
    r"(?:chiến dịch|chương trình|thông tin|yêu cầu|liên kết|đường dẫn|tài nguyên|biểu mẫu)"
    r"|(?:chiến dịch|chương trình|thông tin|yêu cầu|liên kết|đường dẫn|tài nguyên|biểu mẫu).{0,100}"
    r"(?:chưa|không|không thể|không có).{0,80}"
    r"(?:xác minh|xác nhận|kiểm chứng|bằng chứng).{0,80}"
    r"(?:nguồn|kênh|trang|website).{0,20}chính thức"
    # English equivalents, in either natural word order.
    r"|(?:no|not|cannot|could not|unable to|insufficient).{0,80}"
    r"(?:official (?:source|evidence|verification)|(?:source|evidence).{0,20}official).{0,100}"
    r"(?:campaign|claim|program|resource|link|url|form)"
    r"|(?:campaign|claim|program|resource|link|url|form).{0,100}"
    r"(?:no|not|cannot|could not|unable to|insufficient).{0,80}"
    r"(?:official (?:source|evidence|verification)|(?:source|evidence).{0,20}official)"
    r")",
    re.IGNORECASE,
)


def _has_verified_passive_target_allow_open(scope: SecurityScopeResponseV4) -> bool:
    """Whether reviewed ownership establishes a safe domain-only decision."""
    context = scope.security_context
    if not (
        scope.risk is SecurityRiskV4.SAFE
        and SecurityRecommendedActionV4.ALLOW_OPEN in scope.recommended_actions
        and context is not None
        and context.urls
        and context.requested_action in {None, RequestedActionV4.OPEN_LINK}
        and not context.impersonation_signals
        and not context.credential_request
        and not context.otp_request
        and not context.payment_request
        and not context.personal_information_request
    ):
        return False
    def owns_target(item: SecurityEvidenceV4, url: str) -> bool:
        if not item.target:
            return False
        target_host = (urlsplit(url).hostname or "").casefold().rstrip(".")
        evidence_host = item.target.casefold().rstrip(".")
        return target_host == evidence_host or target_host.endswith(f".{evidence_host}")

    def is_origin_only(url: str) -> bool:
        parsed = urlsplit(url)
        return parsed.path in {"", "/"} and not parsed.query and not parsed.fragment

    return all(
        any(
            (
                (item.type.value == "brand_match" and item.signal.casefold() == "official_match")
                or (item.type.value == "domain_familiarity" and item.signal == "reviewed_first_party_domain")
                or (item.type.value == "official_verification" and item.signal == "official_domain_verified")
                # A reviewed platform owns its origin, but this intentionally
                # does not extend to user-controlled resources beneath it.
                or (
                    item.type.value == "domain_familiarity"
                    and item.signal == "reviewed_platform_service"
                    and is_origin_only(url)
                )
            )
            and owns_target(item, url)
            for item in scope.evidence
        )
        for url in context.urls
    )


def _friendly_summary(scope: SecurityScopeResponseV4) -> str:
    assert scope.risk is not None
    # This is a response-selection invariant, not merely an explanation
    # preference. Sender assurance is independent of the verified resource and
    # action, and must not turn their affirmative conclusion into generic
    # caution when composition falls back.
    if _has_verified_official_allow_open(scope):
        verification = scope.official_verification
        assert verification is not None
        summary = "Liên kết và thủ tục bạn hỏi đã được nguồn chính thức xác nhận. Bạn có thể mở liên kết này."
        if verification.sender_verification.status is VerificationStatusV4.UNVERIFIED:
            summary += " Danh tính người gửi chưa được xác minh riêng, nhưng điều đó không thay đổi kết luận về liên kết và thủ tục này."
        return summary

    if _has_verified_passive_target_allow_open(scope):
        return "Tên miền bạn hỏi là tên miền chính thức đã được xác minh và an toàn để mở."

    summary = _RISK_GUIDANCE[scope.risk]
    # A verified submitted resource is affirmative truth even when the message
    # sender has not been authenticated. Do not collapse that distinction into
    # the generic INSUFFICIENT_EVIDENCE caution fallback.
    if _has_verified_exact_resource_endorsement(scope) and scope.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE:
        summary = "Tài nguyên bạn gửi đã được nguồn chính thức xác nhận cho quy trình này."
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
    # The fallback is normally rare, but it must retain the same case facts as
    # the composer.  Risk is a decision; it is not a substitute for the
    # independent organization, claim, resource, and action conclusions.
    verification = scope.official_verification
    if verification is not None and verification.overall_status is not VerificationStatusV4.VERIFIED:
        intent = verification.intent
        facts: list[str] = []
        exact_resource_endorsed = _has_verified_exact_resource_endorsement(scope)
        if intent.organization_name:
            facts.append(f"Tin nhắn tự nhận liên quan đến {intent.organization_name}.")
        # An unreviewed publisher is not a reason to erase the accepted
        # provenance fact for the exact resource.  Do not turn a separate,
        # unresolved campaign component into "no official source" prose.
        if (
            intent.claim_summary
            and verification.claim_verification.status is VerificationStatusV4.UNVERIFIED
            and not exact_resource_endorsed
        ):
            facts.append(f"Chưa xác nhận được thông tin về {intent.claim_summary} từ nguồn chính thức.")
        if verification.resource_verification.status is VerificationStatusV4.UNVERIFIED:
            facts.append("Chưa xác nhận được liên kết được gửi là tài nguyên do tổ chức này công bố.")
        if (
            intent.requested_action is not None
            and verification.action_endorsement_verification.status is VerificationStatusV4.UNVERIFIED
        ):
            facts.append("Chưa có xác nhận chính thức cho đúng hành động mà tin nhắn yêu cầu.")
        if any(
            item.type.value == "redirect" and "redirect_destination_unresolved" in item.signal
            for item in scope.evidence
        ):
            facts.append("Điểm đến cuối của liên kết vẫn chưa xác định được.")
        if facts:
            summary = " ".join([*facts, summary])
    if scope.recommended_actions:
        summary = f"{summary} {_ACTION_GUIDANCE[scope.recommended_actions[0]]}"
    return summary


def policy_grounded_assistant_response(scope: SecurityScopeResponseV4) -> AssistantResponseV4:
    """Last-resort response when the composer cannot produce a safe answer."""
    verified_passive_target = _has_verified_passive_target_allow_open(scope)
    return AssistantResponseV4(
        summary=_friendly_summary(scope),
        # Keep the failure path consistent with the same established security
        # truth. Provider/consent diagnostics are not a user-facing caveat for
        # a verified passive target.
        top_reasons=[] if verified_passive_target else _grounded_plain_reasons(scope),
        uncertainties=[] if verified_passive_target else _public_uncertainties(scope.limitations),
        immediate_steps=_immediate_steps(scope),
        follow_up_offer=None if verified_passive_target else _FOLLOW_UP_OFFER,
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
    if _has_verified_exact_resource_endorsement(scope) and _NEGATES_OFFICIAL_RESOURCE_EVIDENCE.search(combined):
        return SynthesisGroundingCheck(
            None,
            SynthesisGroundingFailure.CONTRADICTS_VERIFIED_EXACT_RESOURCE_ENDORSEMENT,
        )
    if _has_verified_official_allow_open(scope) and not re.search(
        r"(?:có thể mở|được xác minh|đã xác nhận)",
        synthesis.summary.casefold(),
    ):
        # A composer may mention an unverified sender, but it cannot omit the
        # affirmative conclusion that policy has already established.
        return SynthesisGroundingCheck(None, SynthesisGroundingFailure.MISSING_REQUIRED_AFFIRMATION)
    if _has_verified_passive_target_allow_open(scope):
        summary = synthesis.summary.casefold()
        if _CAUTIONARY_SAFE_CONTRADICTION.search(summary):
            return SynthesisGroundingCheck(
                None,
                SynthesisGroundingFailure.CAUTION_CONTRADICTS_VERIFIED_PASSIVE_TARGET,
            )
        if not re.search(r"(?:an toàn|tên miền chính thức|có thể mở|được xác minh|đã xác nhận)", summary):
            return SynthesisGroundingCheck(None, SynthesisGroundingFailure.MISSING_REQUIRED_AFFIRMATION)
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
    try:
        return SynthesisGroundingCheck(
            AssistantResponseV4(
                summary=synthesis.summary,
                top_reasons=[
                    AssistantReasonV4(text=reason.text, evidence_refs=reason.evidence_refs)
                    for reason in synthesis.top_reasons
                ],
                # These remain machine-readable metadata.  The composer, not a
                # frontend template, decides whether and how to mention them.
                uncertainties=_public_uncertainties(scope.limitations),
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
        if not self._ai_enabled:
            return scope.model_copy(update={"assistant_response": policy_grounded_assistant_response(scope)})
        if self._model is None:
            return scope.model_copy(update={"assistant_response": policy_grounded_assistant_response(scope)})

        result = await self._runtime.invoke(
            AssistantOperation.SYNTHESIZE,
            lambda: self._model.synthesize(self._synthesis_payload(scope)),
            AssistantSynthesis,
        )
        checked = check_grounded_ai_response(scope, result.output) if result.output is not None else None
        grounded = checked.response if checked is not None else None
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
            # Do not expose provider, validator, or policy diagnostics to the
            # user.  The deterministic renderer exists solely for this failure
            # path; normal answers are always composer-owned prose.
            logger.warning("security_ai_composer_fallback", extra={"failure_code": reason})
            return scope.model_copy(update={"assistant_response": policy_grounded_assistant_response(scope)})
        logger.info(
            "security_ai_response_trace",
            extra={
                "operation": AssistantOperation.SYNTHESIZE.value,
                "guard_failure": None,
                "final_response_source": "ai",
            },
        )
        return scope.model_copy(update={"assistant_response": grounded})

    @staticmethod
    def _synthesis_payload(scope: SecurityScopeResponseV4) -> dict[str, object]:
        verification = scope.official_verification
        redirect_unresolved = any(
            item.type.value == "redirect" and "redirect_destination_unresolved" in item.signal
            for item in scope.evidence
        )
        malicious_evidence_observed = any(
            any(
                marker in item.signal.casefold()
                for marker in ("malicious", "confirmed_threat", "approved_blacklist_hit", "threat_intelligence_hit")
            )
            for item in scope.evidence
        )
        verified_passive_target = _has_verified_passive_target_allow_open(scope)
        verified_exact_resource_endorsement = _has_verified_exact_resource_endorsement(scope)
        return {
            "contract": "grounded-security-response-context-v1",
            "verdict": scope.risk.value if scope.risk else None,
            # This is the deterministic security conclusion, deliberately
            # separate from the raw evidence list.  The composer owns prose,
            # but it must not infer a weaker conclusion from investigation
            # limitations once policy has established this passive target.
            "authoritative_security_truth": {
                "verified_passive_target": verified_passive_target,
                # This fact is intentionally independent from risk, domain
                # ownership, sender identity, and campaign-wide verification.
                **(
                    {"verified_exact_resource_endorsement": True}
                    if verified_exact_resource_endorsement
                    else {}
                ),
                "credible_malicious_evidence": malicious_evidence_observed,
                "no_risky_requested_action": bool(
                    scope.security_context is not None
                    and not scope.security_context.credential_request
                    and not scope.security_context.otp_request
                    and not scope.security_context.payment_request
                    and not scope.security_context.personal_information_request
                ),
            },
            "allowed_actions": [
                {"code": action.value, "user_guidance": _ACTION_GUIDANCE[action]}
                for action in scope.recommended_actions
            ],
            # Evidence descriptions are operational records and can contain
            # review/provenance vocabulary.  The composer receives only the
            # user-meaningful facts, while evidence refs stay available for its
            # optional audit citations.
            "evidence": [
                {
                    "evidence_ref": item.evidence_ref,
                    "signal": item.signal,
                }
                for item in scope.evidence
                if item.signal
                not in {"claimed_identity_unverified", "entity_target_unverified", "entity_url_relation_unresolved"}
            ],
            # Investigation availability is not user-relevant uncertainty
            # once policy has established a safe passive origin.
            "important_uncertainties": [] if verified_passive_target else _public_uncertainties(scope.limitations),
            "verification_state": (
                {
                    "claimed_organization": verification.intent.organization_name,
                    "program_claim": {
                        "value": verification.intent.claim_summary,
                        "topic": verification.intent.topic.value if verification.intent.topic is not None else None,
                        "status": verification.claim_verification.status.value
                        if verification.claim_verification.status is not None
                        else None,
                    },
                    "requested_action": {
                        "value": verification.intent.requested_action.value
                        if verification.intent.requested_action is not None
                        else None,
                        "endorsement_status": verification.action_endorsement_verification.status.value
                        if verification.action_endorsement_verification.status is not None
                        else None,
                    },
                    "submitted_resource": {
                        "claimed_platforms": [
                            mention.text
                            for mention in (scope.security_context.entity_mentions if scope.security_context else [])
                            if mention.role.value == "platform_provider"
                        ],
                        "status": verification.resource_verification.status.value
                        if verification.resource_verification.status is not None
                        else None,
                        "final_destination": "unresolved" if redirect_unresolved else "not_reported",
                        "official_association": (
                            "officially_owned"
                            if verification.domain_ownership_verification.status is VerificationStatusV4.VERIFIED
                            else "exact_resource_endorsed"
                            if verified_exact_resource_endorsement
                            else "not_established"
                        ),
                    },
                    "domain_ownership": verification.domain_ownership_verification.status.value,
                    "sender_identity": verification.sender_verification.status.value,
                    "malicious_evidence": "observed" if malicious_evidence_observed else "none_observed",
                    "unverified_is_not_a_risk_signal_by_itself": True,
                }
                if verification is not None
                else None
            ),
            "presentation_constraints": {
                "write_one_natural_user_facing_reply": True,
                "do_not_use_a_fixed_report_structure": True,
                "may_choose_order_headings_brevity_and_emphasis": True,
                "do_not_expose_internal_diagnostics": True,
                "verified_exact_resource_endorsement": (
                    "When true, state that an official provenance chain endorses the exact submitted resource. "
                    "Do not say that no official source or evidence verifies that campaign, claim, or resource. "
                    "This does not establish publisher/domain ownership, sender identity, every campaign detail, "
                    "or the overall risk verdict."
                    if verified_exact_resource_endorsement
                    else None
                ),
            },
        }


def _public_uncertainties(limitations: list[str]) -> list[str]:
    """Retain user-relevant uncertainty while never shipping operational diagnostics."""
    internal_markers = (
        "provider",
        "timeout",
        "deadline",
        "grounding",
        "policy",
        "evidence_ref",
        "structured output",
        "semantic",
        "error",
        "lỗi ai",
        "mã",
        "reviewed identity",
        "exact-resource",
        "association",
        "registry",
        "domain và tổ chức",
    )
    return [item for item in limitations if not any(marker in item.casefold() for marker in internal_markers)][:20]


__all__ = [
    "GroundedSecurityResponseService",
    "SynthesisGroundingCheck",
    "SynthesisGroundingFailure",
    "check_grounded_ai_response",
    "grounded_ai_response",
    "policy_grounded_assistant_response",
    "template_assistant_response",
]
