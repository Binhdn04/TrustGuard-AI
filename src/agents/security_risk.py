from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from src.models import (
    SECURITY_RISK_POLICY_VERSION,
    PotentialThreatV4,
    RequestedActionV4,
    SecurityEvidenceV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
)


@dataclass(frozen=True, slots=True)
class _Contribution:
    points: int
    evidence_ref: str


_WEAK_SIGNAL_POINTS = {
    "punycode_domain": 12,
    "credential_path": 18,
    "promotion_lure_domain": 8,
    "ssrf_blocked": 15,
    "new_domain": 15,
    "recent_registration": 15,
    "domain_mismatch": 15,
    "lookalike_domain": 20,
}
_MALICIOUS_REPUTATION_SIGNALS = {"malicious", "confirmed_threat", "threat_intelligence_hit"}
_SAFE_SIGNALS = {
    "approved_whitelist",
    "official_match",
    "official_contact_match",
    "official_confirmed",
    "safe",
}


def _risk_for_score(score: int) -> SecurityRiskV4:
    if score >= 65:
        return SecurityRiskV4.HIGH_RISK
    if score >= 40:
        return SecurityRiskV4.SUSPICIOUS
    if score >= 20:
        return SecurityRiskV4.LOW_RISK
    return SecurityRiskV4.INSUFFICIENT_EVIDENCE


def _actions(scope: SecurityScopeResponseV4, risk: SecurityRiskV4) -> list[SecurityRecommendedActionV4]:
    context = scope.security_context
    if context is None:
        return [SecurityRecommendedActionV4.PROCEED_WITH_CAUTION]
    actions: list[SecurityRecommendedActionV4] = []
    if context.urls or context.requested_action is RequestedActionV4.OPEN_LINK:
        actions.append(SecurityRecommendedActionV4.DO_NOT_OPEN_LINK)
    if context.credential_request:
        actions.append(SecurityRecommendedActionV4.DO_NOT_SHARE_CREDENTIALS)
        actions.append(SecurityRecommendedActionV4.CHANGE_PASSWORD_IF_ALREADY_SHARED)
    if context.otp_request:
        actions.append(SecurityRecommendedActionV4.DO_NOT_SHARE_OTP)
    if context.payment_request:
        actions.append(SecurityRecommendedActionV4.DO_NOT_TRANSFER_MONEY)
        actions.append(SecurityRecommendedActionV4.CONTACT_BANK_IF_ALREADY_PAID)
    if context.claimed_entity or context.impersonation_signals:
        actions.append(SecurityRecommendedActionV4.VERIFY_VIA_OFFICIAL_CHANNEL)
    if risk in {SecurityRiskV4.HIGH_RISK, SecurityRiskV4.MALICIOUS}:
        actions.append(SecurityRecommendedActionV4.REPORT_AND_BLOCK_SENDER)
    if not actions:
        actions.append(SecurityRecommendedActionV4.PROCEED_WITH_CAUTION)
    return list(dict.fromkeys(actions))


def _explanation(risk: SecurityRiskV4, evidence: list[SecurityEvidenceV4]) -> str:
    descriptions = [item.description for item in evidence[:3]]
    prefix = {
        SecurityRiskV4.SAFE: "Bằng chứng xác thực hiện có cho thấy mục tiêu phù hợp với nguồn tin cậy.",
        SecurityRiskV4.LOW_RISK: "Chỉ ghi nhận tín hiệu rủi ro yếu; chưa đủ để kết luận nội dung độc hại.",
        SecurityRiskV4.SUSPICIOUS: "Có nhiều tín hiệu bảo mật đáng ngờ cần được xử lý thận trọng.",
        SecurityRiskV4.HIGH_RISK: "Các yêu cầu và tín hiệu độc lập cho thấy nguy cơ mất tài khoản hoặc tiền cao.",
        SecurityRiskV4.MALICIOUS: "Có bằng chứng mạnh đã được xác nhận về mục tiêu độc hại.",
        SecurityRiskV4.INSUFFICIENT_EVIDENCE: "Chưa có đủ bằng chứng để đánh giá mục tiêu là an toàn hay độc hại.",
    }[risk]
    return prefix + (" Căn cứ: " + " ".join(descriptions) if descriptions else "")


def assess_security_risk(scope: SecurityScopeResponseV4) -> SecurityScopeResponseV4:
    """Apply the versioned v4 policy without claim-stance or prose inputs."""
    context = scope.security_context
    if context is None:
        return scope
    context_evidence = next((item for item in scope.evidence if item.type.value == "security_context"), None)
    context_ref = context_evidence.evidence_ref if context_evidence else ""
    contributions: list[_Contribution] = []

    if context.credential_request:
        contributions.append(_Contribution(35, context_ref))
    if context.otp_request:
        contributions.append(_Contribution(40, context_ref))
    if context.payment_request:
        contributions.append(_Contribution(35, context_ref))
    if context.urgency:
        contributions.append(_Contribution(15, context_ref))
    if context.impersonation_signals:
        contributions.append(_Contribution(18, context_ref))
    if context.potential_threat is not PotentialThreatV4.UNDETERMINED_SECURITY_THREAT and (
        context.credential_request or context.otp_request or context.payment_request
    ):
        contributions.append(_Contribution(20, context_ref))
    if context.scenario.value in {"recruitment", "promotion_prize"} and (
        context.payment_request or context.credential_request
    ):
        contributions.append(_Contribution(10, context_ref))

    strong_refs: list[str] = []
    safe_refs: list[str] = []
    weak_external = 0
    has_whitelist = any(item.signal.casefold() == "approved_whitelist" for item in scope.evidence)
    for item in scope.evidence:
        signal_parts = set(item.signal.casefold().split("+"))
        if item.type.value == "blacklist" and "approved_blacklist_hit" in signal_parts:
            strong_refs.append(item.evidence_ref)
        if item.type.value == "url_reputation" and signal_parts & _MALICIOUS_REPUTATION_SIGNALS:
            strong_refs.append(item.evidence_ref)
        if signal_parts & _SAFE_SIGNALS:
            safe_refs.append(item.evidence_ref)
        points = max((_WEAK_SIGNAL_POINTS.get(signal, 0) for signal in signal_parts), default=0)
        if has_whitelist and item.type.value in {"local_url_rule", "rdap", "brand_match"}:
            points = 0
        if "official_contradicted" in signal_parts:
            points = max(points, 20)
        if points:
            weak_external += points
            contributions.append(_Contribution(points, item.evidence_ref))

    score = min(100, sum(item.points for item in contributions))
    if strong_refs:
        score = max(score, 95)
        risk = SecurityRiskV4.MALICIOUS
    elif safe_refs and score == 0 and not scope.errors:
        risk = SecurityRiskV4.SAFE
    else:
        risk = _risk_for_score(score)
    # Registration/mismatch-style evidence alone is explicitly non-malicious.
    if contributions and sum(item.points for item in contributions) == weak_external:
        risk = SecurityRiskV4.LOW_RISK if score < 45 else SecurityRiskV4.SUSPICIOUS

    refs = list(
        dict.fromkeys([item.evidence_ref for item in contributions if item.evidence_ref] + strong_refs + safe_refs)
    )
    grounded = [item for item in scope.evidence if item.evidence_ref in refs]
    if not grounded and scope.evidence:
        grounded = [scope.evidence[0]]
        refs = [scope.evidence[0].evidence_ref]
    confidence = 0.35
    if context.credential_request or context.otp_request or context.payment_request:
        confidence += 0.3
    if strong_refs or safe_refs:
        confidence += 0.25
    elif len({item.type for item in grounded}) > 1:
        confidence += 0.15
    if scope.errors or scope.limitations:
        confidence = min(confidence, 0.65)

    payload = scope.model_dump()
    payload.update(
        status="completed",
        completed_at=datetime.now(UTC),
        terminal=True,
        next_step="END",
        risk=risk,
        score=score,
        confidence=round(min(confidence, 0.95), 2),
        threat_type=context.potential_threat,
        policy_version=SECURITY_RISK_POLICY_VERSION,
        recommended_actions=_actions(scope, risk),
        explanation=_explanation(risk, grounded),
        explanation_evidence_refs=refs,
    )
    return SecurityScopeResponseV4.model_validate(payload)


__all__ = ["assess_security_risk"]
