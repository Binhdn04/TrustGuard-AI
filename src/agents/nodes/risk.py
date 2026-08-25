from __future__ import annotations

from src.agents.state import AgentState
from src.models import SCORING_VERSION, ClaimStance, EvidenceType, Verdict, risk_level_for_score

_RULE_WEIGHTS = {
    "URL đích bị chặn bởi SSRF guard": 65,
    "Tên miền quốc tế hóa cần thận trọng": 25,
    "Đường dẫn quy trình tài khoản": 0,
    "Tên miền có mẫu mạo danh khuyến mãi": 15,
}
_CLAIM_RELEVANCE_THRESHOLD = 0.6
_DOMAIN_SIGNAL_CAP = 20
_DOMAIN_SIGNAL_WEIGHTS = {
    "new_domain": 20,
    "recent_registration": 20,
    "short_registration": 10,
}


def _domain_registration_score(state: AgentState) -> int:
    score = 0
    for finding in state.get("domain_findings", []):
        for signal in finding.signals:
            score += _DOMAIN_SIGNAL_WEIGHTS.get(signal, 0)
    return min(_DOMAIN_SIGNAL_CAP, score)


def assess_risk(state: AgentState) -> dict:
    """Pure risk-v2 scoring; prose and LLM output never affect the result."""
    score = 0
    for item in state.get("evidence", []):
        if item.type is EvidenceType.URL_RULE:
            score += _RULE_WEIGHTS.get(item.title, 0)
        elif item.type is EvidenceType.BLACKLIST:
            score += 30

    for finding in state.get("url_findings", []):
        if finding.verdict is Verdict.MALICIOUS:
            score += 45
        elif finding.verdict is Verdict.SUSPICIOUS:
            score += 15

    relevant_claims = [
        finding for finding in state.get("claim_findings", []) if finding.relevance >= _CLAIM_RELEVANCE_THRESHOLD
    ]
    claim_stances = {finding.stance for finding in relevant_claims}
    claims_conflict = ClaimStance.SUPPORTS in claim_stances and ClaimStance.REFUTES in claim_stances
    if ClaimStance.REFUTES in claim_stances and not claims_conflict:
        score += 70
    elif any(finding.stance is ClaimStance.MIXED for finding in relevant_claims):
        score += 25

    score += _domain_registration_score(state)
    score = max(0, min(100, score))
    level = risk_level_for_score(score)
    limitations = state.get("limitations", [])
    has_errors = bool(state.get("errors"))
    provider_safe = any(item.verdict is Verdict.SAFE for item in state.get("url_findings", []))
    fact_refuted = ClaimStance.REFUTES in claim_stances and not claims_conflict
    provider_malicious = any(item.verdict is Verdict.MALICIOUS for item in state.get("url_findings", []))

    if fact_refuted or provider_malicious:
        verdict = Verdict.MALICIOUS
    elif score >= 30:
        verdict = Verdict.SUSPICIOUS
    elif limitations or has_errors or not state.get("evidence"):
        verdict = Verdict.INCONCLUSIVE
    elif provider_safe:
        verdict = Verdict.SAFE
    else:
        verdict = Verdict.INCONCLUSIVE

    # Confidence measures target coverage, not confidence that content is safe.
    targets = len(state.get("normalized_urls", [])) + len(state.get("claims", []))
    successful_url_targets = max(len(state.get("url_findings", [])), len(state.get("domain_findings", [])))
    successful = successful_url_targets + (1 if state.get("claim_findings") else 0)
    confidence = 0.2 if targets == 0 else min(0.95, 0.35 + 0.6 * successful / targets)
    if limitations or has_errors:
        confidence = min(confidence, 0.55)
    return {
        "risk_score": score,
        "risk_level": level,
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "scoring_version": SCORING_VERSION,
    }


__all__ = ["assess_risk"]
