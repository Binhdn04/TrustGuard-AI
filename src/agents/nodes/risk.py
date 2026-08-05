from __future__ import annotations

from src.agents.state import AgentState
from src.models import (
    SCORING_VERSION,
    EvidenceType,
    Verdict,
    risk_level_for_score,
)

_RULE_WEIGHTS = {
    "URL đích bị chặn bởi SSRF guard": 65,
    "Tên miền quốc tế hóa cần thận trọng": 25,
    "Đường dẫn yêu cầu thông tin tài khoản": 35,
    "Tên miền có mẫu mạo danh khuyến mãi": 15,
}


def _claim_weight(finding: str) -> int:
    folded = finding.casefold()
    if any(word in folded for word in ("bác bỏ", "sai sự thật", "giả mạo", "không đúng")):
        return 70
    if any(word in folded for word in ("không tìm thấy", "chưa xác nhận", "không có thông báo")):
        return 35
    return 0


def assess_risk(state: AgentState) -> dict:
    """Deterministic risk-v1 scoring; no LLM output can affect the score."""
    score = 0
    for item in state.get("evidence", []):
        if item.type is EvidenceType.URL_RULE:
            score += _RULE_WEIGHTS.get(item.title, 0)
        elif item.type is EvidenceType.BLACKLIST:
            score += 30
        elif item.type in {EvidenceType.FACT_CHECK, EvidenceType.OFFICIAL_SOURCE}:
            score += _claim_weight(item.finding)

    for finding in state.get("url_findings", []):
        if finding.verdict is Verdict.MALICIOUS:
            score += 45
        elif finding.verdict is Verdict.SUSPICIOUS:
            score += 15

    score = max(0, min(100, score))
    level = risk_level_for_score(score)
    limitations = state.get("limitations", [])
    has_errors = bool(state.get("errors"))
    has_positive_risk = score >= 60
    provider_safe = any(item.verdict is Verdict.SAFE for item in state.get("url_findings", []))
    fact_refuted = any(item.type is EvidenceType.FACT_CHECK and _claim_weight(item.finding) >= 70
                       for item in state.get("evidence", []))
    provider_malicious = any(item.verdict is Verdict.MALICIOUS for item in state.get("url_findings", []))

    if fact_refuted or provider_malicious:
        verdict = Verdict.MALICIOUS
    elif has_positive_risk:
        verdict = Verdict.SUSPICIOUS
    elif score >= 30 and not has_errors and not (
        state.get("normalized_urls") and not state.get("consent_to_scan_urls")
    ):
        verdict = Verdict.SUSPICIOUS
    elif limitations or has_errors or not state.get("evidence"):
        verdict = Verdict.INCONCLUSIVE
    elif provider_safe:
        verdict = Verdict.SAFE
    else:
        verdict = Verdict.INCONCLUSIVE

    # Confidence represents evidence coverage, not the inverse of risk.
    targets = len(state.get("normalized_urls", [])) + len(state.get("claims", []))
    successful = len(state.get("url_findings", [])) + (1 if state.get("claim_findings") else 0)
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
