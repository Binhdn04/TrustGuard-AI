from __future__ import annotations

from src.agents.state import AgentState
from src.models import CaseStatus, ClaimStance, RecommendedAction, RiskLevel, Verdict

_SUMMARY = {
    Verdict.SAFE: "Các nguồn đã kiểm tra chưa ghi nhận dấu hiệu rủi ro đáng kể.",
    Verdict.SUSPICIOUS: "Nội dung có dấu hiệu đáng ngờ và cần được xử lý thận trọng.",
    Verdict.MALICIOUS: "Bằng chứng hiện có cho thấy nội dung hoặc liên kết có nguy cơ gây hại.",
    Verdict.INCONCLUSIVE: "Chưa đủ dữ liệu để kết luận nội dung hoặc liên kết là an toàn.",
}


def explain_result(state: AgentState) -> dict:
    """Produce a grounded, deterministic explanation from existing evidence only."""
    reasons: list[str] = []
    for item in state.get("evidence", []):
        reason = f"{item.title}: {item.finding}"
        if reason not in reasons:
            reasons.append(reason)
    if not reasons:
        reasons.append("Không có evidence có cấu trúc đủ mạnh để đưa ra kết luận chắc chắn.")
    relevant_stances = {item.stance for item in state.get("claim_findings", []) if item.relevance >= 0.6}
    if relevant_stances == {ClaimStance.SUPPORTS}:
        summary = (
            "Các nguồn Tier C độc lập tạm thời xác nhận claim."
            if state.get("fact_check_basis") == "provisional"
            else "Các nguồn được trích dẫn xác nhận claim."
        )
    elif relevant_stances == {ClaimStance.REFUTES}:
        summary = (
            "Các nguồn Tier C độc lập tạm thời bác bỏ claim."
            if state.get("fact_check_basis") == "provisional"
            else "Các nguồn được trích dẫn bác bỏ claim."
        )
    elif relevant_stances and relevant_stances <= {ClaimStance.SUPPORTS, ClaimStance.REFUTES, ClaimStance.MIXED}:
        summary = "Các nguồn cho thấy claim đúng một phần hoặc còn mâu thuẫn."
    else:
        summary = _SUMMARY[state["verdict"]]
    return {"summary": summary, "reasons": reasons[:6]}


def route_action(state: AgentState) -> dict:
    level = state["risk_level"]
    if level is RiskLevel.CRITICAL:
        action = RecommendedAction.ESCALATE_FOR_REVIEW
        case_status = CaseStatus.PENDING_REVIEW
    elif level is RiskLevel.HIGH:
        action = RecommendedAction.DO_NOT_OPEN
        case_status = CaseStatus.NOT_REQUIRED
    elif level is RiskLevel.MEDIUM:
        action = RecommendedAction.SHOW_CAUTION
        case_status = CaseStatus.NOT_REQUIRED
    else:
        action = RecommendedAction.ALLOW
        case_status = CaseStatus.NOT_REQUIRED
    return {"recommended_action": action, "case_status": case_status}
