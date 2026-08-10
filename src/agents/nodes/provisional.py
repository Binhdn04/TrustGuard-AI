from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256

from src.agents.contracts import ProvisionalWarning
from src.agents.state import WorkflowState
from src.models import Evidence, EvidenceType, RiskLevel, Verdict, risk_level_for_score

_LOCAL_RULE_WEIGHTS = {
    "URL đích bị chặn bởi SSRF guard": 65,
    "Tên miền quốc tế hóa cần thận trọng": 25,
    "Đường dẫn yêu cầu thông tin tài khoản": 35,
    "Tên miền có mẫu mạo danh khuyến mãi": 15,
}


def _evidence_ref(item: Evidence) -> str:
    material = "\0".join((item.type.value, item.source, item.title, item.finding))
    return f"evidence:sha256:{sha256(material.encode()).hexdigest()}"


def build_provisional_warning(
    state: WorkflowState,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict:
    """Create a warning only from synchronous, policy-approved evidence.

    Provider responses and LLM fields are deliberately ignored. Reputation
    evidence is accepted only through the explicit, unexpired cache contract;
    a live/no-hit provider result can never enter this calculation.
    """
    trusted: list[Evidence] = []
    score = 0
    for item in state.get("evidence", []):
        if item.type is EvidenceType.URL_RULE and item.source == "local-url-rules":
            weight = _LOCAL_RULE_WEIGHTS.get(item.title, 0)
        elif item.type is EvidenceType.BLACKLIST and item.source == "approved-blacklist":
            weight = 30
        else:
            continue
        if weight:
            trusted.append(item)
            score += weight

    cache_refs: list[str] = []
    now = clock()
    for cached in state.get("cached_reputation_evidence", []):
        if cached.expires_at <= now:
            continue
        if cached.finding.verdict is Verdict.MALICIOUS:
            score += 45
        elif cached.finding.verdict is Verdict.SUSPICIOUS:
            score += 15
        else:
            continue
        cache_refs.append(cached.usage_ref)

    level = risk_level_for_score(min(score, 100))
    if level is RiskLevel.LOW or (not trusted and not cache_refs):
        return {"provisional_warning": None}
    warning = ProvisionalWarning(
        risk_level=level,
        summary="Phát hiện dấu hiệu rủi ro ban đầu; hệ thống đang tiếp tục xác minh.",
        evidence_refs=[_evidence_ref(item) for item in trusted] + cache_refs,
    )
    return {"provisional_warning": warning, "active_warning": "provisional"}


__all__ = ["build_provisional_warning"]
