from __future__ import annotations

from typing import TypedDict

from src.models import (
    CaseStatus,
    ClaimEvidence,
    Evidence,
    InputType,
    RecommendedAction,
    RiskLevel,
    ToolError,
    UrlScanResult,
    Verdict,
)


class AgentState(TypedDict, total=False):
    """Frozen LangGraph state contract v1."""

    analysis_id: str
    message: str
    consent_to_scan_urls: bool
    input_type: InputType
    extracted_urls: list[str]
    normalized_urls: list[str]
    claims: list[str]
    url_findings: list[UrlScanResult]
    claim_findings: list[ClaimEvidence]
    evidence: list[Evidence]
    tool_calls_used: int
    errors: list[ToolError]
    risk_score: int
    risk_level: RiskLevel
    verdict: Verdict
    confidence: float
    recommended_action: RecommendedAction
    reasons: list[str]
    limitations: list[str]
    case_status: CaseStatus
    scoring_version: str


class LegacyAgentState(TypedDict, total=False):
    """State used only by the pre-v1 sample `/chat` graph."""

    query: str
    context: str
    analysis: str
    response: str
    error: str
    metadata: dict


__all__ = ["AgentState", "LegacyAgentState"]
