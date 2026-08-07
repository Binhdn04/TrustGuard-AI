from __future__ import annotations

from datetime import datetime
from typing import Literal, TypedDict

from src.agents.contracts import CampaignFeatures, CampaignHypothesis, LiveStepTransition, ProvisionalWarning
from src.models import (
    CaseStatus,
    ClaimEvidence,
    DomainIntelligenceResult,
    Evidence,
    InputType,
    InvestigationStep,
    RecommendedAction,
    RiskLevel,
    ToolError,
    UrlScanResult,
    Verdict,
)

ToolRoute = Literal["execute", "assess"]


class AgentState(TypedDict, total=False):
    """Frozen public AgentState v2 contract."""

    analysis_id: str
    message: str
    consent_to_scan_urls: bool
    input_type: InputType
    extracted_urls: list[str]
    normalized_urls: list[str]
    claims: list[str]
    investigation_plan: list[InvestigationStep]
    url_findings: list[UrlScanResult]
    domain_findings: list[DomainIntelligenceResult]
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


class WorkflowState(AgentState, total=False):
    """Serializable private state used only while the graph is executing."""

    summary: str
    next_tool: ToolRoute
    tool_target: str
    tool_attempts: dict[str, int]
    max_tool_calls: int
    max_tool_retries: int
    deadline_at: datetime
    blocked_urls: list[str]
    blacklisted_domains: list[str]
    provisional_warning: ProvisionalWarning | None
    active_warning: Literal["provisional", "final"]
    step_transitions: list[LiveStepTransition]
    tool_usage_refs: list[str]
    campaign_features: CampaignFeatures
    campaign_hypotheses: list[CampaignHypothesis]
    llm_model: str
    llm_context: str
    llm_emotion: str
    llm_sender_intent: str
    llm_suspected_scam_intent: bool
    llm_scam_indicators: list[str]
    llm_tool_plan: list[dict[str, str]]
    llm_assessment: str
    llm_assessment_agrees: bool
    llm_evidence_indexes: list[int]
    llm_missing_information: list[str]
    llm_response_evidence_indexes: list[int]
    llm_errors: list[str]


class LegacyAgentState(TypedDict, total=False):
    """Compatibility state for the starter `/chat` endpoint."""

    query: str
    context: str
    analysis: str
    response: str
    error: str
    metadata: dict


__all__ = ["AgentState", "LegacyAgentState", "ToolRoute", "WorkflowState"]
