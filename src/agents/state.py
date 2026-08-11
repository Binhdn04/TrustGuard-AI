from __future__ import annotations

from datetime import datetime
from typing import Literal, TypedDict

from src.agents.contracts import (
    CachedReputationEvidence,
    CampaignFeatures,
    CampaignHypothesis,
    LiveStepTransition,
    ProvisionalWarning,
)
from src.agents.fact_check import EmbeddingStatus, ExtractedClaim
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
    consent_to_capture_screenshot: bool
    extracted_claims: list[ExtractedClaim]
    next_tool: ToolRoute
    tool_target: str
    tool_attempts: dict[str, int]
    tool_cost_used_usd: float
    tool_tokens_used: int
    max_tool_calls: int
    max_tool_retries: int
    max_tool_cost_usd: float
    max_tool_tokens: int
    max_llm_calls: int
    llm_calls_used: int
    max_llm_tokens: int
    llm_tokens_used: int
    max_llm_cost_usd: float
    llm_cost_used_usd: float
    deadline_at: datetime
    blocked_urls: list[str]
    blacklisted_domains: list[str]
    enable_redirect_resolution: bool
    cached_reputation_evidence: list[CachedReputationEvidence]
    provisional_warning: ProvisionalWarning | None
    active_warning: Literal["provisional", "final"]
    step_transitions: list[LiveStepTransition]
    tool_usage_refs: list[str]
    campaign_features: CampaignFeatures
    campaign_hypotheses: list[CampaignHypothesis]
    embedding_status: EmbeddingStatus
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
