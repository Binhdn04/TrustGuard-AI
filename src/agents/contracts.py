from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal, Self, TypedDict
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.models import (
    CaseStatus,
    InvestigationStepStatus,
    InvestigationTool,
    RecommendedAction,
    RiskLevel,
    Verdict,
)


class AgentContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="after")
    @classmethod
    def reject_empty_and_non_utc(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError("empty strings are not valid agent contract values")
        if isinstance(value, datetime) and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("timestamps must use UTC")
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and not item.strip():
                    raise ValueError("empty strings are not valid agent contract values")
        return value


class ProvisionalWarning(AgentContractModel):
    risk_level: Literal[RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    summary: str
    evidence_refs: list[str] = Field(min_length=1)
    is_provisional: Literal[True] = True


class LiveStepTransition(AgentContractModel):
    step_id: str
    tool: InvestigationTool
    target: str
    reason_code: str
    depends_on: list[str] = Field(default_factory=list)
    status: InvestigationStepStatus
    occurred_at: datetime


class CampaignFeatures(AgentContractModel):
    registrable_domains: list[str] = Field(default_factory=list)
    redirect_targets: list[str] = Field(default_factory=list)
    claim_feature_refs: list[str] = Field(default_factory=list)
    observed_at: datetime
    feature_version: str


class CampaignHypothesis(AgentContractModel):
    hypothesis_id: UUID
    evidence_refs: list[str] = Field(min_length=1)
    analysis_count: int = Field(ge=3)
    window_started_at: datetime
    window_ended_at: datetime
    clustering_version: str
    reviewer_required: Literal[True] = True
    broad_warning_approved: Literal[False] = False

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if self.window_ended_at < self.window_started_at:
            raise ValueError("campaign window must end after it starts")
        return self


class RiskAssessmentOutput(TypedDict):
    risk_score: int
    risk_level: RiskLevel
    verdict: Verdict
    confidence: float
    scoring_version: str


class ExplanationOutput(TypedDict):
    summary: str
    reasons: list[str]


class ActionOutput(TypedDict):
    recommended_action: RecommendedAction
    case_status: CaseStatus


class CampaignDetectionOutput(TypedDict, total=False):
    campaign_features: CampaignFeatures
    campaign_hypotheses: list[CampaignHypothesis]


class RealtimeNodeOutput(TypedDict, total=False):
    provisional_warning: ProvisionalWarning | None
    active_warning: Literal["provisional", "final"]
    step_transitions: list[LiveStepTransition]
    tool_usage_refs: list[str]


__all__ = [
    "ActionOutput",
    "CampaignDetectionOutput",
    "CampaignFeatures",
    "CampaignHypothesis",
    "ExplanationOutput",
    "LiveStepTransition",
    "ProvisionalWarning",
    "RealtimeNodeOutput",
    "RiskAssessmentOutput",
]
