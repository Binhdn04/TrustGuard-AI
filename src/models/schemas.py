from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CONTRACT_VERSION = "v1"
SCORING_VERSION = "risk-v1"


class InputType(StrEnum):
    TEXT = "text"
    URL = "url"
    TEXT_WITH_URL = "text_with_url"


class AnalysisStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class EvidenceType(StrEnum):
    URL_RULE = "url_rule"
    DOMAIN_REPUTATION = "domain_reputation"
    REDIRECT = "redirect"
    BLACKLIST = "blacklist"
    DOMAIN_REGISTRATION = "domain_registration"
    FACT_CHECK = "fact_check"
    OFFICIAL_SOURCE = "official_source"
    USER_REPORT = "user_report"


class CaseStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class RecommendedAction(StrEnum):
    ALLOW = "allow"
    SHOW_CAUTION = "show_caution"
    DO_NOT_OPEN = "do_not_open"
    ESCALATE_FOR_REVIEW = "escalate_for_review"


class ReviewDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ReviewAction(StrEnum):
    ADD_TO_BLACKLIST = "add_to_blacklist"
    NONE = "none"


class ClaimStance(StrEnum):
    SUPPORTS = "supports"
    REFUTES = "refutes"
    MIXED = "mixed"
    UNRATED = "unrated"


class ErrorCode(StrEnum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ContractModel(BaseModel):
    """Strict base for the frozen v1 JSON contract."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    @field_validator("*", mode="after")
    @classmethod
    def reject_empty_strings(cls, value: Any) -> Any:
        def validate(item: Any) -> None:
            if isinstance(item, str) and not item.strip():
                raise ValueError("empty strings are not valid contract values")
            if isinstance(item, datetime) and (item.tzinfo is None or item.utcoffset() != timedelta(0)):
                raise ValueError("timestamps must use UTC")
            if isinstance(item, list):
                for nested_item in item:
                    validate(nested_item)
            if isinstance(item, dict):
                for nested_item in item.values():
                    validate(nested_item)

        validate(value)
        return value


class ChatRequest(BaseModel):
    """Legacy starter endpoint request. Prefer AnalysisCreateRequest for v1."""

    message: str = Field(..., min_length=1, max_length=5000, description="Tin nhắn từ user")


class ChatResponse(BaseModel):
    """Legacy starter endpoint response. Not part of the analysis v1 contract."""

    response: str = Field(..., description="Phản hồi từ agent")
    analysis: str = Field(default="", description="Phân tích nội bộ")


class AnalysisCreateRequest(ContractModel):
    message: str = Field(min_length=1, max_length=5000)
    consent_to_scan_urls: bool


class AnalysisAcceptedResponse(ContractModel):
    contract_version: Literal["v1"] = CONTRACT_VERSION
    analysis_id: UUID
    status: Literal[AnalysisStatus.QUEUED] = AnalysisStatus.QUEUED
    created_at: datetime


class Evidence(ContractModel):
    type: EvidenceType
    source: str
    title: str
    url: str | None = None
    finding: str
    observed_at: datetime


class UrlScanResult(ContractModel):
    provider: str
    normalized_url: str
    verdict: Verdict
    redirect_chain: list[str]
    signals: list[str]
    observed_at: datetime


class ClaimEvidence(ContractModel):
    source: str
    title: str
    url: str | None = None
    finding: str
    stance: ClaimStance
    relevance: float = Field(ge=0.0, le=1.0)
    observed_at: datetime


class DomainIntelligenceResult(ContractModel):
    provider: str
    domain: str
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    registrar: str | None = None
    country: str | None = None
    status: list[str] = Field(default_factory=list)
    privacy_redacted: bool
    signals: list[str] = Field(default_factory=list)
    observed_at: datetime


class BlacklistEntry(ContractModel):
    domain: str
    decision_id: str
    source: str
    added_at: datetime
    active: bool


class ToolError(ContractModel):
    tool: str
    code: str
    message: str
    retryable: bool


class AnalysisResponse(ContractModel):
    contract_version: Literal["v1"] = CONTRACT_VERSION
    analysis_id: UUID
    status: AnalysisStatus
    input_type: InputType | None = None
    normalized_urls: list[str] | None = None
    claims: list[str] | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    risk_level: RiskLevel | None = None
    verdict: Verdict | None = None
    recommended_action: RecommendedAction | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    summary: str | None = None
    reasons: list[str] | None = None
    evidence: list[Evidence] | None = None
    limitations: list[str] | None = None
    case_status: CaseStatus | None = None
    scoring_version: str | None = None
    created_at: datetime
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_completed_result(self) -> Self:
        if self.status is not AnalysisStatus.COMPLETED:
            return self

        result_fields = (
            "input_type",
            "normalized_urls",
            "claims",
            "risk_score",
            "risk_level",
            "verdict",
            "recommended_action",
            "confidence",
            "summary",
            "reasons",
            "evidence",
            "limitations",
            "case_status",
            "scoring_version",
            "completed_at",
        )
        missing = [name for name in result_fields if getattr(self, name) is None]
        if missing:
            raise ValueError(f"completed analysis is missing fields: {', '.join(missing)}")

        expected_level = risk_level_for_score(self.risk_score)  # type: ignore[arg-type]
        if self.risk_level is not expected_level:
            raise ValueError("risk_level does not match risk_score")
        return self


class AnalysisEvent(ContractModel):
    analysis_id: UUID
    status: AnalysisStatus
    step: str
    occurred_at: datetime


class AnalysisReportRequest(ContractModel):
    reason: str
    comment: str | None = None


class AnalysisReportResponse(ContractModel):
    report_id: UUID
    analysis_id: UUID
    created_at: datetime


class AdminDecisionRequest(ContractModel):
    decision: ReviewDecision
    action: ReviewAction
    note: str

    @model_validator(mode="after")
    def protect_blacklist_write(self) -> Self:
        if self.action is ReviewAction.ADD_TO_BLACKLIST and self.decision is not ReviewDecision.APPROVED:
            raise ValueError("blacklist write requires an approved decision")
        return self


class AdminDecisionResponse(ContractModel):
    decision_id: UUID
    analysis_id: UUID
    case_status: Literal[CaseStatus.APPROVED, CaseStatus.REJECTED]
    reviewed_at: datetime


class ErrorBody(ContractModel):
    code: ErrorCode
    message: str
    retryable: bool
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorEnvelope(ContractModel):
    error: ErrorBody


def risk_level_for_score(score: int) -> RiskLevel:
    if not 0 <= score <= 100:
        raise ValueError("risk score must be between 0 and 100")
    if score < 30:
        return RiskLevel.LOW
    if score < 60:
        return RiskLevel.MEDIUM
    if score < 85:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL
