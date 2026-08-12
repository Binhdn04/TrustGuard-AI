from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CONTRACT_VERSION = "v2"
CONTRACT_VERSION_V3 = "v3"
SCORING_VERSION = "risk-v2"


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


class InvestigationStepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class InvestigationTool(StrEnum):
    LOCAL_RULES = "local_rules"
    BLACKLIST_LOOKUP = "blacklist_lookup"
    URL_SCANNER = "url_scanner"
    REDIRECT_RESOLVER = "redirect_resolver"
    DOMAIN_INTELLIGENCE = "domain_intelligence"
    CLAIM_RETRIEVER = "claim_retriever"


class ClaimStance(StrEnum):
    SUPPORTS = "supports"
    REFUTES = "refutes"
    MIXED = "mixed"
    UNRATED = "unrated"


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


class ReportStatus(StrEnum):
    SUBMITTED = "submitted"
    REVIEWING = "reviewing"
    PROCESSED = "processed"


class ReportReviewDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    DISMISSED = "dismissed"


class ErrorCode(StrEnum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ContractModel(BaseModel):
    """Strict base for the frozen v2 JSON contract."""

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
    """Legacy starter endpoint request. Prefer AnalysisCreateRequest for v2."""

    message: str = Field(..., min_length=1, max_length=5000, description="Tin nhắn từ user")


class ChatResponse(BaseModel):
    """Legacy starter endpoint response. Not part of the analysis v2 contract."""

    response: str = Field(..., description="Phản hồi từ agent")
    analysis: str = Field(default="", description="Phân tích nội bộ")


class AnalysisCreateRequest(ContractModel):
    message: str = Field(min_length=1, max_length=5000)
    consent_to_scan_urls: bool


class AnalysisAcceptedResponse(ContractModel):
    contract_version: Literal["v2"] = CONTRACT_VERSION
    analysis_id: UUID
    status: Literal[AnalysisStatus.QUEUED] = AnalysisStatus.QUEUED
    created_at: datetime


class Evidence(ContractModel):
    type: EvidenceType
    source: str
    title: str
    url: str | None = None
    finding: str
    stance: ClaimStance | None = None
    observed_at: datetime


class InvestigationStep(ContractModel):
    step_id: str
    tool: InvestigationTool
    target: str
    reason_code: str
    depends_on: list[str] = Field(default_factory=list)
    status: InvestigationStepStatus = InvestigationStepStatus.PENDING


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
    relevance: float = Field(ge=0.0, le=1.0)
    stance: ClaimStance = ClaimStance.UNRATED
    observed_at: datetime


class DomainIntelligenceResult(ContractModel):
    provider: str
    domain: str
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    registrar: str | None = None
    country: str | None = None
    status: list[str] = Field(default_factory=list)
    privacy_redacted: bool = False
    signals: list[str] = Field(default_factory=list)
    observed_at: datetime


class BlacklistLookupEntry(ContractModel):
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
    contract_version: Literal["v2"] = CONTRACT_VERSION
    analysis_id: UUID
    status: AnalysisStatus
    input_type: InputType | None = None
    normalized_urls: list[str] | None = None
    claims: list[str] | None = None
    investigation_plan: list[InvestigationStep] = Field(default_factory=list)
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
    step_id: str | None = None
    step_status: InvestigationStepStatus | None = None
    target: str | None = None
    reason_code: str | None = None
    depends_on: list[str] = Field(default_factory=list)
    provisional_risk_level: RiskLevel | None = None
    provisional_summary: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    is_provisional: bool = False


class AnalysisReportRequest(ContractModel):
    reason: str
    comment: str | None = None


class AnalysisReportResponse(ContractModel):
    report_id: UUID
    analysis_id: UUID
    status: ReportStatus = ReportStatus.SUBMITTED
    created_at: datetime


class AnalysisReportRecord(AnalysisReportResponse):
    reporter_id: str
    reason: str
    comment: str | None = None


class ReviewQueueItem(ContractModel):
    item_id: UUID
    report_id: UUID
    analysis_id: UUID
    status: ReportStatus
    reason: str
    comment: str | None = None
    analysis_content: str | None = None
    evidence_snapshot: list[Evidence] = Field(default_factory=list)
    decision: ReportReviewDecision | None = None
    reviewer_id: str | None = None
    reviewer_note: str | None = None
    reviewed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ReviewQueueDecisionRequest(ContractModel):
    decision: ReportReviewDecision
    note: str


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


class AdminDecisionAudit(ContractModel):
    decision_id: UUID
    analysis_id: UUID | None = None
    reviewer_id: str
    decision: ReviewDecision
    action: ReviewAction
    note: str
    decided_at: datetime


class BlacklistEntry(ContractModel):
    domain: str
    decision_id: UUID
    added_at: datetime


class ErrorBody(ContractModel):
    code: ErrorCode
    message: str
    retryable: bool
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorEnvelope(ContractModel):
    error: ErrorBody


# v3 is intentionally modeled separately from v2.  Do not add v3-only nullable
# fields to the v2 resources: the first v3 release keeps the v2 read contract
# stable during its deprecation window.


class AnalysisCreateRequestV3(AnalysisCreateRequest):
    consent_to_capture_screenshot: bool = False


class AnalysisAcceptedResponseV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    analysis_id: UUID
    status: Literal[AnalysisStatus.QUEUED] = AnalysisStatus.QUEUED
    created_at: datetime


class AnalysisResponseV3(AnalysisResponse):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3


class ScreenshotStatus(StrEnum):
    NOT_REQUESTED = "not_requested"
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"
    EXPIRED = "expired"


class ScreenshotArtifactV3(ContractModel):
    artifact_id: UUID
    media_type: Literal["image/png", "image/jpeg", "image/webp"]
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime
    expires_at: datetime
    access_path: str
    access_expires_at: datetime


class ScreenshotStatusResponseV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    analysis_id: UUID
    consented: bool
    status: ScreenshotStatus
    artifact: ScreenshotArtifactV3 | None = None
    failure_code: str | None = None

    @model_validator(mode="after")
    def validate_artifact_state(self) -> Self:
        if self.status is ScreenshotStatus.READY and self.artifact is None:
            raise ValueError("ready screenshot status requires an artifact")
        if self.status is not ScreenshotStatus.READY and self.artifact is not None:
            raise ValueError("only a ready screenshot status may contain an artifact")
        if not self.consented and self.status is not ScreenshotStatus.NOT_REQUESTED:
            raise ValueError("screenshot without consent must remain not_requested")
        return self


class AnalysisReportResponseV3(AnalysisReportResponse):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3


class AnalysisEventType(StrEnum):
    ANALYSIS_STATUS = "analysis_status"
    STEP_TRANSITION = "step_transition"
    PROVISIONAL_WARNING = "provisional_warning"
    FINAL_RESULT = "final_result"
    CASE_UPDATE = "case_update"
    LIMITATION = "limitation"


class AnalysisStatusEventPayload(ContractModel):
    status: AnalysisStatus


class StepTransitionEventPayload(ContractModel):
    step_id: str
    tool: InvestigationTool
    target: str
    reason_code: str
    depends_on: list[str] = Field(default_factory=list)
    status: InvestigationStepStatus


class ProvisionalWarningEventPayload(ContractModel):
    risk_level: Literal[RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    summary: str
    evidence_refs: list[str] = Field(min_length=1)
    is_provisional: Literal[True] = True


class FinalResultEventPayload(ContractModel):
    result_ref: str
    status: Literal[AnalysisStatus.COMPLETED] = AnalysisStatus.COMPLETED


class CaseUpdateEventPayload(ContractModel):
    case_status: CaseStatus
    decision_id: UUID | None = None


class LimitationEventPayload(ContractModel):
    code: str
    message: str
    retryable: bool


class _AnalysisEventV3Base(ContractModel):
    event_id: UUID
    analysis_id: UUID
    sequence: int = Field(ge=1)
    occurred_at: datetime


class AnalysisStatusEventV3(_AnalysisEventV3Base):
    event_type: Literal[AnalysisEventType.ANALYSIS_STATUS] = AnalysisEventType.ANALYSIS_STATUS
    payload: AnalysisStatusEventPayload


class StepTransitionEventV3(_AnalysisEventV3Base):
    event_type: Literal[AnalysisEventType.STEP_TRANSITION] = AnalysisEventType.STEP_TRANSITION
    payload: StepTransitionEventPayload


class ProvisionalWarningEventV3(_AnalysisEventV3Base):
    event_type: Literal[AnalysisEventType.PROVISIONAL_WARNING] = AnalysisEventType.PROVISIONAL_WARNING
    payload: ProvisionalWarningEventPayload


class FinalResultEventV3(_AnalysisEventV3Base):
    event_type: Literal[AnalysisEventType.FINAL_RESULT] = AnalysisEventType.FINAL_RESULT
    payload: FinalResultEventPayload


class CaseUpdateEventV3(_AnalysisEventV3Base):
    event_type: Literal[AnalysisEventType.CASE_UPDATE] = AnalysisEventType.CASE_UPDATE
    payload: CaseUpdateEventPayload


class LimitationEventV3(_AnalysisEventV3Base):
    event_type: Literal[AnalysisEventType.LIMITATION] = AnalysisEventType.LIMITATION
    payload: LimitationEventPayload


AnalysisEventV3 = Annotated[
    AnalysisStatusEventV3
    | StepTransitionEventV3
    | ProvisionalWarningEventV3
    | FinalResultEventV3
    | CaseUpdateEventV3
    | LimitationEventV3,
    Field(discriminator="event_type"),
]


class AnalysisEventPageV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    events: list[AnalysisEventV3]
    next_cursor: str | None = None


class WebSocketTicketRequestV3(ContractModel):
    analysis_id: UUID


class WebSocketTicketResponseV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    ticket: str
    analysis_id: UUID
    expires_at: datetime
    stream_path: str
    single_use: Literal[True] = True


class AppealStatus(StrEnum):
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    RESOLVED = "resolved"


class AppealOutcome(StrEnum):
    UPHOLD = "uphold"
    OVERTURN = "overturn"
    INCONCLUSIVE = "inconclusive"


class AppealCreateRequestV3(ContractModel):
    reason: str = Field(max_length=500)
    comment: str | None = Field(default=None, max_length=5000)


class AppealReceiptV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    appeal_id: UUID
    analysis_id: UUID
    status: Literal[AppealStatus.SUBMITTED] = AppealStatus.SUBMITTED
    created_at: datetime


class AppealResponseV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    appeal_id: UUID
    analysis_id: UUID
    status: AppealStatus
    reason: str
    comment: str | None = None
    outcome: AppealOutcome | None = None
    resolution_note: str | None = None
    created_at: datetime
    resolved_at: datetime | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        resolution_fields = (self.outcome, self.resolution_note, self.resolved_at)
        if self.status is AppealStatus.RESOLVED and any(value is None for value in resolution_fields):
            raise ValueError("resolved appeal requires outcome, resolution_note and resolved_at")
        if self.status is not AppealStatus.RESOLVED and any(value is not None for value in resolution_fields):
            raise ValueError("unresolved appeal cannot contain resolution fields")
        return self


class AppealAdminRecordV3(AppealResponseV3):
    owner_id: str


class AppealPageV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    items: list[AppealAdminRecordV3]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class AppealDecisionRequestV3(ContractModel):
    outcome: AppealOutcome
    note: str = Field(max_length=5000)


class AppealDecisionResponseV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    appeal_id: UUID
    decision_id: UUID
    outcome: AppealOutcome
    decided_at: datetime


class ReviewedAction(StrEnum):
    ADD_TO_BLACKLIST = "add_to_blacklist"
    DISABLE_BLACKLIST = "disable_blacklist"
    BLOCK_DOMAIN = "block_domain"
    PUBLISH_BROAD_WARNING = "publish_broad_warning"
    NONE = "none"


class AdminActionStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class AdminActionRecordV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    action_id: UUID
    analysis_id: UUID | None = None
    campaign_id: UUID | None = None
    action: ReviewedAction
    target: str | None = None
    status: AdminActionStatus
    evidence_snapshot: list[Evidence]
    proposed_at: datetime
    reviewer_id: str | None = None
    review_note: str | None = None
    reviewed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_review(self) -> Self:
        review_fields = (self.reviewer_id, self.review_note, self.reviewed_at)
        is_reviewed = self.status is not AdminActionStatus.PENDING_REVIEW
        if is_reviewed and any(value is None for value in review_fields):
            raise ValueError("reviewed action requires reviewer_id, review_note and reviewed_at")
        if not is_reviewed and any(value is not None for value in review_fields):
            raise ValueError("pending action cannot contain review fields")
        if self.action is ReviewedAction.NONE and self.target is not None:
            raise ValueError("none action cannot have a target")
        if self.action is not ReviewedAction.NONE and self.target is None:
            raise ValueError("reviewed action requires a target")
        if self.action is not ReviewedAction.NONE and not self.evidence_snapshot:
            raise ValueError("reviewed action requires an evidence snapshot")
        return self


class AdminActionDecisionRequestV3(ContractModel):
    decision: ReviewDecision
    note: str = Field(max_length=5000)


class AdminActionDecisionResponseV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    action_id: UUID
    decision_id: UUID
    action: ReviewedAction
    status: Literal[AdminActionStatus.APPROVED, AdminActionStatus.REJECTED]
    reviewed_at: datetime


class AdminActionPageV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    items: list[AdminActionRecordV3]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class CampaignReviewerStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class CampaignAggregateSignalV3(ContractModel):
    signal: str
    count: int = Field(ge=1)


class CampaignSummaryV3(ContractModel):
    campaign_id: UUID
    hypothesis: str
    window_started_at: datetime
    window_ended_at: datetime
    analysis_count: int = Field(ge=3)
    aggregate_signals: list[CampaignAggregateSignalV3]
    reviewer_status: CampaignReviewerStatus
    clustering_version: str

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if self.window_ended_at < self.window_started_at:
            raise ValueError("campaign window must end after it starts")
        return self


class CampaignDetailV3(CampaignSummaryV3):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    evidence_refs: list[str] = Field(min_length=1)
    registrable_domains: list[str]
    redirect_targets: list[str]
    reviewer_id: str | None = None
    review_note: str | None = None
    reviewed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_review(self) -> Self:
        review_fields = (self.reviewer_id, self.review_note, self.reviewed_at)
        is_reviewed = self.reviewer_status is not CampaignReviewerStatus.PENDING_REVIEW
        if is_reviewed and any(value is None for value in review_fields):
            raise ValueError("reviewed campaign requires reviewer_id, review_note and reviewed_at")
        if not is_reviewed and any(value is not None for value in review_fields):
            raise ValueError("pending campaign cannot contain review fields")
        return self


class CampaignPageV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    items: list[CampaignSummaryV3]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class CampaignDecisionRequestV3(ContractModel):
    decision: Literal[CampaignReviewerStatus.CONFIRMED, CampaignReviewerStatus.REJECTED]
    note: str = Field(min_length=1, max_length=5000)


class SourceTierV3(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    UNTRUSTED = "UNTRUSTED"


class SourcePolicyCreateRequestV3(ContractModel):
    publisher: str = Field(min_length=1, max_length=300)
    normalized_pattern: str = Field(min_length=3, max_length=253)
    tier: SourceTierV3
    source_type: str = Field(min_length=1, max_length=100)
    explicit_deny: bool = False
    trusted_claim_review: bool = False
    allowed_operations: set[Literal["search", "read", "compare", "promote"]] = Field(default_factory=set)
    policy_version: str = Field(min_length=1, max_length=100)
    effective_from: datetime
    effective_to: datetime | None = None
    default_freshness_seconds: int = Field(default=21600, gt=0, le=31536000)


class SourcePolicyRecordV3(SourcePolicyCreateRequestV3):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    source_id: UUID
    active: bool
    reviewer_id: str
    reviewed_at: datetime


class CapabilitiesResponseV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    profile: Literal["offline", "partial", "live"]
    capabilities: dict[str, Literal["ready", "degraded", "not_configured"]]


class MetricsWindowV3(ContractModel):
    started_at: datetime
    ended_at: datetime

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if self.ended_at <= self.started_at:
            raise ValueError("metrics window must end after it starts")
        return self


class LatencyMetricV3(ContractModel):
    operation: str
    count: int = Field(ge=0)
    p50_ms: float | None = Field(default=None, ge=0)
    p95_ms: float | None = Field(default=None, ge=0)
    p99_ms: float | None = Field(default=None, ge=0)


class CacheMetricV3(ContractModel):
    provider: str
    hits: int = Field(ge=0)
    misses: int = Field(ge=0)
    hit_rate: float | None = Field(default=None, ge=0, le=1)


class UsageMetricV3(ContractModel):
    provider: str
    model: str | None = None
    calls: int = Field(ge=0)
    tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0)
    quota_used: float | None = Field(default=None, ge=0)
    rate_limited: int = Field(ge=0)
    timed_out: int = Field(ge=0)


class RiskDistributionMetricV3(ContractModel):
    risk_level: RiskLevel
    count: int = Field(ge=0)


class FeedbackMetricV3(ContractModel):
    reports: int = Field(ge=0)
    appeals: int = Field(ge=0)
    appeals_upheld: int = Field(ge=0)
    appeals_overturned: int = Field(ge=0)
    appeals_inconclusive: int = Field(ge=0)
    false_positive_rate: float | None = Field(default=None, ge=0, le=1)


class OperationsMetricsResponseV3(ContractModel):
    contract_version: Literal["v3"] = CONTRACT_VERSION_V3
    window: MetricsWindowV3
    generated_at: datetime
    latency: list[LatencyMetricV3]
    cache: list[CacheMetricV3]
    usage: list[UsageMetricV3]
    risk_distribution: list[RiskDistributionMetricV3]
    feedback: FeedbackMetricV3


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
