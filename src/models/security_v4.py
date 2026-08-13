from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.core.product_boundary import SECURITY_TRIAGE_CONTRACT_VERSION
from src.models.schemas import AnalysisStatus, AppealOutcome, AppealStatus, ReportStatus

CONTRACT_VERSION_V4 = SECURITY_TRIAGE_CONTRACT_VERSION
SECURITY_CONTEXT_VERSION = "security-context-v1"
SECURITY_RISK_POLICY_VERSION = "security-risk-v1"


class SecurityContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="after")
    @classmethod
    def reject_empty_strings(cls, value: Any) -> Any:
        def validate(item: Any) -> None:
            if isinstance(item, str) and not item.strip():
                raise ValueError("empty strings are not valid security contract values")
            if isinstance(item, datetime) and (item.tzinfo is None or item.utcoffset() != timedelta(0)):
                raise ValueError("timestamps must use UTC")
            if isinstance(item, list):
                for nested_item in item:
                    validate(nested_item)

        validate(value)
        return value


class ScopeDecisionV4(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    NEED_MORE_INFO = "NEED_MORE_INFO"
    OUT_OF_SCOPE_GENERAL_FACT_CHECK = "OUT_OF_SCOPE_GENERAL_FACT_CHECK"


class SecurityScenarioV4(StrEnum):
    RECRUITMENT = "recruitment"
    PROMOTION_PRIZE = "promotion_prize"
    ACCOUNT_VERIFICATION = "account_verification"
    PAYMENT = "payment"
    REFUND = "refund"
    UNKNOWN = "unknown"


class RequestedActionV4(StrEnum):
    LOGIN = "login"
    SHARE_OTP = "share_otp"
    SHARE_CREDENTIALS = "share_credentials"
    TRANSFER_MONEY = "transfer_money"
    PAY_FEE = "pay_fee"
    PROVIDE_PERSONAL_INFORMATION = "provide_personal_information"
    OPEN_LINK = "open_link"


class PotentialThreatV4(StrEnum):
    PHISHING = "PHISHING"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    FINANCIAL_SCAM = "FINANCIAL_SCAM"
    RECRUITMENT_SCAM = "RECRUITMENT_SCAM"
    PROMOTION_PRIZE_SCAM = "PROMOTION_PRIZE_SCAM"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    UNDETERMINED_SECURITY_THREAT = "UNDETERMINED_SECURITY_THREAT"


class SecurityRiskV4(StrEnum):
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MALICIOUS = "MALICIOUS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class SecurityRecommendedActionV4(StrEnum):
    DO_NOT_OPEN_LINK = "DO_NOT_OPEN_LINK"
    DO_NOT_SHARE_CREDENTIALS = "DO_NOT_SHARE_CREDENTIALS"
    DO_NOT_SHARE_OTP = "DO_NOT_SHARE_OTP"
    DO_NOT_TRANSFER_MONEY = "DO_NOT_TRANSFER_MONEY"
    VERIFY_VIA_OFFICIAL_CHANNEL = "VERIFY_VIA_OFFICIAL_CHANNEL"
    CHANGE_PASSWORD_IF_ALREADY_SHARED = "CHANGE_PASSWORD_IF_ALREADY_SHARED"
    CONTACT_BANK_IF_ALREADY_PAID = "CONTACT_BANK_IF_ALREADY_PAID"
    REPORT_AND_BLOCK_SENDER = "REPORT_AND_BLOCK_SENDER"
    PROCEED_WITH_CAUTION = "PROCEED_WITH_CAUTION"


class SecurityInvestigationToolV4(StrEnum):
    SECURITY_CONTEXT_ANALYSIS = "security_context_analysis"
    LOCAL_URL_RULES = "local_url_rules"
    BLACKLIST_LOOKUP = "blacklist_lookup"
    DNS = "dns"
    REDIRECT_RESOLVER = "redirect_resolver"
    RDAP = "rdap"
    URL_REPUTATION = "url_reputation"
    BRAND_MATCH = "brand_match"
    WHITELIST_LOOKUP = "whitelist_lookup"
    OFFICIAL_CLAIM_VERIFIER = "official_claim_verifier"


class SecurityInvestigationStepStatusV4(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class SecurityInvestigationStatusV4(StrEnum):
    NOT_STARTED = "not_started"
    COMPLETED = "completed"
    PARTIAL = "partial"


class SecurityEvidenceTypeV4(StrEnum):
    SECURITY_CONTEXT = "security_context"
    LOCAL_URL_RULE = "local_url_rule"
    BLACKLIST = "blacklist"
    DNS = "dns"
    REDIRECT = "redirect"
    RDAP = "rdap"
    URL_REPUTATION = "url_reputation"
    BRAND_MATCH = "brand_match"
    WHITELIST = "whitelist"
    OFFICIAL_VERIFICATION = "official_verification"


class TrustLifecycleV4(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class WhitelistScopeV4(StrEnum):
    DOMAIN = "domain"
    URL = "url"
    CONTACT = "contact"


class OfficialVerificationPurposeV4(StrEnum):
    VERIFY_OFFICIAL_CAMPAIGN = "verify_official_campaign"
    VERIFY_BRAND_ANNOUNCEMENT = "verify_brand_announcement"
    VERIFY_RECRUITMENT_PROGRAM = "verify_recruitment_program"
    VERIFY_OFFICIAL_DOMAIN = "verify_official_domain"
    VERIFY_OFFICIAL_CONTACT = "verify_official_contact"


class OfficialVerificationVerdictV4(StrEnum):
    OFFICIAL_CONFIRMED = "OFFICIAL_CONFIRMED"
    OFFICIAL_CONTRADICTED = "OFFICIAL_CONTRADICTED"
    NOT_FOUND = "NOT_FOUND"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class SecurityMemoryAdminVerdictV4(StrEnum):
    UNREVIEWED = "unreviewed"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SAFE = "safe"
    FALSE_POSITIVE = "false_positive"


class SecurityCampaignReviewerStatusV4(StrEnum):
    PENDING_REVIEW = "pending_review"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class InvestigationStepV4(SecurityContractModel):
    step_id: str = Field(pattern=r"^step-[a-f0-9]{12}$")
    tool: SecurityInvestigationToolV4
    target: str
    reason_code: str = Field(pattern=r"^[a-z0-9_]+$")
    depends_on: list[str] = Field(default_factory=list)
    status: SecurityInvestigationStepStatusV4
    status_reason: str | None = Field(default=None, pattern=r"^[a-z0-9_]+$")


class SecurityEvidenceV4(SecurityContractModel):
    evidence_ref: str = Field(pattern=r"^evidence:[a-f0-9]{16}$")
    type: SecurityEvidenceTypeV4
    source: str
    target: str | None = None
    signal: str
    description: str
    observed_at: datetime
    confidence: float | None = Field(default=None, ge=0, le=1)
    provenance_ref: str | None = None


class SecurityToolErrorV4(SecurityContractModel):
    tool: SecurityInvestigationToolV4
    target: str
    code: str = Field(pattern=r"^[A-Z0-9_]+$")
    message: str
    retryable: bool
    provider: str | None = None


class SecurityConsentV4(SecurityContractModel):
    external_url_lookup: bool = False
    official_source_lookup: bool = False


class BrandCreateRequestV4(SecurityContractModel):
    name: str = Field(min_length=1, max_length=200)
    aliases: list[str] = Field(default_factory=list, max_length=50)
    official_domains: list[str] = Field(default_factory=list, min_length=1, max_length=50)
    official_contacts: list[str] = Field(default_factory=list, max_length=50)
    provenance: str = Field(min_length=1, max_length=1000)
    policy_version: str = Field(default="brand-registry-v1", pattern=r"^[a-z0-9._-]+$")
    effective_from: datetime
    effective_until: datetime | None = None

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("effective_until must be after effective_from")
        return self


class BrandRecordV4(BrandCreateRequestV4):
    brand_id: UUID = Field(default_factory=uuid4)
    lifecycle: TrustLifecycleV4 = TrustLifecycleV4.ACTIVE
    reviewer_id: str
    created_at: datetime


class WhitelistCreateRequestV4(SecurityContractModel):
    indicator: str = Field(min_length=1, max_length=2048)
    scope: WhitelistScopeV4
    provenance: str = Field(min_length=1, max_length=1000)
    policy_version: str = Field(default="whitelist-v1", pattern=r"^[a-z0-9._-]+$")
    effective_from: datetime
    effective_until: datetime | None = None

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("effective_until must be after effective_from")
        return self


class WhitelistRecordV4(WhitelistCreateRequestV4):
    whitelist_id: UUID = Field(default_factory=uuid4)
    lifecycle: TrustLifecycleV4 = TrustLifecycleV4.ACTIVE
    reviewer_id: str
    created_at: datetime


class OfficialSourceFindingV4(SecurityContractModel):
    source_url: str
    finding: Literal["confirmed", "contradicted"]
    title: str
    observed_at: datetime


class OfficialVerificationResultV4(SecurityContractModel):
    verdict: OfficialVerificationVerdictV4
    purpose: OfficialVerificationPurposeV4
    sources_checked: int = Field(ge=0, le=5)
    search_queries_used: int = Field(default=0, ge=0, le=2)
    evidence_refs: list[str] = Field(default_factory=list, max_length=5)


class SecurityTriageCreateRequestV4(SecurityContractModel):
    message: str = Field(min_length=1, max_length=5000)
    consent: SecurityConsentV4 = Field(default_factory=SecurityConsentV4)
    conversation_id: UUID | None = None
    conversation_version: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_conversation_reference(self) -> Self:
        if (self.conversation_id is None) != (self.conversation_version is None):
            raise ValueError("conversation_id and conversation_version must be provided together")
        return self


class SecurityContextV4(SecurityContractModel):
    schema_version: Literal["security-context-v1"] = SECURITY_CONTEXT_VERSION
    claimed_entity: str | None = None
    scenario: SecurityScenarioV4
    requested_action: RequestedActionV4 | None = None
    amount: str | None = None
    urgency: bool
    urls: list[str] = Field(default_factory=list, max_length=10)
    credential_request: bool
    otp_request: bool
    payment_request: bool
    personal_information_request: bool
    impersonation_signals: list[str] = Field(default_factory=list, max_length=10)
    potential_threat: PotentialThreatV4


class SecurityConversationStatusV4(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"


class SecurityConversationSummaryV4(SecurityContractModel):
    security_context: SecurityContextV4 | None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


class SecurityConversationV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    conversation_id: UUID
    status: SecurityConversationStatusV4 = SecurityConversationStatusV4.ACTIVE
    active_analysis_id: UUID
    summary: SecurityConversationSummaryV4
    context_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    expires_at: datetime


class SecurityScopeResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    analysis_id: UUID = Field(default_factory=uuid4)
    conversation_id: UUID = Field(default_factory=uuid4)
    conversation_version: int = Field(default=1, ge=1)
    status: AnalysisStatus = AnalysisStatus.RUNNING
    scope_decision: ScopeDecisionV4
    terminal: bool
    next_step: Literal["END", "INVESTIGATION", "RISK_ASSESSMENT"]
    scope_reasons: list[str] = Field(min_length=1, max_length=10)
    security_context: SecurityContextV4 | None = None
    follow_up_question: str | None = None
    boundary_message: str | None = None
    limitations: list[str] = Field(default_factory=list, max_length=100)
    investigation_status: SecurityInvestigationStatusV4 = SecurityInvestigationStatusV4.NOT_STARTED
    investigation_plan: list[InvestigationStepV4] = Field(default_factory=list, max_length=100)
    evidence: list[SecurityEvidenceV4] = Field(default_factory=list, max_length=100)
    errors: list[SecurityToolErrorV4] = Field(default_factory=list, max_length=100)
    tool_calls_used: int = Field(default=0, ge=0)
    risk: SecurityRiskV4 | None = None
    score: int | None = Field(default=None, ge=0, le=100)
    confidence: float | None = Field(default=None, ge=0, le=1)
    threat_type: PotentialThreatV4 | None = None
    policy_version: Literal["security-risk-v1"] | None = None
    recommended_actions: list[SecurityRecommendedActionV4] = Field(default_factory=list, max_length=20)
    explanation: str | None = None
    explanation_evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_scope_transition(self) -> Self:
        if self.scope_decision is ScopeDecisionV4.IN_SCOPE:
            if self.next_step not in {"END", "INVESTIGATION", "RISK_ASSESSMENT"} or self.security_context is None:
                raise ValueError("in-scope response requires security context")
            if self.follow_up_question is not None or self.boundary_message is not None:
                raise ValueError("in-scope response cannot contain a terminal message")
            if (self.next_step == "END") != self.terminal:
                raise ValueError("in-scope END transition must be terminal")
            if self.next_step == "INVESTIGATION" and self.investigation_status is not SecurityInvestigationStatusV4.NOT_STARTED:
                raise ValueError("investigation transition requires not-started investigation state")
            if self.next_step == "RISK_ASSESSMENT" and self.investigation_status is SecurityInvestigationStatusV4.NOT_STARTED:
                raise ValueError("risk transition requires completed or partial investigation")
            if self.next_step == "END" and self.risk is None:
                raise ValueError("completed in-scope response requires risk result")
        elif self.scope_decision is ScopeDecisionV4.NEED_MORE_INFO:
            if not self.terminal or self.next_step != "END" or self.follow_up_question is None:
                raise ValueError("need-more-info response requires a terminal follow-up question")
            if self.boundary_message is not None:
                raise ValueError("need-more-info response cannot contain a boundary message")
        else:
            if not self.terminal or self.next_step != "END" or self.boundary_message is None:
                raise ValueError("out-of-scope response requires a terminal boundary message")
            if self.follow_up_question is not None or self.security_context is not None:
                raise ValueError("out-of-scope response cannot contain security context or follow-up")
        if self.scope_decision is not ScopeDecisionV4.IN_SCOPE and (
            self.investigation_status is not SecurityInvestigationStatusV4.NOT_STARTED
            or self.investigation_plan
            or self.evidence
            or self.errors
            or self.tool_calls_used
        ):
            raise ValueError("terminal scope response cannot contain investigation output")
        risk_fields = (self.score, self.confidence, self.threat_type, self.policy_version, self.explanation)
        if self.risk is None:
            if any(value is not None for value in risk_fields) or self.recommended_actions or self.explanation_evidence_refs:
                raise ValueError("risk details require a risk class")
        elif any(value is None for value in risk_fields) or not self.recommended_actions:
            raise ValueError("risk result is incomplete")
        if self.status is AnalysisStatus.COMPLETED and self.completed_at is None:
            self.completed_at = self.created_at
        return self


class SecurityAnalysisAcceptedResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    analysis_id: UUID
    status: Literal[AnalysisStatus.QUEUED] = AnalysisStatus.QUEUED
    created_at: datetime


class SecurityAnalysisEventV4(SecurityContractModel):
    event_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    sequence: int = Field(ge=1)
    status: AnalysisStatus
    step: str
    occurred_at: datetime


class SecurityAnalysisEventPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    events: list[SecurityAnalysisEventV4]
    next_cursor: str | None = None


class SecurityWebSocketTicketRequestV4(SecurityContractModel):
    analysis_id: UUID


class SecurityWebSocketTicketResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    ticket: str
    analysis_id: UUID
    expires_at: datetime
    stream_path: str
    single_use: Literal[True] = True


class SecurityReportCreateRequestV4(SecurityContractModel):
    reason: str = Field(min_length=1, max_length=500)
    comment: str | None = Field(default=None, max_length=5000)


class SecurityReportRecordV4(SecurityReportCreateRequestV4):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    report_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    status: ReportStatus = ReportStatus.SUBMITTED
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SecurityAppealCreateRequestV4(SecurityContractModel):
    reason: str = Field(min_length=1, max_length=500)
    comment: str | None = Field(default=None, max_length=5000)


class SecurityAppealRecordV4(SecurityAppealCreateRequestV4):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    appeal_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    status: AppealStatus = AppealStatus.SUBMITTED
    outcome: AppealOutcome | None = None
    resolution_note: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None


class SecurityMemoryRecordV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    memory_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    canonical_domains: list[str] = Field(default_factory=list, max_length=10)
    url_fingerprints: list[str] = Field(default_factory=list, max_length=10)
    redirect_targets: list[str] = Field(default_factory=list, max_length=10)
    claimed_brand: str | None = None
    scenario: SecurityScenarioV4
    requested_action: RequestedActionV4 | None = None
    security_patterns: list[str] = Field(default_factory=list, max_length=20)
    lexical_features: list[str] = Field(default_factory=list, max_length=30)
    threat_type: PotentialThreatV4
    risk: SecurityRiskV4
    risk_policy_version: str
    fingerprint_version: str = Field(default="security-fingerprint-v1", pattern=r"^[a-z0-9._-]+$")
    first_seen_at: datetime
    last_seen_at: datetime
    report_count: int = Field(default=0, ge=0)
    admin_verdict: SecurityMemoryAdminVerdictV4 = SecurityMemoryAdminVerdictV4.UNREVIEWED
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_seen_window(self) -> Self:
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at must not be before first_seen_at")
        return self


class SecurityMemoryCorrectionRequestV4(SecurityContractModel):
    verdict: SecurityMemoryAdminVerdictV4
    note: str = Field(min_length=1, max_length=5000)

    @model_validator(mode="after")
    def reject_unreviewed_correction(self) -> Self:
        if self.verdict is SecurityMemoryAdminVerdictV4.UNREVIEWED:
            raise ValueError("admin correction requires a reviewed verdict")
        return self


class SecurityMemoryAuditRecordV4(SecurityContractModel):
    audit_id: UUID = Field(default_factory=uuid4)
    memory_id: UUID
    previous_verdict: SecurityMemoryAdminVerdictV4
    verdict: SecurityMemoryAdminVerdictV4
    reviewer_id: str
    note: str
    occurred_at: datetime
    risk_policy_version: str
    fingerprint_version: str
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


class SecurityCampaignRecordV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    campaign_id: UUID
    hypothesis: str
    analysis_ids: list[UUID] = Field(min_length=3)
    window_started_at: datetime
    window_ended_at: datetime
    aggregate_signals: dict[str, int]
    reviewer_status: SecurityCampaignReviewerStatusV4 = SecurityCampaignReviewerStatusV4.PENDING_REVIEW
    clustering_version: str = Field(default="security-clustering-v1", pattern=r"^[a-z0-9._-]+$")
    evidence_refs: list[str] = Field(min_length=1, max_length=100)
    reviewer_id: str | None = None
    review_note: str | None = None
    reviewed_at: datetime | None = None
    created_at: datetime

    @model_validator(mode="after")
    def validate_campaign_review(self) -> Self:
        if self.window_ended_at < self.window_started_at:
            raise ValueError("campaign window must end after it starts")
        if len(set(self.analysis_ids)) != len(self.analysis_ids):
            raise ValueError("campaign analysis_ids must be unique")
        reviewed = self.reviewer_status is not SecurityCampaignReviewerStatusV4.PENDING_REVIEW
        review_values = (self.reviewer_id, self.review_note, self.reviewed_at)
        if (reviewed and not all(value is not None for value in review_values)) or (
            not reviewed and any(value is not None for value in review_values)
        ):
            raise ValueError("reviewed campaign requires reviewer, note, and timestamp")
        return self


class SecurityCampaignDecisionRequestV4(SecurityContractModel):
    decision: Literal[
        SecurityCampaignReviewerStatusV4.CONFIRMED,
        SecurityCampaignReviewerStatusV4.REJECTED,
    ]
    note: str = Field(min_length=1, max_length=5000)


class SecurityCampaignAuditRecordV4(SecurityContractModel):
    audit_id: UUID = Field(default_factory=uuid4)
    campaign_id: UUID
    previous_status: SecurityCampaignReviewerStatusV4
    status: SecurityCampaignReviewerStatusV4
    reviewer_id: str
    note: str
    occurred_at: datetime
    clustering_version: str
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


__all__ = [
    "CONTRACT_VERSION_V4",
    "SECURITY_CONTEXT_VERSION",
    "SECURITY_RISK_POLICY_VERSION",
    "PotentialThreatV4",
    "BrandCreateRequestV4",
    "BrandRecordV4",
    "InvestigationStepV4",
    "RequestedActionV4",
    "ScopeDecisionV4",
    "OfficialSourceFindingV4",
    "OfficialVerificationPurposeV4",
    "OfficialVerificationResultV4",
    "OfficialVerificationVerdictV4",
    "SecurityConsentV4",
    "SecurityConversationStatusV4",
    "SecurityConversationSummaryV4",
    "SecurityConversationV4",
    "SecurityContextV4",
    "SecurityAnalysisAcceptedResponseV4",
    "SecurityAnalysisEventPageV4",
    "SecurityAnalysisEventV4",
    "SecurityEvidenceTypeV4",
    "SecurityEvidenceV4",
    "SecurityInvestigationStatusV4",
    "SecurityInvestigationStepStatusV4",
    "SecurityInvestigationToolV4",
    "SecurityScenarioV4",
    "SecurityRecommendedActionV4",
    "SecurityRiskV4",
    "SecurityWebSocketTicketRequestV4",
    "SecurityWebSocketTicketResponseV4",
    "TrustLifecycleV4",
    "WhitelistCreateRequestV4",
    "WhitelistRecordV4",
    "WhitelistScopeV4",
    "SecurityScopeResponseV4",
    "SecurityTriageCreateRequestV4",
    "SecurityToolErrorV4",
    "SecurityReportCreateRequestV4",
    "SecurityReportRecordV4",
    "SecurityAppealCreateRequestV4",
    "SecurityAppealRecordV4",
    "SecurityMemoryAdminVerdictV4",
    "SecurityMemoryRecordV4",
    "SecurityMemoryCorrectionRequestV4",
    "SecurityMemoryAuditRecordV4",
    "SecurityCampaignReviewerStatusV4",
    "SecurityCampaignRecordV4",
    "SecurityCampaignDecisionRequestV4",
    "SecurityCampaignAuditRecordV4",
]
