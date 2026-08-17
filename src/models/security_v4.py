from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.core.product_boundary import SECURITY_TRIAGE_CONTRACT_VERSION
from src.models.schemas import (
    AnalysisStatus,
    AppealOutcome,
    AppealStatus,
    ReportReviewDecision,
    ReportStatus,
)

CONTRACT_VERSION_V4 = SECURITY_TRIAGE_CONTRACT_VERSION
SECURITY_CONTEXT_VERSION = "security-context-v1"
SECURITY_RISK_POLICY_VERSION = "security-risk-v1"
SECURITY_RISK_POLICY_VERSION_V2 = "security-risk-v2"
SECURITY_UNDERSTANDING_VERSION = "security-understanding-v1"
SECURITY_ASSISTANT_RESPONSE_VERSION = "security-assistant-response-v1"


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
    CHARITY = "charity"
    INVESTMENT = "investment"
    ONLINE_TASK = "online_task"
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
    INSTALL_APP = "install_app"
    SHARE_SCREEN = "share_screen"
    SCAN_QR = "scan_qr"


class PotentialThreatV4(StrEnum):
    PHISHING = "PHISHING"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    FINANCIAL_SCAM = "FINANCIAL_SCAM"
    RECRUITMENT_SCAM = "RECRUITMENT_SCAM"
    PROMOTION_PRIZE_SCAM = "PROMOTION_PRIZE_SCAM"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    IMPERSONATION_FINANCIAL_SCAM = "IMPERSONATION_FINANCIAL_SCAM"
    CREDENTIAL_AND_OTP_PHISHING = "CREDENTIAL_AND_OTP_PHISHING"
    RECRUITMENT_IMPERSONATION = "RECRUITMENT_IMPERSONATION"
    CHARITY_IMPERSONATION_SCAM = "CHARITY_IMPERSONATION_SCAM"
    INVESTMENT_IMPERSONATION_SCAM = "INVESTMENT_IMPERSONATION_SCAM"
    ADVANCE_FEE_TASK_SCAM = "ADVANCE_FEE_TASK_SCAM"
    PAYMENT_AND_OTP_PHISHING = "PAYMENT_AND_OTP_PHISHING"
    ADVANCE_FEE_SCAM = "ADVANCE_FEE_SCAM"
    UNDETERMINED_SECURITY_THREAT = "UNDETERMINED_SECURITY_THREAT"


class SecurityRiskV4(StrEnum):
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MALICIOUS = "MALICIOUS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class AssistantProcessingModeV4(StrEnum):
    HYBRID = "hybrid"
    RULES_ONLY = "rules_only"
    FALLBACK = "fallback"


class ExposureStateV4(StrEnum):
    PRE_ACTION = "PRE_ACTION"
    LINK_OPENED = "LINK_OPENED"
    CREDENTIAL_SHARED = "CREDENTIAL_SHARED"
    OTP_SHARED = "OTP_SHARED"
    PAYMENT_SENT = "PAYMENT_SENT"
    UNKNOWN = "UNKNOWN"


class MissingInformationSlotV4(StrEnum):
    ACTION_TAKEN = "action_taken"
    REQUESTED_SENSITIVE_ACTION = "requested_sensitive_action"
    URL_OR_CONTACT = "url_or_contact"
    CLAIMED_ORGANIZATION = "claimed_organization"
    AMOUNT_DEADLINE_CHANNEL = "amount_deadline_channel"


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
    CLOSE_PAGE_AND_DO_NOT_RETURN = "CLOSE_PAGE_AND_DO_NOT_RETURN"
    CHANGE_PASSWORD_FROM_TRUSTED_DEVICE = "CHANGE_PASSWORD_FROM_TRUSTED_DEVICE"
    REVOKE_ACTIVE_SESSIONS = "REVOKE_ACTIVE_SESSIONS"
    CONTACT_BANK_OR_PAYMENT_PROVIDER = "CONTACT_BANK_OR_PAYMENT_PROVIDER"
    PRESERVE_MESSAGE_FOR_REPORTING = "PRESERVE_MESSAGE_FOR_REPORTING"


class AssistantGenerationModeV4(StrEnum):
    AI = "ai"
    POLICY_GROUNDED = "policy_grounded"
    # Kept for reading responses persisted by older deployments. New turns
    # must use POLICY_GROUNDED instead of presenting a template fallback.
    TEMPLATE_FALLBACK = "template_fallback"


class AssistantReasonV4(SecurityContractModel):
    text: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)


class AssistantImmediateStepV4(SecurityContractModel):
    action: SecurityRecommendedActionV4
    policy_ref: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9:_-]+$")


class AssistantResponseV4(SecurityContractModel):
    summary: str = Field(min_length=1, max_length=2000)
    top_reasons: list[AssistantReasonV4] = Field(default_factory=list, max_length=5)
    uncertainties: list[str] = Field(default_factory=list, max_length=20)
    immediate_steps: list[AssistantImmediateStepV4] = Field(min_length=1, max_length=20)
    follow_up_offer: str | None = Field(default=None, max_length=500)
    response_version: Literal["security-assistant-response-v1"] = SECURITY_ASSISTANT_RESPONSE_VERSION
    generation_mode: AssistantGenerationModeV4

    @model_validator(mode="after")
    def validate_unique_grounding(self) -> Self:
        if any(len(reason.evidence_refs) != len(set(reason.evidence_refs)) for reason in self.top_reasons):
            raise ValueError("assistant reason evidence refs must be unique within each reason")
        actions = [step.action for step in self.immediate_steps]
        if len(actions) != len(set(actions)):
            raise ValueError("assistant immediate actions must be unique")
        return self


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
    SECURITY_MEMORY_LOOKUP = "security_memory_lookup"


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
    REVIEWED_SECURITY_MEMORY = "reviewed_security_memory"


class TrustLifecycleV4(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class WhitelistScopeV4(StrEnum):
    DOMAIN = "domain"
    URL = "url"
    CONTACT = "contact"


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


class SecurityExecutionModeV4(StrEnum):
    INLINE = "inline"
    ASYNC = "async"


class SecurityChatRouteV4(StrEnum):
    CONVERSATION = "conversation"
    SECURITY_ANALYSIS = "security_analysis"


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


class BrandPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[BrandRecordV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class WhitelistPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[WhitelistRecordV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class SecurityTriageCreateRequestV4(SecurityContractModel):
    message: str = Field(min_length=1, max_length=5000)
    consent: SecurityConsentV4 = Field(default_factory=SecurityConsentV4)
    execution_mode: SecurityExecutionModeV4 = SecurityExecutionModeV4.INLINE
    conversation_id: UUID | None = None
    conversation_version: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_conversation_reference(self) -> Self:
        if (self.conversation_id is None) != (self.conversation_version is None):
            raise ValueError("conversation_id and conversation_version must be provided together")
        return self


class SecurityChatRequestV4(SecurityContractModel):
    message: str = Field(min_length=1, max_length=5000)


class SecurityChatResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    route: SecurityChatRouteV4
    response: str


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


class AssistantSourceSpanV4(SecurityContractModel):
    field_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9_]+$")
    start: int = Field(ge=0)
    end: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_offsets(self) -> Self:
        if self.end <= self.start:
            raise ValueError("source span end must be greater than start")
        return self


class AssistantContextV4(SecurityContractModel):
    processing_mode: AssistantProcessingModeV4
    sender_intent: str | None = Field(default=None, max_length=500)
    social_engineering_techniques: list[str] = Field(default_factory=list, max_length=20)
    exposure_state: ExposureStateV4 = ExposureStateV4.UNKNOWN
    missing_information: list[str] = Field(default_factory=list, max_length=20)
    field_confidences: dict[str, Annotated[float, Field(ge=0, le=1)]] = Field(
        default_factory=dict,
        max_length=50,
    )
    source_spans: list[AssistantSourceSpanV4] = Field(default_factory=list, max_length=50)
    understanding_version: Literal["security-understanding-v1"] = SECURITY_UNDERSTANDING_VERSION
    model_version: str = Field(min_length=1, max_length=200)


class SecurityConversationStatusV4(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"


class SecurityConversationSummaryV4(SecurityContractModel):
    security_context: SecurityContextV4 | None = None
    assistant_context: AssistantContextV4 | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    unresolved_slots: list[MissingInformationSlotV4] = Field(
        default_factory=list,
        max_length=5,
        exclude_if=lambda value: not value,
    )
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
    assistant_context: AssistantContextV4 | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    follow_up_question: str | None = None
    follow_up_slot: MissingInformationSlotV4 | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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
    policy_version: Literal["security-risk-v1", "security-risk-v2"] | None = None
    recommended_actions: list[SecurityRecommendedActionV4] = Field(default_factory=list, max_length=20)
    explanation: str | None = None
    explanation_evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    assistant_response: AssistantResponseV4 | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_scope_transition(self) -> Self:
        if self.scope_decision is ScopeDecisionV4.IN_SCOPE:
            if self.next_step not in {"END", "INVESTIGATION", "RISK_ASSESSMENT"} or self.security_context is None:
                raise ValueError("in-scope response requires security context")
            if (
                self.follow_up_question is not None
                or self.follow_up_slot is not None
                or self.boundary_message is not None
            ):
                raise ValueError("in-scope response cannot contain a terminal message")
            if (self.next_step == "END") != self.terminal:
                raise ValueError("in-scope END transition must be terminal")
            if (
                self.next_step == "INVESTIGATION"
                and self.investigation_status is not SecurityInvestigationStatusV4.NOT_STARTED
            ):
                raise ValueError("investigation transition requires not-started investigation state")
            if (
                self.next_step == "RISK_ASSESSMENT"
                and self.investigation_status is SecurityInvestigationStatusV4.NOT_STARTED
            ):
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
            if (
                self.follow_up_question is not None
                or self.follow_up_slot is not None
                or self.security_context is not None
            ):
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
            if (
                any(value is not None for value in risk_fields)
                or self.recommended_actions
                or self.explanation_evidence_refs
            ):
                raise ValueError("risk details require a risk class")
        elif any(value is None for value in risk_fields) or not self.recommended_actions:
            raise ValueError("risk result is incomplete")
        if self.assistant_response is not None:
            if self.risk is None or self.policy_version is None:
                raise ValueError("assistant response requires a deterministic risk result")
            available_refs = {item.evidence_ref for item in self.evidence}
            cited_refs = {ref for reason in self.assistant_response.top_reasons for ref in reason.evidence_refs}
            if not cited_refs <= available_refs:
                raise ValueError("assistant response cites evidence that is not present")
            assistant_actions = {item.action for item in self.assistant_response.immediate_steps}
            if not assistant_actions <= set(self.recommended_actions):
                raise ValueError("assistant response contains a non-policy action")
            if any(item.policy_ref != self.policy_version for item in self.assistant_response.immediate_steps):
                raise ValueError("assistant response contains an invalid action policy ref")
        if self.status is AnalysisStatus.COMPLETED and self.completed_at is None:
            self.completed_at = self.created_at
        return self


class SecurityAnalysisAcceptedResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    analysis_id: UUID
    conversation_id: UUID
    conversation_version: int = Field(ge=1)
    status: Literal[AnalysisStatus.QUEUED] = AnalysisStatus.QUEUED
    created_at: datetime


class SecurityAnalysisEventKindV4(StrEnum):
    STATUS = "status"
    PROVISIONAL = "provisional"
    PROGRESS = "progress"
    FINAL = "final"


class SecurityAnalysisEventV4(SecurityContractModel):
    event_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    sequence: int = Field(ge=1)
    status: AnalysisStatus
    step: str
    kind: SecurityAnalysisEventKindV4 = SecurityAnalysisEventKindV4.STATUS
    step_id: str | None = Field(default=None, max_length=200)
    message: str | None = Field(default=None, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    risk_hint: SecurityRiskV4 | None = None
    occurred_at: datetime


class SecurityAnalysisEventPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    events: list[SecurityAnalysisEventV4]
    next_cursor: str | None = None


class SecurityCapabilitiesResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    product_profile: Literal["security_triage_vnext"] = "security_triage_vnext"
    release_profile: Literal["pre_cutover", "cutover"] = "pre_cutover"
    conversation_resume: Literal[True] = True
    admin_feedback_review: Literal[True] = True
    intelligence_explorer: Literal[True] = True
    unified_v4_audit: Literal[True] = True
    admin_action_contract: Literal["v3"] = "v3"
    executable_admin_actions: list[str] = Field(default_factory=lambda: ["add_to_blacklist"])
    deferred_admin_actions: list[str] = Field(
        default_factory=lambda: ["block_domain", "publish_broad_warning", "ai_security_copilot"]
    )
    compatibility_contracts: list[Literal["v2", "v3", "v4"]] = Field(default_factory=lambda: ["v2", "v3", "v4"])
    security_ai_understanding: Literal[True] | None = None
    security_ai_planning: Literal[True] | None = None
    security_ai_explanation: Literal[True] | None = None
    security_async_execution: Literal[True] | None = None
    security_memory_retrieval: Literal[True] | None = None
    security_admin_copilot: Literal[True] | None = None


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
    decision: ReportReviewDecision | None = None
    reviewer_id: str | None = None
    review_note: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reviewed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_review(self) -> Self:
        review_fields = (self.decision, self.reviewer_id, self.review_note, self.reviewed_at)
        if self.status is ReportStatus.PROCESSED and any(value is None for value in review_fields):
            raise ValueError("processed report requires decision, reviewer, note and timestamp")
        if self.status is not ReportStatus.PROCESSED and any(value is not None for value in review_fields):
            raise ValueError("unprocessed report cannot contain review fields")
        return self


class SecurityReportDecisionRequestV4(SecurityContractModel):
    decision: ReportReviewDecision
    note: str = Field(min_length=1, max_length=5000)


class SecurityReportAdminRecordV4(SecurityReportRecordV4):
    owner_id: str


class SecurityReportPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityReportAdminRecordV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


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
    reviewer_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        resolution_fields = (self.outcome, self.resolution_note, self.reviewer_id, self.resolved_at)
        if self.status is AppealStatus.RESOLVED and any(value is None for value in resolution_fields):
            raise ValueError("resolved appeal requires outcome, note, reviewer and timestamp")
        if self.status is not AppealStatus.RESOLVED and any(value is not None for value in resolution_fields):
            raise ValueError("unresolved appeal cannot contain resolution fields")
        return self


class SecurityAppealDecisionRequestV4(SecurityContractModel):
    outcome: AppealOutcome
    note: str = Field(min_length=1, max_length=5000)


class SecurityAppealAdminRecordV4(SecurityAppealRecordV4):
    owner_id: str


class SecurityAppealPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityAppealAdminRecordV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class SecurityAnalysisPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityScopeResponseV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class SecurityConversationPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityConversationV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


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


class SecurityMemoryPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityMemoryRecordV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


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


class SecurityCampaignPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityCampaignRecordV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class SecurityAdminCopilotDispositionV4(StrEnum):
    CONFIRM_MALICIOUS = "confirm_malicious"
    CONFIRM_SAFE = "confirm_safe"
    MARK_FALSE_POSITIVE = "mark_false_positive"
    NEEDS_MORE_INFORMATION = "needs_more_information"
    NO_CHANGE = "no_change"


class SecurityAdminCopilotActionV4(StrEnum):
    ADD_TO_BLACKLIST = "add_to_blacklist"
    BLOCK_DOMAIN = "block_domain"
    PUBLISH_BROAD_WARNING = "publish_broad_warning"
    NONE = "none"


class SecurityAdminCopilotRequestV4(SecurityContractModel):
    refresh: bool = False


class SecurityAdminCopilotRationaleV4(SecurityContractModel):
    text: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)


class SecurityAdminCopilotCampaignV4(SecurityContractModel):
    campaign_id: UUID
    hypothesis: str = Field(min_length=1, max_length=2000)
    reviewed_at: datetime
    evidence_refs: list[str] = Field(min_length=1, max_length=100)


class SecurityAdminCopilotUsageV4(SecurityContractModel):
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0, ge=0)
    status: Literal["ok", "policy_grounded", "fallback"]


class SecurityAdminCopilotResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    suggestion_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    evidence_summary: str = Field(min_length=1, max_length=2000)
    conflicts: list[str] = Field(default_factory=list, max_length=20)
    missing_information: list[str] = Field(default_factory=list, max_length=20)
    related_reviewed_campaigns: list[SecurityAdminCopilotCampaignV4] = Field(default_factory=list, max_length=20)
    proposed_disposition: SecurityAdminCopilotDispositionV4
    proposed_admin_action: SecurityAdminCopilotActionV4 = SecurityAdminCopilotActionV4.NONE
    action_executable: bool = False
    executed: Literal[False] = False
    grounded_rationale: list[SecurityAdminCopilotRationaleV4] = Field(default_factory=list, max_length=5)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    provider: str | None = None
    model: str | None = None
    suggestion_version: Literal["security-admin-copilot-v1"] = "security-admin-copilot-v1"
    generation_mode: AssistantGenerationModeV4
    usage: SecurityAdminCopilotUsageV4
    generated_at: datetime


class SecurityDomainIntelligenceV4(SecurityContractModel):
    domain: str
    analysis_count: int = Field(ge=1)
    report_count: int = Field(ge=0)
    risk_distribution: dict[SecurityRiskV4, int]
    threat_distribution: dict[PotentialThreatV4, int]
    first_seen_at: datetime
    last_seen_at: datetime
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


class SecurityDomainIntelligencePageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityDomainIntelligenceV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class SecurityThreatIntelligenceV4(SecurityContractModel):
    threat_type: PotentialThreatV4
    analysis_count: int = Field(ge=1)
    report_count: int = Field(ge=0)
    risk_distribution: dict[SecurityRiskV4, int]
    domains: list[str] = Field(default_factory=list, max_length=100)
    first_seen_at: datetime
    last_seen_at: datetime
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


class SecurityThreatIntelligencePageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityThreatIntelligenceV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class SecurityAuditResourceV4(StrEnum):
    BRAND = "brand"
    WHITELIST = "whitelist"
    MEMORY = "memory"
    CAMPAIGN = "campaign"
    REPORT = "report"
    APPEAL = "appeal"
    COPILOT = "copilot"


class SecurityAdminAuditEventV4(SecurityContractModel):
    audit_id: UUID = Field(default_factory=uuid4)
    resource_type: SecurityAuditResourceV4
    resource_id: UUID
    action: str = Field(min_length=1, max_length=100)
    actor_id: str
    note: str | None = Field(default=None, max_length=5000)
    occurred_at: datetime
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


class SecurityAdminAuditPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityAdminAuditEventV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


__all__ = [
    "CONTRACT_VERSION_V4",
    "SECURITY_ASSISTANT_RESPONSE_VERSION",
    "SECURITY_CONTEXT_VERSION",
    "SECURITY_RISK_POLICY_VERSION",
    "SECURITY_RISK_POLICY_VERSION_V2",
    "AssistantGenerationModeV4",
    "AssistantImmediateStepV4",
    "AssistantReasonV4",
    "AssistantResponseV4",
    "PotentialThreatV4",
    "BrandCreateRequestV4",
    "BrandRecordV4",
    "BrandPageV4",
    "InvestigationStepV4",
    "RequestedActionV4",
    "ScopeDecisionV4",
    "SecurityConsentV4",
    "SecurityConversationStatusV4",
    "SecurityConversationSummaryV4",
    "SecurityConversationV4",
    "SecurityContextV4",
    "SecurityAnalysisAcceptedResponseV4",
    "SecurityAnalysisEventKindV4",
    "SecurityAnalysisEventPageV4",
    "SecurityAnalysisEventV4",
    "SecurityEvidenceTypeV4",
    "SecurityEvidenceV4",
    "SecurityExecutionModeV4",
    "SecurityInvestigationStatusV4",
    "SecurityInvestigationStepStatusV4",
    "SecurityInvestigationToolV4",
    "SecurityScenarioV4",
    "SecurityRecommendedActionV4",
    "SecurityRiskV4",
    "SecurityWebSocketTicketRequestV4",
    "SecurityWebSocketTicketResponseV4",
    "SecurityCapabilitiesResponseV4",
    "SecurityChatRequestV4",
    "SecurityChatResponseV4",
    "SecurityChatRouteV4",
    "TrustLifecycleV4",
    "WhitelistCreateRequestV4",
    "WhitelistRecordV4",
    "WhitelistPageV4",
    "WhitelistScopeV4",
    "SecurityScopeResponseV4",
    "SecurityTriageCreateRequestV4",
    "SecurityToolErrorV4",
    "SecurityReportCreateRequestV4",
    "SecurityReportRecordV4",
    "SecurityReportDecisionRequestV4",
    "SecurityReportAdminRecordV4",
    "SecurityReportPageV4",
    "SecurityAppealCreateRequestV4",
    "SecurityAppealRecordV4",
    "SecurityAppealDecisionRequestV4",
    "SecurityAppealAdminRecordV4",
    "SecurityAppealPageV4",
    "SecurityAnalysisPageV4",
    "SecurityConversationPageV4",
    "SecurityMemoryAdminVerdictV4",
    "SecurityMemoryRecordV4",
    "SecurityMemoryCorrectionRequestV4",
    "SecurityMemoryAuditRecordV4",
    "SecurityMemoryPageV4",
    "SecurityCampaignReviewerStatusV4",
    "SecurityCampaignRecordV4",
    "SecurityCampaignDecisionRequestV4",
    "SecurityCampaignAuditRecordV4",
    "SecurityCampaignPageV4",
    "SecurityAdminCopilotDispositionV4",
    "SecurityAdminCopilotActionV4",
    "SecurityAdminCopilotRequestV4",
    "SecurityAdminCopilotRationaleV4",
    "SecurityAdminCopilotCampaignV4",
    "SecurityAdminCopilotUsageV4",
    "SecurityAdminCopilotResponseV4",
    "SecurityDomainIntelligenceV4",
    "SecurityDomainIntelligencePageV4",
    "SecurityThreatIntelligenceV4",
    "SecurityThreatIntelligencePageV4",
    "SecurityAuditResourceV4",
    "SecurityAdminAuditEventV4",
    "SecurityAdminAuditPageV4",
]
