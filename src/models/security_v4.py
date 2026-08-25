from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from src.core.product_boundary import SECURITY_TRIAGE_CONTRACT_VERSION
from src.models.schemas import (
    AnalysisStatus,
    AppealOutcome,
    AppealStatus,
    ReportReviewDecision,
    ReportStatus,
)

CONTRACT_VERSION_V4 = SECURITY_TRIAGE_CONTRACT_VERSION
SECURITY_CONTEXT_VERSION_V1 = "security-context-v1"
SECURITY_CONTEXT_VERSION_V2 = "security-context-v2"
SECURITY_CONTEXT_VERSION = SECURITY_CONTEXT_VERSION_V2
SECURITY_RISK_POLICY_VERSION = "security-risk-v1"
SECURITY_RISK_POLICY_VERSION_V2 = "security-risk-v2"
SECURITY_RISK_POLICY_VERSION_V3 = "security-risk-v3"
SECURITY_RISK_POLICY_VERSION_V4 = "security-risk-v4"
SECURITY_RISK_POLICY_VERSION_V5 = "security-risk-v5"
SECURITY_RISK_POLICY_VERSION_V6 = "security-risk-v6"
SECURITY_RISK_POLICY_VERSION_V7 = "security-risk-v7"
SECURITY_UNDERSTANDING_VERSION_V1 = "security-understanding-v1"
SECURITY_UNDERSTANDING_VERSION_V2 = "security-understanding-v2"
SECURITY_UNDERSTANDING_VERSION = SECURITY_UNDERSTANDING_VERSION_V2
SECURITY_ASSISTANT_RESPONSE_VERSION = "security-assistant-response-v1"
OFFICIAL_LINK_VERIFICATION_VERSION = "official-link-verification-v3"
OFFICIAL_LINK_VERIFICATION_VERSION_V3 = "official-link-verification-v3"
OFFICIAL_LINK_VERIFICATION_VERSION_V4 = "official-link-verification-v4"
OFFICIAL_LINK_VERIFICATION_POLICY_VERSION_V4 = "official-link-verification-v4"
OFFICIAL_LINK_VERIFICATION_VERSION_V1 = "official-link-verification-v1"
RESOURCE_IDENTITY_VERSION = "resource-identity-v1"
VERIFICATION_INTENT_VERSION = "verification-intent-v1"


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
    SUBMIT_FORM = "submit_form"
    REGISTER_OR_APPLY = "register_or_apply"
    DOWNLOAD_FILE = "download_file"
    APPLY_FOR_PASSPORT = "apply_for_passport"


class EntityUrlRelationshipV4(StrEnum):
    CLAIMED_OFFICIAL_SITE = "claimed_official_site"
    CLAIMED_ENDORSED_SERVICE = "claimed_endorsed_service"
    REFERENCE_ONLY = "reference_only"


class EntityUrlClaimV4(SecurityContractModel):
    entity_name: str = Field(min_length=1, max_length=200)
    url_index: int = Field(ge=0, lt=10)
    relationship: EntityUrlRelationshipV4
    confidence: float = Field(ge=0.8, le=1)


class VerificationTopicV4(StrEnum):
    RECRUITMENT = "recruitment"
    PROMOTION = "promotion"
    EVENT = "event"
    COURSE = "course"
    SURVEY = "survey"
    ACCOUNT = "account"
    PAYMENT = "payment"
    CHARITY = "charity"
    INVESTMENT = "investment"
    GENERAL_NOTICE = "general_notice"
    UNKNOWN = "unknown"


class LinkRoleV4(StrEnum):
    OFFICIAL_WEBSITE = "official_website"
    OFFICIAL_ANNOUNCEMENT = "official_announcement"
    SOCIAL_PROFILE = "social_profile"
    APPLICATION = "application"
    REGISTRATION = "registration"
    FORM = "form"
    DOWNLOAD = "download"
    LOGIN = "login"
    PAYMENT = "payment"
    CONTACT = "contact"
    OTHER = "other"


class VerificationStatusV4(StrEnum):
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    CONFLICTING = "CONFLICTING"


class OfficialIdentityTypeV4(StrEnum):
    PRIMARY_WEBSITE = "primary_website"
    WEBSITE = "website"
    DOMAIN = "domain"
    CAREERS_PAGE = "careers_page"
    SOCIAL_PROFILE = "social_profile"
    SUB_ORGANIZATION = "sub_organization"


class OfficialIdentityMatchScopeV4(StrEnum):
    EXACT = "exact"
    HOST_AND_SUBDOMAINS = "host_and_subdomains"
    BOUNDED_PHRASE = "bounded_phrase"


class IdentityRelationshipV4(StrEnum):
    OFFICIAL_CONTROLLED = "official_controlled"
    PARENT_ORGANIZATION = "parent_organization"
    ENDORSED_THIRD_PARTY_SERVICE = "endorsed_third_party_service"


class IdentityAssociationAssuranceV4(StrEnum):
    DISCOVERED = "discovered"
    VERIFIED = "verified"
    CONFLICTING = "conflicting"
    PROMOTED = "promoted"
    REJECTED = "rejected"
    CONFIRMED_MISMATCH = "confirmed_mismatch"


class IdentityEvidenceFamilyV4(StrEnum):
    ENTITY_SELF_IDENTIFICATION = "entity_self_identification"
    INDEPENDENT_ENTITY_LINK = "independent_entity_link"
    PARENT_DECLARATION = "parent_declaration"
    CANDIDATE_CORROBORATION = "candidate_corroboration"
    EXACT_RESOURCE_ENDORSEMENT = "exact_resource_endorsement"
    TARGET_RESOURCE_MATCH = "target_resource_match"
    EXPLICIT_OWNERSHIP_CONFLICT = "explicit_ownership_conflict"
    ACTION_ENDORSEMENT = "action_endorsement"


class ResourceTypeV4(StrEnum):
    URL = "url"
    GOOGLE_FORM = "google_form"
    MICROSOFT_FORM = "microsoft_form"
    FILE = "file"
    OTHER = "other"


class ResourceMatchStatusV4(StrEnum):
    EXACT_RESOURCE = "EXACT_RESOURCE"
    EXACT_CANONICAL_URL = "EXACT_CANONICAL_URL"
    DIFFERENT_RESOURCE = "DIFFERENT_RESOURCE"
    UNRESOLVED = "UNRESOLVED"


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
    ALLOW_OPEN = "ALLOW_OPEN"
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
    DOMAIN_FAMILIARITY = "domain_familiarity"
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
    DOMAIN_FAMILIARITY = "domain_familiarity"
    OFFICIAL_VERIFICATION = "official_verification"


class DomainFamiliarityClassificationV4(StrEnum):
    REVIEWED_FIRST_PARTY = "reviewed_first_party"
    REVIEWED_PLATFORM_SERVICE = "reviewed_platform_service"
    RANKED_DOMAIN = "ranked_domain"


class DomainFamiliarityDetailsV4(SecurityContractModel):
    observed_host: str = Field(min_length=1, max_length=253)
    registrable_domain: str = Field(min_length=1, max_length=253)
    classification: DomainFamiliarityClassificationV4
    platform_name: str | None = Field(default=None, max_length=200)
    shared_platform: bool = False
    popularity_rank: int | None = Field(default=None, ge=1)
    popularity_bucket: int | None = Field(default=None, ge=1)
    dataset_window_end: datetime | None = None

    @model_validator(mode="after")
    def validate_classification_fields(self) -> Self:
        if self.classification is DomainFamiliarityClassificationV4.REVIEWED_PLATFORM_SERVICE:
            if not self.shared_platform or self.platform_name is None:
                raise ValueError("reviewed platform familiarity requires platform_name and shared_platform")
        elif self.shared_platform:
            raise ValueError("shared_platform is only valid for reviewed platform services")
        if self.classification is DomainFamiliarityClassificationV4.RANKED_DOMAIN:
            if self.popularity_rank is None and self.popularity_bucket is None:
                raise ValueError("ranked familiarity requires rank or bucket")
        elif self.popularity_rank is not None or self.popularity_bucket is not None:
            raise ValueError("popularity values are only valid for ranked familiarity")
        return self


class TrustLifecycleV4(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class SecurityBlacklistLifecycleV4(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class SecurityBlacklistActionV4(StrEnum):
    ADD = "add_to_blacklist"
    DISABLE = "disable_blacklist"


class SecurityBlacklistActionStatusV4(StrEnum):
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class SecurityBlacklistReviewDecisionV4(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class WhitelistScopeV4(StrEnum):
    DOMAIN = "domain"
    URL = "url"
    CONTACT = "contact"


class SecurityReportResolutionV4(StrEnum):
    CONFIRM_SAFE = "confirm_safe"
    MARK_FALSE_POSITIVE = "mark_false_positive"
    CONFIRM_MALICIOUS = "confirm_malicious"
    NEEDS_MORE_INFORMATION = "needs_more_information"
    NO_CHANGE = "no_change"


class SecurityReportRemediationActionV4(StrEnum):
    NONE = "none"
    UPDATE_MEMORY = "update_memory"
    ADD_TO_WHITELIST = "add_to_whitelist"
    PROPOSE_BLACKLIST = "propose_blacklist"


class SecurityReportRemediationStatusV4(StrEnum):
    NOT_REQUESTED = "not_requested"
    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"


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
    domain_familiarity: DomainFamiliarityDetailsV4 | None = None

    @model_validator(mode="after")
    def validate_domain_familiarity_details(self) -> Self:
        is_familiarity = self.type is SecurityEvidenceTypeV4.DOMAIN_FAMILIARITY
        if is_familiarity != (self.domain_familiarity is not None):
            raise ValueError("domain_familiarity details must appear only on domain familiarity evidence")
        return self


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


class DerivedQueryProvenanceV4(SecurityContractModel):
    query_id: str = Field(pattern=r"^query:[a-f0-9]{16}$")
    derived_from_fields: list[str] = Field(min_length=1, max_length=20)
    transformations: list[str] = Field(default_factory=list, max_length=20)


class VerificationIntentV4(SecurityContractModel):
    schema_version: Literal["verification-intent-v1"] = VERIFICATION_INTENT_VERSION
    organization_name: str | None = Field(default=None, max_length=200)
    derived_organization_names: list[str] = Field(default_factory=list, max_length=10)
    claim_summary: str | None = Field(default=None, max_length=1000)
    topic: VerificationTopicV4 | None = None
    requested_action: RequestedActionV4 | None = None
    action_url_indices: list[Annotated[int, Field(ge=0, lt=10)]] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def require_verifiable_dimension(self) -> Self:
        if not (self.organization_name or self.claim_summary or self.requested_action):
            raise ValueError("verification intent requires an organization, claim, or requested action")
        return self


class OfficialIdentityV4(SecurityContractModel):
    identity_id: UUID = Field(default_factory=uuid4)
    identity_type: OfficialIdentityTypeV4
    canonical_value: str = Field(min_length=1, max_length=2048)
    display_value: str = Field(min_length=1, max_length=2048)
    entity_name: str = Field(min_length=1, max_length=200)
    match_scope: OfficialIdentityMatchScopeV4 = OfficialIdentityMatchScopeV4.EXACT
    relationship: str = Field(default="primary", pattern=r"^[a-z0-9_]+$")
    provenance: str = Field(default="unversioned_contract", min_length=1, max_length=1000)
    policy_version: str = Field(default="official-identity-v1", pattern=r"^[a-z0-9._-]+$")
    effective_from: datetime | None = None
    effective_until: datetime | None = None
    supersedes: UUID | None = None
    lifecycle: TrustLifecycleV4 = TrustLifecycleV4.ACTIVE
    reviewed: bool = False
    source_ref: str | None = Field(default=None, pattern=r"^source:[a-f0-9]{16}$")

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.relationship == "platform_service" and self.identity_type is not OfficialIdentityTypeV4.DOMAIN:
            raise ValueError("platform_service identities must use identity_type=domain")
        if self.effective_until is not None:
            if self.effective_from is None or self.effective_until <= self.effective_from:
                raise ValueError("identity effective_until must be after effective_from")
        return self


class ResourceIdentityV4(SecurityContractModel):
    schema_version: Literal["resource-identity-v1"] = RESOURCE_IDENTITY_VERSION
    resource_type: ResourceTypeV4
    provider: str | None = Field(default=None, max_length=100)
    resource_id: str | None = Field(default=None, max_length=500)
    canonical_url: str | None = Field(default=None, max_length=2048)
    match_key: str = Field(min_length=1, max_length=2048)


class ResourceMatchV4(SecurityContractModel):
    status: ResourceMatchStatusV4
    user_resource: ResourceIdentityV4 | None = None
    official_resource: ResourceIdentityV4 | None = None
    reason_code: str = Field(pattern=r"^[a-z0-9_]+$")


class OfficialSourceReferenceV4(SecurityContractModel):
    source_ref: str = Field(pattern=r"^source:[a-f0-9]{16}$")
    identity: OfficialIdentityV4 | None = None
    display_url: str = Field(min_length=1, max_length=2048)
    canonical_url: str = Field(min_length=1, max_length=2048)
    content_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class OfficialLinkReferenceV4(SecurityContractModel):
    link_ref: str = Field(pattern=r"^link:[a-f0-9]{16}$")
    source_ref: str = Field(pattern=r"^source:[a-f0-9]{16}$")
    role: LinkRoleV4
    display_url: str = Field(min_length=1, max_length=2048)
    canonical_url: str = Field(min_length=1, max_length=2048)
    resource: ResourceIdentityV4 | None = None


class IdentityEvidenceObservationV4(SecurityContractModel):
    evidence_ref: str = Field(pattern=r"^identity-evidence:[a-f0-9]{16}$")
    family: IdentityEvidenceFamilyV4
    source_host: str = Field(min_length=1, max_length=253)
    canonical_url: str = Field(min_length=1, max_length=2048)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime


class IdentityAssociationV4(SecurityContractModel):
    association_id: UUID = Field(default_factory=uuid4)
    entity_name: str = Field(min_length=1, max_length=200)
    canonical_url: str = Field(min_length=1, max_length=2048)
    canonical_domain: str = Field(min_length=1, max_length=253)
    relationship: IdentityRelationshipV4
    assurance: IdentityAssociationAssuranceV4
    confidence: Annotated[float, Field(ge=0, le=1)]
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    discovered_at: datetime
    verified_at: datetime | None = None
    expires_at: datetime | None = None
    policy_version: Literal["identity-discovery-v2"] = "identity-discovery-v2"

    @model_validator(mode="after")
    def validate_ttl(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.discovered_at:
            raise ValueError("association expiry must be after discovery")
        if self.assurance is IdentityAssociationAssuranceV4.VERIFIED and self.verified_at is None:
            raise ValueError("verified associations require verified_at")
        return self


class OfficialVerificationComponentV4(SecurityContractModel):
    applicable: bool
    status: VerificationStatusV4 | None = None
    reason_code: str = Field(pattern=r"^[a-z0-9_]+$")
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_applicability(self) -> Self:
        if self.applicable != (self.status is not None):
            raise ValueError("applicable verification components require a status; non-applicable ones must omit it")
        return self


class PublisherVerificationV4(OfficialVerificationComponentV4):
    identity: OfficialIdentityV4 | None = None


class ClaimVerificationV4(OfficialVerificationComponentV4):
    topic: VerificationTopicV4 | None = None


class ResourceVerificationV4(OfficialVerificationComponentV4):
    match: ResourceMatchV4 | None = None


class OfficialLinkVerificationReportV4(SecurityContractModel):
    schema_version: Literal[
        "official-link-verification-v1",
        "official-link-verification-v2",
        "official-link-verification-v3",
        "official-link-verification-v4",
    ] = OFFICIAL_LINK_VERIFICATION_VERSION_V1
    intent: VerificationIntentV4
    publisher_verification: PublisherVerificationV4
    claim_verification: ClaimVerificationV4
    resource_verification: ResourceVerificationV4
    domain_ownership_verification: OfficialVerificationComponentV4 = Field(
        default_factory=lambda: OfficialVerificationComponentV4(
            applicable=False, status=None, reason_code="not_applicable"
        )
    )
    sender_verification: OfficialVerificationComponentV4 = Field(
        default_factory=lambda: OfficialVerificationComponentV4(
            applicable=False, status=None, reason_code="not_applicable"
        )
    )
    action_endorsement_verification: OfficialVerificationComponentV4 = Field(
        default_factory=lambda: OfficialVerificationComponentV4(
            applicable=False, status=None, reason_code="not_applicable"
        )
    )
    overall_status: VerificationStatusV4
    reason_code: str = Field(pattern=r"^[a-z0-9_]+$")
    source_refs: list[OfficialSourceReferenceV4] = Field(default_factory=list, max_length=20)
    link_refs: list[OfficialLinkReferenceV4] = Field(default_factory=list, max_length=50)
    limitations: list[str] = Field(default_factory=list, max_length=50)
    identity_associations: list[IdentityAssociationV4] = Field(default_factory=list, max_length=20)
    identity_evidence: list[IdentityEvidenceObservationV4] = Field(default_factory=list, max_length=50)
    policy_version: Literal[
        "official-link-verification-v1",
        "official-link-verification-v2",
        "official-link-verification-v3",
        "official-link-verification-v4",
    ] = OFFICIAL_LINK_VERIFICATION_VERSION_V1


class IdentityCandidateV4(IdentityAssociationV4):
    version: int = Field(default=1, ge=1)
    observations: list[IdentityEvidenceObservationV4] = Field(default_factory=list, max_length=50)
    supersedes: UUID | None = None
    terminal_decision_id: UUID | None = None


class IdentityCandidateDecisionActionV4(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    CONFIRM_MISMATCH = "confirm_mismatch"


class IdentityCandidateDecisionRequestV4(SecurityContractModel):
    action: IdentityCandidateDecisionActionV4
    note: str = Field(min_length=1, max_length=5000)
    target_brand_id: UUID | None = None
    relationship: IdentityRelationshipV4 | None = None
    identity_type: OfficialIdentityTypeV4 | None = None


class IdentityCandidateDecisionV4(SecurityContractModel):
    decision_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    action: IdentityCandidateDecisionActionV4
    reviewer_id: str
    note: str = Field(min_length=1, max_length=5000)
    target_brand_id: UUID | None = None
    relationship: IdentityRelationshipV4 | None = None
    identity_type: OfficialIdentityTypeV4 | None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    decided_at: datetime


class IdentityCandidatePageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[IdentityCandidateV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class SecurityExecutionModeV4(StrEnum):
    INLINE = "inline"
    ASYNC = "async"


class SecurityChatRouteV4(StrEnum):
    CONVERSATION = "conversation"
    SECURITY_ANALYSIS = "security_analysis"


class BrandCreateRequestV4(SecurityContractModel):
    name: str = Field(min_length=1, max_length=200)
    aliases: list[str] = Field(default_factory=list, max_length=50)
    official_domains: list[str] = Field(default_factory=list, max_length=50)
    official_identities: list[OfficialIdentityV4] = Field(default_factory=list, max_length=100)
    official_contacts: list[str] = Field(default_factory=list, max_length=50)
    provenance: str = Field(min_length=1, max_length=1000)
    policy_version: str = Field(default="brand-registry-v1", pattern=r"^[a-z0-9._-]+$")
    effective_from: datetime
    effective_until: datetime | None = None

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("effective_until must be after effective_from")
        if not self.official_domains and not any(
            item.lifecycle is TrustLifecycleV4.ACTIVE
            and (item.effective_until is None or item.effective_until > self.effective_from)
            and (self.effective_until is None or (item.effective_from or self.effective_from) < self.effective_until)
            for item in self.official_identities
        ):
            raise ValueError("a brand requires an official domain or an active official identity")
        return self


class BrandRecordV4(BrandCreateRequestV4):
    brand_id: UUID = Field(default_factory=uuid4)
    supersedes: UUID | None = None
    lifecycle: TrustLifecycleV4 = TrustLifecycleV4.ACTIVE
    reviewer_id: str
    created_at: datetime

    @model_validator(mode="after")
    def require_reviewed_identities(self) -> Self:
        if any(not item.reviewed for item in self.official_identities):
            raise ValueError("persisted official identities must be reviewer-approved")
        return self


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


class SecurityBlacklistProposalRequestV4(SecurityContractModel):
    canonical_domain: str = Field(min_length=1, max_length=253)
    reason: str = Field(min_length=1, max_length=5000)
    evidence_refs: list[str] = Field(min_length=1, max_length=100)
    provenance: str = Field(min_length=1, max_length=1000)
    source_analysis_id: UUID | None = None
    source_report_id: UUID | None = None

    @field_validator("canonical_domain")
    @classmethod
    def normalize_proposal_domain(cls, value: str) -> str:
        return SecurityReportBlacklistProposalV4.require_canonical_domain(value)

    @model_validator(mode="after")
    def require_analysis_for_report(self) -> Self:
        if self.source_report_id is not None and self.source_analysis_id is None:
            raise ValueError("source_report_id requires source_analysis_id")
        return self


class SecurityBlacklistDisableRequestV4(SecurityContractModel):
    reason: str = Field(min_length=1, max_length=5000)
    evidence_refs: list[str] = Field(min_length=1, max_length=100)
    provenance: str = Field(min_length=1, max_length=1000)


class SecurityBlacklistRecordV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    blacklist_id: UUID
    canonical_domain: str = Field(min_length=1, max_length=253)
    lifecycle: SecurityBlacklistLifecycleV4
    enabling_action_id: UUID | None = None
    disabling_action_id: UUID | None = None
    reason: str = Field(min_length=1, max_length=5000)
    provenance: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    created_at: datetime
    updated_at: datetime
    version: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("blacklist updated_at cannot precede created_at")
        if self.lifecycle is SecurityBlacklistLifecycleV4.ACTIVE and self.disabling_action_id is not None:
            raise ValueError("active blacklist record cannot contain disabling_action_id")
        return self


class SecurityBlacklistPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityBlacklistRecordV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class SecurityBlacklistActionProposalV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    action_id: UUID
    action: SecurityBlacklistActionV4
    canonical_domain: str
    status: SecurityBlacklistActionStatusV4
    source_analysis_id: UUID | None = None
    source_report_id: UUID | None = None
    proposed_at: datetime


class SecurityBlacklistDecisionRequestV4(SecurityContractModel):
    decision: SecurityBlacklistReviewDecisionV4
    note: str = Field(min_length=1, max_length=5000)


class SecurityBlacklistDecisionResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    action_id: UUID
    action: SecurityBlacklistActionV4
    status: SecurityBlacklistActionStatusV4
    record: SecurityBlacklistRecordV4 | None = None
    reviewed_at: datetime
    executed_at: datetime | None = None
    execution_error: str | None = None


class SecurityBlacklistAuditRecordV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    decision_id: UUID
    action_id: UUID
    decision: SecurityBlacklistReviewDecisionV4
    action: SecurityBlacklistActionV4
    status: SecurityBlacklistActionStatusV4
    note: str
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    decided_at: datetime
    execution_error: str | None = None


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
    conversation_id: UUID | None = None
    conversation_version: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_conversation_reference(self) -> Self:
        if (self.conversation_id is None) != (self.conversation_version is None):
            raise ValueError("conversation_id and conversation_version must be provided together")
        return self


class SecurityChatResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    route: SecurityChatRouteV4
    response: str


class SecurityContextV4(SecurityContractModel):
    schema_version: Literal["security-context-v1", "security-context-v2"] = SECURITY_CONTEXT_VERSION
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
    entity_url_claims: list[EntityUrlClaimV4] = Field(default_factory=list, max_length=10)
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
    derived_query_provenance: list[DerivedQueryProvenanceV4] = Field(default_factory=list, max_length=6)
    understanding_version: Literal["security-understanding-v1", "security-understanding-v2"] = (
        SECURITY_UNDERSTANDING_VERSION
    )
    model_version: str = Field(min_length=1, max_length=200)
    # These are backend-derived assurance facts.  They deliberately contain no
    # message text, provider output, URLs, or secrets.
    action_candidate_present: bool = False
    action_intent_available: bool = True
    grounded_actions: list[dict[str, Any]] = Field(default_factory=list, max_length=20)


class SecurityPolicyMetadataV4(SecurityContractModel):
    release_version: Literal["security-risk-v7"] = SECURITY_RISK_POLICY_VERSION_V7
    activated_features: list[str] = Field(default_factory=list, max_length=10)
    decision_assurance: Literal[
        "passive_target_verified",
        "action_resource_verified",
        "action_intent_unavailable",
        "verification_incomplete",
        "adverse_evidence",
    ]


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
    official_verification: OfficialLinkVerificationReportV4 | None = Field(
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
    policy_version: (
        Literal[
            "security-risk-v1",
            "security-risk-v2",
            "security-risk-v3",
            "security-risk-v4",
            "security-risk-v5",
            "security-risk-v6",
            "security-risk-v7",
        ]
        | None
    ) = None
    policy_metadata: SecurityPolicyMetadataV4 | None = Field(default=None, exclude_if=lambda value: value is None)
    recommended_actions: list[SecurityRecommendedActionV4] = Field(default_factory=list, max_length=20)
    explanation: str | None = None
    explanation_evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    assistant_response: AssistantResponseV4 | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    @classmethod
    def model_validate_stored(cls, value: Any) -> Self:
        """Validate persisted v4 data with narrowly scoped legacy read compatibility."""
        return cls.model_validate(value, context={"stored_security_scope": True})

    @classmethod
    def model_validate_stored_json(cls, value: str | bytes | bytearray) -> Self:
        """Validate persisted JSON without weakening the public v4 contract."""
        return cls.model_validate_json(value, context={"stored_security_scope": True})

    @model_validator(mode="before")
    @classmethod
    def remove_retired_stored_investigation_steps(cls, value: Any, info: ValidationInfo) -> Any:
        if not info.context or not info.context.get("stored_security_scope") or not isinstance(value, dict):
            return value
        # Historical reports never had explicit coverage for ownership,
        # sender, or action endorsement. Preserve their original report
        # version/payload while making the missing assurance visible; never
        # silently reinterpret it as NOT_APPLICABLE on read.
        report = value.get("official_verification")
        if isinstance(report, dict) and report.get("schema_version") in {
            "official-link-verification-v1",
            "official-link-verification-v2",
        }:
            intent = report.get("intent") if isinstance(report.get("intent"), dict) else {}
            has_action = bool(intent.get("requested_action"))
            has_url = bool(intent.get("action_url_indices"))
            report = {
                **report,
                "domain_ownership_verification": {
                    "applicable": has_url,
                    "status": "UNVERIFIED" if has_url else None,
                    "reason_code": "legacy_coverage_unavailable",
                    "evidence_refs": [],
                },
                "sender_verification": {
                    "applicable": has_action,
                    "status": "UNVERIFIED" if has_action else None,
                    "reason_code": "legacy_coverage_unavailable",
                    "evidence_refs": [],
                },
                "action_endorsement_verification": {
                    "applicable": has_action,
                    "status": "UNVERIFIED" if has_action else None,
                    "reason_code": "legacy_coverage_unavailable",
                    "evidence_refs": [],
                },
            }
            value = {**value, "official_verification": report}
        raw_plan = value.get("investigation_plan")
        if not isinstance(raw_plan, list):
            return value

        retired_step_ids = {
            step.get("step_id")
            for step in raw_plan
            if isinstance(step, dict) and step.get("tool") == "official_claim_verifier"
        }
        if not retired_step_ids:
            return value

        normalized_plan: list[Any] = []
        for step in raw_plan:
            if isinstance(step, dict) and step.get("tool") == "official_claim_verifier":
                continue
            if isinstance(step, dict) and isinstance(step.get("depends_on"), list):
                step = {
                    **step,
                    "depends_on": [
                        dependency for dependency in step["depends_on"] if dependency not in retired_step_ids
                    ],
                }
            normalized_plan.append(step)
        return {**value, "investigation_plan": normalized_plan}

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
    admin_action_contract: Literal["v4"] = "v4"
    executable_admin_actions: list[str] = Field(default_factory=lambda: ["add_to_blacklist"])
    deferred_admin_actions: list[str] = Field(
        default_factory=lambda: ["block_domain", "publish_broad_warning", "ai_security_copilot"]
    )
    security_ai_understanding: Literal[True] | None = None
    security_ai_planning: Literal[True] | None = None
    security_ai_explanation: Literal[True] | None = None
    security_async_execution: Literal[True] | None = None
    security_memory_retrieval: Literal[True] | None = None
    security_admin_copilot: Literal[True] | None = None
    official_link_verification: Literal[True] | None = None
    official_web_search_ready: Literal[True] | None = None
    security_page_capture: Literal[True] | None = None
    domain_familiarity: Literal[True] | None = None
    domain_popularity_lookup_ready: Literal[True] | None = None


class SecurityPageCaptureRequestV4(SecurityContractModel):
    url_index: int = Field(ge=0, le=9)
    external_url_lookup: Literal[True]


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


class SecurityReportBlacklistProposalV4(SecurityContractModel):
    canonical_domain: str = Field(min_length=1, max_length=253)
    reason: str = Field(min_length=1, max_length=5000)
    evidence_refs: list[str] = Field(min_length=1, max_length=100)
    provenance: str = Field(min_length=1, max_length=1000)

    @field_validator("canonical_domain")
    @classmethod
    def require_canonical_domain(cls, value: str) -> str:
        candidate = value.casefold().rstrip(".")
        if value != candidate or "://" in value or "/" in value or "@" in value:
            raise ValueError("canonical_domain must be a lowercase hostname without URL syntax")
        try:
            ascii_domain = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("canonical_domain must be valid IDNA") from exc
        if ascii_domain != value:
            raise ValueError("canonical_domain must use its canonical ASCII IDNA form")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError("canonical_domain must be a domain hostname, not an IP address")
        labels = value.split(".")
        if len(labels) < 2 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        ):
            raise ValueError("canonical_domain must be a valid domain hostname")
        return value


class SecurityReportRemediationReferenceV4(SecurityContractModel):
    whitelist_id: UUID | None = None
    memory_id: UUID | None = None
    admin_action_id: UUID | None = None

    @model_validator(mode="after")
    def require_single_reference(self) -> Self:
        references = (self.whitelist_id, self.memory_id, self.admin_action_id)
        if sum(value is not None for value in references) != 1:
            raise ValueError("remediation reference requires exactly one target id")
        return self


class SecurityReportRemediationUpdateV4(SecurityContractModel):
    status: Literal[
        SecurityReportRemediationStatusV4.EXECUTED,
        SecurityReportRemediationStatusV4.FAILED,
    ]
    reference: SecurityReportRemediationReferenceV4 | None = None
    note: str = Field(min_length=1, max_length=5000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def require_executed_reference(self) -> Self:
        if self.status is SecurityReportRemediationStatusV4.EXECUTED and self.reference is None:
            raise ValueError("executed remediation requires a target reference")
        return self


class SecurityReportRecordV4(SecurityReportCreateRequestV4):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    report_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    status: ReportStatus = ReportStatus.SUBMITTED
    decision: ReportReviewDecision | None = None
    resolution: SecurityReportResolutionV4 | None = None
    remediation_action: SecurityReportRemediationActionV4 = SecurityReportRemediationActionV4.NONE
    whitelist_entry: WhitelistCreateRequestV4 | None = None
    blacklist_proposal: SecurityReportBlacklistProposalV4 | None = None
    remediation_status: SecurityReportRemediationStatusV4 = SecurityReportRemediationStatusV4.NOT_REQUESTED
    remediation_reference: SecurityReportRemediationReferenceV4 | None = None
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
        if self.status is not ReportStatus.PROCESSED:
            if self.resolution is not None or self.remediation_action is not SecurityReportRemediationActionV4.NONE:
                raise ValueError("unprocessed report cannot contain a resolution or remediation action")
            if self.whitelist_entry is not None or self.blacklist_proposal is not None:
                raise ValueError("unprocessed report cannot contain remediation input")
            if self.remediation_status is not SecurityReportRemediationStatusV4.NOT_REQUESTED:
                raise ValueError("unprocessed report cannot contain remediation progress")
            if self.remediation_reference is not None:
                raise ValueError("unprocessed report cannot contain a remediation reference")
            return self
        legacy_approved_record = (
            self.decision is ReportReviewDecision.APPROVED
            and self.resolution is None
            and self.remediation_action is SecurityReportRemediationActionV4.NONE
            and self.whitelist_entry is None
            and self.blacklist_proposal is None
            and self.remediation_status is SecurityReportRemediationStatusV4.NOT_REQUESTED
            and self.remediation_reference is None
        )
        if not legacy_approved_record:
            SecurityReportDecisionRequestV4(
                decision=self.decision,
                resolution=self.resolution,
                remediation_action=self.remediation_action,
                whitelist_entry=self.whitelist_entry,
                blacklist_proposal=self.blacklist_proposal,
                note=self.review_note,
            )
        if self.remediation_action is SecurityReportRemediationActionV4.NONE:
            if self.remediation_status is not SecurityReportRemediationStatusV4.NOT_REQUESTED:
                raise ValueError("report without remediation must remain not_requested")
            if self.remediation_reference is not None:
                raise ValueError("report without remediation cannot contain a reference")
        elif self.remediation_status is SecurityReportRemediationStatusV4.NOT_REQUESTED:
            raise ValueError("requested remediation requires a progress status")
        if self.remediation_status is SecurityReportRemediationStatusV4.EXECUTED and self.remediation_reference is None:
            raise ValueError("executed remediation requires a target reference")
        if self.remediation_reference is not None:
            reference_by_action = {
                SecurityReportRemediationActionV4.UPDATE_MEMORY: self.remediation_reference.memory_id,
                SecurityReportRemediationActionV4.ADD_TO_WHITELIST: self.remediation_reference.whitelist_id,
                SecurityReportRemediationActionV4.PROPOSE_BLACKLIST: self.remediation_reference.admin_action_id,
            }
            if reference_by_action.get(self.remediation_action) is None:
                raise ValueError("remediation reference must match the requested action")
        return self


class SecurityReportDecisionRequestV4(SecurityContractModel):
    decision: ReportReviewDecision
    resolution: SecurityReportResolutionV4 | None = None
    remediation_action: SecurityReportRemediationActionV4 = SecurityReportRemediationActionV4.NONE
    whitelist_entry: WhitelistCreateRequestV4 | None = None
    blacklist_proposal: SecurityReportBlacklistProposalV4 | None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    note: str = Field(min_length=1, max_length=5000)

    def audit_evidence_refs(self) -> list[str]:
        proposal_refs = self.blacklist_proposal.evidence_refs if self.blacklist_proposal is not None else []
        return list(dict.fromkeys([*self.evidence_refs, *proposal_refs]))

    @model_validator(mode="after")
    def validate_resolution_and_remediation(self) -> Self:
        if self.decision is not ReportReviewDecision.APPROVED:
            if self.resolution is not None:
                raise ValueError("rejected or dismissed report cannot contain a resolution")
            if self.remediation_action is not SecurityReportRemediationActionV4.NONE:
                raise ValueError("rejected or dismissed report cannot request remediation")
        elif self.resolution is None:
            raise ValueError("approved report requires a resolution")

        if self.remediation_action is SecurityReportRemediationActionV4.ADD_TO_WHITELIST:
            if self.resolution not in {
                SecurityReportResolutionV4.CONFIRM_SAFE,
                SecurityReportResolutionV4.MARK_FALSE_POSITIVE,
            }:
                raise ValueError("whitelist remediation requires a safe or false-positive resolution")
            if self.whitelist_entry is None:
                raise ValueError("whitelist remediation requires indicator, scope, provenance and effective time")
        elif self.whitelist_entry is not None:
            raise ValueError("whitelist_entry is only valid for add_to_whitelist remediation")

        if self.remediation_action is SecurityReportRemediationActionV4.PROPOSE_BLACKLIST:
            if self.resolution is not SecurityReportResolutionV4.CONFIRM_MALICIOUS:
                raise ValueError("blacklist remediation requires a malicious resolution")
            if self.blacklist_proposal is None:
                raise ValueError("blacklist remediation requires domain, reason, evidence and provenance")
        elif self.blacklist_proposal is not None:
            raise ValueError("blacklist_proposal is only valid for propose_blacklist remediation")

        if self.remediation_action is SecurityReportRemediationActionV4.UPDATE_MEMORY and self.resolution in {
            SecurityReportResolutionV4.NEEDS_MORE_INFORMATION,
            SecurityReportResolutionV4.NO_CHANGE,
        }:
            raise ValueError("non-conclusive resolution cannot update Security Memory")
        if (
            self.resolution
            in {
                SecurityReportResolutionV4.NEEDS_MORE_INFORMATION,
                SecurityReportResolutionV4.NO_CHANGE,
            }
            and self.remediation_action is not SecurityReportRemediationActionV4.NONE
        ):
            raise ValueError("non-conclusive resolution cannot request remediation")
        if len(self.audit_evidence_refs()) > 100:
            raise ValueError("combined report decision evidence_refs cannot exceed 100 items")
        return self


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
    IDENTITY_CANDIDATE = "identity_candidate"
    BLACKLIST = "blacklist"


class SecurityReportAuditDetailsV4(SecurityContractModel):
    decision: ReportReviewDecision
    resolution: SecurityReportResolutionV4 | None = None
    remediation_action: SecurityReportRemediationActionV4
    remediation_status: SecurityReportRemediationStatusV4
    remediation_reference: SecurityReportRemediationReferenceV4 | None = None
    whitelist_entry: WhitelistCreateRequestV4 | None = None
    blacklist_proposal: SecurityReportBlacklistProposalV4 | None = None

    @classmethod
    def from_record(cls, record: SecurityReportRecordV4) -> Self:
        if record.decision is None:
            raise ValueError("report audit details require a reviewed decision")
        return cls(
            decision=record.decision,
            resolution=record.resolution,
            remediation_action=record.remediation_action,
            remediation_status=record.remediation_status,
            remediation_reference=record.remediation_reference,
            whitelist_entry=record.whitelist_entry,
            blacklist_proposal=record.blacklist_proposal,
        )


class SecurityAdminAuditEventV4(SecurityContractModel):
    audit_id: UUID = Field(default_factory=uuid4)
    resource_type: SecurityAuditResourceV4
    resource_id: UUID
    action: str = Field(min_length=1, max_length=100)
    actor_id: str
    note: str | None = Field(default=None, max_length=5000)
    occurred_at: datetime
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    report_details: SecurityReportAuditDetailsV4 | None = None


class SecurityAdminAuditPageV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    items: list[SecurityAdminAuditEventV4]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


__all__ = [
    "DomainFamiliarityClassificationV4",
    "DomainFamiliarityDetailsV4",
    "CONTRACT_VERSION_V4",
    "OFFICIAL_LINK_VERIFICATION_VERSION",
    "OFFICIAL_LINK_VERIFICATION_VERSION_V1",
    "OFFICIAL_LINK_VERIFICATION_VERSION_V3",
    "OFFICIAL_LINK_VERIFICATION_POLICY_VERSION_V4",
    "RESOURCE_IDENTITY_VERSION",
    "VERIFICATION_INTENT_VERSION",
    "SECURITY_ASSISTANT_RESPONSE_VERSION",
    "SECURITY_CONTEXT_VERSION",
    "SECURITY_CONTEXT_VERSION_V1",
    "SECURITY_CONTEXT_VERSION_V2",
    "SECURITY_RISK_POLICY_VERSION",
    "SECURITY_RISK_POLICY_VERSION_V2",
    "SECURITY_RISK_POLICY_VERSION_V3",
    "SECURITY_RISK_POLICY_VERSION_V4",
    "SECURITY_RISK_POLICY_VERSION_V5",
    "SECURITY_RISK_POLICY_VERSION_V6",
    "SECURITY_UNDERSTANDING_VERSION",
    "SECURITY_UNDERSTANDING_VERSION_V1",
    "SECURITY_UNDERSTANDING_VERSION_V2",
    "AssistantGenerationModeV4",
    "AssistantImmediateStepV4",
    "AssistantReasonV4",
    "AssistantResponseV4",
    "PotentialThreatV4",
    "BrandCreateRequestV4",
    "BrandRecordV4",
    "BrandPageV4",
    "ClaimVerificationV4",
    "DerivedQueryProvenanceV4",
    "InvestigationStepV4",
    "LinkRoleV4",
    "OfficialIdentityMatchScopeV4",
    "IdentityRelationshipV4",
    "IdentityAssociationAssuranceV4",
    "IdentityEvidenceFamilyV4",
    "IdentityEvidenceObservationV4",
    "IdentityAssociationV4",
    "IdentityCandidateV4",
    "IdentityCandidateDecisionActionV4",
    "IdentityCandidateDecisionRequestV4",
    "IdentityCandidateDecisionV4",
    "IdentityCandidatePageV4",
    "OfficialIdentityTypeV4",
    "OfficialIdentityV4",
    "OfficialLinkReferenceV4",
    "OfficialLinkVerificationReportV4",
    "OfficialSourceReferenceV4",
    "OfficialVerificationComponentV4",
    "PublisherVerificationV4",
    "RequestedActionV4",
    "EntityUrlRelationshipV4",
    "EntityUrlClaimV4",
    "ResourceIdentityV4",
    "ResourceMatchStatusV4",
    "ResourceMatchV4",
    "ResourceTypeV4",
    "ResourceVerificationV4",
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
    "SecurityPageCaptureRequestV4",
    "SecurityWebSocketTicketRequestV4",
    "SecurityWebSocketTicketResponseV4",
    "SecurityCapabilitiesResponseV4",
    "SecurityChatRequestV4",
    "SecurityChatResponseV4",
    "SecurityChatRouteV4",
    "TrustLifecycleV4",
    "SecurityBlacklistLifecycleV4",
    "SecurityBlacklistActionV4",
    "SecurityBlacklistActionStatusV4",
    "SecurityBlacklistReviewDecisionV4",
    "WhitelistCreateRequestV4",
    "WhitelistRecordV4",
    "WhitelistPageV4",
    "WhitelistScopeV4",
    "SecurityBlacklistProposalRequestV4",
    "SecurityBlacklistDisableRequestV4",
    "SecurityBlacklistRecordV4",
    "SecurityBlacklistPageV4",
    "SecurityBlacklistActionProposalV4",
    "SecurityBlacklistDecisionRequestV4",
    "SecurityBlacklistDecisionResponseV4",
    "SecurityBlacklistAuditRecordV4",
    "SecurityScopeResponseV4",
    "SecurityTriageCreateRequestV4",
    "SecurityToolErrorV4",
    "VerificationIntentV4",
    "VerificationStatusV4",
    "VerificationTopicV4",
    "SecurityReportCreateRequestV4",
    "SecurityReportBlacklistProposalV4",
    "SecurityReportRecordV4",
    "SecurityReportDecisionRequestV4",
    "SecurityReportAdminRecordV4",
    "SecurityReportPageV4",
    "SecurityReportResolutionV4",
    "SecurityReportRemediationActionV4",
    "SecurityReportRemediationStatusV4",
    "SecurityReportRemediationReferenceV4",
    "SecurityReportRemediationUpdateV4",
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
    "SecurityReportAuditDetailsV4",
    "SecurityAdminAuditEventV4",
    "SecurityAdminAuditPageV4",
]
