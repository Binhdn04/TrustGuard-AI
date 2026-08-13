from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.core.product_boundary import SECURITY_TRIAGE_CONTRACT_VERSION

CONTRACT_VERSION_V4 = SECURITY_TRIAGE_CONTRACT_VERSION
SECURITY_CONTEXT_VERSION = "security-context-v1"


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


class SecurityInvestigationToolV4(StrEnum):
    SECURITY_CONTEXT_ANALYSIS = "security_context_analysis"
    LOCAL_URL_RULES = "local_url_rules"
    BLACKLIST_LOOKUP = "blacklist_lookup"
    DNS = "dns"
    REDIRECT_RESOLVER = "redirect_resolver"
    RDAP = "rdap"
    URL_REPUTATION = "url_reputation"


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


class SecurityTriageCreateRequestV4(SecurityContractModel):
    message: str = Field(min_length=1, max_length=5000)
    consent: SecurityConsentV4 = Field(default_factory=SecurityConsentV4)


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


class SecurityScopeResponseV4(SecurityContractModel):
    contract_version: Literal["v4"] = CONTRACT_VERSION_V4
    analysis_id: UUID = Field(default_factory=uuid4)
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

    @model_validator(mode="after")
    def validate_scope_transition(self) -> Self:
        if self.scope_decision is ScopeDecisionV4.IN_SCOPE:
            if self.terminal or self.next_step not in {"INVESTIGATION", "RISK_ASSESSMENT"} or self.security_context is None:
                raise ValueError("in-scope response requires non-terminal investigation context")
            if self.follow_up_question is not None or self.boundary_message is not None:
                raise ValueError("in-scope response cannot contain a terminal message")
            if self.next_step == "INVESTIGATION" and self.investigation_status is not SecurityInvestigationStatusV4.NOT_STARTED:
                raise ValueError("investigation transition requires not-started investigation state")
            if self.next_step == "RISK_ASSESSMENT" and self.investigation_status is SecurityInvestigationStatusV4.NOT_STARTED:
                raise ValueError("risk transition requires completed or partial investigation")
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
        return self


__all__ = [
    "CONTRACT_VERSION_V4",
    "SECURITY_CONTEXT_VERSION",
    "PotentialThreatV4",
    "InvestigationStepV4",
    "RequestedActionV4",
    "ScopeDecisionV4",
    "SecurityConsentV4",
    "SecurityContextV4",
    "SecurityEvidenceTypeV4",
    "SecurityEvidenceV4",
    "SecurityInvestigationStatusV4",
    "SecurityInvestigationStepStatusV4",
    "SecurityInvestigationToolV4",
    "SecurityScenarioV4",
    "SecurityScopeResponseV4",
    "SecurityTriageCreateRequestV4",
    "SecurityToolErrorV4",
]
