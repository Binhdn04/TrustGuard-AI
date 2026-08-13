from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Self

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
    scope_decision: ScopeDecisionV4
    terminal: bool
    next_step: Literal["END", "INVESTIGATION"]
    scope_reasons: list[str] = Field(min_length=1, max_length=10)
    security_context: SecurityContextV4 | None = None
    follow_up_question: str | None = None
    boundary_message: str | None = None
    limitations: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def validate_scope_transition(self) -> Self:
        if self.scope_decision is ScopeDecisionV4.IN_SCOPE:
            if self.terminal or self.next_step != "INVESTIGATION" or self.security_context is None:
                raise ValueError("in-scope response requires non-terminal investigation context")
            if self.follow_up_question is not None or self.boundary_message is not None:
                raise ValueError("in-scope response cannot contain a terminal message")
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
        return self


__all__ = [
    "CONTRACT_VERSION_V4",
    "SECURITY_CONTEXT_VERSION",
    "PotentialThreatV4",
    "RequestedActionV4",
    "ScopeDecisionV4",
    "SecurityConsentV4",
    "SecurityContextV4",
    "SecurityScenarioV4",
    "SecurityScopeResponseV4",
    "SecurityTriageCreateRequestV4",
]
