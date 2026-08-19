from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Generic, Literal, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.models.security_v4 import (
    ExposureStateV4,
    MissingInformationSlotV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityScenarioV4,
)


class StrictModel(BaseModel):
    """Base for all provider-facing structured data."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AssistantOperation(StrEnum):
    UNDERSTAND = "understand"
    PRIORITIZE_PLAN = "prioritize_plan"
    SYNTHESIZE = "synthesize"
    DRAFT_ADMIN_REVIEW = "draft_admin_review"


class SemanticSecuritySignal(StrEnum):
    CREDENTIAL_REQUEST = "credential_request"
    OTP_REQUEST = "otp_request"
    PAYMENT_REQUEST = "payment_request"
    PERSONAL_INFORMATION_REQUEST = "personal_information_request"
    URGENCY = "urgency"
    IMPERSONATION = "impersonation"


class UnderstandingSourceSpan(StrictModel):
    field_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9_]+$")
    start: int = Field(ge=0)
    end: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_offsets(self) -> UnderstandingSourceSpan:
        if self.end <= self.start:
            raise ValueError("source span end must be greater than start")
        return self


class Understanding(StrictModel):
    scope_decision: ScopeDecisionV4 | None = None
    sender_intent: str | None = None
    social_engineering_techniques: list[str] = Field(default_factory=list, max_length=20)
    claimed_entity: str | None = None
    scenario: SecurityScenarioV4 | None = None
    requested_action: RequestedActionV4 | None = None
    exposure_state: ExposureStateV4 = ExposureStateV4.UNKNOWN
    security_signals: list[SemanticSecuritySignal] = Field(default_factory=list, max_length=10)
    missing_information: list[str] = Field(default_factory=list)
    follow_up_slot: MissingInformationSlotV4 | None = None
    follow_up_question: str | None = Field(default=None, max_length=500)
    field_confidences: dict[str, Annotated[float, Field(ge=0, le=1)]] = Field(default_factory=dict, max_length=50)
    source_spans: list[UnderstandingSourceSpan] = Field(default_factory=list, max_length=50)
    understanding_version: Literal["security-understanding-v1"] = "security-understanding-v1"

    @field_validator("scope_decision", "scenario", "requested_action", "follow_up_slot", mode="before")
    @classmethod
    def normalize_optional_unknown_enum(cls, value: Any) -> Any:
        """Treat a model's UNKNOWN sentinel as an omitted optional candidate."""
        if isinstance(value, str) and value.strip().casefold() == "unknown":
            return None
        return value

    @field_validator("sender_intent", "claimed_entity", mode="before")
    @classmethod
    def normalize_optional_unknown_text(cls, value: Any) -> Any:
        if isinstance(value, str) and value.strip().casefold() in {"unknown", "n/a", "none"}:
            return None
        return value


class PlanPriority(StrictModel):
    ordered_step_ids: list[str] = Field(default_factory=list, max_length=100)
    skipped_step_ids: list[str] = Field(default_factory=list, max_length=100)
    requested_step_ids: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_unique_step_ids(self) -> PlanPriority:
        for values in (self.ordered_step_ids, self.skipped_step_ids, self.requested_step_ids):
            if len(values) != len(set(values)):
                raise ValueError("planner step ids must be unique")
        if set(self.ordered_step_ids) & set(self.skipped_step_ids):
            raise ValueError("a planner step cannot be both ordered and skipped")
        return self


class SynthesisReason(StrictModel):
    text: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)


class AssistantSynthesis(StrictModel):
    summary: str = Field(min_length=1, max_length=2000)
    top_reasons: list[SynthesisReason] = Field(default_factory=list, max_length=5)
    uncertainties: list[str] = Field(default_factory=list, max_length=20)
    follow_up_offer: str | None = Field(default=None, max_length=500)


class AdminReviewDraft(StrictModel):
    evidence_summary: str = Field(min_length=1, max_length=2000)
    conflicts: list[str] = Field(default_factory=list, max_length=20)
    missing_information: list[str] = Field(default_factory=list, max_length=20)
    proposed_disposition: Literal[
        "confirm_malicious",
        "confirm_safe",
        "mark_false_positive",
        "needs_more_information",
        "no_change",
    ]
    proposed_admin_action: Literal[
        "add_to_blacklist",
        "block_domain",
        "publish_broad_warning",
        "none",
    ] = "none"
    grounded_rationale: list[SynthesisReason] = Field(default_factory=list, max_length=5)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


OutputT = TypeVar("OutputT", bound=StrictModel)


class ModelUsage(StrictModel):
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)


class ModelResponse(StrictModel, Generic[OutputT]):
    output: OutputT
    provider: str
    model: str
    usage: ModelUsage = Field(default_factory=ModelUsage)


@runtime_checkable
class SecurityAssistantModel(Protocol):
    async def understand(self, message: str, conversation_summary: str | None) -> ModelResponse[Understanding]: ...

    async def prioritize_plan(
        self, context: dict[str, Any], candidate_steps: list[dict[str, Any]]
    ) -> ModelResponse[PlanPriority]: ...

    async def synthesize(self, result: dict[str, Any]) -> ModelResponse[AssistantSynthesis]: ...

    async def draft_admin_review(self, case_detail: dict[str, Any]) -> ModelResponse[AdminReviewDraft]: ...
