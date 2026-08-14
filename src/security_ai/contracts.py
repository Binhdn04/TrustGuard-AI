from __future__ import annotations

from enum import StrEnum
from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base for all provider-facing structured data."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AssistantOperation(StrEnum):
    UNDERSTAND = "understand"
    PRIORITIZE_PLAN = "prioritize_plan"
    SYNTHESIZE = "synthesize"
    DRAFT_ADMIN_REVIEW = "draft_admin_review"


class Understanding(StrictModel):
    sender_intent: str | None = None
    scenario: str | None = None
    requested_action: str | None = None
    security_signals: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)


class PlanPriority(StrictModel):
    ordered_step_ids: list[str]
    skipped_step_ids: list[str] = Field(default_factory=list)


class AssistantSynthesis(StrictModel):
    summary: str
    top_reasons: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)


class AdminReviewDraft(StrictModel):
    evidence_summary: str
    conflicts: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    proposed_disposition: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


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
