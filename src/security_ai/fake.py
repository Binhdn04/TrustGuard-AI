from __future__ import annotations

from typing import Any

from src.security_ai.contracts import (
    AdminReviewDraft,
    AssistantSynthesis,
    ModelResponse,
    PlanPriority,
    SecurityAssistantModel,
    Understanding,
)


class DeterministicFakeSecurityAssistant(SecurityAssistantModel):
    """Network-free adapter intended for contract and orchestration tests."""

    def _response(self, output):
        return ModelResponse(output=output, provider="fake", model="deterministic-v1")

    async def understand(self, message: str, conversation_summary: str | None):
        return self._response(Understanding(sender_intent="unknown"))

    async def prioritize_plan(self, context: dict[str, Any], candidate_steps: list[dict[str, Any]]):
        return self._response(PlanPriority(ordered_step_ids=[str(step["id"]) for step in candidate_steps]))

    async def synthesize(self, result: dict[str, Any]):
        return self._response(AssistantSynthesis(summary=str(result.get("summary", "Analysis completed."))))

    async def draft_admin_review(self, case_detail: dict[str, Any]):
        return self._response(AdminReviewDraft(evidence_summary="Review the cited deterministic evidence."))
