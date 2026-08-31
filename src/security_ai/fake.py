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
        return self._response(Understanding())

    async def prioritize_plan(self, context: dict[str, Any], candidate_steps: list[dict[str, Any]]):
        return self._response(PlanPriority(ordered_step_ids=[str(step["step_id"]) for step in candidate_steps]))

    async def synthesize(self, result: dict[str, Any]):
        evidence = list(result.get("evidence", []))
        reasons = [
            {"text": str(item["description"]), "evidence_refs": [str(item["evidence_ref"])]} for item in evidence[:3]
        ]
        return self._response(
            AssistantSynthesis(
                summary=str(result.get("explanation", "Analysis completed.")),
                top_reasons=reasons,
            )
        )

    async def draft_admin_review(self, case_detail: dict[str, Any]):
        refs = [str(item["evidence_ref"]) for item in case_detail.get("evidence", [])[:3]]
        rationale = (
            [{"text": "The deterministic case evidence supports manual review.", "evidence_refs": refs[:1]}]
            if refs
            else []
        )
        return self._response(
            AdminReviewDraft(
                evidence_summary="Review the cited deterministic evidence.",
                proposed_disposition="needs_more_information",
                proposed_admin_action="none",
                grounded_rationale=rationale,
                evidence_refs=refs,
            )
        )
