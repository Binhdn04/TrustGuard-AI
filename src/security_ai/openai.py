from __future__ import annotations

import json
from typing import Any

from langchain_openai import ChatOpenAI

from src.security_ai.contracts import (
    AdminReviewDraft,
    AssistantSynthesis,
    ModelResponse,
    ModelUsage,
    PlanPriority,
    SecurityAssistantModel,
    Understanding,
)


class OpenAISecurityAssistant(SecurityAssistantModel):
    """OpenAI adapter. Policy and fallback remain owned by the caller/runtime."""

    def __init__(self, *, api_key: str, small_model: str, synthesis_model: str, timeout: float) -> None:
        if not api_key.strip():
            raise ValueError("OpenAI API key is required")
        common = {"api_key": api_key, "temperature": 0, "timeout": timeout, "max_retries": 0}
        self._small = ChatOpenAI(model=small_model, **common)
        self._synthesis = ChatOpenAI(model=synthesis_model, **common)
        self.small_model = small_model
        self.synthesis_model = synthesis_model

    async def _call(self, client, model: str, schema, payload: dict[str, Any]):
        # JSON is data, not instructions; the operation label is fixed by the
        # adapter and no chain-of-thought is requested or retained.
        result = await client.with_structured_output(schema, include_raw=True).ainvoke(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        )
        parsed = schema.model_validate(result["parsed"])
        metadata = getattr(result.get("raw"), "usage_metadata", None) or {}
        usage = ModelUsage(
            input_tokens=metadata.get("input_tokens", 0),
            output_tokens=metadata.get("output_tokens", 0),
        )
        return ModelResponse(output=parsed, provider="openai", model=model, usage=usage)

    async def understand(self, message: str, conversation_summary: str | None):
        return await self._call(self._small, self.small_model, Understanding, {
            "operation": "security_message_understanding",
            "message": message,
            "conversation_summary": conversation_summary,
        })

    async def prioritize_plan(self, context: dict[str, Any], candidate_steps: list[dict[str, Any]]):
        return await self._call(self._small, self.small_model, PlanPriority, {
            "operation": "rank_only_the_supplied_candidate_steps",
            "context": context,
            "candidate_steps": candidate_steps,
        })

    async def synthesize(self, result: dict[str, Any]):
        return await self._call(self._synthesis, self.synthesis_model, AssistantSynthesis, {
            "operation": "explain_only_the_supplied_security_result",
            "result": result,
        })

    async def draft_admin_review(self, case_detail: dict[str, Any]):
        return await self._call(self._synthesis, self.synthesis_model, AdminReviewDraft, {
            "operation": "draft_non_executing_admin_review",
            "case_detail": case_detail,
        })
