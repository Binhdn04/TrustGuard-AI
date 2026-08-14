from __future__ import annotations

import re

from src.models import (
    SECURITY_ASSISTANT_RESPONSE_VERSION,
    AssistantGenerationModeV4,
    AssistantImmediateStepV4,
    AssistantReasonV4,
    AssistantResponseV4,
    SecurityScopeResponseV4,
)
from src.security_ai.contracts import AssistantOperation, AssistantSynthesis, SecurityAssistantModel
from src.security_ai.runtime import SecurityAssistantRuntime

_UNSAFE_LINK_TEXT = re.compile(r"(?:https?://|www\.)\S*", re.IGNORECASE)
_FALLBACK_LIMITATION = "AI explanation không khả dụng; đã dùng phản hồi mẫu được policy kiểm soát."
_FOLLOW_UP_OFFER = "Bạn có thể gửi thêm thông tin không nhạy cảm để tiếp tục đánh giá trong case này."


def _immediate_steps(scope: SecurityScopeResponseV4) -> list[AssistantImmediateStepV4]:
    assert scope.policy_version is not None
    return [
        AssistantImmediateStepV4(action=action, policy_ref=scope.policy_version) for action in scope.recommended_actions
    ]


def template_assistant_response(scope: SecurityScopeResponseV4) -> AssistantResponseV4:
    """Build a complete response without relying on provider prose."""
    evidence_by_ref = {item.evidence_ref: item for item in scope.evidence}
    reasons = [
        AssistantReasonV4(text=evidence_by_ref[ref].description, evidence_refs=[ref])
        for ref in scope.explanation_evidence_refs
        if ref in evidence_by_ref
    ][:3]
    return AssistantResponseV4(
        summary=scope.explanation or "Đã hoàn tất đánh giá bảo mật theo policy hiện hành.",
        top_reasons=reasons,
        uncertainties=list(scope.limitations)[:20],
        immediate_steps=_immediate_steps(scope),
        follow_up_offer=_FOLLOW_UP_OFFER,
        generation_mode=AssistantGenerationModeV4.TEMPLATE_FALLBACK,
    )


def grounded_ai_response(
    scope: SecurityScopeResponseV4,
    synthesis: AssistantSynthesis,
) -> AssistantResponseV4 | None:
    """Reject ungrounded citations, procedural inventions, and link reproduction."""
    available_refs = {item.evidence_ref for item in scope.evidence}
    cited_refs = {ref for reason in synthesis.top_reasons for ref in reason.evidence_refs}
    texts = [
        synthesis.summary,
        *(reason.text for reason in synthesis.top_reasons),
        *synthesis.uncertainties,
        *([synthesis.follow_up_offer] if synthesis.follow_up_offer else []),
    ]
    if cited_refs - available_refs or any(_UNSAFE_LINK_TEXT.search(text) for text in texts):
        return None
    if available_refs and not synthesis.top_reasons:
        return None
    try:
        return AssistantResponseV4(
            summary=synthesis.summary,
            top_reasons=[
                AssistantReasonV4(text=reason.text, evidence_refs=reason.evidence_refs)
                for reason in synthesis.top_reasons
            ],
            # Uncertainty and procedural fields remain deterministic even when
            # prose synthesis succeeds.
            uncertainties=list(scope.limitations)[:20],
            immediate_steps=_immediate_steps(scope),
            follow_up_offer=_FOLLOW_UP_OFFER,
            response_version=SECURITY_ASSISTANT_RESPONSE_VERSION,
            generation_mode=AssistantGenerationModeV4.AI,
        )
    except ValueError:
        return None


class GroundedSecurityResponseService:
    def __init__(
        self,
        *,
        ai_enabled: bool,
        model: SecurityAssistantModel | None,
        runtime: SecurityAssistantRuntime,
    ) -> None:
        self._ai_enabled = ai_enabled
        self._model = model
        self._runtime = runtime

    async def enrich(self, scope: SecurityScopeResponseV4) -> SecurityScopeResponseV4:
        if scope.risk is None or scope.policy_version is None:
            return scope
        fallback = template_assistant_response(scope)
        if not self._ai_enabled:
            return scope.model_copy(update={"assistant_response": fallback})
        if self._model is None:
            return self._fallback(scope, fallback)

        result = await self._runtime.invoke(
            AssistantOperation.SYNTHESIZE,
            lambda: self._model.synthesize(self._synthesis_payload(scope)),
            AssistantSynthesis,
        )
        grounded = grounded_ai_response(scope, result.output) if result.output is not None else None
        if grounded is None:
            return self._fallback(scope, fallback)
        return scope.model_copy(update={"assistant_response": grounded})

    @staticmethod
    def _fallback(
        scope: SecurityScopeResponseV4,
        response: AssistantResponseV4,
    ) -> SecurityScopeResponseV4:
        limitations = list(dict.fromkeys([*scope.limitations, _FALLBACK_LIMITATION]))
        response = response.model_copy(update={"uncertainties": limitations[:20]})
        return scope.model_copy(update={"assistant_response": response, "limitations": limitations})

    @staticmethod
    def _synthesis_payload(scope: SecurityScopeResponseV4) -> dict[str, object]:
        return {
            "risk": scope.risk.value if scope.risk else None,
            "score": scope.score,
            "confidence": scope.confidence,
            "threat_type": scope.threat_type.value if scope.threat_type else None,
            "policy_version": scope.policy_version,
            "recommended_actions": [action.value for action in scope.recommended_actions],
            "explanation": scope.explanation,
            "evidence": [
                {
                    "evidence_ref": item.evidence_ref,
                    "type": item.type.value,
                    "source": item.source,
                    "signal": item.signal,
                    "description": item.description,
                }
                for item in scope.evidence
            ],
            "limitations": list(scope.limitations),
        }


__all__ = [
    "GroundedSecurityResponseService",
    "grounded_ai_response",
    "template_assistant_response",
]
