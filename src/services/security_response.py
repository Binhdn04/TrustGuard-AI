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
_AI_SYNTHESIS_LIMITATION = (
    "AI diễn đạt không khả dụng; phản hồi vẫn được tạo trực tiếp từ kết quả, bằng chứng và hành động đã kiểm chứng."
)
_AI_FAILURE_REASON_LABELS = {
    "budget_exceeded": "vượt ngân sách lượt gọi",
    "invalid_structured_output": "structured output không hợp lệ",
    "provider_unconfigured": "provider AI chưa được cấu hình",
    "provider_error": "provider trả lỗi",
    "timeout": "provider quá thời gian chờ",
    "turn_deadline_exceeded": "lượt phân tích vượt deadline",
    "grounding_rejected": "phản hồi AI không vượt qua kiểm tra grounding",
}
_FOLLOW_UP_OFFER = "Bạn có thể gửi thêm thông tin không nhạy cảm để tiếp tục đánh giá trong case này."


def _immediate_steps(scope: SecurityScopeResponseV4) -> list[AssistantImmediateStepV4]:
    assert scope.policy_version is not None
    return [
        AssistantImmediateStepV4(action=action, policy_ref=scope.policy_version) for action in scope.recommended_actions
    ]


def policy_grounded_assistant_response(scope: SecurityScopeResponseV4) -> AssistantResponseV4:
    """Answer the user from verified case data without a canned template."""
    evidence_by_ref = {item.evidence_ref: item for item in scope.evidence}
    reasons = [
        AssistantReasonV4(text=evidence_by_ref[ref].description, evidence_refs=[ref])
        for ref in scope.explanation_evidence_refs
        if ref in evidence_by_ref
    ][:3]
    return AssistantResponseV4(
        summary=scope.explanation or "Mình đã kiểm tra nội dung này theo các tín hiệu bảo mật hiện có.",
        top_reasons=reasons,
        uncertainties=list(scope.limitations)[:20],
        immediate_steps=_immediate_steps(scope),
        follow_up_offer=_FOLLOW_UP_OFFER,
        generation_mode=AssistantGenerationModeV4.POLICY_GROUNDED,
    )


# Compatibility import for integrations that have not migrated to the new
# name. New responses produced through it are still policy-grounded.
template_assistant_response = policy_grounded_assistant_response


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
        response = policy_grounded_assistant_response(scope)
        if not self._ai_enabled:
            return scope.model_copy(update={"assistant_response": response})
        if self._model is None:
            return self._with_ai_limitation(scope, response, reason="provider_unconfigured")

        result = await self._runtime.invoke(
            AssistantOperation.SYNTHESIZE,
            lambda: self._model.synthesize(self._synthesis_payload(scope)),
            AssistantSynthesis,
        )
        grounded = grounded_ai_response(scope, result.output) if result.output is not None else None
        if grounded is None:
            reason = result.error or "grounding_rejected"
            return self._with_ai_limitation(scope, response, reason=reason)
        return scope.model_copy(update={"assistant_response": grounded})

    @staticmethod
    def _with_ai_limitation(
        scope: SecurityScopeResponseV4,
        response: AssistantResponseV4,
        *,
        reason: str,
    ) -> SecurityScopeResponseV4:
        reason_label = _AI_FAILURE_REASON_LABELS.get(reason, "lỗi AI không xác định")
        limitation = f"{_AI_SYNTHESIS_LIMITATION} Nguyên nhân: {reason_label} ({reason})."
        limitations = list(dict.fromkeys([*scope.limitations, limitation]))
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
    "policy_grounded_assistant_response",
    "template_assistant_response",
]
