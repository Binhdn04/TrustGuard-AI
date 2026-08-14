from __future__ import annotations

import json

from src.agents.security_scope import derive_potential_threat, partial_security_context
from src.models import (
    AssistantContextV4,
    AssistantProcessingModeV4,
    AssistantSourceSpanV4,
    ExposureStateV4,
    ScopeDecisionV4,
    SecurityContextV4,
    SecurityScenarioV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import (
    AssistantOperation,
    SecurityAssistantModel,
    SemanticSecuritySignal,
    Understanding,
)
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_conversation_policy import (
    apply_adaptive_conversation_policy,
    detect_local_exposure,
    highest_exposure,
    select_missing_slot,
)

_MIN_GROUNDED_CONFIDENCE = 0.80
_FOLLOW_UP_QUESTION = (
    "Bạn có thể gửi nội dung đầy đủ của tin nhắn, tên người gửi và đường link hoặc hành động họ yêu cầu không?"
)
_BOUNDARY_MESSAGE = (
    "Trợ lý này chỉ đánh giá rủi ro phishing, lừa đảo, giả mạo và các yêu cầu có thể gây mất tài khoản "
    "hoặc tiền; hệ thống không xác minh tin tức hay kiến thức phổ thông."
)
_FALLBACK_LIMITATION = "AI semantic understanding không khả dụng; kết quả chỉ dùng rule cục bộ."
_UNGROUNDED_LIMITATION = "AI semantic field thiếu confidence hoặc source span hợp lệ đã bị loại."
_CONFLICT_LIMITATION = "AI semantic understanding xung đột với rule signal; rule được giữ nguyên."
_BOUNDARY_CONFLICT_LIMITATION = "AI và rule xung đột về phạm vi; cần thêm thông tin trước khi điều tra."
_EXPLICIT_GENERAL_FACT_REASONS = {
    "general_fact_check_sports",
    "general_fact_check_politics",
    "general_fact_check_medical_science",
    "general_fact_check_news",
}


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))


def _valid_spans(message: str, output: Understanding) -> dict[str, list[AssistantSourceSpanV4]]:
    valid: dict[str, list[AssistantSourceSpanV4]] = {}
    for span in output.source_spans:
        if span.end > len(message) or not message[span.start : span.end].strip():
            continue
        converted = AssistantSourceSpanV4(
            field_name=span.field_name,
            start=span.start,
            end=span.end,
        )
        valid.setdefault(span.field_name, []).append(converted)
    return valid


def _grounded(
    field_name: str,
    output: Understanding,
    spans: dict[str, list[AssistantSourceSpanV4]],
) -> bool:
    return output.field_confidences.get(field_name, 0) >= _MIN_GROUNDED_CONFIDENCE and bool(spans.get(field_name))


def _has_security_information(context: SecurityContextV4) -> bool:
    return bool(
        context.urls
        or context.claimed_entity
        or context.requested_action
        or context.scenario is not SecurityScenarioV4.UNKNOWN
        or context.credential_request
        or context.otp_request
        or context.payment_request
        or context.personal_information_request
        or context.impersonation_signals
    )


def _rules_only_context(
    mode: AssistantProcessingModeV4,
    existing: AssistantContextV4 | None = None,
) -> AssistantContextV4:
    return AssistantContextV4(
        processing_mode=mode,
        exposure_state=existing.exposure_state if existing else ExposureStateV4.UNKNOWN,
        missing_information=existing.missing_information if existing else [],
        model_version="rules-only-v1" if mode is AssistantProcessingModeV4.RULES_ONLY else "unavailable",
    )


def merge_semantic_understanding(
    message: str,
    scope: SecurityScopeResponseV4,
    output: Understanding,
    *,
    model_version: str,
) -> SecurityScopeResponseV4:
    """Ground and merge AI candidates without weakening deterministic signals."""
    spans = _valid_spans(message, output)
    accepted_fields: set[str] = set()
    rejected_impact_field = False

    def accept(field_name: str, present: bool) -> bool:
        nonlocal rejected_impact_field
        if not present:
            return False
        if _grounded(field_name, output, spans):
            accepted_fields.add(field_name)
            return True
        rejected_impact_field = True
        return False

    accepted_scope = output.scope_decision if accept("scope_decision", output.scope_decision is not None) else None
    sender_intent = output.sender_intent if accept("sender_intent", bool(output.sender_intent)) else None
    techniques = (
        _unique(output.social_engineering_techniques)[:20]
        if accept("social_engineering_techniques", bool(output.social_engineering_techniques))
        else []
    )
    entity = output.claimed_entity if accept("claimed_entity", bool(output.claimed_entity)) else None
    scenario = (
        output.scenario
        if accept("scenario", output.scenario is not None and output.scenario is not SecurityScenarioV4.UNKNOWN)
        else None
    )
    requested_action = (
        output.requested_action if accept("requested_action", output.requested_action is not None) else None
    )
    extracted_exposure = (
        output.exposure_state
        if accept("exposure_state", output.exposure_state is not ExposureStateV4.UNKNOWN)
        else ExposureStateV4.UNKNOWN
    )
    exposure_state = highest_exposure(
        scope.assistant_context.exposure_state if scope.assistant_context else ExposureStateV4.UNKNOWN,
        extracted_exposure,
    )
    signals = {signal for signal in output.security_signals if accept(signal.value, True)}

    base = scope.security_context or partial_security_context(message)
    updates: dict[str, object] = {}
    conflicts = False
    if entity:
        if base.claimed_entity and base.claimed_entity.casefold() != entity.casefold():
            conflicts = True
        elif not base.claimed_entity:
            updates["claimed_entity"] = entity
    if scenario is not None:
        if base.scenario is not SecurityScenarioV4.UNKNOWN and base.scenario is not scenario:
            conflicts = True
        elif base.scenario is SecurityScenarioV4.UNKNOWN:
            updates["scenario"] = scenario
    if requested_action is not None:
        if base.requested_action is not None and base.requested_action is not requested_action:
            conflicts = True
        elif base.requested_action is None:
            updates["requested_action"] = requested_action

    # AI candidates are additions only. Existing true rule signals are never removed.
    updates.update(
        credential_request=(base.credential_request or SemanticSecuritySignal.CREDENTIAL_REQUEST in signals),
        otp_request=base.otp_request or SemanticSecuritySignal.OTP_REQUEST in signals,
        payment_request=base.payment_request or SemanticSecuritySignal.PAYMENT_REQUEST in signals,
        personal_information_request=(
            base.personal_information_request or SemanticSecuritySignal.PERSONAL_INFORMATION_REQUEST in signals
        ),
        urgency=base.urgency or SemanticSecuritySignal.URGENCY in signals,
    )
    if SemanticSecuritySignal.IMPERSONATION in signals:
        updates["impersonation_signals"] = _unique([*base.impersonation_signals, "ai_grounded_impersonation"])[:10]
    merged = base.model_copy(update=updates)
    merged = merged.model_copy(update={"potential_threat": derive_potential_threat(merged)})

    accepted_spans = [span for field_name in accepted_fields for span in spans.get(field_name, [])][:50]
    assistant_context = AssistantContextV4(
        processing_mode=AssistantProcessingModeV4.HYBRID,
        sender_intent=sender_intent,
        social_engineering_techniques=techniques,
        exposure_state=exposure_state,
        missing_information=_unique(output.missing_information)[:20],
        field_confidences={field_name: output.field_confidences[field_name] for field_name in accepted_fields},
        source_spans=accepted_spans,
        understanding_version=output.understanding_version,
        model_version=model_version,
    )
    limitations = list(scope.limitations)
    if rejected_impact_field:
        limitations.append(_UNGROUNDED_LIMITATION)
    if conflicts:
        limitations.append(_CONFLICT_LIMITATION)

    update: dict[str, object] = {
        "security_context": merged,
        "assistant_context": assistant_context,
        "limitations": _unique(limitations),
    }
    if scope.scope_decision is ScopeDecisionV4.IN_SCOPE:
        if accepted_scope is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK:
            update.update(
                scope_decision=ScopeDecisionV4.NEED_MORE_INFO,
                terminal=True,
                next_step="END",
                follow_up_question=_FOLLOW_UP_QUESTION,
                boundary_message=None,
                limitations=_unique([*limitations, _BOUNDARY_CONFLICT_LIMITATION]),
            )
    elif accepted_scope is ScopeDecisionV4.IN_SCOPE and _has_security_information(merged):
        update.update(
            scope_decision=ScopeDecisionV4.IN_SCOPE,
            terminal=False,
            next_step="INVESTIGATION",
            follow_up_question=None,
            boundary_message=None,
            scope_reasons=_unique([*scope.scope_reasons, "ai_semantic_in_scope"]),
        )
    elif accepted_scope is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK:
        update.update(
            scope_decision=ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK,
            terminal=True,
            next_step="END",
            security_context=None,
            follow_up_question=None,
            boundary_message=_BOUNDARY_MESSAGE,
            scope_reasons=_unique([*scope.scope_reasons, "ai_general_fact_check"]),
        )
    elif scope.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK:
        update.update(
            scope_decision=ScopeDecisionV4.NEED_MORE_INFO,
            terminal=True,
            next_step="END",
            security_context=None,
            follow_up_question=_FOLLOW_UP_QUESTION,
            boundary_message=None,
        )
    return scope.model_copy(update=update)


class SecuritySemanticUnderstandingService:
    def __init__(
        self,
        *,
        enabled: bool,
        model: SecurityAssistantModel | None,
        runtime: SecurityAssistantRuntime,
    ) -> None:
        self._enabled = enabled
        self._model = model
        self._runtime = runtime

    async def enrich(
        self,
        request: SecurityTriageCreateRequestV4,
        scope: SecurityScopeResponseV4,
    ) -> SecurityScopeResponseV4:
        if not self._enabled:
            return scope
        if set(scope.scope_reasons) & _EXPLICIT_GENERAL_FACT_REASONS:
            rules_only = scope.model_copy(
                update={
                    "assistant_context": _rules_only_context(
                        AssistantProcessingModeV4.RULES_ONLY,
                        scope.assistant_context,
                    )
                }
            )
            return apply_adaptive_conversation_policy(request.message, rules_only)
        if self._model is None:
            return self._fallback(request.message, scope)
        preview_exposure = highest_exposure(
            scope.assistant_context.exposure_state if scope.assistant_context else ExposureStateV4.UNKNOWN,
            detect_local_exposure(request.message),
        )
        selected_slot = select_missing_slot(scope.security_context, preview_exposure)
        conversation_summary = None
        if scope.security_context is not None or preview_exposure is not ExposureStateV4.UNKNOWN:
            conversation_summary = json.dumps(
                {
                    "security_context": (
                        scope.security_context.model_dump(mode="json", exclude_none=True)
                        if scope.security_context is not None
                        else None
                    ),
                    "exposure_state": preview_exposure.value,
                    "policy_selected_follow_up_slot": selected_slot.value if selected_slot else None,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        result = await self._runtime.invoke(
            AssistantOperation.UNDERSTAND,
            lambda: self._model.understand(request.message, conversation_summary),
            Understanding,
        )
        if result.output is None or result.model is None:
            return self._fallback(request.message, scope)
        merged = merge_semantic_understanding(
            request.message,
            scope,
            result.output,
            model_version=result.model,
        )
        return apply_adaptive_conversation_policy(
            request.message,
            merged,
            drafted_slot=result.output.follow_up_slot,
            drafted_question=result.output.follow_up_question,
        )

    @staticmethod
    def _fallback(message: str, scope: SecurityScopeResponseV4) -> SecurityScopeResponseV4:
        fallback = scope.model_copy(
            update={
                "assistant_context": _rules_only_context(
                    AssistantProcessingModeV4.FALLBACK,
                    scope.assistant_context,
                ),
                "limitations": _unique([*scope.limitations, _FALLBACK_LIMITATION]),
            }
        )
        return apply_adaptive_conversation_policy(message, fallback)


__all__ = [
    "SecuritySemanticUnderstandingService",
    "merge_semantic_understanding",
]
