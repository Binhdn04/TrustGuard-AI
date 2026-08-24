from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable

from src.agents.nodes.extraction import extract_urls
from src.agents.security_scope import derive_potential_threat, partial_security_context
from src.models import (
    SECURITY_UNDERSTANDING_VERSION,
    AssistantContextV4,
    AssistantProcessingModeV4,
    AssistantSourceSpanV4,
    BrandRecordV4,
    EntityUrlClaimV4,
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
    UnderstandingSourceSpan,
)
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_conversation_policy import (
    apply_adaptive_conversation_policy,
    detect_local_exposure,
    highest_exposure,
    select_missing_slot,
)
from src.services.security_entity_mentions import (
    EntityMentionCandidate,
    OrganizationGazetteer,
    deterministic_entity_url_claims,
    extract_entity_mentions,
    extract_recovery_phrases,
)
from src.services.security_span_candidates import SemanticSpanCandidate, generate_semantic_span_candidates

GazetteerLoader = Callable[[], Awaitable[list[BrandRecordV4]]]

_MIN_GROUNDED_CONFIDENCE = 0.80
_FOLLOW_UP_QUESTION = (
    "Bạn có thể gửi nội dung đầy đủ của tin nhắn, tên người gửi và đường link hoặc hành động họ yêu cầu không?"
)
_BOUNDARY_MESSAGE = (
    "Trợ lý này chỉ đánh giá rủi ro phishing, lừa đảo, giả mạo và các yêu cầu có thể gây mất tài khoản "
    "hoặc tiền; hệ thống không xác minh tin tức hay kiến thức phổ thông."
)
_FALLBACK_LIMITATION = "AI semantic understanding không khả dụng; kết quả chỉ dùng rule cục bộ."
_CONFLICT_LIMITATION = "AI semantic understanding xung đột với rule signal; rule được giữ nguyên."
_BOUNDARY_CONFLICT_LIMITATION = "AI và rule xung đột về phạm vi; cần thêm thông tin trước khi điều tra."
_GROUNDING_FAILURE_LABELS = {
    "missing_confidence": "thiếu confidence",
    "low_confidence": "confidence dưới ngưỡng 0.80",
    "missing_source_span": "thiếu source span",
    "invalid_source_span": "source span không hợp lệ",
    "invalid_reference": "tham chiếu candidate hoặc URL không hợp lệ",
}
_GROUNDING_FAILURE_ORDER = tuple(_GROUNDING_FAILURE_LABELS)
_LOCAL_CONVERSATION_REASONS = {"assistant_capabilities", "assistant_greeting"}
_LITERAL_ORGANIZATION_PREFIXES = (
    "bệnh viện ",
    "benh vien ",
    "đại học ",
    "dai hoc ",
    "trường ",
    "truong ",
    "ngân hàng ",
    "ngan hang ",
    "công ty ",
    "cong ty ",
    "tập đoàn ",
    "tap doan ",
    "university ",
    "hospital ",
    "bank ",
)

logger = logging.getLogger("trustguard.security_ai")


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))


def _valid_spans(message: str, output: Understanding) -> dict[str, list[AssistantSourceSpanV4]]:
    valid: dict[str, list[AssistantSourceSpanV4]] = {}
    for span in output.source_spans:
        if span.end <= span.start or span.end > len(message) or not message[span.start : span.end].strip():
            continue
        converted = AssistantSourceSpanV4(
            field_name=span.field_name,
            start=span.start,
            end=span.end,
        )
        valid.setdefault(span.field_name, []).append(converted)
    return valid


def _resolve_span_selections(
    output: Understanding,
    candidates: list[SemanticSpanCandidate],
) -> tuple[Understanding, set[str]]:
    """Resolve provider-selected IDs while retaining legacy fixture spans."""
    by_id = {item.span_id: item for item in candidates}
    resolved = list(output.source_spans)
    invalid_fields: set[str] = set()
    for selection in output.span_selections:
        selected = [by_id.get(span_id) for span_id in selection.span_ids]
        if not selection.span_ids or any(item is None for item in selected):
            invalid_fields.add(selection.field_name)
            continue
        valid = [item for item in selected if item is not None]
        best_specificity = max(item.specificity for item in valid)
        for item in valid:
            if item.specificity == best_specificity:
                resolved.append(
                    UnderstandingSourceSpan(
                        field_name=selection.field_name,
                        start=item.start,
                        end=item.end,
                    )
                )
    return output.model_copy(update={"source_spans": resolved}), invalid_fields


def _literal_url_spans(message: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    cursor = 0
    for value in extract_urls(message):
        start = message.find(value, cursor)
        if start < 0:
            start = message.find(value)
        if start >= 0:
            spans.append((start, start + len(value)))
            cursor = start + len(value)
    return spans


def _ground_backend_entity_references(
    message: str,
    output: Understanding,
    mentions: list[EntityMentionCandidate],
) -> tuple[Understanding, set[str]]:
    """Resolve model-selected stable IDs to backend-owned values and spans."""
    by_id = {item.mention_id: item for item in mentions}
    invalid_fields: set[str] = set()
    confidences = dict(output.field_confidences)
    source_spans = list(output.source_spans)
    claimed_entity = output.claimed_entity
    selected_candidate_id = output.claimed_entity_candidate_id or output.claimed_entity_id
    selected_entity = by_id.get(selected_candidate_id or "")
    if selected_candidate_id is not None:
        if selected_entity is None:
            invalid_fields.add("claimed_entity")
            claimed_entity = None
        else:
            claimed_entity = selected_entity.text
            confidences["claimed_entity"] = confidences.get(
                "claimed_entity_candidate_id",
                confidences.get("claimed_entity_id", confidences.get("claimed_entity", 0)),
            )
            source_spans.append(
                UnderstandingSourceSpan(
                    field_name="claimed_entity",
                    start=selected_entity.start,
                    end=selected_entity.end,
                )
            )

    url_spans = _literal_url_spans(message)
    grounded_claims = []
    for claim in output.entity_url_claims:
        candidate_id = claim.entity_candidate_id or claim.entity_mention_id
        entity = by_id.get(candidate_id or "") if candidate_id else None
        entity_name = entity.text if entity is not None else claim.entity_name
        if candidate_id is not None and entity is None:
            invalid_fields.add("entity_url_claims")
            continue
        if entity_name is None or claim.url_index >= len(url_spans):
            invalid_fields.add("entity_url_claims")
            continue
        grounded_claims.append(claim.model_copy(update={"entity_name": entity_name}))
        if entity is not None:
            url_start, url_end = url_spans[claim.url_index]
            source_spans.append(
                UnderstandingSourceSpan(
                    field_name="entity_url_claims",
                    start=min(entity.start, url_start),
                    end=max(entity.end, url_end),
                )
            )
            if selected_entity is None and claimed_entity is None:
                selected_entity = entity
                claimed_entity = entity.text
                confidences["claimed_entity"] = confidences.get("entity_url_claims", 0)
                source_spans.append(
                    UnderstandingSourceSpan(
                        field_name="claimed_entity",
                        start=entity.start,
                        end=entity.end,
                    )
                )

    return (
        output.model_copy(
            update={
                "claimed_entity": claimed_entity,
                "entity_url_claims": grounded_claims,
                "field_confidences": confidences,
                "source_spans": source_spans,
            }
        ),
        invalid_fields,
    )


def _backend_context_source_spans(
    message: str,
    context: SecurityContextV4,
) -> list[AssistantSourceSpanV4]:
    mentions = extract_entity_mentions(
        message,
        (context.claimed_entity,) if context.claimed_entity else (),
    )
    url_spans = _literal_url_spans(message)
    spans: list[AssistantSourceSpanV4] = []
    entity_mentions = {item.text.casefold(): item for item in mentions}
    if context.claimed_entity:
        entity = entity_mentions.get(context.claimed_entity.casefold())
        if entity is not None:
            spans.append(
                AssistantSourceSpanV4(
                    field_name="claimed_entity",
                    start=entity.start,
                    end=entity.end,
                )
            )
    for claim in context.entity_url_claims:
        entity = entity_mentions.get(claim.entity_name.casefold())
        if entity is None or claim.url_index >= len(url_spans):
            continue
        url_start, url_end = url_spans[claim.url_index]
        spans.append(
            AssistantSourceSpanV4(
                field_name="entity_url_claims",
                start=min(entity.start, url_start),
                end=max(entity.end, url_end),
            )
        )
    return spans


def _add_literal_claimed_entity_grounding(
    message: str,
    output: Understanding,
    spans: dict[str, list[AssistantSourceSpanV4]],
) -> Understanding:
    """Ground a bounded entity candidate that occurs verbatim in the request.

    Model-provided offsets and confidence remain required for inferred or
    normalized entities. A literal value with a deterministic organization
    prefix is independently verifiable, so missing model metadata must not
    erase it or let arbitrary model-selected text become an entity.
    """
    entity = output.claimed_entity
    if (
        not entity
        or len(entity) > 200
        or spans.get("claimed_entity")
        or not entity.casefold().startswith(_LITERAL_ORGANIZATION_PREFIXES)
    ):
        return output
    start = message.casefold().find(entity.casefold())
    if start < 0:
        return output
    spans["claimed_entity"] = [
        AssistantSourceSpanV4(
            field_name="claimed_entity",
            start=start,
            end=start + len(entity),
        )
    ]
    confidences = dict(output.field_confidences)
    confidences["claimed_entity"] = max(confidences.get("claimed_entity", 0), 1.0)
    return output.model_copy(update={"field_confidences": confidences})


def _grounded(
    field_name: str,
    output: Understanding,
    spans: dict[str, list[AssistantSourceSpanV4]],
) -> bool:
    return output.field_confidences.get(field_name, 0) >= _MIN_GROUNDED_CONFIDENCE and bool(spans.get(field_name))


def _grounding_failures(
    field_name: str,
    output: Understanding,
    spans: dict[str, list[AssistantSourceSpanV4]],
) -> set[str]:
    failures: set[str] = set()
    if field_name not in output.field_confidences:
        failures.add("missing_confidence")
    elif output.field_confidences[field_name] < _MIN_GROUNDED_CONFIDENCE:
        failures.add("low_confidence")

    candidate_spans = [span for span in output.source_spans if span.field_name == field_name]
    if not candidate_spans:
        failures.add("missing_source_span")
    elif not spans.get(field_name):
        failures.add("invalid_source_span")
    return failures


def _append_grounding_limitations(
    limitations: list[str],
    rejected_fields: dict[str, set[str]],
) -> list[str]:
    updated = list(limitations)
    for failure_code in _GROUNDING_FAILURE_ORDER:
        fields = sorted(field for field, failures in rejected_fields.items() if failure_code in failures)
        if not fields:
            continue
        updated.append(
            "AI semantic field đã bị loại do "
            f"{_GROUNDING_FAILURE_LABELS[failure_code]} ({failure_code}): {', '.join(fields)}."
        )
        for field_name in fields:
            logger.warning(
                "security_ai_semantic_field_rejected",
                extra={
                    "operation": AssistantOperation.UNDERSTAND.value,
                    "field_name": field_name,
                    "failure_code": failure_code,
                },
            )
    return _unique(updated)


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
    entity_candidates: list[EntityMentionCandidate] | None = None,
    span_candidates: list[SemanticSpanCandidate] | None = None,
) -> SecurityScopeResponseV4:
    """Ground and merge AI candidates without weakening deterministic signals."""
    output, invalid_span_fields = _resolve_span_selections(
        output,
        span_candidates or generate_semantic_span_candidates(message, entity_candidates),
    )
    output, invalid_candidate_fields = _ground_backend_entity_references(
        message,
        output,
        entity_candidates
        if entity_candidates is not None
        else extract_entity_mentions(
            message,
            (scope.security_context.claimed_entity,)
            if scope.security_context is not None and scope.security_context.claimed_entity
            else (),
        ),
    )
    spans = _valid_spans(message, output)
    output = _add_literal_claimed_entity_grounding(message, output, spans)
    accepted_fields: set[str] = set()
    rejected_field_failures: dict[str, set[str]] = {
        field_name: {"invalid_reference"} for field_name in invalid_candidate_fields
    }
    for field_name in invalid_span_fields:
        rejected_field_failures.setdefault(field_name, set()).add("invalid_source_span")

    def accept(field_name: str, present: bool) -> bool:
        if not present:
            return False
        if _grounded(field_name, output, spans):
            accepted_fields.add(field_name)
            return True
        rejected_field_failures.setdefault(field_name, set()).update(_grounding_failures(field_name, output, spans))
        return False

    accepted_scope = output.scope_decision if accept("scope_decision", output.scope_decision is not None) else None
    sender_intent = output.sender_intent if accept("sender_intent", bool(output.sender_intent)) else None
    techniques = (
        _unique(output.social_engineering_techniques)[:20]
        if accept("social_engineering_techniques", bool(output.social_engineering_techniques))
        else []
    )
    entity = output.claimed_entity if accept("claimed_entity", bool(output.claimed_entity)) else None
    entity_url_claims: list[EntityUrlClaimV4] = []
    if output.entity_url_claims:
        if accept("entity_url_claims", True) and entity is not None:
            for claim in output.entity_url_claims:
                if (
                    claim.url_index < len((scope.security_context or partial_security_context(message)).urls)
                    and claim.entity_name is not None
                    and claim.entity_name.casefold() == entity.casefold()
                    and message.casefold().find(claim.entity_name.casefold()) >= 0
                ):
                    entity_url_claims.append(
                        EntityUrlClaimV4(
                            entity_name=entity,
                            url_index=claim.url_index,
                            relationship=claim.relationship,
                            confidence=output.field_confidences["entity_url_claims"],
                        )
                    )
                else:
                    rejected_field_failures.setdefault("entity_url_claims", set()).add("invalid_reference")
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
    if entity_url_claims:
        updates["entity_url_claims"] = entity_url_claims

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

    candidate_spans = [
        *[span for field_name in accepted_fields for span in spans.get(field_name, [])],
        *_backend_context_source_spans(message, merged),
    ]
    accepted_spans = list({(span.field_name, span.start, span.end): span for span in candidate_spans}.values())[:50]
    accepted_confidences = {field_name: output.field_confidences[field_name] for field_name in accepted_fields}
    for span in accepted_spans:
        if span.field_name in {"claimed_entity", "entity_url_claims"}:
            accepted_confidences.setdefault(span.field_name, 1.0)
    assistant_context = AssistantContextV4(
        processing_mode=AssistantProcessingModeV4.HYBRID,
        sender_intent=sender_intent,
        social_engineering_techniques=techniques,
        exposure_state=exposure_state,
        missing_information=_unique(output.missing_information)[:20],
        field_confidences=accepted_confidences,
        source_spans=accepted_spans,
        derived_query_provenance=output.derived_query_provenance,
        understanding_version=SECURITY_UNDERSTANDING_VERSION,
        model_version=model_version,
    )
    limitations = list(scope.limitations)
    if rejected_field_failures:
        limitations = _append_grounding_limitations(limitations, rejected_field_failures)
    if conflicts:
        limitations.append(_CONFLICT_LIMITATION)

    update: dict[str, object] = {
        "security_context": merged,
        "assistant_context": assistant_context,
        "limitations": _unique(limitations),
    }
    if scope.scope_decision is ScopeDecisionV4.IN_SCOPE:
        if accepted_scope is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK:
            # A grounded model disagreement is retained, but cannot erase a
            # deterministic positive security signal or stop investigation.
            update["limitations"] = _unique([*limitations, _BOUNDARY_CONFLICT_LIMITATION])
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
        gazetteer_loader: GazetteerLoader | None = None,
    ) -> None:
        self._enabled = enabled
        self._model = model
        self._runtime = runtime
        self._gazetteer_loader = gazetteer_loader

    async def enrich(
        self,
        request: SecurityTriageCreateRequestV4,
        scope: SecurityScopeResponseV4,
    ) -> SecurityScopeResponseV4:
        if (
            scope.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
            and set(scope.scope_reasons) & _LOCAL_CONVERSATION_REASONS
        ):
            rules_only = scope.model_copy(
                update={
                    "assistant_context": _rules_only_context(
                        AssistantProcessingModeV4.RULES_ONLY,
                        scope.assistant_context,
                    )
                }
            )
            return rules_only
        organization_candidates = await self._organization_candidates(request.message, scope)
        scope = self._merge_local_candidates(request.message, scope, organization_candidates)
        if not self._enabled:
            return scope
        if self._model is None:
            return self._fallback(request.message, scope)
        preview_exposure = highest_exposure(
            scope.assistant_context.exposure_state if scope.assistant_context else ExposureStateV4.UNKNOWN,
            detect_local_exposure(request.message),
        )
        selected_slot = select_missing_slot(scope.security_context, preview_exposure)
        # Always provide the policy-selected slot, including on the first vague
        # security turn where no structured context exists yet. This lets the
        # model phrase the one permitted question without choosing policy.
        summary_payload = {
            "security_context": (
                scope.security_context.model_dump(mode="json", exclude_none=True)
                if scope.security_context is not None
                else None
            ),
            "exposure_state": preview_exposure.value,
            "policy_selected_follow_up_slot": selected_slot.value if selected_slot else None,
        }
        if organization_candidates:
            summary_payload["organization_candidates"] = [item.as_prompt_data() for item in organization_candidates]
        phrase_candidates = extract_recovery_phrases(request.message, organization_candidates)
        if phrase_candidates:
            summary_payload["phrase_candidates"] = [item.as_prompt_data() for item in phrase_candidates]
        entity_candidates = [*organization_candidates, *phrase_candidates]
        span_candidates = generate_semantic_span_candidates(request.message, entity_candidates)
        summary_payload["span_candidates"] = [item.as_prompt_data(request.message) for item in span_candidates]
        conversation_summary = json.dumps(
            summary_payload,
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
            entity_candidates=entity_candidates,
            span_candidates=span_candidates,
        )
        return apply_adaptive_conversation_policy(
            request.message,
            merged,
            drafted_slot=result.output.follow_up_slot,
            drafted_question=result.output.follow_up_question,
        )

    async def _organization_candidates(
        self,
        message: str,
        scope: SecurityScopeResponseV4,
    ) -> list[EntityMentionCandidate]:
        brands: list[BrandRecordV4] = []
        if self._gazetteer_loader is not None:
            try:
                brands = await self._gazetteer_loader()
            except Exception:
                brands = []
        gazetteer = OrganizationGazetteer.from_brands(brands)
        literal_entities = (
            (scope.security_context.claimed_entity,)
            if scope.security_context is not None and scope.security_context.claimed_entity
            else ()
        )
        return extract_entity_mentions(
            message,
            literal_entities,
            gazetteer,
        )

    @staticmethod
    def _merge_local_candidates(
        message: str,
        scope: SecurityScopeResponseV4,
        candidates: list[EntityMentionCandidate],
    ) -> SecurityScopeResponseV4:
        context = scope.security_context
        if context is None or not context.urls:
            return scope
        claims = deterministic_entity_url_claims(message, candidates, len(context.urls))
        entity = context.claimed_entity
        if entity is None:
            if claims:
                entity = claims[0].entity_name
            elif len(candidates) == 1:
                entity = candidates[0].text
        combined_claims = list(
            {
                (item.entity_name.casefold(), item.url_index, item.relationship): item
                for item in [*context.entity_url_claims, *claims]
            }.values()
        )
        if entity == context.claimed_entity and combined_claims == context.entity_url_claims:
            return scope
        signals = list(context.impersonation_signals)
        if entity and "claimed_organization" not in signals:
            signals.append("claimed_organization")
        merged = context.model_copy(
            update={
                "claimed_entity": entity,
                "entity_url_claims": combined_claims,
                "impersonation_signals": signals,
            }
        )
        merged = merged.model_copy(update={"potential_threat": derive_potential_threat(merged)})
        return scope.model_copy(update={"security_context": merged})

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
