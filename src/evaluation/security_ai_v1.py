from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from src.core.auth import Principal, UserRole
from src.models import (
    AnalysisStatus,
    AssistantGenerationModeV4,
    AssistantProcessingModeV4,
    ExposureStateV4,
    MissingInformationSlotV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityScenarioV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import (
    AssistantSynthesis,
    ModelResponse,
    ModelUsage,
    SemanticSecuritySignal,
    Understanding,
    UnderstandingSourceSpan,
)
from src.security_ai.runtime import SecurityAssistantRuntime, TurnBudget
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_response import GroundedSecurityResponseService
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_understanding import SecuritySemanticUnderstandingService

SECURITY_AI_EVALUATION_VERSION = "security-ai-eval-v1"
REQUIRED_CATEGORIES = frozenset(
    {
        "recruitment",
        "promotion_prize",
        "credential_theft",
        "financial",
        "incident_exposure",
        "multi_turn",
        "prompt_injection",
        "fallback",
        "out_of_scope",
    }
)
_ADMIN = Principal("security-ai-evaluator", UserRole.USER)
_EVIDENCE_REF = "evidence:0123456789abcdef"
_FIELD_NAMES = (
    "scope_decision",
    "scenario",
    "requested_action",
    "exposure_state",
    "claimed_entity",
    "urgency",
    "credential_request",
    "otp_request",
    "payment_request",
    "personal_information_request",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvaluationUnderstanding(_StrictModel):
    scope_decision: ScopeDecisionV4 | None = None
    sender_intent: str | None = None
    social_engineering_techniques: list[str] = Field(default_factory=list)
    claimed_entity: str | None = None
    scenario: SecurityScenarioV4 | None = None
    requested_action: RequestedActionV4 | None = None
    exposure_state: ExposureStateV4 = ExposureStateV4.UNKNOWN
    security_signals: list[SemanticSecuritySignal] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    follow_up_slot: MissingInformationSlotV4 | None = None
    follow_up_question: str | None = None


class SecurityAIEvaluationTurn(_StrictModel):
    message: str = Field(min_length=1)
    understanding: EvaluationUnderstanding | None = None
    provider_failure: bool = False


class SecurityAIEvaluationExpected(_StrictModel):
    scope_decision: ScopeDecisionV4
    fields: dict[str, str | bool] = Field(default_factory=dict)
    exposure_state: ExposureStateV4
    turns_to_verdict: int | None = Field(default=None, ge=1)
    follow_up_completed: bool = False
    max_provider_calls: int = Field(ge=0)
    fallback_expected: bool = False


class SecurityAIEvaluationCase(_StrictModel):
    dataset_version: Literal["security-ai-eval-v1"]
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    category: str
    scenario_group: str
    turns: list[SecurityAIEvaluationTurn] = Field(min_length=1, max_length=5)
    synthesis_mode: Literal["valid", "invalid_ref", "provider_failure"] = "valid"
    expected: SecurityAIEvaluationExpected


class SecurityAICaseResult(_StrictModel):
    id: str
    category: str
    scenario_group: str
    scope_decision: ScopeDecisionV4
    exposure_state: ExposureStateV4
    actual_turns_to_verdict: int | None
    turn_count: int = Field(ge=1)
    field_true_positive: int
    field_false_positive: int
    field_false_negative: int
    scope_pass: bool
    exposure_pass: bool
    follow_up_pass: bool
    turns_pass: bool
    grounded_reasons: int
    total_reasons: int
    hallucinated_evidence: int
    hallucinated_actions: int
    provider_calls: int
    max_provider_calls: int
    fallback_expected: bool
    fallback_pass: bool
    latency_ms: float
    tokens: int
    cost_usd: float


class _FixtureModel:
    def __init__(
        self,
        understanding: Understanding | None = None,
        *,
        understanding_failure: bool = False,
        synthesis_mode: str = "valid",
    ) -> None:
        self._understanding = understanding
        self._understanding_failure = understanding_failure
        self._synthesis_mode = synthesis_mode

    async def understand(self, message: str, conversation_summary: str | None):
        del message, conversation_summary
        if self._understanding_failure:
            raise RuntimeError("fixture provider failure")
        return ModelResponse(
            output=self._understanding or Understanding(),
            provider="deterministic-fixture",
            model="security-ai-eval-v1",
            usage=ModelUsage(input_tokens=20, output_tokens=10, cost_usd=0.00001),
        )

    async def synthesize(self, result: dict):
        del result
        if self._synthesis_mode == "provider_failure":
            raise RuntimeError("fixture synthesis failure")
        ref = "evidence:ffffffffffffffff" if self._synthesis_mode == "invalid_ref" else _EVIDENCE_REF
        return ModelResponse(
            output=AssistantSynthesis(
                summary="Grounded security evaluation summary.",
                top_reasons=[{"text": "The recorded evidence supports the warning.", "evidence_refs": [ref]}],
            ),
            provider="deterministic-fixture",
            model="security-ai-eval-v1",
            usage=ModelUsage(input_tokens=30, output_tokens=20, cost_usd=0.00002),
        )

    async def prioritize_plan(self, context, candidate_steps):  # pragma: no cover - evaluator boundary
        raise AssertionError("planner is outside the AI quality tier")

    async def draft_admin_review(self, case_detail):  # pragma: no cover - evaluator boundary
        raise AssertionError("admin review is covered by WP7 gates")


def _understanding(message: str, fixture: EvaluationUnderstanding | None) -> Understanding | None:
    if fixture is None:
        return None
    data = fixture.model_dump()
    grounded: list[str] = []
    for field_name in (
        "scope_decision",
        "sender_intent",
        "social_engineering_techniques",
        "claimed_entity",
        "scenario",
        "requested_action",
        "exposure_state",
    ):
        value = data[field_name]
        if value not in (None, [], ExposureStateV4.UNKNOWN):
            grounded.append(field_name)
    grounded.extend(item.value for item in fixture.security_signals)
    return Understanding(
        **data,
        field_confidences={item: 0.95 for item in grounded},
        source_spans=[UnderstandingSourceSpan(field_name=item, start=0, end=len(message)) for item in grounded],
    )


def _positive(value: str | bool | None) -> bool:
    return value not in (None, False, "UNKNOWN", "unknown")


def _predicted_fields(result) -> dict[str, str | bool | None]:
    context = result.security_context
    assistant = result.assistant_context
    return {
        "scope_decision": result.scope_decision.value,
        "scenario": context.scenario.value if context else None,
        "requested_action": context.requested_action.value if context and context.requested_action else None,
        "exposure_state": assistant.exposure_state.value if assistant else ExposureStateV4.UNKNOWN.value,
        "claimed_entity": context.claimed_entity if context else None,
        "urgency": context.urgency if context else False,
        "credential_request": context.credential_request if context else False,
        "otp_request": context.otp_request if context else False,
        "payment_request": context.payment_request if context else False,
        "personal_information_request": context.personal_information_request if context else False,
    }


def _field_counts(predicted: dict[str, str | bool | None], expected: dict[str, str | bool]) -> tuple[int, int, int]:
    tp = fp = fn = 0
    for field_name in _FIELD_NAMES:
        actual = predicted.get(field_name)
        wanted = expected.get(field_name)
        actual_positive = _positive(actual)
        expected_positive = _positive(wanted)
        if actual_positive and expected_positive and actual == wanted:
            tp += 1
        else:
            fp += int(actual_positive)
            fn += int(expected_positive)
    return tp, fp, fn


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _ratio(numerator: int, denominator: int, *, empty: float = 1.0) -> float:
    return round(numerator / denominator, 4) if denominator else empty


def load_ai_evaluation_set(path: str | Path) -> list[SecurityAIEvaluationCase]:
    cases = [
        SecurityAIEvaluationCase.model_validate_json(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not cases or len({case.id for case in cases}) != len(cases):
        raise ValueError("Security AI evaluation requires unique non-empty cases")
    missing = REQUIRED_CATEGORIES - {case.category for case in cases}
    if missing:
        raise ValueError("Security AI evaluation is missing categories: " + ", ".join(sorted(missing)))
    return cases


async def evaluate_ai_case(case: SecurityAIEvaluationCase) -> SecurityAICaseResult:
    analyses = SecurityAnalysisService()
    conversation_id = None
    conversation_version = None
    final = None
    verdict_turn = None
    follow_up_before_verdict = True
    provider_calls = tokens = 0
    cost = latency = 0.0
    fallback_seen = False

    for turn_number, turn in enumerate(case.turns, start=1):
        request = SecurityTriageCreateRequestV4(
            message=turn.message,
            conversation_id=conversation_id,
            conversation_version=conversation_version,
        )
        scoped = SecurityTriageScopeService().assess(request)
        scoped = await analyses.begin_turn(request, scoped, _ADMIN, persist=False)
        runtime = SecurityAssistantRuntime(max_retries=0, budget=TurnBudget(max_calls=4))
        model = _FixtureModel(
            _understanding(turn.message, turn.understanding),
            understanding_failure=turn.provider_failure,
        )
        scoped = await SecuritySemanticUnderstandingService(
            enabled=True,
            model=model,
            runtime=runtime,
        ).enrich(request, scoped)
        final = scoped
        conversation_id = scoped.conversation_id
        conversation_version = scoped.conversation_version
        provider_calls += runtime.budget.calls
        tokens += runtime.budget.input_tokens + runtime.budget.output_tokens
        cost += runtime.budget.cost_usd
        latency += sum(item.latency_ms for item in runtime.metrics)
        fallback_seen = fallback_seen or (
            scoped.assistant_context is not None
            and scoped.assistant_context.processing_mode is AssistantProcessingModeV4.FALLBACK
        )
        if scoped.scope_decision is ScopeDecisionV4.IN_SCOPE and verdict_turn is None:
            verdict_turn = turn_number
        elif verdict_turn is None:
            follow_up_before_verdict = follow_up_before_verdict and bool(scoped.follow_up_question)

    assert final is not None
    grounded_reasons = total_reasons = hallucinated_evidence = hallucinated_actions = 0
    if final.scope_decision is ScopeDecisionV4.IN_SCOPE and final.security_context is not None:
        evidence = SecurityEvidenceV4(
            evidence_ref=_EVIDENCE_REF,
            type=SecurityEvidenceTypeV4.SECURITY_CONTEXT,
            source="security-ai-evaluation",
            signal="evaluated_security_context",
            description="Structured context supports a deterministic warning.",
            observed_at=datetime(2026, 8, 15, tzinfo=UTC),
        )
        completed = final.model_copy(
            update={
                "status": AnalysisStatus.COMPLETED,
                "terminal": True,
                "next_step": "END",
                "investigation_status": SecurityInvestigationStatusV4.COMPLETED,
                "evidence": [evidence],
                "risk": SecurityRiskV4.HIGH_RISK,
                "score": 80,
                "confidence": 0.9,
                "threat_type": final.security_context.potential_threat,
                "policy_version": "security-risk-v1",
                "recommended_actions": [SecurityRecommendedActionV4.DO_NOT_OPEN_LINK],
                "explanation": "Deterministic warning grounded in structured context.",
                "explanation_evidence_refs": [_EVIDENCE_REF],
                "completed_at": datetime.now(UTC),
            }
        )
        runtime = SecurityAssistantRuntime(max_retries=0, budget=TurnBudget(max_calls=4))
        completed = await GroundedSecurityResponseService(
            ai_enabled=True,
            model=_FixtureModel(synthesis_mode=case.synthesis_mode),
            runtime=runtime,
        ).enrich(completed)
        provider_calls += runtime.budget.calls
        tokens += runtime.budget.input_tokens + runtime.budget.output_tokens
        cost += runtime.budget.cost_usd
        latency += sum(item.latency_ms for item in runtime.metrics)
        response = completed.assistant_response
        assert response is not None
        fallback_seen = fallback_seen or response.generation_mode in {
            AssistantGenerationModeV4.POLICY_GROUNDED,
            AssistantGenerationModeV4.TEMPLATE_FALLBACK,
        }
        # A guarded synthesis can now be safely repaired component by
        # component.  Treat that as a successful resilience path rather than
        # requiring an unnecessary all-policy fallback.
        fallback_seen = fallback_seen or any("AI diễn đạt đã được làm sạch" in item for item in completed.limitations)
        available_refs = {item.evidence_ref for item in completed.evidence}
        allowed_actions = set(completed.recommended_actions)
        total_reasons = len(response.top_reasons)
        grounded_reasons = sum(set(reason.evidence_refs) <= available_refs for reason in response.top_reasons)
        hallucinated_evidence = sum(len(set(reason.evidence_refs) - available_refs) for reason in response.top_reasons)
        hallucinated_actions = sum(step.action not in allowed_actions for step in response.immediate_steps)

    predicted = _predicted_fields(final)
    tp, fp, fn = _field_counts(predicted, case.expected.fields)
    turns_pass = case.expected.turns_to_verdict == verdict_turn
    follow_up_pass = follow_up_before_verdict and turns_pass if case.expected.follow_up_completed else True
    safe_out_of_scope_short_circuit = (
        final.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK and provider_calls == 0
    )
    fallback_pass = fallback_seen or safe_out_of_scope_short_circuit if case.expected.fallback_expected else True
    return SecurityAICaseResult(
        id=case.id,
        category=case.category,
        scenario_group=case.scenario_group,
        scope_decision=final.scope_decision,
        exposure_state=(final.assistant_context.exposure_state if final.assistant_context else ExposureStateV4.UNKNOWN),
        actual_turns_to_verdict=verdict_turn,
        turn_count=len(case.turns),
        field_true_positive=tp,
        field_false_positive=fp,
        field_false_negative=fn,
        scope_pass=final.scope_decision is case.expected.scope_decision,
        exposure_pass=(
            final.assistant_context is not None
            and final.assistant_context.exposure_state is case.expected.exposure_state
        ),
        follow_up_pass=follow_up_pass,
        turns_pass=turns_pass,
        grounded_reasons=grounded_reasons,
        total_reasons=total_reasons,
        hallucinated_evidence=hallucinated_evidence,
        hallucinated_actions=hallucinated_actions,
        provider_calls=provider_calls,
        max_provider_calls=case.expected.max_provider_calls,
        fallback_expected=case.expected.fallback_expected,
        fallback_pass=fallback_pass,
        latency_ms=round(latency, 3),
        tokens=tokens,
        cost_usd=round(cost, 6),
    )


async def evaluate_ai_set(cases: list[SecurityAIEvaluationCase]) -> dict[str, object]:
    results = [await evaluate_ai_case(case) for case in cases]
    tp = sum(item.field_true_positive for item in results)
    fp = sum(item.field_false_positive for item in results)
    fn = sum(item.field_false_negative for item in results)
    reason_count = sum(item.total_reasons for item in results)
    provider_calls = sum(item.provider_calls for item in results)
    unnecessary = sum(max(0, item.provider_calls - item.max_provider_calls) for item in results)
    fallback_cases = [item for item in results if item.fallback_expected]
    expected_by_id = {item.id: item.expected for item in cases}
    follow_up_cases = [item for item in results if expected_by_id[item.id].follow_up_completed]
    verdict_cases = [item for item in results if expected_by_id[item.id].turns_to_verdict is not None]
    scenarios: dict[str, dict[str, float | int]] = {}
    for scenario in sorted({item.scenario_group for item in results}):
        selected = [item for item in results if item.scenario_group == scenario]
        scenario_tp = sum(item.field_true_positive for item in selected)
        scenario_fp = sum(item.field_false_positive for item in selected)
        scenario_fn = sum(item.field_false_negative for item in selected)
        scenarios[scenario] = {
            "case_count": len(selected),
            "precision": _ratio(scenario_tp, scenario_tp + scenario_fp),
            "recall": _ratio(scenario_tp, scenario_tp + scenario_fn),
        }
    per_turn_tokens = [item.tokens / item.turn_count for item in results]
    per_turn_cost = [item.cost_usd / item.turn_count for item in results]
    per_turn_latency = [item.latency_ms / item.turn_count for item in results]
    metrics = {
        "case_count": len(results),
        "field_precision": _ratio(tp, tp + fp),
        "field_recall": _ratio(tp, tp + fn),
        "field_metrics_by_scenario": scenarios,
        "scope_routing_accuracy": _ratio(sum(item.scope_pass for item in results), len(results)),
        "exposure_state_accuracy": _ratio(sum(item.exposure_pass for item in results), len(results)),
        "follow_up_completion_rate": _ratio(sum(item.follow_up_pass for item in follow_up_cases), len(follow_up_cases)),
        "turns_to_verdict_accuracy": _ratio(sum(item.turns_pass for item in verdict_cases), len(verdict_cases)),
        "grounded_reason_rate": _ratio(sum(item.grounded_reasons for item in results), reason_count),
        "hallucinated_evidence_rate": _ratio(
            sum(item.hallucinated_evidence for item in results), reason_count, empty=0
        ),
        "hallucinated_action_rate": _ratio(sum(item.hallucinated_actions for item in results), reason_count, empty=0),
        "unnecessary_provider_call_rate": _ratio(unnecessary, provider_calls, empty=0),
        "llm_fallback_success_rate": _ratio(sum(item.fallback_pass for item in fallback_cases), len(fallback_cases)),
        "p95_latency_ms": round(_percentile(per_turn_latency, 0.95), 3),
        "p95_tokens_per_turn": int(_percentile(per_turn_tokens, 0.95)),
        "p95_cost_usd_per_turn": round(_percentile(per_turn_cost, 0.95), 6),
        "mean_tokens_per_turn": round(fmean(per_turn_tokens), 2),
        "mean_cost_usd_per_turn": round(fmean(per_turn_cost), 6),
    }
    gates = {
        "field_precision": metrics["field_precision"] >= 0.90,
        "field_recall": metrics["field_recall"] >= 0.90,
        "scope_routing_accuracy": metrics["scope_routing_accuracy"] >= 0.95,
        "exposure_state_accuracy": metrics["exposure_state_accuracy"] >= 0.95,
        "follow_up_completion_rate": metrics["follow_up_completion_rate"] == 1,
        "turns_to_verdict_accuracy": metrics["turns_to_verdict_accuracy"] == 1,
        "grounded_reason_rate": metrics["grounded_reason_rate"] == 1,
        "hallucinated_evidence_rate": metrics["hallucinated_evidence_rate"] == 0,
        "hallucinated_action_rate": metrics["hallucinated_action_rate"] == 0,
        "unnecessary_provider_call_rate": metrics["unnecessary_provider_call_rate"] == 0,
        "llm_fallback_success_rate": metrics["llm_fallback_success_rate"] == 1,
        "p95_latency_ms": metrics["p95_latency_ms"] <= 15_000,
        "p95_tokens_per_turn": metrics["p95_tokens_per_turn"] <= 10_000,
        "p95_cost_usd_per_turn": metrics["p95_cost_usd_per_turn"] <= 0.05,
    }
    canonical = "\n".join(case.model_dump_json(exclude_none=True) for case in sorted(cases, key=lambda item: item.id))
    return {
        "dataset_version": SECURITY_AI_EVALUATION_VERSION,
        "dataset_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "evaluation_profile": "offline_ai_understanding_conversation_grounding",
        "threshold_profile": "security-ai-release-gates-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "limitations": [
            "Deterministic model fixtures validate orchestration and safety contracts; hosted OIDC, PostgreSQL, Redis, live-provider reliability, latency, token, and cost evidence remains mandatory before rollout."
        ],
        "metrics": metrics,
        "gates": gates,
        "passed": all(gates.values()),
        "cases": [item.model_dump(mode="json") for item in results],
    }


def write_ai_report(report: dict[str, object], output: str | Path) -> None:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "REQUIRED_CATEGORIES",
    "SECURITY_AI_EVALUATION_VERSION",
    "SecurityAIEvaluationCase",
    "evaluate_ai_case",
    "evaluate_ai_set",
    "load_ai_evaluation_set",
    "write_ai_report",
]
