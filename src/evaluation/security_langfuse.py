"""Versioned Security Triage evaluation models, metrics, and Langfuse adapters."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from statistics import fmean
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.models import PotentialThreatV4, ScopeDecisionV4, SecurityInvestigationToolV4, SecurityRiskV4

SECURITY_LANGFUSE_DATASET_VERSION = "security-triage-langfuse-v1"
DEFAULT_LANGFUSE_DATASET = "trustguard-security-triage-v1"
_SECRET_RE = re.compile(
    r"(?i)(?:otp|password|mật khẩu|token|secret|api[_ -]?key|authorization)\s*[:=]\s*\S+"
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SecurityAction(StrEnum):
    ALLOW = "ALLOW"
    CAUTION = "CAUTION"
    DO_NOT_PROCEED = "DO_NOT_PROCEED"
    NEEDS_MORE_INFO = "NEEDS_MORE_INFO"


class DatasetSplit(StrEnum):
    DEV = "dev"
    TEST = "test"


class MetricStatus(StrEnum):
    SCORED = "scored"
    UNAVAILABLE = "unavailable"


class EvaluationConsent(_StrictModel):
    external_url_lookup: bool = False
    official_source_lookup: bool = False


class EvaluationInput(_StrictModel):
    message: str = Field(min_length=1, max_length=5000)
    prior_turns: list[str] = Field(default_factory=list, max_length=4)
    consent: EvaluationConsent = Field(default_factory=EvaluationConsent)
    execution_mode: Literal["inline"] = "inline"


class EvaluationExpectedOutput(_StrictModel):
    scope_decision: ScopeDecisionV4
    security_action: SecurityAction
    accepted_risks: list[SecurityRiskV4] = Field(min_length=1)
    threat_type: PotentialThreatV4 | None = None
    required_actions: list[str] = Field(default_factory=list)
    required_response_elements: list[
        Literal["summary", "reasons", "uncertainties", "immediate_steps", "follow_up"]
    ] = Field(default_factory=lambda: ["summary", "immediate_steps"])
    required_tools: list[SecurityInvestigationToolV4] = Field(default_factory=list)
    allowed_tools: list[SecurityInvestigationToolV4] = Field(default_factory=list)
    forbidden_tools: list[SecurityInvestigationToolV4] = Field(default_factory=list)
    max_provider_calls: int = Field(default=8, ge=0)

    @model_validator(mode="after")
    def validate_tool_policy(self) -> Self:
        required, allowed, forbidden = map(set, (self.required_tools, self.allowed_tools, self.forbidden_tools))
        if required - allowed:
            raise ValueError("required tools must also be allowed")
        if (required | allowed) & forbidden:
            raise ValueError("allowed/required tools cannot be forbidden")
        if self.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK and self.max_provider_calls:
            raise ValueError("out-of-scope cases must allow zero provider calls")
        return self


class EvaluationMetadata(_StrictModel):
    category: str = Field(pattern=r"^[a-z0-9_]+$")
    difficulty: Literal["easy", "medium", "hard"]
    language: Literal["vi"] = "vi"
    polarity: Literal["unsafe", "benign", "abstain"]
    split: DatasetSplit
    source: Literal["synthetic"] = "synthetic"
    tags: list[str] = Field(default_factory=list)
    annotation_rationale: str = Field(min_length=1, max_length=1000)


class SecurityEvaluationCase(_StrictModel):
    dataset_version: Literal["security-triage-langfuse-v1"]
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    input: EvaluationInput
    expected_output: EvaluationExpectedOutput
    metadata: EvaluationMetadata

    @model_validator(mode="after")
    def validate_label_coherence(self) -> Self:
        expected_polarity = {
            SecurityAction.DO_NOT_PROCEED: "unsafe",
            SecurityAction.ALLOW: "benign",
            SecurityAction.CAUTION: "benign",
            SecurityAction.NEEDS_MORE_INFO: "abstain",
        }[self.expected_output.security_action]
        if self.metadata.polarity != expected_polarity:
            raise ValueError("polarity must agree with expected security action")
        if _SECRET_RE.search(self.input.message):
            raise ValueError("evaluation messages must not contain literal secret values")
        return self


class TraceOutput(_StrictModel):
    status: str | None = None
    scope: str | None = None
    risk: str | None = None
    threat_type: str | None = None
    recommended_actions: list[str] | None = None
    tools_called: list[str] | None = None
    tool_calls_used: int | None = Field(default=None, ge=0)
    evidence_refs: list[str] | None = None
    explanation_evidence_refs: list[str] | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)
    assistant_response: dict[str, Any] | None = None
    boundary_message: str | None = None
    follow_up_question: str | None = None
    latency_ms: float | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)


class MetricResult(_StrictModel):
    name: str
    value: float | int | None
    status: MetricStatus = MetricStatus.SCORED
    reason: str
    failure_codes: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class CaseEvaluation(_StrictModel):
    case_id: str
    category: str
    split: DatasetSplit
    expected_action: SecurityAction
    actual_action: SecurityAction | None
    metrics: list[MetricResult]
    latency_ms: float | None = None
    cost_usd: float | None = None


def load_security_evaluation_set(path: str | Path) -> list[SecurityEvaluationCase]:
    cases = [
        SecurityEvaluationCase.model_validate_json(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(cases) != 40:
        raise ValueError(f"security evaluation dataset must contain exactly 40 cases, got {len(cases)}")
    if len({case.id for case in cases}) != len(cases):
        raise ValueError("security evaluation case IDs must be unique")
    if {case.metadata.split for case in cases} != {DatasetSplit.DEV, DatasetSplit.TEST}:
        raise ValueError("security evaluation dataset must contain dev and test splits")
    if {case.metadata.polarity for case in cases} != {"unsafe", "benign", "abstain"}:
        raise ValueError("security evaluation dataset must cover unsafe, benign, and abstain labels")
    return cases


def dataset_sha256(cases: list[SecurityEvaluationCase]) -> str:
    canonical = "\n".join(case.model_dump_json(exclude_none=True) for case in sorted(cases, key=lambda c: c.id))
    return hashlib.sha256(canonical.encode()).hexdigest()


def to_langfuse_item(case: SecurityEvaluationCase) -> dict[str, Any]:
    return {
        "input": case.input.model_dump(mode="json"),
        "expected_output": case.expected_output.model_dump(mode="json", exclude_none=True),
        "metadata": {
            **case.metadata.model_dump(mode="json"),
            "case_id": case.id,
            "dataset_version": case.dataset_version,
        },
    }


_UNSAFE_RISKS = {SecurityRiskV4.SUSPICIOUS.value, SecurityRiskV4.HIGH_RISK.value, SecurityRiskV4.MALICIOUS.value}
_CAUTION_ACTIONS = {"PROCEED_WITH_CAUTION", "VERIFY_VIA_OFFICIAL_CHANNEL"}
_BLOCK_ACTIONS = {
    "DO_NOT_OPEN_LINK",
    "DO_NOT_SHARE_CREDENTIALS",
    "DO_NOT_SHARE_OTP",
    "DO_NOT_TRANSFER_MONEY",
    "CLOSE_PAGE_AND_DO_NOT_RETURN",
}


def infer_security_action(output: TraceOutput) -> SecurityAction | None:
    if output.scope == ScopeDecisionV4.NEED_MORE_INFO.value:
        return SecurityAction.NEEDS_MORE_INFO
    if output.scope == ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK.value:
        return SecurityAction.NEEDS_MORE_INFO
    actions = set(output.recommended_actions or [])
    if actions & _BLOCK_ACTIONS or output.risk in _UNSAFE_RISKS:
        return SecurityAction.DO_NOT_PROCEED
    if "ALLOW_OPEN" in actions or output.risk == SecurityRiskV4.SAFE.value:
        return SecurityAction.ALLOW
    if actions & _CAUTION_ACTIONS or output.risk == SecurityRiskV4.LOW_RISK.value:
        return SecurityAction.CAUTION
    if output.risk == SecurityRiskV4.INSUFFICIENT_EVIDENCE.value:
        return SecurityAction.NEEDS_MORE_INFO
    return None


def _metric(name: str, passed: bool, reason: str, *failure_codes: str, details: dict[str, Any] | None = None):
    return MetricResult(
        name=name,
        value=int(passed),
        reason=reason,
        failure_codes=[] if passed else list(failure_codes),
        details=details or {},
    )


def _unavailable(name: str, reason: str) -> MetricResult:
    return MetricResult(name=name, value=None, status=MetricStatus.UNAVAILABLE, reason=reason)


def evaluate_case(case: SecurityEvaluationCase, output: TraceOutput) -> CaseEvaluation:
    expected = case.expected_output
    actual_action = infer_security_action(output)
    accepted_risks = {risk.value for risk in expected.accepted_risks}
    risk_ok = (
        output.risk in accepted_risks
        if expected.scope_decision is ScopeDecisionV4.IN_SCOPE
        else output.risk is None or output.risk in accepted_risks
    )
    decision_ok = actual_action is expected.security_action and risk_ok
    decision = _metric(
        "security_decision_accuracy",
        decision_ok,
        (
            f"expected {expected.security_action.value}/{sorted(accepted_risks)}, observed "
            f"{actual_action.value if actual_action else 'UNKNOWN'}/{output.risk or 'NONE'}"
        ),
        "security_decision_mismatch",
    )

    response = output.assistant_response
    if expected.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK:
        completed = output.scope == expected.scope_decision.value and output.tool_calls_used == 0
        completion = _metric(
            "task_completion",
            completed,
            "out-of-scope request terminated without provider calls" if completed else "out-of-scope termination failed",
            "out_of_scope_not_terminated",
        )
    elif expected.scope_decision is ScopeDecisionV4.NEED_MORE_INFO:
        completed = output.scope == expected.scope_decision.value and bool(output.follow_up_question)
        completion = _metric(
            "task_completion",
            completed,
            "a targeted follow-up was returned" if completed else "need-more-info response lacks a follow-up question",
            "missing_follow_up",
        )
    elif response is None:
        completion = _unavailable("task_completion", "assistant response was not captured in this observation")
    else:
        missing = []
        for element in expected.required_response_elements:
            key = {"reasons": "top_reasons", "immediate_steps": "immediate_steps"}.get(element, element)
            if response.get(key) in (None, "", []):
                missing.append(element)
        actual_steps = {
            item.get("action") for item in response.get("immediate_steps", []) if isinstance(item, dict)
        }
        missing_actions = sorted(set(expected.required_actions) - actual_steps)
        completion_ok = not missing and not missing_actions and output.status not in {"failed", "error"}
        completion = _metric(
            "task_completion",
            completion_ok,
            "all required response elements and actions are present" if completion_ok else "required response content is missing",
            "incomplete_response",
            details={"missing_elements": missing, "missing_actions": missing_actions},
        )

    if output.tools_called is None:
        tool_correctness = _unavailable("tool_correctness", "tool identities were not captured in this observation")
    else:
        called = set(output.tools_called)
        required = {tool.value for tool in expected.required_tools}
        forbidden = {tool.value for tool in expected.forbidden_tools}
        missing_tools = sorted(required - called)
        forbidden_tools = sorted(forbidden & called)
        over_budget = (output.tool_calls_used or len(output.tools_called)) > expected.max_provider_calls
        tool_ok = not missing_tools and not forbidden_tools and not over_budget
        failure_codes = []
        if missing_tools:
            failure_codes.append("required_tool_missing")
        if forbidden_tools:
            failure_codes.append("forbidden_or_unconsented_tool")
        if over_budget:
            failure_codes.append("provider_call_budget_exceeded")
        tool_correctness = _metric(
            "tool_correctness",
            tool_ok,
            "tool policy satisfied" if tool_ok else "tool call policy mismatch",
            *failure_codes,
            details={"missing": missing_tools, "forbidden": forbidden_tools, "called": sorted(called)},
        )

    if response is None or output.evidence_refs is None:
        faithfulness = _unavailable("faithfulness", "response or evidence-reference inventory is unavailable")
    else:
        available = set(output.evidence_refs)
        cited = {
            ref
            for reason in response.get("top_reasons", [])
            if isinstance(reason, dict)
            for ref in reason.get("evidence_refs", [])
        }
        cited.update(output.explanation_evidence_refs or [])
        fabricated = sorted(cited - available)
        response_actions = {
            item.get("action") for item in response.get("immediate_steps", []) if isinstance(item, dict)
        }
        unsupported_actions = sorted(response_actions - set(output.recommended_actions or []))
        faithful = not fabricated and not unsupported_actions
        faithfulness = _metric(
            "faithfulness",
            faithful,
            "all claims close over policy evidence/actions" if faithful else "response introduced unsupported evidence or actions",
            "unsupported_evidence_or_action",
            details={"fabricated_refs": fabricated, "unsupported_actions": unsupported_actions},
        )

    contextual = _unavailable(
        "contextual_precision",
        "requires a calibrated LLM judge; deterministic evidence precision remains in faithfulness",
    )
    return CaseEvaluation(
        case_id=case.id,
        category=case.metadata.category,
        split=case.metadata.split,
        expected_action=expected.security_action,
        actual_action=actual_action,
        metrics=[decision, completion, tool_correctness, contextual, faithfulness],
        latency_ms=output.latency_ms,
        cost_usd=output.cost_usd,
    )


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(len(ordered) * percentile) - 1)], 6)


def aggregate_results(results: list[CaseEvaluation]) -> dict[str, Any]:
    binary = [item for item in results if item.expected_action is not SecurityAction.NEEDS_MORE_INFO]
    tp = sum(item.expected_action is SecurityAction.DO_NOT_PROCEED and item.actual_action is SecurityAction.DO_NOT_PROCEED for item in binary)
    fp = sum(item.expected_action is not SecurityAction.DO_NOT_PROCEED and item.actual_action is SecurityAction.DO_NOT_PROCEED for item in binary)
    fn = sum(item.expected_action is SecurityAction.DO_NOT_PROCEED and item.actual_action is not SecurityAction.DO_NOT_PROCEED for item in binary)
    tn = sum(item.expected_action is not SecurityAction.DO_NOT_PROCEED and item.actual_action is not SecurityAction.DO_NOT_PROCEED for item in binary)
    abstentions = sum(item.actual_action in {None, SecurityAction.NEEDS_MORE_INFO} for item in results)
    failures = Counter(code for item in results for metric in item.metrics for code in metric.failure_codes)
    metric_values: dict[str, list[float]] = {}
    unavailable: Counter[str] = Counter()
    for item in results:
        for metric in item.metrics:
            if metric.status is MetricStatus.SCORED and metric.value is not None:
                metric_values.setdefault(metric.name, []).append(float(metric.value))
            else:
                unavailable[metric.name] += 1
    latency = [item.latency_ms for item in results if item.latency_ms is not None]
    cost = [item.cost_usd for item in results if item.cost_usd is not None]
    return {
        "case_count": len(results),
        "metrics": {name: round(fmean(values), 4) for name, values in sorted(metric_values.items())},
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "security_accuracy": _safe_ratio(tp + tn, len(binary)),
        "false_positive_rate": _safe_ratio(fp, fp + tn),
        "false_negative_rate": _safe_ratio(fn, fn + tp),
        "abstention_rate": _safe_ratio(abstentions, len(results)),
        "latency_ms": {"mean": round(fmean(latency), 3) if latency else None, "p50": _percentile(latency, 0.5), "p95": _percentile(latency, 0.95)},
        "cost_usd": {"mean": round(fmean(cost), 6) if cost else None, "p50": _percentile(cost, 0.5), "p95": _percentile(cost, 0.95)},
        "unavailable_metric_counts": dict(sorted(unavailable.items())),
        "failure_taxonomy": dict(failures.most_common()),
    }


def build_report(cases: list[SecurityEvaluationCase], results: list[CaseEvaluation], *, source: str) -> dict[str, Any]:
    by_split = {
        split.value: aggregate_results([item for item in results if item.split is split]) for split in DatasetSplit
    }
    categories = {
        category: aggregate_results([item for item in results if item.category == category])
        for category in sorted({item.category for item in results})
    }
    return {
        "evaluation_version": SECURITY_LANGFUSE_DATASET_VERSION,
        "dataset_sha256": dataset_sha256(cases),
        "source": source,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": aggregate_results(results),
        "splits": by_split,
        "categories": categories,
        "cases": [item.model_dump(mode="json") for item in results],
    }


def write_report(report: dict[str, Any], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "DEFAULT_LANGFUSE_DATASET",
    "CaseEvaluation",
    "DatasetSplit",
    "MetricResult",
    "MetricStatus",
    "SecurityAction",
    "SecurityEvaluationCase",
    "TraceOutput",
    "aggregate_results",
    "build_report",
    "dataset_sha256",
    "evaluate_case",
    "load_security_evaluation_set",
    "to_langfuse_item",
    "write_report",
]
