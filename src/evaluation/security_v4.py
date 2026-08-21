from __future__ import annotations

import hashlib
import json
import math
import time
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.agents.security_investigation import build_security_investigation_plan
from src.agents.security_risk import assess_security_risk
from src.models import (
    ExposureStateV4,
    PotentialThreatV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityInvestigationStepStatusV4,
    SecurityInvestigationToolV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityScenarioV4,
    SecurityToolErrorV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import (
    SemanticSecuritySignal,
    Understanding,
    UnderstandingSourceSpan,
)
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_understanding import merge_semantic_understanding

SECURITY_V4_EVALUATION_VERSION = "security-v4-eval-v1"
REQUIRED_CATEGORIES = frozenset(
    {
        "phishing",
        "credential_otp",
        "financial",
        "recruitment",
        "promotion_prize",
        "brand_impersonation",
        "safe_whitelist",
        "mismatch_only",
        "new_domain_only",
        "provider_timeout",
        "provider_no_hit",
        "out_of_scope",
        "need_more_info",
        "multi_turn",
        "no_consent",
        "wide_action",
        "semantic_typo",
        "semantic_no_diacritics",
        "semantic_slang",
        "semantic_indirect",
        "semantic_install_app",
        "semantic_screen_share",
        "semantic_qr_payment",
        "semantic_prompt_injection",
    }
)
EXTERNAL_TOOLS = frozenset(
    {
        SecurityInvestigationToolV4.DNS,
        SecurityInvestigationToolV4.REDIRECT_RESOLVER,
        SecurityInvestigationToolV4.RDAP,
        SecurityInvestigationToolV4.URL_REPUTATION,
    }
)
HIGH_RISKS = frozenset({SecurityRiskV4.HIGH_RISK, SecurityRiskV4.MALICIOUS})
RELEASE_BASELINE = {
    "malicious_precision": 1.0,
    "false_positive_rate": 0.0,
    "unnecessary_provider_call_rate": 0.0,
}


class EvaluationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: SecurityEvidenceTypeV4
    signal: str = Field(min_length=1)
    description: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)


class EvaluationExpected(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_decision: ScopeDecisionV4
    threat_type: PotentialThreatV4 | None = None
    accepted_risks: list[SecurityRiskV4] = Field(default_factory=list)
    required_tools: list[SecurityInvestigationToolV4] = Field(default_factory=list)
    forbidden_tools: list[SecurityInvestigationToolV4] = Field(default_factory=list)
    max_provider_calls: int = Field(default=0, ge=0)
    high_risk: bool = False
    required_actions: list[SecurityRecommendedActionV4] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_scope_expectations(self) -> EvaluationExpected:
        if self.scope_decision is ScopeDecisionV4.IN_SCOPE:
            if self.threat_type is None or not self.accepted_risks:
                raise ValueError("in-scope evaluation requires threat_type and accepted_risks")
        elif self.threat_type is not None or self.accepted_risks or self.required_tools:
            raise ValueError("out-of-scope evaluation cannot require investigation output")
        return self


class EvaluationSemanticUnderstanding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_decision: ScopeDecisionV4 | None = None
    sender_intent: str | None = None
    social_engineering_techniques: list[str] = Field(default_factory=list)
    claimed_entity: str | None = None
    scenario: SecurityScenarioV4 | None = None
    requested_action: RequestedActionV4 | None = None
    exposure_state: ExposureStateV4 = ExposureStateV4.UNKNOWN
    security_signals: list[SemanticSecuritySignal] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)


class SecurityEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_version: str
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    category: str
    message: str = Field(min_length=1)
    conversation_turn: int = Field(default=1, ge=1)
    consent: dict[str, bool] = Field(default_factory=dict)
    fixture_evidence: list[EvaluationEvidence] = Field(default_factory=list)
    fixture_error: str | None = None
    estimated_cost_usd: float = Field(default=0, ge=0)
    semantic_understanding: EvaluationSemanticUnderstanding | None = None
    expected: EvaluationExpected


class EvaluationCaseResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    scope_decision: ScopeDecisionV4
    threat_type: PotentialThreatV4 | None
    risk: SecurityRiskV4 | None
    planned_tools: list[SecurityInvestigationToolV4]
    planned_provider_calls: int
    routing_pass: bool
    scope_pass: bool
    threat_pass: bool
    risk_pass: bool
    actions_pass: bool
    grounding_pass: bool
    latency_ms: float
    estimated_cost_usd: float


def _evidence_ref(case_id: str, signal: str) -> str:
    digest = hashlib.sha256(f"{case_id}\0{signal}".encode()).hexdigest()[:16]
    return f"evidence:{digest}"


def _fixture_evidence(case: SecurityEvaluationCase) -> list[SecurityEvidenceV4]:
    observed_at = datetime(2026, 8, 14, tzinfo=UTC)
    context = SecurityEvidenceV4(
        evidence_ref=_evidence_ref(case.id, "security_context"),
        type=SecurityEvidenceTypeV4.SECURITY_CONTEXT,
        source="security-v4-evaluation",
        signal="security_context_extracted",
        description="Structured SecurityContext extracted by the production scope boundary.",
        observed_at=observed_at,
        provenance_ref=f"dataset:{case.dataset_version}:{case.id}",
    )
    injected = [
        SecurityEvidenceV4(
            evidence_ref=_evidence_ref(case.id, item.signal),
            type=item.type,
            source="security-v4-evaluation-fixture",
            signal=item.signal,
            description=item.description,
            observed_at=observed_at,
            confidence=item.confidence,
            provenance_ref=f"dataset:{case.dataset_version}:{case.id}",
        )
        for item in case.fixture_evidence
    ]
    return [context, *injected]


def _semantic_fixture_output(case: SecurityEvaluationCase) -> Understanding | None:
    fixture = case.semantic_understanding
    if fixture is None:
        return None
    field_names: list[str] = []
    for field_name in (
        "scope_decision",
        "sender_intent",
        "social_engineering_techniques",
        "claimed_entity",
        "scenario",
        "requested_action",
        "exposure_state",
    ):
        value = getattr(fixture, field_name)
        if value not in (None, [], ExposureStateV4.UNKNOWN):
            field_names.append(field_name)
    field_names.extend(signal.value for signal in fixture.security_signals)
    return Understanding(
        **fixture.model_dump(),
        field_confidences={field_name: 0.95 for field_name in field_names},
        source_spans=[
            UnderstandingSourceSpan(
                field_name=field_name,
                start=0,
                end=len(case.message),
            )
            for field_name in field_names
        ],
    )


def load_evaluation_set(path: str | Path) -> list[SecurityEvaluationCase]:
    source = Path(path)
    cases = [
        SecurityEvaluationCase.model_validate_json(line)
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not cases:
        raise ValueError("security evaluation set must not be empty")
    if len({case.id for case in cases}) != len(cases):
        raise ValueError("security evaluation case IDs must be unique")
    versions = {case.dataset_version for case in cases}
    if versions != {SECURITY_V4_EVALUATION_VERSION}:
        raise ValueError(f"unexpected evaluation dataset versions: {sorted(versions)}")
    missing = REQUIRED_CATEGORIES - {case.category for case in cases}
    if missing:
        raise ValueError("security evaluation set is missing categories: " + ", ".join(sorted(missing)))
    return cases


def evaluate_case(case: SecurityEvaluationCase) -> EvaluationCaseResult:
    started = time.perf_counter()
    request = SecurityTriageCreateRequestV4(
        message=case.message,
        consent={
            "external_url_lookup": case.consent.get("external_url_lookup", False),
        },
    )
    scoped = SecurityTriageScopeService().assess(request)
    semantic_output = _semantic_fixture_output(case)
    if semantic_output is not None:
        scoped = merge_semantic_understanding(
            case.message,
            scoped,
            semantic_output,
            model_version="deterministic-semantic-eval-v1",
        )
    plan = []
    result = scoped
    if scoped.scope_decision is ScopeDecisionV4.IN_SCOPE and scoped.security_context is not None:
        plan = build_security_investigation_plan(
            scoped.security_context,
            external_url_lookup=request.consent.external_url_lookup,
        )
        errors = []
        if case.fixture_error:
            errors.append(
                SecurityToolErrorV4(
                    tool=SecurityInvestigationToolV4.URL_REPUTATION,
                    target="fixture-target",
                    code=case.fixture_error,
                    message="Deterministic evaluation provider outcome.",
                    retryable=case.fixture_error == "PROVIDER_TIMEOUT",
                    provider="security-v4-evaluation-fixture",
                )
            )
        result = scoped.model_copy(
            update={
                "next_step": "RISK_ASSESSMENT",
                "investigation_status": (
                    SecurityInvestigationStatusV4.PARTIAL if errors else SecurityInvestigationStatusV4.COMPLETED
                ),
                "investigation_plan": plan,
                "evidence": _fixture_evidence(case),
                "errors": errors,
                "limitations": [*scoped.limitations, *(["Provider outcome unavailable."] if errors else [])],
                "tool_calls_used": sum(
                    step.tool in EXTERNAL_TOOLS and step.status is SecurityInvestigationStepStatusV4.PENDING
                    for step in plan
                ),
            }
        )
        result = assess_security_risk(result)

    tools = list(dict.fromkeys(step.tool for step in plan))
    provider_calls = sum(
        step.tool in EXTERNAL_TOOLS and step.status is SecurityInvestigationStepStatusV4.PENDING for step in plan
    )
    expected = case.expected
    evidence_refs = {item.evidence_ref for item in result.evidence}
    grounding_pass = (
        result.scope_decision is not ScopeDecisionV4.IN_SCOPE
        or bool(result.explanation)
        and bool(result.explanation_evidence_refs)
        and set(result.explanation_evidence_refs) <= evidence_refs
    )
    return EvaluationCaseResult(
        id=case.id,
        category=case.category,
        scope_decision=result.scope_decision,
        threat_type=result.threat_type,
        risk=result.risk,
        planned_tools=tools,
        planned_provider_calls=provider_calls,
        routing_pass=(
            set(expected.required_tools) <= set(tools)
            and not set(expected.forbidden_tools) & set(tools)
            and provider_calls <= expected.max_provider_calls
        ),
        scope_pass=result.scope_decision is expected.scope_decision,
        threat_pass=result.threat_type is expected.threat_type,
        risk_pass=(result.risk in expected.accepted_risks if expected.accepted_risks else result.risk is None),
        actions_pass=set(expected.required_actions) <= set(result.recommended_actions),
        grounding_pass=grounding_pass,
        latency_ms=round((time.perf_counter() - started) * 1000, 3),
        estimated_cost_usd=case.estimated_cost_usd,
    )


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)] if ordered else 0.0


def evaluate_set(cases: list[SecurityEvaluationCase]) -> dict[str, object]:
    results = [evaluate_case(case) for case in cases]
    expected_by_id = {case.id: case.expected for case in cases}
    true_positive = false_positive = false_negative = true_negative = 0
    malicious_true_positive = malicious_false_positive = 0
    unnecessary_calls = total_provider_calls = 0
    for result in results:
        expected = expected_by_id[result.id]
        predicted_high = result.risk in HIGH_RISKS
        if expected.high_risk and predicted_high:
            true_positive += 1
        elif not expected.high_risk and predicted_high:
            false_positive += 1
        elif expected.high_risk:
            false_negative += 1
        else:
            true_negative += 1
        if result.risk is SecurityRiskV4.MALICIOUS:
            if SecurityRiskV4.MALICIOUS in expected.accepted_risks:
                malicious_true_positive += 1
            else:
                malicious_false_positive += 1
        total_provider_calls += result.planned_provider_calls
        unnecessary_calls += max(0, result.planned_provider_calls - expected.max_provider_calls)

    metrics = {
        "case_count": len(results),
        "scope_accuracy": _ratio(sum(item.scope_pass for item in results), len(results)),
        "tool_routing_accuracy": _ratio(sum(item.routing_pass for item in results), len(results)),
        "threat_accuracy": _ratio(sum(item.threat_pass for item in results), len(results)),
        "risk_accuracy": _ratio(sum(item.risk_pass for item in results), len(results)),
        "grounded_explanation_rate": _ratio(sum(item.grounding_pass for item in results), len(results)),
        "action_accuracy": _ratio(sum(item.actions_pass for item in results), len(results)),
        "high_risk_precision": _ratio(true_positive, true_positive + false_positive),
        "high_risk_recall": _ratio(true_positive, true_positive + false_negative),
        "false_positive_rate": _ratio(false_positive, false_positive + true_negative),
        "false_negative_rate": _ratio(false_negative, false_negative + true_positive),
        "malicious_precision": _ratio(
            malicious_true_positive,
            malicious_true_positive + malicious_false_positive,
        ),
        "unnecessary_provider_call_rate": _ratio(unnecessary_calls, total_provider_calls),
        "mean_latency_ms": round(fmean(item.latency_ms for item in results), 3),
        "p95_latency_ms": round(_percentile([item.latency_ms for item in results], 0.95), 3),
        "p95_estimated_cost_usd": round(_percentile([item.estimated_cost_usd for item in results], 0.95), 6),
        "total_estimated_cost_usd": round(sum(item.estimated_cost_usd for item in results), 6),
    }
    gates = {
        "scope_accuracy": metrics["scope_accuracy"] >= 0.95,
        "tool_routing_accuracy": metrics["tool_routing_accuracy"] >= 0.95,
        "risk_accuracy": metrics["risk_accuracy"] >= 0.90,
        "grounded_explanation_rate": metrics["grounded_explanation_rate"] == 1,
        "high_risk_recall": metrics["high_risk_recall"] >= 0.90,
        "malicious_precision_no_regression": (
            metrics["malicious_precision"] >= RELEASE_BASELINE["malicious_precision"]
        ),
        "false_positive_rate_no_regression": (
            metrics["false_positive_rate"] <= RELEASE_BASELINE["false_positive_rate"]
        ),
        "unnecessary_provider_call_rate": (
            metrics["unnecessary_provider_call_rate"] <= RELEASE_BASELINE["unnecessary_provider_call_rate"]
        ),
        "p95_latency_ms": metrics["p95_latency_ms"] <= 15_000,
        "p95_estimated_cost_usd": metrics["p95_estimated_cost_usd"] <= 0.05,
    }
    dataset_payload = "\n".join(
        case.model_dump_json(exclude_none=True) for case in sorted(cases, key=lambda item: item.id)
    )
    return {
        "dataset_version": SECURITY_V4_EVALUATION_VERSION,
        "dataset_sha256": hashlib.sha256(dataset_payload.encode()).hexdigest(),
        "evaluation_profile": "offline_deterministic_security_v4",
        "threshold_profile": "security-v4-release-gates-v1",
        "release_baseline": RELEASE_BASELINE,
        "generated_at": datetime.now(UTC).isoformat(),
        "limitations": [
            "Fixture evaluation does not replace hosted OIDC, PostgreSQL, Redis, provider, load, backup/restore, or multi-turn transport evidence."
        ],
        "metrics": metrics,
        "gates": gates,
        "passed": all(gates.values()),
        "cases": [item.model_dump(mode="json") for item in results],
    }


def write_report(report: dict[str, object], output: str | Path) -> None:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "REQUIRED_CATEGORIES",
    "RELEASE_BASELINE",
    "SECURITY_V4_EVALUATION_VERSION",
    "SecurityEvaluationCase",
    "evaluate_case",
    "evaluate_set",
    "load_evaluation_set",
    "write_report",
]
