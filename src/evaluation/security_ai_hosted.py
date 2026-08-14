from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

HOSTED_AI_EVALUATION_VERSION = "security-ai-hosted-eval-v1"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostedReleaseBaseline(_StrictModel):
    malicious_precision: float = Field(ge=0, le=1)
    false_positive_rate: float = Field(ge=0, le=1)
    unnecessary_provider_call_rate: float = Field(ge=0, le=1)
    report_appeal_overturn_rate: float = Field(ge=0, le=1)


class HostedAIObservation(_StrictModel):
    id: str = Field(pattern=r"^[a-z0-9_-]+$")
    success: bool
    fallback_expected: bool = False
    fallback_success: bool = False
    latency_ms: float = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_usd: float = Field(ge=0)
    grounded_reasons: int = Field(ge=0)
    total_reasons: int = Field(ge=0)
    hallucinated_evidence: int = Field(ge=0)
    hallucinated_actions: int = Field(ge=0)
    provider_calls: int = Field(ge=0)
    max_expected_provider_calls: int = Field(ge=0)
    report_appeal_decisions: int = Field(default=0, ge=0)
    report_appeal_overturns: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_feedback_counts(self) -> Self:
        if self.report_appeal_overturns > self.report_appeal_decisions:
            raise ValueError("overturn count cannot exceed reviewed decisions")
        return self


class HostedAIEvidence(_StrictModel):
    evaluation_version: Literal["security-ai-hosted-eval-v1"]
    rollout_stage: Literal[
        "understanding",
        "conversation",
        "explanation",
        "planning",
        "async_execution",
        "reviewed_memory",
        "admin_copilot",
    ]
    environment: str = Field(min_length=1)
    oidc_verified: bool
    postgresql_verified: bool
    redis_verified: bool
    live_provider_verified: bool
    observed_malicious_precision: float = Field(ge=0, le=1)
    observed_false_positive_rate: float = Field(ge=0, le=1)
    baseline: HostedReleaseBaseline
    observations: list[HostedAIObservation] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_observations(self) -> Self:
        if len({item.id for item in self.observations}) != len(self.observations):
            raise ValueError("hosted observation IDs must be unique")
        return self


def _ratio(numerator: int, denominator: int, *, empty: float = 1.0) -> float:
    return round(numerator / denominator, 4) if denominator else empty


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)] if ordered else 0.0


def load_hosted_ai_evidence(path: str | Path) -> HostedAIEvidence:
    return HostedAIEvidence.model_validate_json(Path(path).read_text(encoding="utf-8"))


def evaluate_hosted_ai_evidence(evidence: HostedAIEvidence) -> dict[str, object]:
    observations = evidence.observations
    reasons = sum(item.total_reasons for item in observations)
    calls = sum(item.provider_calls for item in observations)
    unnecessary = sum(max(0, item.provider_calls - item.max_expected_provider_calls) for item in observations)
    fallback = [item for item in observations if item.fallback_expected]
    decisions = sum(item.report_appeal_decisions for item in observations)
    overturns = sum(item.report_appeal_overturns for item in observations)
    metrics = {
        "observation_count": len(observations),
        "reliability_rate": _ratio(sum(item.success for item in observations), len(observations)),
        "grounded_reason_rate": _ratio(sum(item.grounded_reasons for item in observations), reasons),
        "hallucinated_evidence_rate": _ratio(
            sum(item.hallucinated_evidence for item in observations), reasons, empty=0
        ),
        "hallucinated_action_rate": _ratio(
            sum(item.hallucinated_actions for item in observations), reasons, empty=0
        ),
        "unnecessary_provider_call_rate": _ratio(unnecessary, calls, empty=0),
        "llm_fallback_success_rate": _ratio(sum(item.fallback_success for item in fallback), len(fallback)),
        "malicious_precision": evidence.observed_malicious_precision,
        "false_positive_rate": evidence.observed_false_positive_rate,
        "report_appeal_overturn_rate": _ratio(overturns, decisions, empty=0),
        "p95_latency_ms": round(_p95([item.latency_ms for item in observations]), 3),
        "p95_tokens_per_turn": int(_p95([float(item.input_tokens + item.output_tokens) for item in observations])),
        "p95_cost_usd_per_turn": round(_p95([item.cost_usd for item in observations]), 6),
    }
    gates = {
        "oidc_verified": evidence.oidc_verified,
        "postgresql_verified": evidence.postgresql_verified,
        "redis_verified": evidence.redis_verified,
        "live_provider_verified": evidence.live_provider_verified,
        "reliability_rate": metrics["reliability_rate"] >= 0.99,
        "grounded_reason_rate": metrics["grounded_reason_rate"] == 1,
        "hallucinated_evidence_rate": metrics["hallucinated_evidence_rate"] == 0,
        "hallucinated_action_rate": metrics["hallucinated_action_rate"] == 0,
        "unnecessary_provider_call_rate": (
            metrics["unnecessary_provider_call_rate"] <= evidence.baseline.unnecessary_provider_call_rate
        ),
        "llm_fallback_success_rate": metrics["llm_fallback_success_rate"] == 1,
        "malicious_precision_no_regression": (
            metrics["malicious_precision"] >= evidence.baseline.malicious_precision
        ),
        "false_positive_rate_no_regression": (
            metrics["false_positive_rate"] <= evidence.baseline.false_positive_rate
        ),
        "report_appeal_overturn_rate_no_regression": (
            metrics["report_appeal_overturn_rate"] <= evidence.baseline.report_appeal_overturn_rate
        ),
        "p95_latency_ms": metrics["p95_latency_ms"] <= 15_000,
        "p95_tokens_per_turn": metrics["p95_tokens_per_turn"] <= 10_000,
        "p95_cost_usd_per_turn": metrics["p95_cost_usd_per_turn"] <= 0.05,
    }
    payload = evidence.model_dump_json(exclude_none=True)
    return {
        "evaluation_version": HOSTED_AI_EVALUATION_VERSION,
        "evidence_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "evaluation_profile": "hosted_ai_reliability_cost_latency",
        "rollout_stage": evidence.rollout_stage,
        "environment": evidence.environment,
        "generated_at": datetime.now(UTC).isoformat(),
        "baseline": evidence.baseline.model_dump(mode="json"),
        "metrics": metrics,
        "gates": gates,
        "passed": all(gates.values()),
    }


def write_hosted_ai_report(report: dict[str, object], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "HOSTED_AI_EVALUATION_VERSION",
    "HostedAIEvidence",
    "evaluate_hosted_ai_evidence",
    "load_hosted_ai_evidence",
    "write_hosted_ai_report",
]
