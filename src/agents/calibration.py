from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Literal

from src.agents.contracts import RiskAssessmentOutput
from src.models import RiskLevel, Verdict

FeedbackKind = Literal["report", "appeal"]


@dataclass(frozen=True, slots=True)
class CalibrationExample:
    """A reviewer-labelled snapshot; unreviewed feedback must never enter evaluation."""

    example_id: str
    feedback_kind: FeedbackKind
    feedback_ref: str
    state: Mapping[str, Any]
    expected_risk_level: RiskLevel
    expected_verdict: Verdict
    reviewed_by: str
    reviewed_at: datetime

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.example_id, self.feedback_ref, self.reviewed_by)):
            raise ValueError("calibration identity fields must not be empty")
        if self.reviewed_at.tzinfo is None or self.reviewed_at.utcoffset() != timedelta(0):
            raise ValueError("reviewed_at must use UTC")
        # Freeze the complete snapshot so later workflow mutation cannot relabel history.
        object.__setattr__(self, "state", _freeze(self.state))


@dataclass(frozen=True, slots=True)
class VersionedEvaluationSet:
    version: str
    examples: tuple[CalibrationExample, ...]
    content_sha256: str
    created_at: datetime

    @classmethod
    def build(
        cls,
        version: str,
        examples: Sequence[CalibrationExample],
        *,
        created_at: datetime,
    ) -> VersionedEvaluationSet:
        if not version.strip() or not examples:
            raise ValueError("evaluation set requires a version and reviewed examples")
        if created_at.tzinfo is None or created_at.utcoffset() != timedelta(0):
            raise ValueError("created_at must use UTC")
        ordered = tuple(sorted(examples, key=lambda item: item.example_id))
        if len({item.example_id for item in ordered}) != len(ordered):
            raise ValueError("evaluation example ids must be unique")
        digest_payload = [
            {
                "example_id": item.example_id,
                "feedback_kind": item.feedback_kind,
                "feedback_ref": item.feedback_ref,
                "state": _jsonable(item.state),
                "expected_risk_level": item.expected_risk_level.value,
                "expected_verdict": item.expected_verdict.value,
                "reviewed_by": item.reviewed_by,
                "reviewed_at": item.reviewed_at.isoformat(),
            }
            for item in ordered
        ]
        digest = sha256(json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return cls(version=version, examples=ordered, content_sha256=digest, created_at=created_at)


@dataclass(frozen=True, slots=True)
class RiskLevelMetrics:
    precision: float
    recall: float
    false_positive_rate: float
    support: int


@dataclass(frozen=True, slots=True)
class CalibrationMetrics:
    by_risk_level: Mapping[RiskLevel, RiskLevelMetrics]
    verdict_accuracy: float
    inconclusive_rate: float
    example_count: int


@dataclass(frozen=True, slots=True)
class RegressionPolicy:
    max_precision_drop: float = 0.0
    max_recall_drop: float = 0.0
    max_false_positive_rate_increase: float = 0.0
    max_inconclusive_rate_increase: float = 0.0

    def __post_init__(self) -> None:
        if any(
            value < 0
            for value in (
                self.max_precision_drop,
                self.max_recall_drop,
                self.max_false_positive_rate_increase,
                self.max_inconclusive_rate_increase,
            )
        ):
            raise ValueError("regression tolerances must be non-negative")


@dataclass(frozen=True, slots=True)
class CalibrationRun:
    candidate_version: str
    evaluation_set_version: str
    evaluation_set_sha256: str
    metrics: CalibrationMetrics
    baseline_metrics: CalibrationMetrics | None
    regression_passed: bool
    failures: tuple[str, ...]
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovedReleaseRecord:
    candidate_version: str
    evaluation_set_version: str
    evaluation_set_sha256: str
    run_sha256: str
    approved_by: str
    approved_at: datetime


RiskEvaluator = Callable[[Mapping[str, Any]], RiskAssessmentOutput]


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, datetime):
        return value.isoformat()
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str):
        return enum_value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported calibration snapshot value: {type(value).__name__}")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze(item) for item in value)
    return value


def evaluate(engine: RiskEvaluator, evaluation_set: VersionedEvaluationSet) -> CalibrationMetrics:
    predictions = [(item, engine(item.state)) for item in evaluation_set.examples]
    if not predictions:
        raise ValueError("evaluation set must contain at least one example")
    metrics: dict[RiskLevel, RiskLevelMetrics] = {}
    for level in RiskLevel:
        true_positive = sum(
            prediction["risk_level"] is level and item.expected_risk_level is level for item, prediction in predictions
        )
        false_positive = sum(
            prediction["risk_level"] is level and item.expected_risk_level is not level
            for item, prediction in predictions
        )
        false_negative = sum(
            prediction["risk_level"] is not level and item.expected_risk_level is level
            for item, prediction in predictions
        )
        true_negative = len(predictions) - true_positive - false_positive - false_negative
        metrics[level] = RiskLevelMetrics(
            precision=true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0,
            recall=true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0,
            false_positive_rate=(
                false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
            ),
            support=true_positive + false_negative,
        )
    count = len(predictions)
    return CalibrationMetrics(
        by_risk_level=MappingProxyType(metrics),
        verdict_accuracy=sum(prediction["verdict"] is item.expected_verdict for item, prediction in predictions)
        / count,
        inconclusive_rate=sum(prediction["verdict"] is Verdict.INCONCLUSIVE for _, prediction in predictions) / count,
        example_count=count,
    )


def run_regression(
    candidate_version: str,
    candidate_engine: RiskEvaluator,
    evaluation_set: VersionedEvaluationSet,
    *,
    baseline_engine: RiskEvaluator | None = None,
    policy: RegressionPolicy = RegressionPolicy(),
    completed_at: datetime,
) -> CalibrationRun:
    if not candidate_version.strip():
        raise ValueError("candidate version must not be empty")
    if completed_at.tzinfo is None or completed_at.utcoffset() != timedelta(0):
        raise ValueError("completed_at must use UTC")
    candidate = evaluate(candidate_engine, evaluation_set)
    baseline = evaluate(baseline_engine, evaluation_set) if baseline_engine else None
    failures: list[str] = []
    if baseline:
        for level in RiskLevel:
            before = baseline.by_risk_level[level]
            after = candidate.by_risk_level[level]
            if before.precision - after.precision > policy.max_precision_drop:
                failures.append(f"{level.value}:precision")
            if before.recall - after.recall > policy.max_recall_drop:
                failures.append(f"{level.value}:recall")
            if after.false_positive_rate - before.false_positive_rate > policy.max_false_positive_rate_increase:
                failures.append(f"{level.value}:false_positive_rate")
        if candidate.inconclusive_rate - baseline.inconclusive_rate > policy.max_inconclusive_rate_increase:
            failures.append("inconclusive_rate")
    return CalibrationRun(
        candidate_version=candidate_version,
        evaluation_set_version=evaluation_set.version,
        evaluation_set_sha256=evaluation_set.content_sha256,
        metrics=candidate,
        baseline_metrics=baseline,
        regression_passed=not failures,
        failures=tuple(failures),
        completed_at=completed_at,
    )


def approve_release(run: CalibrationRun, *, approved_by: str, approved_at: datetime) -> ApprovedReleaseRecord:
    """Create the explicit release record required before activating a change."""
    if not run.regression_passed:
        raise ValueError("a failed regression run cannot be approved")
    if not approved_by.strip():
        raise ValueError("approved_by must not be empty")
    if approved_at.tzinfo is None or approved_at.utcoffset() != timedelta(0):
        raise ValueError("approved_at must use UTC")
    if approved_at < run.completed_at:
        raise ValueError("approval cannot precede the regression run")

    def metrics_payload(metrics: CalibrationMetrics | None) -> Any:
        if metrics is None:
            return None
        return {
            "verdict_accuracy": metrics.verdict_accuracy,
            "inconclusive_rate": metrics.inconclusive_rate,
            "example_count": metrics.example_count,
            "by_risk_level": {
                level.value: {
                    "precision": metric.precision,
                    "recall": metric.recall,
                    "false_positive_rate": metric.false_positive_rate,
                    "support": metric.support,
                }
                for level, metric in metrics.by_risk_level.items()
            },
        }

    payload = {
        "candidate_version": run.candidate_version,
        "evaluation_set_version": run.evaluation_set_version,
        "evaluation_set_sha256": run.evaluation_set_sha256,
        "completed_at": run.completed_at.isoformat(),
        "regression_passed": run.regression_passed,
        "failures": run.failures,
        "metrics": metrics_payload(run.metrics),
        "baseline_metrics": metrics_payload(run.baseline_metrics),
    }
    run_digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ApprovedReleaseRecord(
        candidate_version=run.candidate_version,
        evaluation_set_version=run.evaluation_set_version,
        evaluation_set_sha256=run.evaluation_set_sha256,
        run_sha256=run_digest,
        approved_by=approved_by,
        approved_at=approved_at,
    )


__all__ = [
    "ApprovedReleaseRecord",
    "CalibrationExample",
    "CalibrationMetrics",
    "CalibrationRun",
    "RegressionPolicy",
    "RiskLevelMetrics",
    "VersionedEvaluationSet",
    "approve_release",
    "evaluate",
    "run_regression",
]
