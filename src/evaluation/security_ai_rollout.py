from __future__ import annotations

import json
import re
from enum import StrEnum
from pathlib import Path

from src.config import Settings


class SecurityAIRolloutStage(StrEnum):
    OFF = "off"
    UNDERSTANDING = "understanding"
    CONVERSATION = "conversation"
    EXPLANATION = "explanation"
    PLANNING = "planning"
    ASYNC_EXECUTION = "async_execution"
    REVIEWED_MEMORY = "reviewed_memory"
    ADMIN_COPILOT = "admin_copilot"


_STAGES = list(SecurityAIRolloutStage)
_FLAGS = {
    "security_ai_understanding_enabled": SecurityAIRolloutStage.UNDERSTANDING,
    "security_ai_explanation_enabled": SecurityAIRolloutStage.EXPLANATION,
    "security_ai_planning_enabled": SecurityAIRolloutStage.PLANNING,
    "security_async_execution_enabled": SecurityAIRolloutStage.ASYNC_EXECUTION,
    "security_memory_retrieval_enabled": SecurityAIRolloutStage.REVIEWED_MEMORY,
    "security_admin_copilot_enabled": SecurityAIRolloutStage.ADMIN_COPILOT,
}
_ROLLBACK_FLAG = {
    SecurityAIRolloutStage.UNDERSTANDING: "SECURITY_AI_UNDERSTANDING_ENABLED",
    SecurityAIRolloutStage.CONVERSATION: "SECURITY_AI_UNDERSTANDING_ENABLED",
    SecurityAIRolloutStage.EXPLANATION: "SECURITY_AI_EXPLANATION_ENABLED",
    SecurityAIRolloutStage.PLANNING: "SECURITY_AI_PLANNING_ENABLED",
    SecurityAIRolloutStage.ASYNC_EXECUTION: "SECURITY_ASYNC_EXECUTION_ENABLED",
    SecurityAIRolloutStage.REVIEWED_MEMORY: "SECURITY_MEMORY_RETRIEVAL_ENABLED",
    SecurityAIRolloutStage.ADMIN_COPILOT: "SECURITY_ADMIN_COPILOT_ENABLED",
}

_HOSTED_GATE_NAMES = {
    "oidc_verified",
    "postgresql_verified",
    "redis_verified",
    "live_provider_verified",
    "reliability_rate",
    "grounded_reason_rate",
    "hallucinated_evidence_rate",
    "hallucinated_action_rate",
    "unnecessary_provider_call_rate",
    "llm_fallback_success_rate",
    "malicious_precision_no_regression",
    "false_positive_rate_no_regression",
    "report_appeal_overturn_rate_no_regression",
    "p95_latency_ms",
    "p95_tokens_per_turn",
    "p95_cost_usd_per_turn",
}
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def load_evaluation_report(path: str | Path | None) -> dict | None:
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def _report_passed(report: dict | None, version_key: str, version: str, hash_key: str) -> bool:
    return bool(
        report
        and report.get("passed") is True
        and report.get(version_key) == version
        and isinstance(report.get(hash_key), str)
        and len(report[hash_key]) == 64
    )


def _hosted_report_passed(report: dict | None, target_stage: SecurityAIRolloutStage) -> bool:
    """Accept only the complete output of the hosted evidence evaluator.

    A small hand-authored object containing ``passed=true`` is not hosted
    observation evidence.  The evaluator output includes the observation hash,
    profile, metrics, baseline and every infrastructure/quality gate.
    """
    if not isinstance(report, dict):
        return False
    gates = report.get("gates")
    metrics = report.get("metrics")
    baseline = report.get("baseline")
    environment = report.get("environment")
    evidence_hash = report.get("evidence_sha256")
    return bool(
        report.get("passed") is True
        and report.get("evaluation_version") == "security-ai-hosted-eval-v1"
        and report.get("evaluation_profile") == "hosted_ai_reliability_cost_latency"
        and report.get("rollout_stage") == target_stage.value
        and isinstance(environment, str)
        and environment.strip()
        and "replace-with" not in environment.lower()
        and isinstance(evidence_hash, str)
        and _SHA256_PATTERN.fullmatch(evidence_hash)
        and isinstance(metrics, dict)
        and metrics.get("observation_count", 0) > 0
        and isinstance(baseline, dict)
        and isinstance(gates, dict)
        and _HOSTED_GATE_NAMES <= gates.keys()
        and all(gates[name] is True for name in _HOSTED_GATE_NAMES)
    )


def evaluate_rollout_readiness(
    settings: Settings,
    target_stage: SecurityAIRolloutStage,
    *,
    deterministic_report: dict | None,
    ai_report: dict | None,
    memory_report: dict | None = None,
    hosted_report: dict | None = None,
) -> dict[str, object]:
    target_index = _STAGES.index(target_stage)
    gates: dict[str, bool] = {
        "deterministic_evaluation": _report_passed(
            deterministic_report, "dataset_version", "security-v4-eval-v1", "dataset_sha256"
        ),
        "ai_evaluation": _report_passed(ai_report, "dataset_version", "security-ai-eval-v1", "dataset_sha256"),
        "hosted_evaluation": _hosted_report_passed(hosted_report, target_stage),
    }
    if target_stage is SecurityAIRolloutStage.OFF:
        gates.update(
            deterministic_evaluation=True,
            ai_evaluation=True,
            hosted_evaluation=True,
        )
    if target_index >= _STAGES.index(SecurityAIRolloutStage.REVIEWED_MEMORY):
        gates["reviewed_memory_evaluation"] = _report_passed(
            memory_report, "evaluation_version", "security-memory-v2-eval-v1", "dataset_sha256"
        )

    for flag_name, introduced_at in _FLAGS.items():
        should_enable = target_index >= _STAGES.index(introduced_at)
        gates[f"flag_{flag_name}"] = bool(getattr(settings, flag_name)) is should_enable

    if target_index >= _STAGES.index(SecurityAIRolloutStage.ASYNC_EXECUTION):
        gates["durable_postgresql_ready"] = (
            settings.database_url.startswith(("postgresql://", "postgresql+asyncpg://")) and settings.run_durable_worker
        )
    if target_index >= _STAGES.index(SecurityAIRolloutStage.UNDERSTANDING):
        gates["ai_provider_configured"] = settings.security_ai_provider_configuration_valid()

    rollback_flag = _ROLLBACK_FLAG.get(target_stage)
    passed = all(gates.values())
    production_rollout_complete = passed and target_stage is SecurityAIRolloutStage.ADMIN_COPILOT
    return {
        "target_stage": target_stage.value,
        "gates": gates,
        "passed": passed,
        "rollout_status": (
            "production_rollout_complete"
            if production_rollout_complete
            else "stage_ready"
            if passed and target_stage is not SecurityAIRolloutStage.OFF
            else "disabled"
            if passed
            else "blocked"
        ),
        "production_rollout_complete": production_rollout_complete,
        "rollback": {
            "disable_flag": rollback_flag,
            "database_action": "none",
            "instruction": (
                f"Set {rollback_flag}=false; keep additive schema and audit data."
                if rollback_flag
                else "All Security AI rollout flags remain disabled."
            ),
        },
    }


__all__ = [
    "SecurityAIRolloutStage",
    "evaluate_rollout_readiness",
    "load_evaluation_report",
]
