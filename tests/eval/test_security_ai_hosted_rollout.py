from __future__ import annotations

from src.config import Settings
from src.evaluation.security_ai_hosted import HostedAIEvidence, evaluate_hosted_ai_evidence
from src.evaluation.security_ai_rollout import SecurityAIRolloutStage, evaluate_rollout_readiness


def _hosted_evidence(**updates) -> HostedAIEvidence:
    payload = {
        "evaluation_version": "security-ai-hosted-eval-v1",
        "rollout_stage": "understanding",
        "environment": "hosted-staging",
        "oidc_verified": True,
        "postgresql_verified": True,
        "redis_verified": True,
        "live_provider_verified": True,
        "observed_malicious_precision": 0.96,
        "observed_false_positive_rate": 0.03,
        "baseline": {
            "malicious_precision": 0.95,
            "false_positive_rate": 0.04,
            "unnecessary_provider_call_rate": 0,
            "report_appeal_overturn_rate": 0.2,
        },
        "observations": [
            {
                "id": "normal-turn",
                "success": True,
                "latency_ms": 1200,
                "input_tokens": 300,
                "output_tokens": 100,
                "cost_usd": 0.002,
                "grounded_reasons": 2,
                "total_reasons": 2,
                "hallucinated_evidence": 0,
                "hallucinated_actions": 0,
                "provider_calls": 2,
                "max_expected_provider_calls": 2,
                "report_appeal_decisions": 9,
                "report_appeal_overturns": 1,
            },
            {
                "id": "fallback-turn",
                "success": True,
                "fallback_expected": True,
                "fallback_success": True,
                "latency_ms": 800,
                "input_tokens": 100,
                "output_tokens": 20,
                "cost_usd": 0.0005,
                "grounded_reasons": 1,
                "total_reasons": 1,
                "hallucinated_evidence": 0,
                "hallucinated_actions": 0,
                "provider_calls": 1,
                "max_expected_provider_calls": 1,
                "report_appeal_decisions": 1,
                "report_appeal_overturns": 0,
            },
        ],
    }
    payload.update(updates)
    return HostedAIEvidence.model_validate(payload)


def test_hosted_evidence_computes_reliability_cost_latency_and_quality_gates() -> None:
    report = evaluate_hosted_ai_evidence(_hosted_evidence())
    assert report["passed"] is True
    assert report["metrics"]["grounded_reason_rate"] == 1
    assert report["metrics"]["hallucinated_action_rate"] == 0
    assert report["metrics"]["report_appeal_overturn_rate"] == 0.1
    assert report["metrics"]["p95_latency_ms"] == 1200


def test_hosted_evidence_fails_closed_on_missing_infrastructure_or_hallucination() -> None:
    evidence = _hosted_evidence(oidc_verified=False)
    evidence.observations[0].hallucinated_actions = 1
    report = evaluate_hosted_ai_evidence(evidence)
    assert report["passed"] is False
    assert report["gates"]["oidc_verified"] is False
    assert report["gates"]["hallucinated_action_rate"] is False


def test_rollout_requires_sequential_flags_and_hosted_evidence() -> None:
    deterministic = {"passed": True, "dataset_version": "security-v4-eval-v1", "dataset_sha256": "a" * 64}
    ai = {"passed": True, "dataset_version": "security-ai-eval-v1", "dataset_sha256": "b" * 64}
    hosted = evaluate_hosted_ai_evidence(_hosted_evidence(rollout_stage="planning"))
    settings = Settings(
        openai_api_key="configured-provider",
        security_ai_understanding_enabled=True,
        security_ai_explanation_enabled=True,
        security_ai_planning_enabled=True,
        _env_file=None,
    )
    ready = evaluate_rollout_readiness(
        settings,
        SecurityAIRolloutStage.PLANNING,
        deterministic_report=deterministic,
        ai_report=ai,
        hosted_report=hosted,
    )
    assert ready["passed"] is True
    assert ready["rollout_status"] == "stage_ready"
    assert ready["production_rollout_complete"] is False
    assert ready["rollback"]["disable_flag"] == "SECURITY_AI_PLANNING_ENABLED"
    assert ready["rollback"]["database_action"] == "none"

    missing_hosted = evaluate_rollout_readiness(
        settings,
        SecurityAIRolloutStage.PLANNING,
        deterministic_report=deterministic,
        ai_report=ai,
    )
    assert missing_hosted["passed"] is False
    assert missing_hosted["gates"]["hosted_evaluation"] is False


def test_rollout_rejects_hand_authored_hosted_pass_marker() -> None:
    deterministic = {"passed": True, "dataset_version": "security-v4-eval-v1", "dataset_sha256": "a" * 64}
    ai = {"passed": True, "dataset_version": "security-ai-eval-v1", "dataset_sha256": "b" * 64}
    hosted = {
        "passed": True,
        "evaluation_version": "security-ai-hosted-eval-v1",
        "rollout_stage": "understanding",
        "evidence_sha256": "c" * 64,
    }
    settings = Settings(
        openai_api_key="configured-provider",
        security_ai_understanding_enabled=True,
        _env_file=None,
    )
    result = evaluate_rollout_readiness(
        settings,
        SecurityAIRolloutStage.UNDERSTANDING,
        deterministic_report=deterministic,
        ai_report=ai,
        hosted_report=hosted,
    )
    assert result["passed"] is False
    assert result["rollout_status"] == "blocked"
    assert result["production_rollout_complete"] is False
    assert result["gates"]["hosted_evaluation"] is False


def test_rollout_rejects_skipping_directly_to_admin_copilot() -> None:
    deterministic = {"passed": True, "dataset_version": "security-v4-eval-v1", "dataset_sha256": "a" * 64}
    ai = {"passed": True, "dataset_version": "security-ai-eval-v1", "dataset_sha256": "b" * 64}
    memory = {"passed": True, "evaluation_version": "security-memory-v2-eval-v1", "dataset_sha256": "c" * 64}
    hosted = evaluate_hosted_ai_evidence(_hosted_evidence(rollout_stage="admin_copilot"))
    settings = Settings(
        openai_api_key="configured-provider",
        security_admin_copilot_enabled=True,
        _env_file=None,
    )
    result = evaluate_rollout_readiness(
        settings,
        SecurityAIRolloutStage.ADMIN_COPILOT,
        deterministic_report=deterministic,
        ai_report=ai,
        memory_report=memory,
        hosted_report=hosted,
    )
    assert result["passed"] is False
    assert result["gates"]["flag_security_ai_understanding_enabled"] is False
    assert result["gates"]["flag_security_async_execution_enabled"] is False
