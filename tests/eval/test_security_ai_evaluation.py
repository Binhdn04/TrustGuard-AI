from __future__ import annotations

import json

import pytest

from src.evaluation.security_ai_v1 import (
    REQUIRED_CATEGORIES,
    SECURITY_AI_EVALUATION_VERSION,
    evaluate_ai_set,
    load_ai_evaluation_set,
)

DATASET = "tests/eval/security_ai_v1.jsonl"


def test_security_ai_dataset_is_versioned_and_complete() -> None:
    cases = load_ai_evaluation_set(DATASET)
    assert {item.dataset_version for item in cases} == {SECURITY_AI_EVALUATION_VERSION}
    assert REQUIRED_CATEGORIES <= {item.category for item in cases}


@pytest.mark.asyncio
async def test_security_ai_evaluation_passes_all_wp8_offline_gates() -> None:
    report = await evaluate_ai_set(load_ai_evaluation_set(DATASET))
    assert report["passed"] is True
    assert all(report["gates"].values())
    assert report["metrics"]["grounded_reason_rate"] == 1
    assert report["metrics"]["hallucinated_evidence_rate"] == 0
    assert report["metrics"]["hallucinated_action_rate"] == 0
    assert report["metrics"]["unnecessary_provider_call_rate"] == 0
    assert report["metrics"]["llm_fallback_success_rate"] == 1


def test_security_ai_loader_rejects_incomplete_dataset(tmp_path) -> None:
    target = tmp_path / "incomplete.jsonl"
    target.write_text(
        json.dumps(
            {
                "dataset_version": SECURITY_AI_EVALUATION_VERSION,
                "id": "only_case",
                "category": "fallback",
                "scenario_group": "unknown",
                "turns": [{"message": "test", "provider_failure": True}],
                "expected": {
                    "scope_decision": "NEED_MORE_INFO",
                    "exposure_state": "UNKNOWN",
                    "max_provider_calls": 1,
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing categories"):
        load_ai_evaluation_set(target)
