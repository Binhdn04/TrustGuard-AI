from __future__ import annotations

import json

import pytest

from src.evaluation.security_v4 import (
    REQUIRED_CATEGORIES,
    SECURITY_V4_EVALUATION_VERSION,
    evaluate_set,
    load_evaluation_set,
)

DATASET = "tests/eval/security_v4_v1.jsonl"


def test_versioned_evaluation_set_covers_release_categories() -> None:
    cases = load_evaluation_set(DATASET)

    assert {case.dataset_version for case in cases} == {SECURITY_V4_EVALUATION_VERSION}
    assert REQUIRED_CATEGORIES <= {case.category for case in cases}
    assert len(cases) == len({case.id for case in cases})


def test_security_v4_evaluation_passes_release_gates() -> None:
    report = evaluate_set(load_evaluation_set(DATASET))

    assert report["passed"] is True
    assert all(report["gates"].values())
    assert report["metrics"]["unnecessary_provider_call_rate"] == 0
    assert report["metrics"]["malicious_precision"] == 1
    assert report["metrics"]["grounded_explanation_rate"] == 1
    assert report["gates"]["malicious_precision_no_regression"] is True
    assert report["gates"]["false_positive_rate_no_regression"] is True


def test_no_consent_and_boundary_cases_do_not_plan_provider_calls() -> None:
    report = evaluate_set(load_evaluation_set(DATASET))
    by_id = {item["id"]: item for item in report["cases"]}

    assert by_id["consent_denied_external"]["planned_provider_calls"] == 0
    assert by_id["general_politics_boundary"]["planned_tools"] == []
    assert by_id["vague_security_boundary"]["planned_tools"] == []


def test_loader_rejects_incomplete_dataset(tmp_path) -> None:
    target = tmp_path / "incomplete.jsonl"
    target.write_text(
        json.dumps(
            {
                "dataset_version": SECURITY_V4_EVALUATION_VERSION,
                "id": "only_case",
                "category": "phishing",
                "message": "dang nhap",
                "expected": {
                    "scope_decision": "IN_SCOPE",
                    "threat_type": "CREDENTIAL_THEFT",
                    "accepted_risks": ["LOW_RISK"],
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing categories"):
        load_evaluation_set(target)
