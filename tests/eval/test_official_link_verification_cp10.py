from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.evaluation.official_link_verification import (
    REQUIRED_CATEGORIES,
    SECURITY_V4_V2_DATASET_VERSION,
    evaluate_set,
    load_evaluation_set,
)

DATASET_V1 = "tests/eval/security_v4_v1.jsonl"
DATASET_V2 = "tests/eval/security_v4_v2.jsonl"
IMMUTABLE_V1_SHA256 = "dc78b477a43d14beb5ec19e517fb1bdb8dd21cc6d95addc80fd897a1721aa710"


def test_security_v4_v2_is_additive_and_v1_remains_immutable() -> None:
    assert hashlib.sha256(Path(DATASET_V1).read_bytes()).hexdigest() == IMMUTABLE_V1_SHA256
    cases = load_evaluation_set(DATASET_V2)
    assert {case.dataset_version for case in cases} == {SECURITY_V4_V2_DATASET_VERSION}
    assert REQUIRED_CATEGORIES <= {case.category for case in cases}
    assert len(cases) == len({case.id for case in cases})


@pytest.mark.asyncio
async def test_security_v4_v2_passes_cp10_offline_release_gates() -> None:
    report = await evaluate_set(load_evaluation_set(DATASET_V2), dataset_path=DATASET_V2)

    assert report["passed"] is True
    assert all(report["gates"].values())
    metrics = report["metrics"]
    assert metrics["scope_accuracy"] == pytest.approx(1)
    assert metrics["component_status_accuracy"] == pytest.approx(1)
    assert metrics["labeled_resource_match_precision"] == pytest.approx(1)
    assert metrics["evidence_reference_closure_rate"] == pytest.approx(1)
    assert metrics["grounded_explanation_rate"] == pytest.approx(1)
    assert metrics["fabricated_ref_count"] == 0
    assert metrics["fabricated_url_count"] == 0
    assert metrics["oos_provider_network_ai_calls"] == 0
    assert metrics["not_found_to_malicious_count"] == 0
    assert metrics["ssrf_bypass_count"] == 0
    assert metrics["max_estimated_cost_usd_per_analysis"] <= 0.05
    assert metrics["p95_latency_ms"] <= 30_000


@pytest.mark.asyncio
async def test_required_hard_case_executes_english_query_and_matches_redirected_form() -> None:
    report = await evaluate_set(load_evaluation_set(DATASET_V2), dataset_path=DATASET_V2)
    hard = next(item for item in report["cases"] if item["id"] == "hard_vietnamese_social_short_form")
    fixture = next(item for item in load_evaluation_set(DATASET_V2) if item.id == hard["id"])

    assert fixture.official_source_kind == "social_announcement"
    # Discovery now also reserves an ownership query for the submitted host;
    # preserve the English campaign-recall requirement without coupling this
    # release gate to query ordering or the number of bounded queries.
    assert "Dai hoc VinUni recruitment official" in hard["queries"]
    assert hard["overall_status"] == "VERIFIED"
    assert hard["resource_match_status"] == "EXACT_RESOURCE"
    assert hard["reference_closure_pass"] is True
    assert hard["fabricated_ref_count"] == hard["fabricated_url_count"] == 0


def test_v2_loader_rejects_missing_release_categories(tmp_path) -> None:
    target = tmp_path / "incomplete.jsonl"
    target.write_text(
        json.dumps(
            {
                "dataset_version": SECURITY_V4_V2_DATASET_VERSION,
                "id": "only_case",
                "category": "verified",
                "message": "Check this security message",
                "expected": {"scope_decision": "NEED_MORE_INFO"},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing categories"):
        load_evaluation_set(target)
