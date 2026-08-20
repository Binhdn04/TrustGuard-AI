from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from scripts.smoke_official_link_verification import validate_hard_case
from src.evaluation.official_link_verification_hosted import (
    REQUIRED_HOSTED_CHECKS,
    evaluate_hosted_evidence,
    load_hosted_evidence,
)

NOW = datetime(2026, 8, 20, 12, tzinfo=UTC)


def _payload() -> dict[str, object]:
    checks = [
        {
            "name": name,
            "status": "passed",
            "evidence_ref": f"review://{name}",
            "reviewed_by": "release-reviewer",
            "observed_at": NOW.isoformat(),
        }
        for name in sorted(REQUIRED_HOSTED_CHECKS)
    ]
    stages = []
    for index, stage in enumerate(("shadow", "visible", "enforced", "visible", "off")):
        started = NOW + timedelta(hours=index)
        stages.append(
            {
                "stage": stage,
                "started_at": started.isoformat(),
                "ended_at": (started + timedelta(minutes=30)).isoformat(),
                "sample_count": 20,
                "p95_latency_ms": 1200,
                "max_estimated_cost_usd": 0.01,
                "error_rate": 0,
                "evidence_ref": f"deploy://stage-{index}",
            }
        )
    return {
        "schema_version": "official-link-verification-hosted-evidence-v1",
        "commit_sha": "a" * 40,
        "environment": "staging",
        "deployment_ref": "deploy://staging-123",
        "collected_at": (NOW + timedelta(hours=6)).isoformat(),
        "checks": checks,
        "stages": stages,
        "hard_case": {
            "input_language": "vi",
            "derived_query_language": "en",
            "official_source_kind": "social_announcement",
            "short_url_observed": True,
            "third_party_form_observed": True,
            "overall_status": "VERIFIED",
            "resource_match_status": "EXACT_RESOURCE",
            "evidence_reference_closure": True,
            "fabricated_ref_count": 0,
            "fabricated_url_count": 0,
            "latency_ms": 1500,
            "estimated_cost_usd": 0.012,
            "evidence_ref": "smoke://hard-case",
        },
    }


def test_reviewed_hosted_evidence_passes_only_with_all_release_observations(tmp_path) -> None:
    target = tmp_path / "hosted.json"
    target.write_text(json.dumps(_payload()), encoding="utf-8")
    evidence, digest = load_hosted_evidence(target)
    report = evaluate_hosted_evidence(evidence, digest, expected_commit_sha="a" * 40)

    assert report["passed"] is True
    assert all(report["gates"].values())
    assert report["metrics"]["total_stage_samples"] == 100


def test_hosted_validator_rejects_evidence_from_a_different_candidate(tmp_path) -> None:
    target = tmp_path / "old-candidate.json"
    target.write_text(json.dumps(_payload()), encoding="utf-8")
    evidence, digest = load_hosted_evidence(target)

    report = evaluate_hosted_evidence(evidence, digest, expected_commit_sha="b" * 40)

    assert report["gates"]["candidate_commit"] is False
    assert report["passed"] is False


def test_hosted_validator_rejects_missing_review_and_wrong_rollout_sequence(tmp_path) -> None:
    payload = _payload()
    payload["checks"] = payload["checks"][:-1]  # type: ignore[index]
    payload["stages"] = list(reversed(payload["stages"]))  # type: ignore[arg-type]
    target = tmp_path / "invalid.json"
    target.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValidationError):
        load_hosted_evidence(target)


def test_hosted_validator_rejects_pending_or_unreviewed_claims(tmp_path) -> None:
    payload = _payload()
    payload["checks"][0]["status"] = "pending"  # type: ignore[index]
    target = tmp_path / "pending.json"
    target.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValidationError):
        load_hosted_evidence(target)


def _hosted_hard_case_response() -> dict[str, object]:
    return {
        "contract_version": "v4",
        "analysis_id": "analysis-123",
        "scope_decision": "IN_SCOPE",
        "official_verification": {
            "overall_status": "VERIFIED",
            "intent": {"derived_organization_names": ["VinUni"]},
            "source_refs": [
                {
                    "source_ref": "source:official-social",
                    "canonical_url": "https://facebook.com/VinUniOfficial",
                    "identity": {"identity_type": "social_profile"},
                }
            ],
            "link_refs": [
                {
                    "link_ref": "link:application",
                    "source_ref": "source:official-social",
                    "display_url": "https://bit.ly/VinUniApply",
                    "canonical_url": "https://forms.gle/OfficialAlias",
                }
            ],
            "publisher_verification": {"evidence_refs": ["source:official-social"]},
            "claim_verification": {"evidence_refs": ["source:official-social"]},
            "resource_verification": {
                "evidence_refs": ["link:application"],
                "match": {
                    "status": "EXACT_RESOURCE",
                    "official_resource": {"resource_type": "google_form"},
                },
            },
        },
    }


def test_hosted_hard_case_smoke_accepts_only_closed_social_short_form_chain() -> None:
    summary = validate_hard_case(_hosted_hard_case_response(), latency_ms=1_500)

    assert summary["official_social_source"] is True
    assert summary["short_url_observed"] is True
    assert summary["third_party_form_observed"] is True
    assert summary["evidence_reference_closure"] is True


def test_hosted_hard_case_smoke_rejects_fabricated_reference() -> None:
    response = _hosted_hard_case_response()
    response["official_verification"]["claim_verification"]["evidence_refs"] = [  # type: ignore[index]
        "source:fabricated"
    ]

    with pytest.raises(ValueError, match="not closed"):
        validate_hard_case(response, latency_ms=1_500)
