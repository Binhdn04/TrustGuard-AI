from __future__ import annotations

import pytest

from scripts.live_provider_smoke import validate_security_v4_result


def completed_result() -> dict:
    return {
        "contract_version": "v4",
        "analysis_id": "analysis-1",
        "scope_decision": "IN_SCOPE",
        "status": "completed",
        "terminal": True,
        "risk": "HIGH_RISK",
        "tool_calls_used": 2,
        "evidence": [
            {"evidence_ref": "evidence:1234567890abcdef", "type": "security_context"},
            {"evidence_ref": "evidence:abcdef1234567890", "type": "url_reputation"},
        ],
        "explanation_evidence_refs": ["evidence:abcdef1234567890"],
        "limitations": [],
        "errors": [],
    }


def test_live_smoke_validates_v4_provider_and_grounding() -> None:
    summary = validate_security_v4_result(
        completed_result(),
        expected_risk="HIGH_RISK",
        require_official_verification=False,
    )

    assert summary["evidence_types"] == ["security_context", "url_reputation"]
    assert summary["tool_calls_used"] == 2


def test_live_smoke_rejects_missing_provider_evidence() -> None:
    result = completed_result()
    result["evidence"] = result["evidence"][:1]

    with pytest.raises(ValueError, match="URL-reputation"):
        validate_security_v4_result(
            result,
            expected_risk=None,
            require_official_verification=False,
        )
