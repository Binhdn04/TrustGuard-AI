from datetime import UTC, datetime
from typing import get_type_hints
from uuid import UUID

import pytest
from pydantic import ValidationError

from src.agents.state import AgentState
from src.models import (
    AdminDecisionRequest,
    AnalysisAcceptedResponse,
    AnalysisCreateRequest,
    AnalysisResponse,
    AnalysisStatus,
    CaseStatus,
    ErrorBody,
    Evidence,
    EvidenceType,
    InputType,
    RecommendedAction,
    RiskLevel,
    Verdict,
    risk_level_for_score,
)

ANALYSIS_ID = UUID("550e8400-e29b-41d4-a716-446655440000")
NOW = datetime(2026, 8, 3, 13, 0, tzinfo=UTC)


def test_contract_enums_have_frozen_values() -> None:
    assert {item.value for item in InputType} == {"text", "url", "text_with_url"}
    assert {item.value for item in AnalysisStatus} == {"queued", "running", "completed", "failed"}
    assert {item.value for item in RiskLevel} == {"low", "medium", "high", "critical"}
    assert {item.value for item in Verdict} == {"safe", "suspicious", "malicious", "inconclusive"}
    assert {item.value for item in EvidenceType} == {
        "url_rule",
        "domain_reputation",
        "redirect",
        "blacklist",
        "fact_check",
        "official_source",
        "user_report",
    }
    assert {item.value for item in CaseStatus} == {
        "not_required",
        "pending_review",
        "approved",
        "rejected",
    }
    assert {item.value for item in RecommendedAction} == {
        "allow",
        "show_caution",
        "do_not_open",
        "escalate_for_review",
    }


@pytest.mark.parametrize("message", ["", "   ", "x" * 5001])
def test_analysis_request_rejects_invalid_message(message: str) -> None:
    with pytest.raises(ValidationError):
        AnalysisCreateRequest(message=message, consent_to_scan_urls=True)


def test_analysis_request_accepts_contract_boundaries() -> None:
    assert AnalysisCreateRequest(message="x", consent_to_scan_urls=False).message == "x"
    assert len(AnalysisCreateRequest(message="x" * 5000, consent_to_scan_urls=True).message) == 5000


def test_accepted_response_serializes_contract_version_and_utc() -> None:
    response = AnalysisAcceptedResponse(analysis_id=ANALYSIS_ID, created_at=NOW)
    assert response.model_dump(mode="json") == {
        "contract_version": "v1",
        "analysis_id": str(ANALYSIS_ID),
        "status": "queued",
        "created_at": "2026-08-03T13:00:00Z",
    }


def test_contract_rejects_non_utc_timestamp() -> None:
    with pytest.raises(ValidationError, match="timestamps must use UTC"):
        AnalysisAcceptedResponse(analysis_id=ANALYSIS_ID, created_at=datetime(2026, 8, 3, 13, 0))


def test_contract_rejects_empty_strings_in_nested_dictionary() -> None:
    with pytest.raises(ValidationError, match="empty strings are not valid contract values"):
        ErrorBody(
            code="VALIDATION_ERROR",
            message="Invalid request.",
            retryable=False,
            details={"context": {"reason": "   "}},
        )


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, RiskLevel.LOW),
        (29, RiskLevel.LOW),
        (30, RiskLevel.MEDIUM),
        (59, RiskLevel.MEDIUM),
        (60, RiskLevel.HIGH),
        (84, RiskLevel.HIGH),
        (85, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_boundaries(score: int, expected: RiskLevel) -> None:
    assert risk_level_for_score(score) is expected


def completed_payload() -> dict:
    return {
        "analysis_id": ANALYSIS_ID,
        "status": "completed",
        "input_type": "url",
        "normalized_urls": ["https://official.example/security"],
        "claims": [],
        "risk_score": 10,
        "risk_level": "low",
        "verdict": "safe",
        "recommended_action": "allow",
        "confidence": 0.9,
        "summary": "Không phát hiện tín hiệu rủi ro trong bằng chứng hiện có.",
        "reasons": ["Tên miền thuộc danh sách chính thức."],
        "evidence": [
            Evidence(
                type="official_source",
                source="official-domain-registry",
                title="Tên miền chính thức",
                url="https://official.example/security",
                finding="Tên miền có trong danh sách chính thức.",
                observed_at=NOW,
            )
        ],
        "limitations": [],
        "case_status": "not_required",
        "scoring_version": "risk-v1",
        "created_at": NOW,
        "completed_at": NOW,
    }


def test_completed_analysis_requires_all_result_fields() -> None:
    payload = completed_payload()
    payload.pop("limitations")
    with pytest.raises(ValidationError, match="completed analysis is missing fields: limitations"):
        AnalysisResponse.model_validate(payload)


def test_completed_analysis_enforces_score_bucket() -> None:
    payload = completed_payload()
    payload["risk_level"] = "critical"
    with pytest.raises(ValidationError, match="risk_level does not match risk_score"):
        AnalysisResponse.model_validate(payload)


def test_running_analysis_allows_nullable_result_fields() -> None:
    response = AnalysisResponse(
        analysis_id=ANALYSIS_ID,
        status="running",
        created_at=NOW,
    )
    assert response.risk_score is None
    assert response.completed_at is None


def test_rejected_admin_decision_cannot_request_blacklist_write() -> None:
    with pytest.raises(ValidationError, match="blacklist write requires an approved decision"):
        AdminDecisionRequest(
            decision="rejected",
            action="add_to_blacklist",
            note="Evidence is insufficient.",
        )


def test_agent_state_matches_frozen_contract() -> None:
    assert set(get_type_hints(AgentState)) == {
        "analysis_id",
        "message",
        "consent_to_scan_urls",
        "input_type",
        "extracted_urls",
        "normalized_urls",
        "claims",
        "url_findings",
        "claim_findings",
        "evidence",
        "tool_calls_used",
        "errors",
        "risk_score",
        "risk_level",
        "verdict",
        "confidence",
        "recommended_action",
        "reasons",
        "limitations",
        "case_status",
        "scoring_version",
    }
