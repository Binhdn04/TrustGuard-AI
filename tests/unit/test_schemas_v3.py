from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import TypeAdapter, ValidationError

from src.models import (
    AdminActionRecordV3,
    AdminActionStatus,
    AnalysisEventType,
    AnalysisEventV3,
    AppealOutcome,
    AppealResponseV3,
    AppealStatus,
    ProvisionalWarningEventV3,
    ReviewedAction,
)

ANALYSIS_ID = UUID("550e8400-e29b-41d4-a716-446655440000")
EVENT_ID = UUID("650e8400-e29b-41d4-a716-446655440000")
ACTION_ID = UUID("750e8400-e29b-41d4-a716-446655440000")
APPEAL_ID = UUID("850e8400-e29b-41d4-a716-446655440000")
NOW = datetime(2026, 8, 7, 13, 0, tzinfo=UTC)


def test_v3_event_and_action_enums_are_frozen() -> None:
    assert {item.value for item in AnalysisEventType} == {
        "analysis_status",
        "step_transition",
        "provisional_warning",
        "final_result",
        "case_update",
        "limitation",
    }
    assert {item.value for item in ReviewedAction} == {
        "add_to_blacklist",
        "disable_blacklist",
        "block_domain",
        "publish_broad_warning",
        "none",
    }


def test_v3_event_union_uses_event_type_discriminator() -> None:
    payload = {
        "event_id": EVENT_ID,
        "analysis_id": ANALYSIS_ID,
        "sequence": 2,
        "event_type": "provisional_warning",
        "occurred_at": NOW,
        "payload": {
            "risk_level": "high",
            "summary": "Local evidence indicates elevated risk while checks continue.",
            "evidence_refs": ["evidence:local-rule:1"],
            "is_provisional": True,
        },
    }

    event = TypeAdapter(AnalysisEventV3).validate_python(payload)
    assert isinstance(event, ProvisionalWarningEventV3)
    assert event.payload.is_provisional is True

    schema = TypeAdapter(AnalysisEventV3).json_schema()
    assert schema["discriminator"]["propertyName"] == "event_type"


def test_provisional_warning_cannot_claim_low_risk_or_have_no_evidence() -> None:
    common = {
        "event_id": EVENT_ID,
        "analysis_id": ANALYSIS_ID,
        "sequence": 1,
        "occurred_at": NOW,
    }
    with pytest.raises(ValidationError):
        ProvisionalWarningEventV3(
            **common,
            payload={
                "risk_level": "low",
                "summary": "No risk found.",
                "evidence_refs": ["evidence:1"],
            },
        )
    with pytest.raises(ValidationError):
        ProvisionalWarningEventV3(
            **common,
            payload={
                "risk_level": "high",
                "summary": "Risk found.",
                "evidence_refs": [],
            },
        )


def test_appeal_resolution_fields_are_atomic() -> None:
    with pytest.raises(ValidationError, match="resolved appeal requires"):
        AppealResponseV3(
            appeal_id=APPEAL_ID,
            analysis_id=ANALYSIS_ID,
            status=AppealStatus.RESOLVED,
            reason="The warning is incorrect.",
            created_at=NOW,
        )

    appeal = AppealResponseV3(
        appeal_id=APPEAL_ID,
        analysis_id=ANALYSIS_ID,
        status=AppealStatus.RESOLVED,
        reason="The warning is incorrect.",
        outcome=AppealOutcome.OVERTURN,
        resolution_note="Trusted evidence supports the appeal.",
        created_at=NOW,
        resolved_at=NOW,
    )
    assert appeal.contract_version == "v3"


def test_non_none_admin_action_requires_target_and_review_audit() -> None:
    with pytest.raises(ValidationError, match="requires a target"):
        AdminActionRecordV3(
            action_id=ACTION_ID,
            action=ReviewedAction.BLOCK_DOMAIN,
            status=AdminActionStatus.PENDING_REVIEW,
            evidence_snapshot=[],
            proposed_at=NOW,
        )

    with pytest.raises(ValidationError, match="reviewed action requires reviewer"):
        AdminActionRecordV3(
            action_id=ACTION_ID,
            action=ReviewedAction.BLOCK_DOMAIN,
            target="malicious.example",
            status=AdminActionStatus.APPROVED,
            evidence_snapshot=[],
            proposed_at=NOW,
        )

    with pytest.raises(ValidationError, match="requires an evidence snapshot"):
        AdminActionRecordV3(
            action_id=ACTION_ID,
            action=ReviewedAction.BLOCK_DOMAIN,
            target="malicious.example",
            status=AdminActionStatus.PENDING_REVIEW,
            evidence_snapshot=[],
            proposed_at=NOW,
        )
