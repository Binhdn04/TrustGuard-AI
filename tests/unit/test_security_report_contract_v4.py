from datetime import UTC, datetime, timedelta
from itertools import product
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.models import (
    ReportReviewDecision,
    ReportStatus,
    SecurityAdminCopilotDispositionV4,
    SecurityReportBlacklistProposalV4,
    SecurityReportDecisionRequestV4,
    SecurityReportRecordV4,
    SecurityReportRemediationActionV4,
    SecurityReportRemediationReferenceV4,
    SecurityReportRemediationStatusV4,
    SecurityReportResolutionV4,
    WhitelistCreateRequestV4,
    WhitelistScopeV4,
)

NOW = datetime(2026, 8, 24, 8, tzinfo=UTC)


def _whitelist_entry(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "indicator": "example.com",
        "scope": WhitelistScopeV4.DOMAIN,
        "provenance": "report:reviewed-evidence",
        "effective_from": NOW,
        "effective_until": NOW + timedelta(days=30),
    }
    payload.update(updates)
    return payload


def _blacklist_proposal(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "canonical_domain": "malicious.example",
        "reason": "Reviewed credential-theft evidence",
        "evidence_refs": ["evidence:0123456789abcdef"],
        "provenance": "report:reviewed-evidence",
    }
    payload.update(updates)
    return payload


def _decision_payload(
    decision: ReportReviewDecision,
    resolution: SecurityReportResolutionV4 | None,
    action: SecurityReportRemediationActionV4,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "decision": decision,
        "resolution": resolution,
        "remediation_action": action,
        "note": "Reviewed against the immutable evidence snapshot",
    }
    if action is SecurityReportRemediationActionV4.ADD_TO_WHITELIST:
        payload["whitelist_entry"] = _whitelist_entry()
    if action is SecurityReportRemediationActionV4.PROPOSE_BLACKLIST:
        payload["blacklist_proposal"] = _blacklist_proposal()
    return payload


def _combination_is_valid(
    decision: ReportReviewDecision,
    resolution: SecurityReportResolutionV4 | None,
    action: SecurityReportRemediationActionV4,
) -> bool:
    if decision is not ReportReviewDecision.APPROVED:
        return resolution is None and action is SecurityReportRemediationActionV4.NONE
    if resolution is None:
        return False
    allowed_actions = {
        SecurityReportResolutionV4.CONFIRM_SAFE: {
            SecurityReportRemediationActionV4.NONE,
            SecurityReportRemediationActionV4.UPDATE_MEMORY,
            SecurityReportRemediationActionV4.ADD_TO_WHITELIST,
        },
        SecurityReportResolutionV4.MARK_FALSE_POSITIVE: {
            SecurityReportRemediationActionV4.NONE,
            SecurityReportRemediationActionV4.UPDATE_MEMORY,
            SecurityReportRemediationActionV4.ADD_TO_WHITELIST,
        },
        SecurityReportResolutionV4.CONFIRM_MALICIOUS: {
            SecurityReportRemediationActionV4.NONE,
            SecurityReportRemediationActionV4.UPDATE_MEMORY,
            SecurityReportRemediationActionV4.PROPOSE_BLACKLIST,
        },
        SecurityReportResolutionV4.NEEDS_MORE_INFORMATION: {
            SecurityReportRemediationActionV4.NONE,
        },
        SecurityReportResolutionV4.NO_CHANGE: {
            SecurityReportRemediationActionV4.NONE,
        },
    }
    return action in allowed_actions[resolution]


@pytest.mark.parametrize(
    ("decision", "resolution", "action"),
    list(
        product(
            list(ReportReviewDecision),
            [None, *list(SecurityReportResolutionV4)],
            list(SecurityReportRemediationActionV4),
        )
    ),
)
def test_report_decision_resolution_remediation_matrix(
    decision: ReportReviewDecision,
    resolution: SecurityReportResolutionV4 | None,
    action: SecurityReportRemediationActionV4,
) -> None:
    payload = _decision_payload(decision, resolution, action)
    if _combination_is_valid(decision, resolution, action):
        parsed = SecurityReportDecisionRequestV4.model_validate(payload)
        assert parsed.decision is decision
        assert parsed.resolution is resolution
        assert parsed.remediation_action is action
    else:
        with pytest.raises(ValidationError):
            SecurityReportDecisionRequestV4.model_validate(payload)


def test_report_resolution_is_independent_from_admin_copilot_disposition() -> None:
    assert SecurityReportResolutionV4 is not SecurityAdminCopilotDispositionV4
    assert set(SecurityReportResolutionV4) == {
        SecurityReportResolutionV4.CONFIRM_SAFE,
        SecurityReportResolutionV4.MARK_FALSE_POSITIVE,
        SecurityReportResolutionV4.CONFIRM_MALICIOUS,
        SecurityReportResolutionV4.NEEDS_MORE_INFORMATION,
        SecurityReportResolutionV4.NO_CHANGE,
    }


@pytest.mark.parametrize("missing", ["indicator", "scope", "provenance", "effective_from"])
def test_whitelist_remediation_requires_complete_trust_input(missing: str) -> None:
    entry = _whitelist_entry()
    entry.pop(missing)
    payload = _decision_payload(
        ReportReviewDecision.APPROVED,
        SecurityReportResolutionV4.CONFIRM_SAFE,
        SecurityReportRemediationActionV4.ADD_TO_WHITELIST,
    )
    payload["whitelist_entry"] = entry
    with pytest.raises(ValidationError):
        SecurityReportDecisionRequestV4.model_validate(payload)


def test_whitelist_remediation_rejects_invalid_effective_interval() -> None:
    payload = _decision_payload(
        ReportReviewDecision.APPROVED,
        SecurityReportResolutionV4.MARK_FALSE_POSITIVE,
        SecurityReportRemediationActionV4.ADD_TO_WHITELIST,
    )
    payload["whitelist_entry"] = _whitelist_entry(effective_until=NOW)
    with pytest.raises(ValidationError, match="effective_until must be after effective_from"):
        SecurityReportDecisionRequestV4.model_validate(payload)


@pytest.mark.parametrize("missing", ["canonical_domain", "reason", "evidence_refs", "provenance"])
def test_blacklist_remediation_requires_complete_review_input(missing: str) -> None:
    proposal = _blacklist_proposal()
    proposal.pop(missing)
    payload = _decision_payload(
        ReportReviewDecision.APPROVED,
        SecurityReportResolutionV4.CONFIRM_MALICIOUS,
        SecurityReportRemediationActionV4.PROPOSE_BLACKLIST,
    )
    payload["blacklist_proposal"] = proposal
    with pytest.raises(ValidationError):
        SecurityReportDecisionRequestV4.model_validate(payload)


@pytest.mark.parametrize(
    "domain",
    [
        "HTTPS://malicious.example/path",
        "Malicious.Example",
        "malicious.example.",
        "mã-độc.example",
        "localhost",
        "192.0.2.1",
    ],
)
def test_blacklist_remediation_requires_canonical_ascii_domain(domain: str) -> None:
    with pytest.raises(ValidationError, match="canonical_domain"):
        SecurityReportBlacklistProposalV4.model_validate(_blacklist_proposal(canonical_domain=domain))


def test_remediation_payload_is_rejected_for_another_action() -> None:
    with pytest.raises(ValidationError, match="whitelist_entry is only valid"):
        SecurityReportDecisionRequestV4(
            decision=ReportReviewDecision.APPROVED,
            resolution=SecurityReportResolutionV4.CONFIRM_SAFE,
            remediation_action=SecurityReportRemediationActionV4.NONE,
            whitelist_entry=WhitelistCreateRequestV4.model_validate(_whitelist_entry()),
            note="No side effect requested",
        )


def test_report_decision_audit_evidence_combines_and_deduplicates_refs() -> None:
    payload = _decision_payload(
        ReportReviewDecision.APPROVED,
        SecurityReportResolutionV4.CONFIRM_MALICIOUS,
        SecurityReportRemediationActionV4.PROPOSE_BLACKLIST,
    )
    payload["evidence_refs"] = ["evidence:shared", "evidence:decision"]
    proposal = _blacklist_proposal()
    proposal["evidence_refs"] = ["evidence:shared", "evidence:blacklist"]
    payload["blacklist_proposal"] = proposal
    request = SecurityReportDecisionRequestV4.model_validate(payload)
    assert request.audit_evidence_refs() == [
        "evidence:shared",
        "evidence:decision",
        "evidence:blacklist",
    ]


def test_report_decision_rejects_more_than_one_hundred_combined_evidence_refs() -> None:
    payload = _decision_payload(
        ReportReviewDecision.APPROVED,
        SecurityReportResolutionV4.CONFIRM_MALICIOUS,
        SecurityReportRemediationActionV4.PROPOSE_BLACKLIST,
    )
    payload["evidence_refs"] = [f"evidence:decision-{index}" for index in range(100)]
    with pytest.raises(ValidationError, match="combined report decision evidence_refs"):
        SecurityReportDecisionRequestV4.model_validate(payload)


def test_legacy_unprocessed_report_uses_safe_remediation_defaults() -> None:
    record = SecurityReportRecordV4(analysis_id=uuid4(), reason="Legacy report")
    assert record.resolution is None
    assert record.remediation_action is SecurityReportRemediationActionV4.NONE
    assert record.remediation_status is SecurityReportRemediationStatusV4.NOT_REQUESTED
    assert record.remediation_reference is None


def test_legacy_processed_approved_report_without_resolution_remains_readable() -> None:
    record = SecurityReportRecordV4.model_validate(
        {
            "analysis_id": uuid4(),
            "reason": "Legacy reviewed report",
            "status": "processed",
            "decision": "approved",
            "reviewer_id": "legacy-admin",
            "review_note": "Reviewed before structured resolutions",
            "reviewed_at": NOW,
        }
    )
    assert record.resolution is None
    assert record.remediation_action is SecurityReportRemediationActionV4.NONE
    assert record.remediation_status is SecurityReportRemediationStatusV4.NOT_REQUESTED


def test_processed_report_tracks_pending_remediation_separately() -> None:
    record = SecurityReportRecordV4(
        analysis_id=uuid4(),
        reason="Reviewed report",
        status=ReportStatus.PROCESSED,
        decision=ReportReviewDecision.APPROVED,
        resolution=SecurityReportResolutionV4.CONFIRM_MALICIOUS,
        remediation_action=SecurityReportRemediationActionV4.PROPOSE_BLACKLIST,
        blacklist_proposal=SecurityReportBlacklistProposalV4.model_validate(_blacklist_proposal()),
        remediation_status=SecurityReportRemediationStatusV4.PENDING,
        reviewer_id="admin-1",
        review_note="Confirmed malicious; proposal still needs execution",
        reviewed_at=NOW,
    )
    assert record.status is ReportStatus.PROCESSED
    assert record.remediation_status is SecurityReportRemediationStatusV4.PENDING
    assert record.remediation_reference is None


def test_executed_remediation_requires_matching_reference() -> None:
    common = {
        "analysis_id": uuid4(),
        "reason": "Reviewed report",
        "status": ReportStatus.PROCESSED,
        "decision": ReportReviewDecision.APPROVED,
        "resolution": SecurityReportResolutionV4.CONFIRM_SAFE,
        "remediation_action": SecurityReportRemediationActionV4.UPDATE_MEMORY,
        "remediation_status": SecurityReportRemediationStatusV4.EXECUTED,
        "reviewer_id": "admin-1",
        "review_note": "Memory updated",
        "reviewed_at": NOW,
    }
    with pytest.raises(ValidationError, match="target reference"):
        SecurityReportRecordV4(**common)
    with pytest.raises(ValidationError, match="must match"):
        SecurityReportRecordV4(
            **common,
            remediation_reference=SecurityReportRemediationReferenceV4(whitelist_id=uuid4()),
        )
    record = SecurityReportRecordV4(
        **common,
        remediation_reference=SecurityReportRemediationReferenceV4(memory_id=uuid4()),
    )
    assert record.remediation_reference is not None
    assert record.remediation_reference.memory_id is not None


def test_remediation_reference_rejects_zero_or_multiple_targets() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        SecurityReportRemediationReferenceV4()
    with pytest.raises(ValidationError, match="exactly one"):
        SecurityReportRemediationReferenceV4(memory_id=uuid4(), whitelist_id=uuid4())
