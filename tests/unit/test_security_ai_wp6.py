from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.tools.security_memory import SecurityMemoryLookupTool
from src.core.auth import Principal, UserRole
from src.models import (
    PotentialThreatV4,
    SecurityCampaignRecordV4,
    SecurityCampaignReviewerStatusV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryRecordV4,
    SecurityRiskV4,
    SecurityScenarioV4,
    SecurityTriageCreateRequestV4,
)
from src.repositories.blacklist import SQLiteBlacklistRepository
from src.services.security_memory import (
    ReviewedCampaignCandidate,
    ReviewedMemoryCandidate,
    SecurityMemoryService,
)
from src.services.security_triage import SecurityTriageScopeService

NOW = datetime(2026, 8, 15, 8, tzinfo=UTC)
ADMIN = Principal("reviewer", UserRole.SECURITY_ADMIN)


def _memory(
    analysis_id: UUID,
    verdict: SecurityMemoryAdminVerdictV4,
    *,
    domain: str = "reviewed.example",
) -> SecurityMemoryRecordV4:
    return SecurityMemoryRecordV4(
        analysis_id=analysis_id,
        canonical_domains=[domain],
        scenario=SecurityScenarioV4.UNKNOWN,
        threat_type=PotentialThreatV4.UNDETERMINED_SECURITY_THREAT,
        risk=SecurityRiskV4.SUSPICIOUS,
        risk_policy_version="security-risk-v1",
        first_seen_at=NOW,
        last_seen_at=NOW,
        admin_verdict=verdict,
        evidence_refs=["evidence:1111111111111111"],
    )


async def _investigated(url: str = "https://reviewed.example/login"):
    request = SecurityTriageCreateRequestV4(message=f"Kiểm tra link {url}")
    scoped = SecurityTriageScopeService().assess(request)
    return await SecurityInvestigationService().investigate(request, scoped)


class _Candidates:
    def __init__(self, memories=(), campaigns=()) -> None:
        self.memories = list(memories)
        self.campaigns = list(campaigns)

    async def reviewed_candidates(self, owner_id, current_analysis_id):
        assert owner_id == "owner-a"
        del current_analysis_id
        return self.memories, self.campaigns


@pytest.mark.asyncio
async def test_lookup_uses_only_allowed_reviewed_verdicts_and_minimizes_public_evidence() -> None:
    scope = await _investigated()
    malicious = _memory(uuid4(), SecurityMemoryAdminVerdictV4.MALICIOUS)
    suspicious = _memory(uuid4(), SecurityMemoryAdminVerdictV4.SUSPICIOUS)
    unreviewed = _memory(uuid4(), SecurityMemoryAdminVerdictV4.UNREVIEWED)
    candidates = _Candidates(
        memories=[
            ReviewedMemoryCandidate(malicious, NOW),
            ReviewedMemoryCandidate(suspicious, NOW),
            ReviewedMemoryCandidate(unreviewed, NOW),
        ]
    )

    enriched = await SecurityMemoryLookupTool(candidates, enabled=True).enrich(scope, owner_id="owner-a")
    reviewed = [item for item in enriched.evidence if item.type is SecurityEvidenceTypeV4.REVIEWED_SECURITY_MEMORY]

    assert len(reviewed) == 1
    assert reviewed[0].signal.startswith("reviewed_memory_malicious+")
    assert reviewed[0].provenance_ref == f"security-memory:{malicious.memory_id}"
    serialized = reviewed[0].model_dump_json()
    assert "owner-a" not in serialized
    assert str(malicious.analysis_id) not in serialized
    assert "reviewed_at=" in reviewed[0].description


@pytest.mark.asyncio
async def test_lookup_rejects_self_match_and_non_confirmed_campaigns() -> None:
    scope = await _investigated()
    member_ids = [uuid4(), uuid4(), uuid4()]

    def campaign(status, campaign_id=None):
        reviewed = status is SecurityCampaignReviewerStatusV4.CONFIRMED
        return SecurityCampaignRecordV4(
            campaign_id=campaign_id or uuid4(),
            hypothesis="Reviewed named-signal cluster",
            analysis_ids=member_ids,
            window_started_at=NOW,
            window_ended_at=NOW,
            aggregate_signals={"domain:reviewed.example": 3},
            reviewer_status=status,
            evidence_refs=["evidence:2222222222222222"],
            reviewer_id="reviewer" if reviewed else None,
            review_note="Confirmed pattern" if reviewed else None,
            reviewed_at=NOW if reviewed else None,
            created_at=NOW,
        )

    self_memory = _memory(scope.analysis_id, SecurityMemoryAdminVerdictV4.MALICIOUS)
    confirmed = campaign(SecurityCampaignReviewerStatusV4.CONFIRMED)
    pending = campaign(SecurityCampaignReviewerStatusV4.PENDING_REVIEW)
    enriched = await SecurityMemoryLookupTool(
        _Candidates(
            memories=[ReviewedMemoryCandidate(self_memory, NOW)],
            campaigns=[ReviewedCampaignCandidate(confirmed), ReviewedCampaignCandidate(pending)],
        ),
        enabled=True,
    ).enrich(scope, owner_id="owner-a")
    reviewed = [item for item in enriched.evidence if item.type is SecurityEvidenceTypeV4.REVIEWED_SECURITY_MEMORY]

    assert len(reviewed) == 1
    assert reviewed[0].signal.startswith("reviewed_campaign_confirmed+")
    assert all(str(item) not in reviewed[0].model_dump_json() for item in confirmed.analysis_ids)


@pytest.mark.asyncio
async def test_sqlite_reviewed_lookup_enforces_owner_and_excludes_unreviewed(tmp_path) -> None:
    repository = SQLiteBlacklistRepository(tmp_path / "wp6.db")
    service = SecurityMemoryService(repository, clock=lambda: NOW)

    async def store(owner: str, verdict: SecurityMemoryAdminVerdictV4):
        result = assess_security_risk(await _investigated())
        await repository.save_security_analysis(owner, result, [])
        record = await service.record(result, owner)
        assert record is not None
        if verdict is not SecurityMemoryAdminVerdictV4.UNREVIEWED:
            record = await service.correct_memory(record.memory_id, verdict, "reviewed", ADMIN)
        return record

    owned = await store("owner-a", SecurityMemoryAdminVerdictV4.MALICIOUS)
    await store("owner-b", SecurityMemoryAdminVerdictV4.MALICIOUS)
    await store("owner-a", SecurityMemoryAdminVerdictV4.UNREVIEWED)

    memories, campaigns = await service.reviewed_candidates("owner-a", uuid4())
    await repository.close()

    assert [item.record.memory_id for item in memories] == [owned.memory_id]
    assert campaigns == []


@pytest.mark.asyncio
async def _security_risk_v2_uses_malicious_memory_and_false_positive_only_suppresses_weak_signals() -> None:
    scope = await _investigated()
    context_evidence = next(item for item in scope.evidence if item.type is SecurityEvidenceTypeV4.SECURITY_CONTEXT)
    weak = SecurityEvidenceV4(
        evidence_ref="evidence:3333333333333333",
        type=SecurityEvidenceTypeV4.RDAP,
        source="fixture",
        target="reviewed.example",
        signal="new_domain+lookalike_domain",
        description="Weak domain-age and lookalike signals.",
        observed_at=NOW,
    )
    false_positive = SecurityEvidenceV4(
        evidence_ref="evidence:4444444444444444",
        type=SecurityEvidenceTypeV4.REVIEWED_SECURITY_MEMORY,
        source="security_memory_lookup",
        target="reviewed.example",
        signal="reviewed_memory_false_positive+domain",
        description="Reviewed false-positive pattern.",
        observed_at=NOW,
        provenance_ref=f"security-memory:{uuid4()}",
    )
    malicious = false_positive.model_copy(
        update={
            "evidence_ref": "evidence:5555555555555555",
            "signal": "reviewed_memory_malicious+domain",
            "description": "Reviewed malicious pattern.",
        }
    )
    unrelated_weak = weak.model_copy(update={"evidence_ref": "evidence:8888888888888888", "target": "other.example"})
    blacklist = SecurityEvidenceV4(
        evidence_ref="evidence:6666666666666666",
        type=SecurityEvidenceTypeV4.BLACKLIST,
        source="approved-blacklist",
        target="reviewed.example",
        signal="approved_blacklist_hit",
        description="Approved blacklist hit.",
        observed_at=NOW,
    )

    weak_scope = scope.model_copy(update={"evidence": [context_evidence, weak]})
    baseline = assess_security_risk(weak_scope, memory_enabled=True)
    suppressed = assess_security_risk(
        scope.model_copy(update={"evidence": [context_evidence, weak, false_positive]}),
        memory_enabled=True,
    )
    raised = assess_security_risk(
        scope.model_copy(update={"evidence": [context_evidence, malicious]}),
        memory_enabled=True,
    )
    protected = assess_security_risk(
        scope.model_copy(update={"evidence": [context_evidence, weak, false_positive, blacklist]}),
        memory_enabled=True,
    )
    targeted = assess_security_risk(
        scope.model_copy(update={"evidence": [context_evidence, weak, unrelated_weak, false_positive]}),
        memory_enabled=True,
    )
    unrelated_only = assess_security_risk(
        scope.model_copy(update={"evidence": [context_evidence, unrelated_weak]}),
        memory_enabled=True,
    )

    assert baseline.policy_version == suppressed.policy_version == raised.policy_version == "security-risk-v2"
    assert suppressed.score < baseline.score
    assert suppressed.risk is not SecurityRiskV4.SAFE
    assert raised.score >= 50
    assert targeted.score == unrelated_only.score
    assert protected.risk is SecurityRiskV4.MALICIOUS
    assert protected.score >= 95


@pytest.mark.asyncio
async def _disabled_lookup_is_byte_compatible_and_uses_current_risk_policy() -> None:
    scope = await _investigated()
    unchanged = await SecurityMemoryLookupTool(_Candidates(), enabled=False).enrich(scope, owner_id="owner-a")
    result = assess_security_risk(unchanged)

    assert unchanged.model_dump_json() == scope.model_dump_json()
    assert result.policy_version == "security-risk-v1"
    assert all(item.type is not SecurityEvidenceTypeV4.REVIEWED_SECURITY_MEMORY for item in result.evidence)


@pytest.mark.asyncio
async def _lookup_failure_falls_back_without_failing_analysis() -> None:
    class FailingMemory:
        async def reviewed_candidates(self, owner_id, current_analysis_id):
            del owner_id, current_analysis_id
            raise ConnectionError("repository unavailable")

    enriched = await SecurityMemoryLookupTool(FailingMemory(), enabled=True).enrich(
        await _investigated(),
        owner_id="owner-a",
    )
    result = assess_security_risk(enriched, memory_enabled=True)

    assert result.status.value == "completed"
    assert result.policy_version == "security-risk-v2"
    assert any(item.code == "MEMORY_LOOKUP_FAILED" for item in result.errors)
    assert any("Security Memory" in item for item in result.limitations)
