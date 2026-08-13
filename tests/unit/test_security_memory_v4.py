from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from src.agents.campaign import (
    SecurityCampaignConfig,
    build_security_memory_record,
    cluster_security_memory,
)
from src.core.auth import Principal, UserRole
from src.models import (
    AnalysisStatus,
    PotentialThreatV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityCampaignReviewerStatusV4,
    SecurityContextV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryRecordV4,
    SecurityRecommendedActionV4,
    SecurityReportRecordV4,
    SecurityRiskV4,
    SecurityScenarioV4,
    SecurityScopeResponseV4,
)
from src.repositories.blacklist import SQLiteBlacklistRepository
from src.services.security_memory import SecurityMemoryService

NOW = datetime(2026, 8, 13, 8, tzinfo=UTC)
ADMIN = Principal("security-reviewer", UserRole.SECURITY_ADMIN)


def _memory(
    *,
    domain: str | None = None,
    redirect: str | None = None,
    brand: str | None = None,
    scenario: SecurityScenarioV4 = SecurityScenarioV4.UNKNOWN,
    action: RequestedActionV4 | None = None,
    patterns: list[str] | None = None,
    seen: datetime = NOW,
) -> SecurityMemoryRecordV4:
    return SecurityMemoryRecordV4(
        analysis_id=uuid4(),
        canonical_domains=[domain] if domain else [],
        url_fingerprints=[],
        redirect_targets=[redirect] if redirect else [],
        claimed_brand=brand,
        scenario=scenario,
        requested_action=action,
        security_patterns=patterns or [],
        lexical_features=[],
        threat_type=PotentialThreatV4.PHISHING,
        risk=SecurityRiskV4.HIGH_RISK,
        risk_policy_version="security-risk-v1",
        first_seen_at=seen,
        last_seen_at=seen,
        evidence_refs=[f"evidence:{uuid4().hex[:16]}"],
    )


def _response(url: str, *, completed_at: datetime = NOW) -> SecurityScopeResponseV4:
    return SecurityScopeResponseV4(
        status=AnalysisStatus.COMPLETED,
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        terminal=True,
        next_step="END",
        scope_reasons=["security_request"],
        security_context=SecurityContextV4(
            claimed_entity="ACME Bank",
            scenario=SecurityScenarioV4.ACCOUNT_VERIFICATION,
            requested_action=RequestedActionV4.SHARE_OTP,
            urgency=True,
            urls=[url],
            credential_request=False,
            otp_request=True,
            payment_request=False,
            personal_information_request=False,
            impersonation_signals=["brand_claim"],
            potential_threat=PotentialThreatV4.CREDENTIAL_THEFT,
        ),
        risk=SecurityRiskV4.HIGH_RISK,
        score=90,
        confidence=0.9,
        threat_type=PotentialThreatV4.CREDENTIAL_THEFT,
        policy_version="security-risk-v1",
        recommended_actions=[SecurityRecommendedActionV4.DO_NOT_SHARE_OTP],
        explanation="High-risk OTP request.",
        explanation_evidence_refs=["evidence:0123456789abcdef"],
        created_at=completed_at - timedelta(seconds=1),
        completed_at=completed_at,
    )


@pytest.mark.parametrize(
    "records,expected_signal",
    [
        ([_memory(domain="bad.example") for _ in range(3)], "domain:bad.example"),
        ([_memory(domain=f"bad-{i}.example", redirect="landing.example") for i in range(3)], "redirect:landing.example"),
        ([_memory(domain=f"bad-{i}.example", brand="acme") for i in range(3)], "brand:acme"),
        (
            [
                _memory(
                    domain=f"jobs-{i}.example",
                    scenario=SecurityScenarioV4.RECRUITMENT,
                    action=RequestedActionV4.PAY_FEE,
                    patterns=["payment_request"],
                )
                for i in range(3)
            ],
            "scenario:recruitment",
        ),
    ],
)
def test_explainable_security_signals_form_campaign(records, expected_signal) -> None:
    campaigns = cluster_security_memory(records)

    assert len(campaigns) == 1
    assert campaigns[0].reviewer_status is SecurityCampaignReviewerStatusV4.PENDING_REVIEW
    assert campaigns[0].aggregate_signals[expected_signal] == 3
    assert campaigns[0].clustering_version == "security-clustering-v1"


def test_unrelated_or_out_of_window_memory_does_not_cluster() -> None:
    unrelated = [
        _memory(domain="alpha.example", scenario=SecurityScenarioV4.PAYMENT),
        _memory(domain="beta.example", scenario=SecurityScenarioV4.RECRUITMENT),
        _memory(domain="gamma.example", scenario=SecurityScenarioV4.PROMOTION_PRIZE),
    ]
    expired = [
        _memory(domain="same.example", seen=NOW - timedelta(hours=26)),
        _memory(domain="same.example", seen=NOW - timedelta(hours=25)),
        _memory(domain="same.example", seen=NOW),
    ]

    assert cluster_security_memory(unrelated) == []
    assert cluster_security_memory(expired, config=SecurityCampaignConfig(window=timedelta(hours=24))) == []


def test_fingerprint_is_privacy_minimized_and_versioned() -> None:
    response = SecurityScopeResponseV4(
        status=AnalysisStatus.COMPLETED,
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        terminal=True,
        next_step="END",
        scope_reasons=["security_request"],
        security_context=SecurityContextV4(
            claimed_entity="ACME Bank",
            scenario=SecurityScenarioV4.ACCOUNT_VERIFICATION,
            requested_action=RequestedActionV4.SHARE_OTP,
            urgency=True,
            urls=["https://login-acme.example/verify?token=private-token"],
            credential_request=False,
            otp_request=True,
            payment_request=False,
            personal_information_request=False,
            impersonation_signals=["brand_claim"],
            potential_threat=PotentialThreatV4.CREDENTIAL_THEFT,
        ),
        risk=SecurityRiskV4.HIGH_RISK,
        score=90,
        confidence=0.9,
        threat_type=PotentialThreatV4.CREDENTIAL_THEFT,
        policy_version="security-risk-v1",
        recommended_actions=[SecurityRecommendedActionV4.DO_NOT_SHARE_OTP],
        explanation="High-risk OTP request.",
        explanation_evidence_refs=["evidence:0123456789abcdef"],
        completed_at=NOW,
    )

    record = build_security_memory_record(response)
    serialized = record.model_dump_json()

    assert record.canonical_domains == ["login-acme.example"]
    assert record.claimed_brand == "acme bank"
    assert record.security_patterns == ["otp_request", "urgency"]
    assert "path:verify" in record.lexical_features
    assert record.fingerprint_version == "security-fingerprint-v1"
    assert "private-token" not in serialized
    assert response.explanation not in serialized


@pytest.mark.asyncio
async def test_admin_correction_and_campaign_review_append_immutable_audit() -> None:
    service = SecurityMemoryService()
    records = [_memory(domain="coordinated.example") for _ in range(3)]
    for record in records:
        service._memory.records[record.memory_id] = record  # deterministic unit-store fixture
    campaign = cluster_security_memory(records)[0]
    service._memory.campaigns[campaign.campaign_id] = campaign

    corrected = await service.correct_memory(
        records[0].memory_id,
        SecurityMemoryAdminVerdictV4.FALSE_POSITIVE,
        "Verified as a false positive.",
        ADMIN,
    )
    corrected_again = await service.correct_memory(
        records[0].memory_id,
        SecurityMemoryAdminVerdictV4.SUSPICIOUS,
        "New provenance requires review.",
        ADMIN,
    )
    reviewed = await service.review_campaign(
        campaign.campaign_id,
        SecurityCampaignReviewerStatusV4.REJECTED,
        "Shared domain belongs to a test fixture.",
        ADMIN,
    )

    memory_audit = await service.memory_audit(records[0].memory_id, ADMIN)
    campaign_audit = await service.campaign_audit(campaign.campaign_id, ADMIN)
    assert corrected.admin_verdict is SecurityMemoryAdminVerdictV4.FALSE_POSITIVE
    assert corrected_again.admin_verdict is SecurityMemoryAdminVerdictV4.SUSPICIOUS
    assert [item.previous_verdict for item in memory_audit] == [
        SecurityMemoryAdminVerdictV4.UNREVIEWED,
        SecurityMemoryAdminVerdictV4.FALSE_POSITIVE,
    ]
    assert all(item.fingerprint_version == "security-fingerprint-v1" for item in memory_audit)
    assert reviewed.reviewer_status is SecurityCampaignReviewerStatusV4.REJECTED
    assert len(campaign_audit) == 1
    assert campaign_audit[0].evidence_refs == campaign.evidence_refs


@pytest.mark.asyncio
async def test_sqlite_persists_memory_campaign_audit_and_report_count(tmp_path) -> None:
    database = tmp_path / "security-memory.db"
    repository = SQLiteBlacklistRepository(database)
    service = SecurityMemoryService(repository)
    responses = [_response(f"https://persistent.example/{index}") for index in range(3)]
    for response in responses:
        await repository.save_security_analysis("owner", response, [])
        await service.record(response)
    records = await service.list_memory(ADMIN)
    await repository.save_security_report(
        "owner",
        SecurityReportRecordV4(analysis_id=records[0].analysis_id, reason="User report"),
    )
    corrected = await service.correct_memory(
        records[0].memory_id,
        SecurityMemoryAdminVerdictV4.MALICIOUS,
        "Confirmed by incident response.",
        ADMIN,
    )
    campaigns = await service.list_campaigns(ADMIN)
    await service.review_campaign(
        campaigns[0].campaign_id,
        SecurityCampaignReviewerStatusV4.CONFIRMED,
        "Coordinated infrastructure.",
        ADMIN,
    )
    await repository.close()

    reopened = SQLiteBlacklistRepository(database)
    restored = SecurityMemoryService(reopened)
    restored_records = await restored.list_memory(ADMIN)
    restored_campaigns = await restored.list_campaigns(ADMIN)

    restored_record = next(item for item in restored_records if item.memory_id == corrected.memory_id)
    assert restored_record.admin_verdict is SecurityMemoryAdminVerdictV4.MALICIOUS
    assert restored_record.report_count == 1
    assert len(await restored.memory_audit(corrected.memory_id, ADMIN)) == 1
    assert restored_campaigns[0].reviewer_status is SecurityCampaignReviewerStatusV4.CONFIRMED
    assert len(await restored.campaign_audit(restored_campaigns[0].campaign_id, ADMIN)) == 1
    await reopened.close()
