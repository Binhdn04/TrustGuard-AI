from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest

from src.api.dependencies import get_analysis_service, get_wave2_service
from src.core.auth import Principal, UserRole
from src.main import app
from src.models import Evidence, EvidenceType, ReviewedAction
from src.services.analysis import AnalysisService
from src.services.platform_wave2 import (
    ArtifactRecord,
    ArtifactSigner,
    CampaignWrite,
    EvidenceSnapshotWrite,
    FactCheckCorpusRecordWrite,
    FactCheckResultWrite,
    MemoryWave2Repository,
    SourceRegistryEntry,
    SourceTier,
    UsageLedgerEntry,
    Wave2PlatformService,
)

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}
NOW = datetime(2026, 8, 10, 10, 0, tzinfo=UTC)


@pytest.fixture
def wave2_platform():
    analysis = AnalysisService()
    repository = MemoryWave2Repository()
    service = Wave2PlatformService(repository, ArtifactSigner("wave2-test-signing-key"))
    app.dependency_overrides[get_analysis_service] = lambda: analysis
    app.dependency_overrides[get_wave2_service] = lambda: service
    try:
        yield analysis, repository, service
    finally:
        app.dependency_overrides.pop(get_analysis_service, None)
        app.dependency_overrides.pop(get_wave2_service, None)


async def _analysis(client) -> str:
    response = await client.post(
        "/api/v3/analyses",
        headers=USER_HEADERS,
        json={"message": "Kiểm tra nội dung", "consent_to_scan_urls": False},
    )
    assert response.status_code == 202
    return response.json()["analysis_id"]


@pytest.mark.asyncio
async def test_appeal_owner_admin_decision_notification_and_immutable_conflict(client, wave2_platform):
    _, repository, _ = wave2_platform
    analysis_id = await _analysis(client)

    created = await client.post(
        f"/api/v3/analyses/{analysis_id}/appeals",
        headers=USER_HEADERS,
        json={"reason": "The conclusion is incorrect.", "comment": "Please review the evidence."},
    )
    assert created.status_code == 201
    appeal_id = created.json()["appeal_id"]

    duplicate = await client.post(
        f"/api/v3/analyses/{analysis_id}/appeals",
        headers=USER_HEADERS,
        json={"reason": "Duplicate active appeal."},
    )
    assert duplicate.status_code == 409

    queue = await client.get("/api/v3/admin/appeals", headers=ADMIN_HEADERS)
    assert queue.status_code == 200
    assert queue.json()["items"][0]["owner_id"] == "demo-user"

    decision = await client.post(
        f"/api/v3/admin/appeals/{appeal_id}/decision",
        headers=ADMIN_HEADERS,
        json={"outcome": "overturn", "note": "Reviewed evidence supports the user."},
    )
    assert decision.status_code == 200
    assert decision.json()["outcome"] == "overturn"
    assert len(repository.audit) == 1
    assert repository.notifications[0]["event_type"] == "appeal.resolved"

    detail = await client.get(f"/api/v3/appeals/{appeal_id}", headers=USER_HEADERS)
    assert detail.json()["status"] == "resolved"
    assert detail.json()["outcome"] == "overturn"

    repeated = await client.post(
        f"/api/v3/admin/appeals/{appeal_id}/decision",
        headers=ADMIN_HEADERS,
        json={"outcome": "uphold", "note": "Must not overwrite audit."},
    )
    assert repeated.status_code == 409
    assert len(repository.audit) == 1


@pytest.mark.asyncio
async def test_reviewed_action_requires_one_approved_transaction(client, wave2_platform):
    _, repository, _ = wave2_platform
    evidence = Evidence(
        type=EvidenceType.BLACKLIST,
        source="reviewed-evidence",
        title="Known malicious domain",
        url="https://malicious.example/path?secret=redacted",
        finding="The domain matches reviewed threat intelligence.",
        observed_at=NOW,
    )
    action = await repository.propose_admin_action(
        analysis_id=None,
        campaign_id=None,
        action=ReviewedAction.ADD_TO_BLACKLIST,
        target="https://Malicious.Example/path?token=secret",
        evidence=[evidence],
    )
    assert action.target == "malicious.example"

    response = await client.post(
        f"/api/v3/admin/actions/{action.action_id}/decision",
        headers=ADMIN_HEADERS,
        json={"decision": "approved", "note": "Evidence snapshot reviewed."},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    assert len(repository.audit) == 1

    duplicate = await client.post(
        f"/api/v3/admin/actions/{action.action_id}/decision",
        headers=ADMIN_HEADERS,
        json={"decision": "rejected", "note": "Cannot mutate an immutable decision."},
    )
    assert duplicate.status_code == 409
    assert len(repository.audit) == 1


@pytest.mark.asyncio
async def test_campaign_and_metrics_admin_apis_do_not_expose_private_content(client, wave2_platform):
    _, repository, _ = wave2_platform
    members = [(uuid4(), "domain", 1.0, [f"evidence:{index}"]) for index in range(3)]
    campaign = await repository.record_campaign(
        CampaignWrite(
            hypothesis="Three analyses share a registrable domain.",
            window_started_at=NOW - timedelta(hours=1),
            window_ended_at=NOW,
            clustering_version="campaign-v1",
            members=members,
            aggregate_signals={"shared_domain": 3},
            evidence_refs=["evidence:0", "evidence:1", "evidence:2"],
            registrable_domains=["example.com"],
        )
    )
    await repository.record_usage(
        UsageLedgerEntry(
            analysis_id=members[0][0],
            provider="openai",
            model="text-embedding-3-small",
            provider_version="v1",
            operation="embed_batch",
            input_tokens=12,
            estimated_cost_usd=0.001,
            latency_ms=120,
            cache_status="miss",
            outcome="success",
            observed_at=NOW,
        )
    )

    detail = await client.get(f"/api/v3/admin/campaigns/{campaign.campaign_id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    assert detail.json()["reviewer_status"] == "pending_review"
    assert "message" not in detail.text.lower()

    metrics = await client.get(
        "/api/v3/admin/metrics",
        headers=ADMIN_HEADERS,
        params={"from": (NOW - timedelta(days=1)).isoformat(), "to": (NOW + timedelta(days=1)).isoformat()},
    )
    assert metrics.status_code == 200
    assert metrics.json()["usage"][0]["calls"] == 1
    assert metrics.json()["usage"][0]["tokens"] == 12
    assert "prompt" not in metrics.text.lower()


@pytest.mark.asyncio
async def test_source_registry_deny_promotion_and_artifact_signing(wave2_platform):
    _, repository, service = wave2_platform
    await repository.register_source(
        SourceRegistryEntry(
            publisher="Denied government host",
            normalized_pattern="blocked.gov.vn",
            tier=SourceTier.UNTRUSTED,
            source_type="deny",
            explicit_deny=True,
            allowed_operations=set(),
            policy_version="deny-v1",
            effective_from=NOW - timedelta(days=1),
            default_freshness_seconds=3600,
            reviewer_id="security-admin",
            reviewed_at=NOW,
        )
    )
    registry = await service.source_registry(NOW)
    assert registry.classify("https://portal.gov.vn/news", NOW).tier is SourceTier.A
    denied = registry.classify("https://blocked.gov.vn/news", NOW)
    assert denied.explicit_deny is True
    assert not denied.allows("read")
    assert registry.classify("https://notgov.vn", NOW).tier is SourceTier.UNTRUSTED

    analysis_id = uuid4()
    content_hash = sha256(b"clean evidence").hexdigest()
    tier_c = FactCheckResultWrite(
        analysis_id=analysis_id,
        claim_hash=sha256(b"claim").hexdigest(),
        language="vi",
        is_temporal=False,
        stance="inconclusive",
        evidence_refs=["evidence:tier-c"],
        contradiction_refs=[],
        limitations=[],
        comparator_model="gpt-4o-mini",
        comparator_version="comparator-v1",
        source_policy_version="source-policy-v1",
        embedding_status="complete",
        evidence=[
            EvidenceSnapshotWrite(
                evidence_ref="evidence:tier-c",
                source="news",
                source_version="v1",
                source_tier=SourceTier.C,
                policy_version="source-policy-v1",
                canonical_url="https://news.example/article?secret=removed",
                cleaned_content="clean evidence",
                retrieved_at=NOW,
                temporal_compatible=True,
                content_hash=content_hash,
                validation_status="validated",
            )
        ],
    )
    await repository.cache_fact_check_result(tier_c)
    assert await repository.promote_evidence(tier_c.result_id, "evidence:tier-c", "admin") is False

    tier_a_source = repository.sources[0]
    corpus_record = FactCheckCorpusRecordWrite(
        source_id=tier_a_source.source_id,
        source_url="https://portal.gov.vn/fact-check?tracking=removed",
        publisher="Vietnam government",
        normalized_claim="Nội dung đã được cơ quan công bố.",
        stance="supports",
        language="vi",
        published_at=NOW - timedelta(hours=1),
        source_updated_at=NOW,
        retrieved_at=NOW,
        content_hash=sha256(b"reviewed-source-record").hexdigest(),
        record_version="v1",
        ingestion_provenance="reviewed-import",
        policy_version="source-policy-v1",
    )
    await repository.cache_corpus_record(corpus_record)
    assert await repository.promote_corpus_record(corpus_record.record_id, "admin") is True
    assert repository.corpus_records[corpus_record.record_id].promotion_status == "trusted"
    # Runtime comparator output remains in its separate cache and never becomes a corpus record.
    assert tier_c.result_id not in repository.corpus_records

    owner = "auth0|user.name@example.com"
    artifact = ArtifactRecord(
        analysis_id=analysis_id,
        owner_id=owner,
        storage_key="screenshots/opaque-key.png",
        media_type="image/png",
        size_bytes=10,
        sha256=sha256(b"screenshot").hexdigest(),
        created_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )
    await repository.register_artifact(artifact)
    access = await service.issue_artifact_access(
        artifact.artifact_id, Principal(user_id=owner, role=UserRole.USER)
    )
    token = access.access_path.split("token=", 1)[1]
    assert service.artifact_signer.verify(token, artifact.artifact_id, owner)
    assert not service.artifact_signer.verify(token, artifact.artifact_id, "another-user")
