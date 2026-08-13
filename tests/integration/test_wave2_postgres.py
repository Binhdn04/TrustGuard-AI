import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from src.core.auth import Principal, UserRole
from src.models import (
    AdminActionStatus,
    AnalysisCreateRequest,
    AppealCreateRequestV3,
    AppealDecisionRequestV3,
    AppealOutcome,
    Evidence,
    EvidenceType,
    ReviewDecision,
    ReviewedAction,
)
from src.repositories.postgres import PostgresPlatformRepository
from src.services.analysis import AnalysisService
from src.services.platform_wave2 import (
    ArtifactRecord,
    CampaignWrite,
    EvidenceSnapshotWrite,
    FactCheckResultWrite,
    SourceTier,
    UsageLedgerEntry,
)

DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="TEST_DATABASE_URL is not configured")


@pytest.mark.asyncio
async def test_wave2_postgres_transactions_and_idempotency() -> None:
    repository = PostgresPlatformRepository(DATABASE_URL or "postgresql://unused", "integration-secret")
    analysis_service = AnalysisService(blacklist=repository, durable_jobs=True)
    principal = Principal(user_id="wave2-integration-user", role=UserRole.USER)
    now = datetime.now(UTC)
    analysis_ids = []
    try:
        for index in range(3):
            accepted = await analysis_service.create(
                AnalysisCreateRequest(
                    message=f"Wave 2 integration claim {index}",
                    consent_to_scan_urls=False,
                ),
                principal,
            )
            analysis_ids.append(accepted.analysis_id)

        appeal = await repository.create_appeal(
            analysis_ids[0],
            principal.user_id,
            AppealCreateRequestV3(reason="Integration appeal", comment="Review this result."),
            [],
        )
        decision = await repository.decide_appeal(
            appeal.appeal_id,
            AppealDecisionRequestV3(outcome=AppealOutcome.OVERTURN, note="Corrective decision."),
            "integration-admin",
        )
        assert decision is not None
        assert (await repository.get_appeal(appeal.appeal_id))[1].outcome is AppealOutcome.OVERTURN

        evidence = Evidence(
            type=EvidenceType.BLACKLIST,
            source="integration",
            title="Reviewed domain",
            url="https://wave2-malicious.example/path?secret=removed",
            finding="Reviewed malicious evidence.",
            observed_at=now,
        )
        action = await repository.propose_admin_action(
            analysis_id=analysis_ids[0],
            campaign_id=None,
            action=ReviewedAction.ADD_TO_BLACKLIST,
            target="wave2-malicious.example",
            evidence=[evidence],
        )
        action_decision = await repository.decide_admin_action(
            action.action_id,
            ReviewDecision.APPROVED,
            "Approve reviewed evidence.",
            "integration-admin",
        )
        assert action_decision is not None
        assert action_decision.status is AdminActionStatus.EXECUTED
        assert await repository.contains("wave2-malicious.example")

        policies = await repository.load_source_policies(now)
        assert any(item.normalized_pattern == "*.gov.vn" and item.tier is SourceTier.A for item in policies)

        result = FactCheckResultWrite(
            analysis_id=analysis_ids[0],
            claim_hash=sha256(b"wave2 integration claim").hexdigest(),
            normalized_claim="wave2 integration claim",
            language="en",
            is_temporal=False,
            stance="inconclusive",
            evidence_refs=["evidence:integration"],
            contradiction_refs=[],
            limitations=["Integration fixture."],
            comparator_model="gpt-4o-mini",
            comparator_version="integration-v1",
            source_policy_version="source-policy-v1",
            embedding_status="pending",
            evidence=[
                EvidenceSnapshotWrite(
                    evidence_ref="evidence:integration",
                    source="integration-source",
                    source_version="v1",
                    source_tier=SourceTier.C,
                    policy_version="source-policy-v1",
                    canonical_url="https://evidence.example/article?query=removed",
                    cleaned_content="Minimized evidence.",
                    retrieved_at=now,
                    temporal_compatible=True,
                    content_hash=sha256(b"Minimized evidence.").hexdigest(),
                    validation_status="validated",
                )
            ],
        )
        assert await repository.cache_fact_check_result(result) == result.result_id
        assert await repository.cache_fact_check_result(result) == result.result_id
        assert not await repository.promote_evidence(result.result_id, "evidence:integration", "integration-admin")

        campaign = await repository.record_campaign(
            CampaignWrite(
                hypothesis="Integration campaign hypothesis.",
                window_started_at=now - timedelta(hours=1),
                window_ended_at=now,
                clustering_version="integration-v1",
                members=[
                    (analysis_id, "domain", 1.0, [f"evidence:{index}"])
                    for index, analysis_id in enumerate(analysis_ids)
                ],
                aggregate_signals={"shared_domain": 3},
                evidence_refs=["evidence:0", "evidence:1", "evidence:2"],
                registrable_domains=["integration.example"],
            )
        )
        assert campaign.analysis_count == 3
        assert campaign.reviewer_status.value == "pending_review"

        await repository.record_usage(
            UsageLedgerEntry(
                analysis_id=analysis_ids[0],
                provider="integration-provider",
                model="integration-model",
                provider_version="v1",
                operation="integration-call",
                input_tokens=5,
                output_tokens=3,
                estimated_cost_usd=0.01,
                latency_ms=20,
                cache_status="miss",
                outcome="success",
                quota_used=0.25,
                observed_at=now,
            )
        )
        metrics = await repository.operations_metrics(now - timedelta(minutes=1), now + timedelta(minutes=1))
        usage = next(item for item in metrics.usage if item.provider == "integration-provider")
        assert usage.tokens == 8
        assert usage.quota_used == 0.25

        artifact = ArtifactRecord(
            analysis_id=analysis_ids[0],
            owner_id=principal.user_id,
            storage_key=f"integration/{analysis_ids[0]}.png",
            media_type="image/png",
            size_bytes=10,
            sha256=sha256(b"artifact").hexdigest(),
            created_at=now,
            expires_at=now + timedelta(minutes=1),
        )
        await repository.register_artifact(artifact)
        assert (await repository.get_artifact(artifact.artifact_id)).storage_key == artifact.storage_key
        assert artifact.storage_key in await repository.expire_artifacts(now + timedelta(minutes=2))
    finally:
        await analysis_service.aclose()
