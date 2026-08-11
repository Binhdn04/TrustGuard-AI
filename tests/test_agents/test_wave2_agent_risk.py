from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime

import pytest

from src.agents.calibration import (
    CalibrationExample,
    RegressionPolicy,
    VersionedEvaluationSet,
    approve_release,
    evaluate,
    run_regression,
)
from src.agents.campaign import (
    CampaignConfig,
    ClaimFeature,
    ConfigurableCampaignDetector,
    InMemoryCampaignObservationStore,
)
from src.agents.fact_check import (
    EmbeddingStatus,
    EvidenceCandidate,
    ExtractedClaim,
    FactCheckOrchestrator,
    SourceTier,
    canonicalize_claim,
    evaluate_evidence_sufficiency,
)
from src.agents.graph import build_graph
from src.agents.tools.models import (
    CacheMetadata,
    CacheStatus,
    FactCheckCorpusMatch,
    FactCheckCorpusRecord,
    FactCheckSearchResult,
    NormalizedToolResult,
    ToolResultStatus,
    UsageMetadata,
)
from src.models import ClaimStance, RiskLevel, Verdict

NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)


class Corpus:
    provider = "trusted-corpus"

    def __init__(self, matches):
        self.matches = matches

    async def search(self, _claim: str, limit: int = 5):
        del limit
        return NormalizedToolResult(
            status=ToolResultStatus.SUCCESS if self.matches else ToolResultStatus.INCONCLUSIVE,
            result=FactCheckSearchResult(matches=self.matches, corpus_version="corpus-2026-08-09"),
            cache=CacheMetadata(status=CacheStatus.MISS),
            usage=UsageMetadata(
                usage_ref="usage:corpus:1",
                provider=self.provider,
                provider_version="v1",
                operation="search",
                attempts=1,
                network_calls=0,
                latency_ms=1,
                observed_at=NOW,
            ),
        )


def corpus_match(stance: ClaimStance, similarity: float = 0.92):
    return FactCheckCorpusMatch(
        similarity=similarity,
        record=FactCheckCorpusRecord(
            record_id=f"record-{stance.value}",
            record_version="v3",
            publisher="Trusted Publisher",
            source_url=f"https://facts.example/{stance.value}",
            claim="Reviewed claim text",
            stance=stance,
            language="vi",
            published_at=NOW,
            updated_at=NOW,
            embedding_model="fixture",
            embedding_version="v1",
            ingestion_source="allowlist:v1",
        ),
    )


@pytest.mark.asyncio
async def test_corpus_similarity_routes_records_but_stance_comes_from_record() -> None:
    result = await build_graph(fact_check_corpus=Corpus([corpus_match(ClaimStance.REFUTES)])).ainvoke(
        {"message": "Ngân hàng yêu cầu nộp phí mở khóa tài khoản", "consent_to_scan_urls": False}
    )

    assert result["claim_findings"][0].stance is ClaimStance.REFUTES
    assert "record-refutes@v3" in result["claim_findings"][0].source
    assert result["tool_usage_refs"] == ["usage:corpus:1"]
    assert result["verdict"] is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_conflicting_trusted_corpus_records_are_inconclusive() -> None:
    corpus = Corpus([corpus_match(ClaimStance.REFUTES), corpus_match(ClaimStance.SUPPORTS)])
    result = await build_graph(fact_check_corpus=corpus).ainvoke(
        {"message": "Ngân hàng yêu cầu nộp phí mở khóa tài khoản", "consent_to_scan_urls": False}
    )

    assert result["verdict"] is Verdict.INCONCLUSIVE
    assert any("mâu thuẫn" in item for item in result["limitations"])


class Encoder:
    version = "fixture-v1"

    async def encode(self, claims):
        return [ClaimFeature(feature_ref="claim:sha256:fixture", vector=(1.0, 0.0))] if claims else []


class ConcurrentEmbedding:
    def __init__(self) -> None:
        self._arrived = 0
        self._ready = asyncio.Event()

    async def embed_batch(self, claims):
        self._arrived += 1
        if self._arrived == 2:
            self._ready.set()
        await self._ready.wait()
        provider = claims[0]
        return NormalizedToolResult(
            status=ToolResultStatus.SUCCESS,
            result=[{"vector": (1.0, 0.0)}],
            cache=CacheMetadata(status=CacheStatus.MISS),
            usage=UsageMetadata(
                usage_ref=f"usage:{provider}",
                provider=provider,
                provider_version="v1",
                operation="embed",
                attempts=1,
                network_calls=1,
                latency_ms=1,
                observed_at=NOW,
            ),
        )


@pytest.mark.asyncio
async def test_fact_check_usage_is_scoped_to_each_concurrent_verification() -> None:
    pipeline = FactCheckOrchestrator(embedding_provider=ConcurrentEmbedding())
    first, second = await asyncio.gather(
        pipeline.verify([ExtractedClaim.from_text("first claim")]),
        pipeline.verify([ExtractedClaim.from_text("second claim")]),
    )

    assert [item.provider for item in first.usage_records] == ["first claim"]
    assert [item.provider for item in second.usage_records] == ["second claim"]
    assert pipeline._usage_records.get() is None


class FailingEncoder:
    version = "must-not-run"

    async def encode(self, claims):
        raise AssertionError("fact-check embedding must be reused")


@pytest.mark.asyncio
async def test_campaign_detector_reuses_fact_check_embedding() -> None:
    store = InMemoryCampaignObservationStore()
    detector = ConfigurableCampaignDetector(store, encoder=FailingEncoder(), clock=lambda: NOW)
    result = await detector.detect(
        {
            "analysis_id": "analysis-reused-vector",
            "claims": ["a normalized claim"],
            "claim_feature_vectors": [("claim-feature:sha256:fixture", (1.0, 0.0))],
        }
    )
    assert result["campaign_features"].claim_feature_refs == ["claim-feature:sha256:fixture"]


@pytest.mark.asyncio
async def test_campaign_detector_requires_three_and_never_approves_broad_warning() -> None:
    store = InMemoryCampaignObservationStore()
    detector = ConfigurableCampaignDetector(
        store,
        encoder=Encoder(),
        config=CampaignConfig(),
        clock=lambda: NOW,
    )
    outputs = []
    for index in range(3):
        outputs.append(
            await detector.detect(
                {
                    "analysis_id": f"analysis-{index}",
                    "claims": [f"private raw claim {index}"],
                    "normalized_urls": [f"https://sub{index}.same.example/path"],
                }
            )
        )

    assert outputs[0]["campaign_hypotheses"] == []
    hypothesis = outputs[-1]["campaign_hypotheses"][0]
    assert hypothesis.analysis_count == 3
    assert hypothesis.reviewer_required is True
    assert hypothesis.broad_warning_approved is False
    assert all("private raw claim" not in ref for ref in hypothesis.evidence_refs)


def assessment(level: RiskLevel, verdict: Verdict):
    score = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 30, RiskLevel.HIGH: 60, RiskLevel.CRITICAL: 85}[level]

    def engine(_state):
        return {
            "risk_score": score,
            "risk_level": level,
            "verdict": verdict,
            "confidence": 1.0,
            "scoring_version": "fixture",
        }

    return engine


def test_calibration_change_requires_passing_regression_and_approval() -> None:
    example = CalibrationExample(
        example_id="appeal-1",
        feedback_kind="appeal",
        feedback_ref="appeal:1",
        state={"evidence": []},
        expected_risk_level=RiskLevel.LOW,
        expected_verdict=Verdict.INCONCLUSIVE,
        reviewed_by="admin-1",
        reviewed_at=NOW,
    )
    evaluation_set = VersionedEvaluationSet.build("eval-v1", [example], created_at=NOW)
    failed = run_regression(
        "risk-v3",
        assessment(RiskLevel.HIGH, Verdict.MALICIOUS),
        evaluation_set,
        baseline_engine=assessment(RiskLevel.LOW, Verdict.INCONCLUSIVE),
        policy=RegressionPolicy(),
        completed_at=NOW,
    )
    with pytest.raises(ValueError, match="failed regression"):
        approve_release(failed, approved_by="security-admin", approved_at=NOW)

    passed = run_regression(
        "risk-v3-fixed",
        assessment(RiskLevel.LOW, Verdict.INCONCLUSIVE),
        evaluation_set,
        baseline_engine=assessment(RiskLevel.LOW, Verdict.INCONCLUSIVE),
        completed_at=NOW,
    )
    release = approve_release(passed, approved_by="security-admin", approved_at=NOW)
    assert release.candidate_version == "risk-v3-fixed"
    assert release.evaluation_set_sha256 == evaluation_set.content_sha256


def test_calibration_evaluate_rejects_an_empty_set_constructed_without_build() -> None:
    evaluation_set = VersionedEvaluationSet(
        version="eval-empty",
        examples=(),
        content_sha256="unused",
        created_at=NOW,
    )

    with pytest.raises(ValueError, match="at least one example"):
        evaluate(assessment(RiskLevel.LOW, Verdict.INCONCLUSIVE), evaluation_set)


class BatchEmbedding:
    def __init__(self, *, fail: bool = False):
        self.calls = []
        self.fail = fail

    async def embed_batch(self, claims):
        self.calls.append(tuple(claims))
        if self.fail:
            raise TimeoutError("fixture timeout")
        return [[1.0, float(index)] for index, _ in enumerate(claims)]


class ParallelGoogle:
    def __init__(self, evidence):
        self.evidence = evidence
        self.active = 0
        self.maximum_active = 0

    async def search(self, _claim):
        import asyncio

        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        await asyncio.sleep(0)
        self.active -= 1
        return self.evidence


class EmptyCorpus:
    async def search(self, _claim, *, vector=None):
        del vector
        return []


class CountingWeb:
    def __init__(self):
        self.calls = 0

    async def search(self, _claim, *, max_results=10):
        assert max_results == 10
        self.calls += 1
        return []


class CitingComparator:
    def __init__(self):
        self.calls = 0

    async def compare(self, _claim, evidence):
        self.calls += 1
        return {"stance": "refutes", "evidence_refs": [evidence[0].evidence_ref]}


def candidate(ref: str, tier: SourceTier, *, published_at=NOW):
    return EvidenceCandidate(
        evidence_ref=ref,
        source_url=f"https://source.example/{ref}",
        publisher=f"publisher-{ref}",
        source_tier=tier,
        published_at=published_at,
        observed_at=NOW,
    )


@pytest.mark.asyncio
async def test_wave2_pipeline_batches_once_bounds_fanout_and_skips_web_when_sufficient() -> None:
    embedding = BatchEmbedding()
    google = ParallelGoogle([candidate("tier-a", SourceTier.A)])
    web = CountingWeb()
    comparator = CitingComparator()
    pipeline = FactCheckOrchestrator(
        embedding_provider=embedding,
        google_claim_search=google,
        corpus_retriever=EmptyCorpus(),
        tavily_search=web,
        comparator=comparator,
    )
    claims = [ExtractedClaim.from_text(f"Claim number {index}") for index in range(5)]

    result = await pipeline.verify(claims)

    assert len(embedding.calls) == 1
    assert len(embedding.calls[0]) == 5
    assert google.maximum_active == 3
    assert web.calls == 0
    assert comparator.calls == 5
    assert result.embedding_status is EmbeddingStatus.COMPLETE
    assert all(item.stance is ClaimStance.REFUTES for item in result.claim_findings)


@pytest.mark.asyncio
async def test_embedding_failure_continues_and_tier_c_alone_stays_inconclusive() -> None:
    embedding = BatchEmbedding(fail=True)
    google = ParallelGoogle([candidate("tier-c", SourceTier.C)])
    web = CountingWeb()
    comparator = CitingComparator()
    pipeline = FactCheckOrchestrator(
        embedding_provider=embedding,
        google_claim_search=google,
        corpus_retriever=EmptyCorpus(),
        tavily_search=web,
        comparator=comparator,
    )

    result = await pipeline.verify([ExtractedClaim.from_text("A temporal-looking claim")])

    assert result.embedding_status is EmbeddingStatus.PENDING
    assert web.calls == 1
    assert comparator.calls == 0
    assert result.claim_findings == ()
    assert any("Embedding" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_temporal_wrong_tier_a_is_excluded_before_comparator() -> None:
    google = ParallelGoogle([candidate("old-official", SourceTier.A, published_at=datetime(2020, 1, 1, tzinfo=UTC))])
    web = CountingWeb()
    comparator = CitingComparator()
    pipeline = FactCheckOrchestrator(google_claim_search=google, tavily_search=web, comparator=comparator)
    claim = ExtractedClaim.from_text(
        "Policy applies in 2026",
        is_temporal=True,
        claim_date_start=datetime(2026, 1, 1, tzinfo=UTC).date(),
        claim_date_end=datetime(2026, 12, 31, tzinfo=UTC).date(),
    )

    result = await pipeline.verify([claim])

    assert web.calls == 1
    assert comparator.calls == 0
    assert any("thời gian" in item for item in result.limitations)


def test_claim_canonicalization_redacts_secrets_and_url_queries() -> None:
    normalized = canonicalize_claim("OTP: 123456 gửi tới test@example.com qua https://example.com/path?token=secret")
    assert "123456" not in normalized
    assert "test@example.com" not in normalized
    assert "token=secret" not in normalized


def test_claim_canonicalization_handles_long_secret_separator_without_backtracking() -> None:
    normalized = canonicalize_claim("OTP" + (" " * 100_000) + ": 123456")

    assert normalized == "[SECRET]"


def test_temporal_start_only_claim_accepts_later_evidence() -> None:
    claim = ExtractedClaim.from_text(
        "Policy applies from 2026 onwards",
        claim_date_start=date(2026, 1, 1),
    )
    later = candidate("later-official", SourceTier.A, published_at=datetime(2027, 1, 1, tzinfo=UTC))

    assert evaluate_evidence_sufficiency(claim, [later]).sufficient is True


def test_temporal_end_only_claim_accepts_earlier_evidence() -> None:
    claim = ExtractedClaim.from_text(
        "Policy applied through 2026",
        claim_date_end=date(2026, 12, 31),
    )
    earlier = candidate("earlier-official", SourceTier.A, published_at=datetime(2025, 1, 1, tzinfo=UTC))

    assert evaluate_evidence_sufficiency(claim, [earlier]).sufficient is True
