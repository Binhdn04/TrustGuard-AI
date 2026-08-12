from __future__ import annotations

import asyncio
import json
from datetime import UTC, date, datetime
from hashlib import sha256

import httpx
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
    ClaimSearchQuery,
    EmbeddingStatus,
    EvidenceCandidate,
    ExtractedClaim,
    FactCheckOrchestrator,
    SourceTier,
    _as_candidate,
    canonicalize_claim,
    evaluate_evidence_sufficiency,
)
from src.agents.graph import build_graph
from src.agents.tools.advanced import (
    GoogleClaimSearchAdapter,
    TavilyExtractAdapter,
    TavilySearchAdapter,
)
from src.agents.tools.models import (
    CacheMetadata,
    CacheStatus,
    ExtractedWebEvidence,
    FactCheckCorpusMatch,
    FactCheckCorpusRecord,
    FactCheckSearchResult,
    GoogleClaimReviewMatch,
    NormalizedToolResult,
    TavilyExtractBatch,
    ToolErrorCode,
    ToolResultStatus,
    UsageMetadata,
    WebCandidate,
)
from src.agents.tools.runtime import OpenAIEvidenceComparator
from src.models import ClaimStance, RiskLevel, Verdict
from src.services.platform_wave2 import VersionedSourceRegistry, default_source_policies

NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)


def test_language_names_normalize_and_identical_query_text_is_not_repeated() -> None:
    claim = ExtractedClaim.from_text(
        "Vietnam will completely ban motorbikes starting in 2027.",
        language="English",
        search_queries=(
            ClaimSearchQuery(
                text="Vietnam will completely ban motorbikes starting in 2027.",
                language="en",
            ),
        ),
    )

    assert claim.language == "en"
    assert [(item.text, item.language) for item in claim.query_variants] == [
        ("Vietnam will completely ban motorbikes starting in 2027.", "en")
    ]
    assert (
        claim.claim_id
        == ExtractedClaim.from_text("Vietnam will completely ban motorbikes starting in 2027.", language="en").claim_id
    )


@pytest.mark.asyncio
async def test_comparator_normalizes_confirmed_narrower_scope_to_refutes() -> None:
    class Runnable:
        async def ainvoke(self, _prompt):
            return {
                "stance": "inconclusive",
                "scope_relation": "narrower_than_claim",
                "evidence_refs": ["official:1"],
                "contradiction_refs": [],
                "limitations": [
                    {
                        "code": "SCOPE_MISMATCH",
                        "message_vi": "Chính sách chỉ áp dụng tại một khu vực, không phải toàn quốc.",
                        "impacts_verdict": True,
                    }
                ],
            }

    class Llm:
        def with_structured_output(self, _schema):
            return Runnable()

    comparator = OpenAIEvidenceComparator(Llm())
    evidence = [
        EvidenceCandidate(
            evidence_ref="official:1",
            source_url="https://xaydungchinhsach.chinhphu.vn/policy",
            publisher="Vietnam government",
            source_tier=SourceTier.A,
            finding="The restriction applies only within a specified Hanoi zone.",
            observed_at=NOW,
        )
    ]

    result = await comparator.compare(
        ExtractedClaim.from_text("Vietnam will completely ban motorbikes starting in 2027.", language="English"),
        evidence,
    )

    assert result.result is not None
    assert result.result.stance == "refutes"
    assert result.result.limitations == []


@pytest.mark.asyncio
async def test_comparator_rejects_impossible_future_event_against_as_of_date() -> None:
    class Runnable:
        async def ainvoke(self, prompt):
            assert "AS_OF_UTC_DATE: 2026-08-12" in prompt
            return {
                "stance": "inconclusive",
                "scope_relation": "matches_claim",
                "temporal_relation": "future",
                "blocking_date": "2026-07-19",
                "evidence_refs": [],
                "contradiction_refs": [],
                "limitations": [
                    {
                        "code": "FUTURE_EVENT",
                        "message_vi": "Bằng chứng đề cập đến một sự kiện trong tương lai.",
                        "impacts_verdict": True,
                    }
                ],
            }

    class Llm:
        def with_structured_output(self, _schema):
            return Runnable()

    comparator = OpenAIEvidenceComparator(
        Llm(), clock=lambda: datetime(2026, 8, 12, 12, tzinfo=UTC)
    )
    result = await comparator.compare(
        ExtractedClaim.from_text("Tây Ban Nha vô địch World Cup", language="vi"),
        [
            EvidenceCandidate(
                evidence_ref="source:1",
                source_url="https://example.com/world-cup",
                publisher="Example",
                source_tier=SourceTier.B,
                finding="Spain celebrated its World Cup victory on July 19, 2026.",
                observed_at=NOW,
            )
        ],
    )

    assert result.result is not None
    assert result.result.as_of_date == date(2026, 8, 12)
    assert result.result.temporal_relation == "past"
    assert result.result.limitations == []


def test_google_claim_review_mapping_preserves_url_and_claim_text() -> None:
    item = GoogleClaimReviewMatch(
        claim_text="COVID-19 vaccines contain microchips",
        review_ref="claimreview:1",
        review_url="https://www.factcheck.org/review/1",
        reviewer="FactCheck.org",
        publisher="FactCheck.org",
        title="Vaccines do not contain microchips",
        textual_rating="False",
        stance=ClaimStance.REFUTES,
        source_tier="b",
        trusted_claim_review=True,
        observed_at=NOW,
    )

    mapped = _as_candidate(item, default_ref_prefix="google")

    assert mapped.source_url == item.review_url
    assert mapped.finding == item.claim_text
    assert mapped.stance is ClaimStance.REFUTES


def test_default_registry_trusts_reviewed_fact_check_publishers() -> None:
    registry = VersionedSourceRegistry(default_source_policies())

    decision = registry.classify("https://www.factcheck.org/review/1", NOW)

    assert decision.tier.value == "B"
    assert decision.trusted_claim_review is True


def test_default_registry_treats_the_government_portal_as_tier_a() -> None:
    registry = VersionedSourceRegistry(default_source_policies())

    decision = registry.classify("https://xaydungchinhsach.chinhphu.vn/policy", NOW)

    assert decision.tier.value == "A"
    assert decision.publisher == "Vietnam government"
    assert "chinhphu.vn" in registry.official_domains()


def test_default_registry_treats_fifa_as_tier_a() -> None:
    registry = VersionedSourceRegistry(default_source_policies())

    decision = registry.classify("https://www.fifa.com/world-cup/final", NOW)

    assert decision.tier.value == "A"
    assert decision.publisher == "FIFA"
    assert "fifa.com" in registry.official_domains()


def test_default_registry_covers_supplied_vietnam_source_catalog() -> None:
    domains = set(
        """chinhphu.vn vbpl.vn moj.gov.vn quochoi.vn nso.gov.vn mof.gov.vn sbv.gov.vn gdt.gov.vn
        customs.gov.vn ssc.gov.vn hsx.vn hnx.vn moh.gov.vn dav.gov.vn vfa.gov.vn moet.gov.vn mst.gov.vn
        vast.gov.vn mae.gov.vn cem.gov.vn nbca.gov.vn ppd.gov.vn moc.gov.vn moit.gov.vn evn.com.vn
        mps.gov.vn mod.gov.vn mofa.gov.vn baohiemxahoi.gov.vn nchmf.gov.vn phongchongthientai.mard.gov.vn
        vnexpress.net tuoitre.vn thanhnien.vn vietnamplus.vn baotintuc.vn nhandan.vn vtv.vn vov.vn
        vietnamnet.vn laodong.vn dantri.com.vn tienphong.vn qdnd.vn cand.com.vn vneconomy.vn vir.com.vn
        cafef.vn thoibaotaichinhvietnam.vn baodautu.vn suckhoedoisong.vn giaoducthoidai.vn
        khoahocphattrien.vn congthuong.vn nongnghiepmoitruong.vn baoxaydung.vn hanoi.gov.vn
        hochiminhcity.gov.vn danang.gov.vn hanoimoi.vn sggp.org.vn thuvienphapluat.vn plo.vn congly.vn
        danviet.vn tapchibaohiemxahoi.gov.vn bachmai.gov.vn choray.vn benhvien108.vn vinmec.com
        vnu.edu.vn vnuhcm.edu.vn hust.edu.vn neu.edu.vn ctu.edu.vn giaoduc.net.vn ais.gov.vn viettel.com.vn
        vnpt.com.vn fpt.com.vn ictvietnam.vn tinhte.vn vietcombank.com.vn bidv.com.vn vietinbank.vn
        agribank.com.vn baonganhang.vn brandsvietnam.com drvn.gov.vn vietnamairlines.com vnr.com.vn
        vietnamairport.vn vietnamtourism.gov.vn thethaovanhoa.vn baovanhoa.vn webthethao.vn batdongsan.com.vn
        reatimes.vn lamnghiep.gov.vn""".split()
    )
    registry = VersionedSourceRegistry(default_source_policies())

    assert len(domains) == 99
    assert all(registry.classify(f"https://{domain}/", NOW).tier.value in {"A", "B"} for domain in domains)
    assert registry.classify("https://vbpl.vn/", NOW).tier.value == "A"
    assert registry.classify("https://hanoi.gov.vn/", NOW).tier.value == "A"
    assert registry.classify("https://vnexpress.net/", NOW).tier.value == "B"
    assert registry.classify("https://vinmec.com/", NOW).tier.value == "B"


@pytest.mark.asyncio
async def test_google_claim_search_uses_vi_and_en_queries_and_deduplicates_reviews() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        calls.append((params["query"], params["languageCode"]))
        return httpx.Response(
            200,
            json={
                "claims": [
                    {
                        "text": "Hot lemon water does not cure cancer",
                        "claimReview": [
                            {
                                "publisher": {"name": "AFP Fact Check"},
                                "url": "https://factcheck.afp.com/doc.afp.com.123",
                                "title": "Lemon water does not cure cancer",
                                "textualRating": "False",
                            }
                        ],
                    }
                ]
            },
        )

    registry = VersionedSourceRegistry(default_source_policies())
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = GoogleClaimSearchAdapter("test-key", client=client, classify_source=registry.classify)
    claim = ExtractedClaim.from_text(
        "Uống nước chanh mỗi ngày có thể chữa khỏi ung thư",
        language="vi",
        search_queries=(ClaimSearchQuery(text="Drinking lemon water every day can cure cancer", language="en"),),
    )

    result = await adapter.search(claim)
    await client.aclose()

    assert set(calls) == {
        ("Uống nước chanh mỗi ngày có thể chữa khỏi ung thư", "vi"),
        ("Drinking lemon water every day can cure cancer", "en"),
    }
    assert result.status is ToolResultStatus.SUCCESS
    assert len(result.result or []) == 1
    assert (result.result or [])[0].policy_version == "source-policy-claim-review-v1"
    assert result.usage is not None and result.usage.network_calls == 2


@pytest.mark.asyncio
async def test_tavily_search_uses_query_variants_and_deduplicates_urls() -> None:
    queries: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.headers["Authorization"] == "Bearer test-key"
        queries.append(body["query"])
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "url": "https://factcheck.afp.com/doc.afp.com.123",
                        "title": "Lemon water does not cure cancer",
                        "content": "The claim is false.",
                    }
                ]
            },
        )

    registry = VersionedSourceRegistry(default_source_policies())
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = TavilySearchAdapter("test-key", client=client, classify_source=registry.classify)
    claim = ExtractedClaim.from_text(
        "Uống nước chanh mỗi ngày có thể chữa khỏi ung thư",
        language="vi",
        search_queries=(ClaimSearchQuery(text="Drinking lemon water every day can cure cancer", language="en"),),
    )

    result = await adapter.search(claim)
    await client.aclose()

    assert set(queries) == {
        "Uống nước chanh mỗi ngày có thể chữa khỏi ung thư",
        "Drinking lemon water every day can cure cancer",
    }
    assert result.status is ToolResultStatus.SUCCESS
    assert len(result.result or []) == 1
    assert result.usage is not None and result.usage.network_calls == 2


@pytest.mark.asyncio
async def test_tavily_search_prioritizes_independent_publishers() -> None:
    results = [
        {
            "url": f"https://e.vnexpress.net/news/article-{index}.html",
            "title": f"VnExpress result {index}",
            "content": "Motorbike policy report.",
        }
        for index in range(6)
    ]
    results.extend(
        [
            {
                "url": "https://en.vietnamplus.vn/motorbike-policy-post1.vnp",
                "title": "VietnamPlus result",
                "content": "Motorbike policy report.",
            },
            {
                "url": "https://xaydungchinhsach.chinhphu.vn/motorbike-emissions.htm",
                "title": "Government result",
                "content": "Official motorbike emissions roadmap.",
            },
        ]
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": results})

    registry = VersionedSourceRegistry(default_source_policies())
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = TavilySearchAdapter("test-key", client=client, classify_source=registry.classify)

    result = await adapter.search(ExtractedClaim.from_text("Vietnam motorbike policy", language="English"))
    await client.aclose()

    assert result.status is ToolResultStatus.SUCCESS
    assert [item.publisher for item in (result.result or [])[:3]] == [
        "VnExpress",
        "VietnamPlus",
        "Vietnam government",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "expected_code", "expected_status"),
    [
        (httpx.Response(503), ToolErrorCode.PROVIDER_ERROR, 503),
        (httpx.Response(429, headers={"retry-after": "2"}), ToolErrorCode.RATE_LIMITED, 429),
    ],
)
async def test_tavily_search_preserves_http_failure_details(response, expected_code, expected_status) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return response

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = TavilySearchAdapter("test-key", client=client)

    result = await adapter.search(ExtractedClaim.from_text("A claim", language="en"))
    await client.aclose()

    assert result.status is ToolResultStatus.FAILED
    assert result.error is not None
    assert result.error.code is expected_code
    assert result.error.http_status_code == expected_status
    assert f"HTTP {expected_status}" in result.error.message


@pytest.mark.asyncio
async def test_tavily_search_preserves_timeout_code() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("fixture timeout", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = TavilySearchAdapter("test-key", client=client)

    result = await adapter.search(ExtractedClaim.from_text("A claim", language="en"))
    await client.aclose()

    assert result.error is not None
    assert result.error.code is ToolErrorCode.PROVIDER_TIMEOUT
    assert "timeout" in result.error.message


@pytest.mark.asyncio
async def test_tavily_does_not_treat_claim_effective_dates_as_publication_filters() -> None:
    request_body = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_body
        request_body = json.loads(request.content)
        return httpx.Response(200, json={"results": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = TavilySearchAdapter("test-key", client=client)
    claim = ExtractedClaim.from_text(
        "A policy will apply starting in 2027",
        language="en",
        is_temporal=True,
        claim_date_start=date(2027, 1, 1),
        claim_date_end=date(2027, 12, 31),
    )

    await adapter.search(claim)
    await client.aclose()

    assert request_body is not None
    assert "start_date" not in request_body
    assert "end_date" not in request_body


@pytest.mark.asyncio
async def test_tavily_routes_official_query_to_tier_a_domains_with_advanced_search() -> None:
    request_bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"results": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = TavilySearchAdapter(
        "test-key",
        client=client,
        excluded_domains=lambda _claim: ["blocked.example"],
        official_domains=lambda _claim: ["chinhphu.vn"],
    )
    claim = ExtractedClaim.from_text(
        "Vietnam will completely ban motorbikes starting in 2027.",
        language="en",
        search_queries=(
            ClaimSearchQuery(
                text="Vietnam motorbike ban 2027 nationwide official sources",
                language="en",
            ),
        ),
    )

    await adapter.search(claim)
    await client.aclose()

    by_query = {body["query"]: body for body in request_bodies}
    assert "include_domains" not in by_query[claim.normalized_text]
    assert by_query[claim.normalized_text]["exclude_domains"] == ["blocked.example"]
    assert by_query[claim.search_queries[0].text]["include_domains"] == ["chinhphu.vn"]
    assert by_query[claim.normalized_text]["search_depth"] == "basic"
    assert by_query[claim.search_queries[0].text]["search_depth"] == "advanced"


@pytest.mark.asyncio
async def test_tavily_discovers_unregistered_domains_as_tier_c() -> None:
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={"results": [{"url": "https://sports.example/final", "title": "Final", "content": "Spain won."}]},
        )

    registry = VersionedSourceRegistry(default_source_policies())
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = TavilySearchAdapter("test-key", client=client, classify_source=registry.classify)

    result = await adapter.search(ExtractedClaim.from_text("Spain won the World Cup", language="en"))
    await client.aclose()

    assert "include_domains" not in bodies[0]
    assert result.result and result.result[0].source_tier == "c"
    assert result.result[0].policy_version == "discovery-v1"


@pytest.mark.asyncio
async def test_tavily_extract_batches_urls_and_preserves_search_excerpt() -> None:
    class Guard:
        async def validate(self, _url):
            return None

    request_body = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_body
        request_body = json.loads(request.content)
        assert request.headers["Authorization"] == "Bearer test-key"
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "url": "https://chinhphu.vn/policy",
                        "raw_content": "The official policy applies only to specified wards.",
                    }
                ],
                "failed_results": [],
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = TavilyExtractAdapter("test-key", client=client, guard=Guard(), timeout=9)
    candidate = WebCandidate(
        evidence_ref="web:official:1",
        canonical_url="https://chinhphu.vn/policy",
        title="Official 2027 roadmap",
        snippet="The 2027 phase applies only to specified Hanoi wards.",
        publisher="Vietnam government",
        source_tier="A",
        source_version="fixture",
    )

    claim = ExtractedClaim.from_text("Vietnam will ban all motorbikes in 2027", language="en")
    result = await adapter.extract(claim, [candidate])
    await client.aclose()

    assert request_body == {
        "urls": ["https://chinhphu.vn/policy"],
        "query": claim.normalized_text,
        "chunks_per_source": 3,
        "extract_depth": "basic",
        "format": "markdown",
        "include_images": False,
        "timeout": 9,
        "include_usage": True,
    }
    assert result.result is not None and len(result.result.evidence) == 1
    assert result.result.evidence[0].text.startswith(
        "Official 2027 roadmap\n\nThe 2027 phase applies only to specified Hanoi wards."
    )
    assert "The official policy applies only to specified wards." in result.result.evidence[0].text


@pytest.mark.asyncio
async def test_tavily_extract_keeps_partial_results_and_reports_failed_urls() -> None:
    class Guard:
        async def validate(self, _url):
            return None

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [{"url": "https://chinhphu.vn/policy", "raw_content": "Relevant policy text."}],
                "failed_results": [{"url": "https://vnexpress.net/missing", "error": "blocked"}],
            },
        )

    candidates = [
        WebCandidate(
            evidence_ref="web:official:1",
            canonical_url="https://chinhphu.vn/policy",
            title="Official policy",
            snippet="Policy excerpt.",
            publisher="Vietnam government",
            source_tier="A",
            source_version="fixture",
        ),
        WebCandidate(
            evidence_ref="web:news:1",
            canonical_url="https://vnexpress.net/missing",
            title="News report",
            snippet="News excerpt.",
            publisher="VnExpress",
            source_tier="B",
            source_version="fixture",
        ),
    ]
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await TavilyExtractAdapter("test-key", client=client, guard=Guard()).extract(
        ExtractedClaim.from_text("A policy claim"), candidates
    )
    await client.aclose()

    assert result.status is ToolResultStatus.SUCCESS
    assert result.result is not None
    assert [item.canonical_url for item in result.result.evidence] == ["https://chinhphu.vn/policy"]
    assert result.result.failed_urls == ["https://vnexpress.net/missing"]


@pytest.mark.asyncio
async def test_tavily_extract_preserves_timeout_code() -> None:
    class Guard:
        async def validate(self, _url):
            return None

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("fixture timeout", request=request)

    candidate = WebCandidate(
        evidence_ref="web:official:1",
        canonical_url="https://chinhphu.vn/policy",
        title="Official policy",
        snippet="Policy excerpt.",
        publisher="Vietnam government",
        source_tier="A",
        source_version="fixture",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await TavilyExtractAdapter("test-key", client=client, guard=Guard()).extract(
        ExtractedClaim.from_text("A policy claim"), [candidate]
    )
    await client.aclose()

    assert result.status is ToolResultStatus.FAILED
    assert result.error is not None and result.error.code is ToolErrorCode.PROVIDER_TIMEOUT


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


class StaticWeb:
    def __init__(self, candidates):
        self.candidates = candidates

    async def search(self, _claim, *, max_results=10):
        return self.candidates[:max_results]


class RecordingExtract:
    def __init__(self):
        self.publishers = []

    async def extract(self, _claim, candidates):
        self.publishers.extend(candidate.publisher for candidate in candidates)
        return TavilyExtractBatch(
            evidence=[
                ExtractedWebEvidence(
                    evidence_ref=candidate.evidence_ref,
                    canonical_url=candidate.canonical_url,
                    title=candidate.title,
                    text=candidate.snippet,
                    content_sha256=sha256(candidate.snippet.encode()).hexdigest(),
                    publisher=candidate.publisher,
                    source_tier=candidate.source_tier,
                    source_version=candidate.source_version,
                    search_score=candidate.search_score,
                    observed_at=NOW,
                )
                for candidate in candidates
            ],
            failed_urls=[],
        )


class CitingComparator:
    def __init__(self):
        self.calls = 0

    async def compare(self, _claim, evidence):
        self.calls += 1
        return {"stance": "refutes", "evidence_refs": [evidence[0].evidence_ref]}


class CitingAllComparator:
    async def compare(self, _claim, evidence):
        return {
            "stance": "supports",
            "scope_relation": "matches_claim",
            "evidence_refs": [item.evidence_ref for item in evidence],
            "contradiction_refs": [],
            "limitations": [],
        }


class InconclusiveComparator:
    async def compare(self, _claim, _evidence):
        return {
            "stance": "inconclusive",
            "evidence_refs": [],
            "limitations": [
                {
                    "code": "ADJACENT_SCOPE_UNCERTAIN",
                    "message_vi": "Chưa đủ dữ liệu về một chủ đề liên quan ngoài phạm vi claim.",
                    "impacts_verdict": True,
                }
            ],
        }


@pytest.mark.asyncio
async def test_web_fallback_spends_extract_budget_on_independent_publishers_first() -> None:
    candidates = [
        WebCandidate(
            evidence_ref=f"web:vnexpress:{index}",
            canonical_url=f"https://e.vnexpress.net/news/article-{index}.html",
            title=f"VnExpress {index}",
            snippet="Vietnam will apply limited motorbike emission rules, not a nationwide ban.",
            publisher="VnExpress",
            source_tier="B",
            source_version="fixture",
        )
        for index in range(6)
    ]
    candidates.extend(
        [
            WebCandidate(
                evidence_ref="web:vietnamplus:1",
                canonical_url="https://en.vietnamplus.vn/motorbike-policy-post1.vnp",
                title="VietnamPlus",
                snippet="The restriction applies only to specified areas and vehicles.",
                publisher="VietnamPlus",
                source_tier="B",
                source_version="fixture",
            ),
            WebCandidate(
                evidence_ref="web:government:1",
                canonical_url="https://xaydungchinhsach.chinhphu.vn/motorbike-emissions.htm",
                title="Official roadmap",
                snippet="The 2027 roadmap requires emissions inspections in Hanoi and Ho Chi Minh City.",
                publisher="Vietnam government",
                source_tier="A",
                source_version="fixture",
            ),
            WebCandidate(
                evidence_ref="web:government:2",
                canonical_url="https://thanglong.chinhphu.vn/english/second-policy.htm",
                title="Official implementation detail",
                snippet="The 2027 phase covers specified wards in central Hanoi.",
                publisher="Vietnam government",
                source_tier="A",
                source_version="fixture",
            ),
        ]
    )
    extractor = RecordingExtract()
    pipeline = FactCheckOrchestrator(
        tavily_search=StaticWeb(candidates),
        tavily_extract=extractor,
        comparator=CitingComparator(),
        source_registry=VersionedSourceRegistry(default_source_policies()),
    )

    result = await pipeline.verify(
        [
            ExtractedClaim.from_text(
                "Vietnam will completely ban motorbikes starting in 2027.",
                language="English",
                is_temporal=True,
            )
        ]
    )

    assert extractor.publishers[:3] == ["VnExpress", "VietnamPlus", "Vietnam government"]
    assert extractor.publishers.count("Vietnam government") == 2
    assert result.claim_findings


@pytest.mark.asyncio
async def test_one_tier_c_source_produces_provisional_support() -> None:
    candidates = [
        WebCandidate(
            evidence_ref=f"web:c:{index}",
            canonical_url=f"https://source{index}.example/final",
            title=f"Source {index}",
            snippet=f"Source {index} reports Spain won the 2026 World Cup final.",
            publisher=f"source{index}.example",
            source_tier="c",
            source_version="fixture",
            policy_version="discovery-v1",
        )
        for index in range(1)
    ]
    pipeline = FactCheckOrchestrator(
        tavily_search=StaticWeb(candidates),
        tavily_extract=RecordingExtract(),
        comparator=CitingAllComparator(),
        source_registry=VersionedSourceRegistry(default_source_policies()),
    )

    result = await pipeline.verify([ExtractedClaim.from_text("Spain won the 2026 World Cup", language="en")])

    assert len(result.claim_findings) == 1
    assert all(item.stance is ClaimStance.SUPPORTS for item in result.claim_findings)
    assert all(item.provisional for item in result.claim_findings)
    assert {item.source_tier for item in result.claim_findings} == {"c"}


def test_one_tier_c_source_is_sufficient_for_provisional_comparison() -> None:
    claim = ExtractedClaim.from_text("Spain won the 2026 World Cup", language="en")
    evidence = [
        EvidenceCandidate(
            evidence_ref=f"c:{index}",
            source_url=f"https://source{index}.example/final",
            publisher=f"source{index}.example",
            source_tier=SourceTier.C,
        )
        for index in range(1)
    ]

    result = evaluate_evidence_sufficiency(claim, evidence)
    assert result.sufficient is True
    assert result.matched_rule == "one_tier_c"


def candidate(ref: str, tier: SourceTier, *, published_at=NOW, effective_from=None, effective_to=None):
    return EvidenceCandidate(
        evidence_ref=ref,
        source_url=f"https://source.example/{ref}",
        publisher=f"publisher-{ref}",
        source_tier=tier,
        published_at=published_at,
        effective_from=effective_from,
        effective_to=effective_to,
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
async def test_inconclusive_comparator_does_not_project_adjacent_trusted_rating() -> None:
    rated = EvidenceCandidate(
        evidence_ref="trusted-rating",
        source_url="https://www.factcheck.org/review/1",
        publisher="FactCheck.org",
        source_tier=SourceTier.B,
        stance=ClaimStance.REFUTES,
        trusted_claim_review=True,
        observed_at=NOW,
    )
    pipeline = FactCheckOrchestrator(
        google_claim_search=ParallelGoogle([rated]),
        comparator=InconclusiveComparator(),
    )

    result = await pipeline.verify([ExtractedClaim.from_text("COVID vaccines contain microchips")])

    assert result.claim_findings == ()
    assert "Chưa đủ dữ liệu về một chủ đề liên quan ngoài phạm vi claim." in result.limitations


@pytest.mark.asyncio
async def test_adjacent_claim_review_triggers_one_web_fallback_and_clears_stale_limitation() -> None:
    class TwoPassComparator:
        def __init__(self):
            self.calls = 0

        async def compare(self, _claim, evidence):
            self.calls += 1
            if self.calls == 1:
                return {
                    "stance": "inconclusive",
                    "scope_relation": "adjacent_claim",
                    "evidence_refs": [],
                    "limitations": [
                        {
                            "code": "ADJACENT_SCOPE_UNCERTAIN",
                            "message_vi": "Nguồn đầu tiên kiểm chứng một claim lân cận.",
                            "impacts_verdict": True,
                        }
                    ],
                }
            assert evidence[0].publisher == "FIFA"
            return {
                "stance": "supports",
                "scope_relation": "matches_claim",
                "evidence_refs": [evidence[0].evidence_ref],
                "contradiction_refs": [],
                "limitations": [],
            }

    snopes = EvidenceCandidate(
        evidence_ref="claimreview:snopes",
        source_url="https://www.snopes.com/fact-check/cropped-photo/",
        publisher="Snopes.com",
        source_tier=SourceTier.B,
        stance=ClaimStance.UNRATED,
        trusted_claim_review=True,
        finding="A photo cropped Trump after Spain celebrated its World Cup victory.",
        observed_at=NOW,
    )
    fifa = WebCandidate(
        evidence_ref="web:fifa",
        canonical_url="https://www.fifa.com/world-cup/final",
        title="Spain win the World Cup",
        snippet="Spain won the World Cup final.",
        publisher="FIFA",
        source_tier="a",
        source_version="fixture",
    )
    comparator = TwoPassComparator()
    pipeline = FactCheckOrchestrator(
        google_claim_search=ParallelGoogle([snopes]),
        tavily_search=StaticWeb([fifa]),
        tavily_extract=RecordingExtract(),
        comparator=comparator,
        source_registry=VersionedSourceRegistry(default_source_policies()),
    )

    result = await pipeline.verify(
        [ExtractedClaim.from_text("Tây Ban Nha vô địch World Cup", language="vi")]
    )

    assert comparator.calls == 2
    assert [item.stance for item in result.claim_findings] == [ClaimStance.SUPPORTS]
    assert "Nguồn đầu tiên kiểm chứng một claim lân cận." not in result.limitations
    assert "Không có đủ evidence nhất quán để kết luận claim." not in result.limitations


@pytest.mark.asyncio
async def test_embedding_failure_continues_and_one_tier_c_can_be_provisional() -> None:
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
    assert web.calls == 0
    assert comparator.calls == 1
    assert len(result.claim_findings) == 1
    assert result.claim_findings[0].provisional is True
    assert any("Embedding" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_temporal_wrong_tier_a_is_excluded_before_comparator() -> None:
    google = ParallelGoogle(
        [
            candidate(
                "old-official",
                SourceTier.A,
                published_at=datetime(2020, 1, 1, tzinfo=UTC),
                effective_from=date(2020, 1, 1),
                effective_to=date(2020, 12, 31),
            )
        ]
    )
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


def test_source_published_before_a_future_policy_can_still_support_the_claim() -> None:
    claim = ExtractedClaim.from_text(
        "Policy applies in 2027",
        language="en",
        is_temporal=True,
        claim_date_start=date(2027, 1, 1),
        claim_date_end=date(2027, 12, 31),
    )
    official = candidate("official-announcement", SourceTier.A, published_at=NOW)

    result = evaluate_evidence_sufficiency(claim, [official])

    assert result.sufficient is True


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
