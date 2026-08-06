import pytest

from src.agents.tools import (
    FakeBlacklistRepository,
    FakeClaimRetriever,
    FakeDomainIntelligence,
    FakeToolCallError,
    FakeUrlScanner,
)
from src.models import DomainIntelligenceResult, ToolError, UrlScanResult, Verdict
from tests.fixture_loader import (
    load_analyses,
    load_blacklist_responses,
    load_claim_retriever_responses,
    load_domain_intelligence_responses,
    load_url_scanner_responses,
)

EXPECTED_FIXTURE_IDS = {
    "safe_official_001",
    "phishing_brand_001",
    "short_url_redirect_001",
    "suspicious_claim_001",
    "false_claim_001",
    "no_url_or_claim_001",
    "no_consent_001",
    "provider_timeout_001",
    "unicode_domain_001",
    "ssrf_private_ip_001",
    "empty_message_001",
    "admin_review_001",
}


def test_loads_exactly_the_12_frozen_analysis_fixtures() -> None:
    fixtures = load_analyses()
    ids = [fixture.id for fixture in fixtures]
    assert len(ids) == 12
    assert len(ids) == len(set(ids))
    assert set(ids) == EXPECTED_FIXTURE_IDS


def test_all_mock_references_resolve() -> None:
    url_responses = load_url_scanner_responses()
    claim_responses = load_claim_retriever_responses()
    blacklist_responses = load_blacklist_responses()

    for fixture in load_analyses():
        if fixture.mocks.url_scanner is not None:
            assert fixture.mocks.url_scanner in url_responses
        if fixture.mocks.claim_retriever is not None:
            assert fixture.mocks.claim_retriever in claim_responses
        if fixture.mocks.blacklist is not None:
            assert fixture.mocks.blacklist in blacklist_responses


def test_negative_fixtures_encode_safety_invariants() -> None:
    fixtures = {fixture.id: fixture for fixture in load_analyses()}
    assert fixtures["no_consent_001"].expected.external_url_scan_allowed is False
    assert fixtures["provider_timeout_001"].expected.verdict == "inconclusive"
    assert fixtures["provider_timeout_001"].expected.required_limitation is True
    assert fixtures["ssrf_private_ip_001"].expected.ssrf_blocked is True
    assert fixtures["empty_message_001"].expected.http_status == 422
    assert fixtures["admin_review_001"].expected.blacklist_write is True


@pytest.mark.asyncio
async def test_fake_url_scanner_returns_typed_copy_without_network() -> None:
    loaded = load_url_scanner_responses()["url_safe_001"]
    assert loaded.result is not None
    scanner = FakeUrlScanner({"url_safe_001": loaded.result}, "url_safe_001")

    result = await scanner.scan("https://official.example/security")

    assert isinstance(result, UrlScanResult)
    assert result.verdict is Verdict.SAFE
    assert scanner.calls == ["https://official.example/security"]
    assert result is not loaded.result


@pytest.mark.asyncio
async def test_fake_url_scanner_replays_timeout() -> None:
    loaded = load_url_scanner_responses()["url_timeout_001"]
    assert loaded.error is not None
    scanner = FakeUrlScanner({"url_timeout_001": loaded.error}, "url_timeout_001")

    with pytest.raises(FakeToolCallError) as raised:
        await scanner.scan("https://timeout.example/login")

    assert isinstance(raised.value.error, ToolError)
    assert raised.value.error.code == "PROVIDER_TIMEOUT"


@pytest.mark.asyncio
async def test_fake_url_scanner_reports_unconfigured_response_id() -> None:
    scanner = FakeUrlScanner({}, "missing-response")

    with pytest.raises(ValueError, match="missing-response"):
        await scanner.scan("https://example.com")


@pytest.mark.asyncio
async def test_fake_claim_retriever_honors_limit() -> None:
    loaded = load_claim_retriever_responses()["claim_false_001"]
    assert loaded.results is not None
    retriever = FakeClaimRetriever({"claim_false_001": loaded.results}, "claim_false_001")

    assert len(await retriever.search("claim", limit=1)) == 1
    assert await retriever.search("claim", limit=0) == []


@pytest.mark.asyncio
async def test_fake_domain_intelligence_returns_typed_copy_without_network() -> None:
    loaded = load_domain_intelligence_responses()["domain_new_001"]
    assert loaded.result is not None
    adapter = FakeDomainIntelligence({"domain_new_001": loaded.result}, "domain_new_001")

    result = await adapter.lookup("example.com")

    assert isinstance(result, DomainIntelligenceResult)
    assert result.domain == "example.com"
    assert result.signals == ["recent_registration"]


@pytest.mark.asyncio
async def test_fake_blacklist_is_case_insensitive_and_tracks_approved_write() -> None:
    domains = load_blacklist_responses()["domain_listed_001"].domains
    repository = FakeBlacklistRepository(domains)

    assert await repository.contains("KNOWN-BAD.EXAMPLE") is True
    await repository.add_approved("New-Bad.Example", "decision-001")
    assert await repository.contains("new-bad.example") is True
    assert repository.approved_writes == [("new-bad.example", "decision-001")]
