from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.agents.tools import (
    CacheMetadata,
    GoogleWebRiskProvider,
    GuardedRedirectResolver,
    NormalizedRdapProvider,
    NormalizedToolResult,
    SsrfGuard,
    ToolResultStatus,
    UrlReputationFinding,
    UrlReputationService,
    UsageMetadata,
    VirusTotalUrlProvider,
    canonicalize_url,
)
from src.models import DomainIntelligenceResult, Verdict

NOW = datetime(2026, 8, 8, tzinfo=UTC)


def test_shared_canonicalizer_handles_subdomain_suffix_idna_and_fragment():
    assert canonicalize_url("HTTPS://BÜCHER.Example:443/a?q=1#secret") == "https://xn--bcher-kva.example/a?q=1"
    assert canonicalize_url("http://sub.example.co.uk") == "http://sub.example.co.uk/"
    with pytest.raises(ValueError, match="credentials"):
        canonicalize_url("https://user:secret@example.com")


@pytest.mark.asyncio
async def test_guarded_redirect_resolver_revalidates_and_normalizes_chain():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "start.example":
            return httpx.Response(302, headers={"location": "https://final.example/landing#tracking"})
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = GuardedRedirectResolver(client=client, guard=SsrfGuard(resolver=resolver))
        envelope = await adapter.resolve("https://start.example")

    assert envelope.status is ToolResultStatus.SUCCESS
    assert envelope.result is not None
    assert envelope.result.redirect_chain == ["https://start.example/", "https://final.example/landing"]


@pytest.mark.asyncio
async def test_redirect_private_hop_fails_closed():
    async def resolver(host: str, _port: int) -> list[str]:
        return ["93.184.216.34"] if host == "start.example" else ["127.0.0.1"]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://private.example/admin"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await GuardedRedirectResolver(client=client, guard=SsrfGuard(resolver=resolver)).resolve(
            "https://start.example/"
        )
    assert result.status is ToolResultStatus.BLOCKED
    assert result.error is not None and result.error.code.value == "SSRF_BLOCKED"


@pytest.mark.asyncio
async def test_web_risk_and_virus_total_normalize_without_raw_body():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8"]

    def web_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}, "raw": "secret"})

    def vt_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}})

    guard = SsrfGuard(resolver=resolver)
    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(web_handler)) as web_client,
        httpx.AsyncClient(transport=httpx.MockTransport(vt_handler)) as vt_client,
    ):
        web = await GoogleWebRiskProvider("key", client=web_client, guard=guard).lookup("https://bad.example")
        vt = await VirusTotalUrlProvider("key", client=vt_client, guard=guard).lookup("https://unknown.example")
    assert web.result is not None and web.result.verdict is Verdict.MALICIOUS
    assert vt.status is ToolResultStatus.INCONCLUSIVE
    assert "raw" not in web.model_dump_json()


class _FixtureProvider:
    def __init__(self, name: str, verdict: Verdict, *, failures: int = 0):
        self.provider, self.provider_version = name, "v1"
        self.verdict, self.failures, self.calls = verdict, failures, 0

    async def lookup(self, url: str):
        self.calls += 1
        usage = UsageMetadata(usage_ref=f"usage:{self.calls}", provider=self.provider, provider_version="v1",
                              operation="lookup", attempts=1, network_calls=1, latency_ms=1, observed_at=NOW)
        if self.calls <= self.failures:
            from src.agents.tools import NormalizedToolError, ToolErrorCode, ToolName
            return NormalizedToolResult(status="failed",
                error=NormalizedToolError(tool=ToolName.URL_REPUTATION, code=ToolErrorCode.RATE_LIMITED,
                                          message="limited", retryable=True, provider=self.provider, retry_after_ms=0),
                cache=CacheMetadata(status="miss"), usage=usage)
        finding = UrlReputationFinding(provider=self.provider, provider_version="v1", normalized_url=url,
                                       matched=self.verdict is Verdict.MALICIOUS, verdict=self.verdict, observed_at=NOW)
        return NormalizedToolResult(status="success" if finding.matched else "inconclusive", result=finding,
                                    cache=CacheMetadata(status="miss"), usage=usage)


@pytest.mark.asyncio
async def test_cascade_disagreement_retry_and_provider_versioned_memory_hit():
    primary = _FixtureProvider("web-risk", Verdict.MALICIOUS, failures=1)
    secondary = _FixtureProvider("virus-total", Verdict.INCONCLUSIVE)
    service = UrlReputationService(primary, secondary, backoff_seconds=0, clock=lambda: NOW)
    first = await service.assess("https://bad.example", high_risk=True)
    second = await service.assess("https://bad.example", high_risk=True)

    assert first.result is not None and first.result.provider_conflict is True
    assert primary.calls == 2 and secondary.calls == 1
    assert second.cache.status.value == "hit" and second.usage.network_calls == 0


@pytest.mark.asyncio
async def test_circuit_breaker_stops_repeated_provider_calls():
    provider = _FixtureProvider("web-risk", Verdict.INCONCLUSIVE, failures=20)
    service = UrlReputationService(provider, failure_threshold=1, max_attempts=1,
                                   circuit_cooldown=timedelta(minutes=1), clock=lambda: NOW)
    first = await service.assess("https://one.example")
    second = await service.assess("https://two.example")
    assert first.status is ToolResultStatus.FAILED and second.status is ToolResultStatus.FAILED
    assert provider.calls == 1


def test_real_provider_clients_are_lazy_before_consent():
    web = GoogleWebRiskProvider("key")
    vt = VirusTotalUrlProvider("key")
    redirect = GuardedRedirectResolver()
    assert web._client is None
    assert vt._client is None
    assert redirect._client is None


@pytest.mark.asyncio
async def test_secondary_provider_requires_positive_policy_budget():
    primary = _FixtureProvider("web-risk", Verdict.MALICIOUS)
    secondary = _FixtureProvider("virus-total", Verdict.INCONCLUSIVE)
    service = UrlReputationService(primary, secondary, backoff_seconds=0, clock=lambda: NOW)
    result = await service.assess("https://bad.example", high_risk=True, secondary_budget_remaining=0)
    assert result.result is not None
    assert secondary.calls == 0


class _FakeLegacyRdap:
    provider = "fixture-rdap/v1"

    def __init__(self):
        self.calls = 0

    def registrable_domain(self, domain: str):
        return None if domain in {"com", "127.0.0.1"} else "example.com"

    async def lookup(self, domain: str):
        self.calls += 1
        return DomainIntelligenceResult(provider=self.provider, domain=domain, signals=["recent_registration"],
                                        privacy_redacted=True, observed_at=datetime.now(UTC))

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_rdap_v3_is_normalized_versioned_cached_and_rejects_ip_literal():
    legacy = _FakeLegacyRdap()
    provider = NormalizedRdapProvider(legacy)
    first = await provider.lookup("login.example.com")
    second = await provider.lookup("example.com")
    invalid = await provider.lookup("127.0.0.1")
    assert first.status is ToolResultStatus.SUCCESS
    assert first.result is not None and first.result.privacy_redacted is True
    assert second.cache.status.value == "hit" and second.usage.network_calls == 0
    assert invalid.status is ToolResultStatus.FAILED
    assert invalid.error is not None and invalid.error.code.value == "INVALID_TARGET"
    assert legacy.calls == 1
