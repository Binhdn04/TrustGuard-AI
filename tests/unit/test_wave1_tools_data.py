from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.agents.tools import (
    CacheMetadata,
    GuardedRedirectResolver,
    NormalizedRdapProvider,
    NormalizedToolResult,
    RdapDomainIntelligence,
    RedirectResolutionStatus,
    SsrfGuard,
    ToolCallError,
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
async def test_terminal_http_error_is_unresolved_not_successful_no_redirect():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(404))) as client:
        envelope = await GuardedRedirectResolver(client=client, guard=SsrfGuard(resolver=resolver)).resolve(
            "https://short.example/form"
        )

    assert envelope.status is ToolResultStatus.INCONCLUSIVE
    assert envelope.result is not None
    assert envelope.result.status is RedirectResolutionStatus.UNRESOLVED
    assert envelope.result.http_status_code == 404
    assert "http_404" in envelope.result.signals


@pytest.mark.asyncio
async def test_redirect_resolver_retries_a_bot_challenge_with_navigation_headers():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    target = "https://short.example/form"
    destination = "https://forms.example/d/official-form"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("user-agent", "").startswith("python-httpx"):
            return httpx.Response(403)
        assert request.headers["accept-language"] == "en-US,en;q=0.9"
        if request.url.path == "/form":
            return httpx.Response(302, headers={"location": destination})
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        envelope = await GuardedRedirectResolver(client=client, guard=SsrfGuard(resolver=resolver)).resolve(target)

    assert envelope.status is ToolResultStatus.SUCCESS
    assert envelope.result is not None
    assert envelope.result.status is RedirectResolutionStatus.RESOLVED
    assert envelope.result.final_url == destination
    assert envelope.result.redirect_chain == [target, destination]
    assert envelope.usage.attempts == 2
    assert envelope.usage.network_calls == 3


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
async def test_virus_total_no_hit_is_inconclusive_without_raw_body():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8"]

    def vt_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0}, "raw": "secret"}}},
        )

    guard = SsrfGuard(resolver=resolver)
    async with httpx.AsyncClient(transport=httpx.MockTransport(vt_handler)) as vt_client:
        vt = await VirusTotalUrlProvider("key", client=vt_client, guard=guard).lookup("https://unknown.example")

    assert vt.status is ToolResultStatus.INCONCLUSIVE
    assert vt.result is not None and vt.result.verdict is Verdict.INCONCLUSIVE
    assert "secret" not in vt.model_dump_json()


class _FixtureProvider:
    def __init__(self, name: str, verdict: Verdict, *, failures: int = 0):
        self.provider, self.provider_version = name, "v1"
        self.verdict, self.failures, self.calls = verdict, failures, 0

    async def lookup(self, url: str):
        self.calls += 1
        usage = UsageMetadata(
            usage_ref=f"usage:{self.calls}",
            provider=self.provider,
            provider_version="v1",
            operation="lookup",
            attempts=1,
            network_calls=1,
            latency_ms=1,
            observed_at=NOW,
        )
        if self.calls <= self.failures:
            from src.agents.tools import NormalizedToolError, ToolErrorCode, ToolName

            return NormalizedToolResult(
                status="failed",
                error=NormalizedToolError(
                    tool=ToolName.URL_REPUTATION,
                    code=ToolErrorCode.RATE_LIMITED,
                    message="limited",
                    retryable=True,
                    provider=self.provider,
                    retry_after_ms=0,
                ),
                cache=CacheMetadata(status="miss"),
                usage=usage,
            )
        finding = UrlReputationFinding(
            provider=self.provider,
            provider_version="v1",
            normalized_url=url,
            matched=self.verdict is Verdict.MALICIOUS,
            verdict=self.verdict,
            observed_at=NOW,
        )
        return NormalizedToolResult(
            status="success" if finding.matched else "inconclusive",
            result=finding,
            cache=CacheMetadata(status="miss"),
            usage=usage,
        )


@pytest.mark.asyncio
async def test_cascade_disagreement_retry_and_provider_versioned_memory_hit():
    primary = _FixtureProvider("primary-reputation", Verdict.MALICIOUS, failures=1)
    secondary = _FixtureProvider("secondary-reputation", Verdict.INCONCLUSIVE)
    service = UrlReputationService(primary, secondary, backoff_seconds=0, clock=lambda: NOW)
    first = await service.assess("https://bad.example", high_risk=True)
    second = await service.assess("https://bad.example", high_risk=True)

    assert first.result is not None and first.result.provider_conflict is True
    assert primary.calls == 2 and secondary.calls == 1
    assert second.cache.status.value == "hit" and second.usage.network_calls == 0


@pytest.mark.asyncio
async def test_circuit_breaker_stops_repeated_provider_calls():
    provider = _FixtureProvider("primary-reputation", Verdict.INCONCLUSIVE, failures=20)
    service = UrlReputationService(
        provider, failure_threshold=1, max_attempts=1, circuit_cooldown=timedelta(minutes=1), clock=lambda: NOW
    )
    first = await service.assess("https://one.example")
    second = await service.assess("https://two.example")
    assert first.status is ToolResultStatus.FAILED and second.status is ToolResultStatus.FAILED
    assert provider.calls == 1


def test_runtime_provider_clients_are_lazy_before_consent():
    vt = VirusTotalUrlProvider("key")
    redirect = GuardedRedirectResolver()
    assert vt._client is None
    assert redirect._client is None


@pytest.mark.asyncio
async def test_secondary_provider_requires_positive_policy_budget():
    primary = _FixtureProvider("primary-reputation", Verdict.MALICIOUS)
    secondary = _FixtureProvider("secondary-reputation", Verdict.INCONCLUSIVE)
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
        return DomainIntelligenceResult(
            provider=self.provider,
            domain=domain,
            signals=["recent_registration"],
            privacy_redacted=True,
            observed_at=datetime.now(UTC),
        )

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


@pytest.mark.asyncio
async def test_rdap_missing_bootstrap_service_is_inconclusive_and_cached():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["192.0.32.8"]

    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers["host"] == "data.iana.org"
        assert request.url.path == "/rdap/dns.json"
        return httpx.Response(200, json={"services": [[["net"], ["https://rdap.example.net/"]]]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = RdapDomainIntelligence(client=client, guard=SsrfGuard(resolver=resolver))
        provider = NormalizedRdapProvider(adapter)
        first = await provider.lookup("example.com")
        second = await provider.lookup("example.com")

    assert first.status is ToolResultStatus.INCONCLUSIVE
    assert first.error is None
    assert first.result is not None and first.result.signals == ["service_unavailable"]
    assert second.status is ToolResultStatus.INCONCLUSIVE
    assert second.cache.status.value == "hit"
    assert second.usage.network_calls == 0
    assert calls == 1


@pytest.mark.asyncio
async def test_rdap_provider_failure_is_inconclusive_and_cached_not_a_tool_error():
    class _UnavailableRdap:
        provider = "fixture-rdap/v1"
        calls = 0

        async def lookup(self, _domain: str):
            self.calls += 1
            raise ToolCallError("domain_intelligence", "PROVIDER_ERROR", "registry unavailable", retryable=True)

        async def aclose(self):
            return None

    adapter = _UnavailableRdap()
    provider = NormalizedRdapProvider(adapter)  # type: ignore[arg-type]
    first = await provider.lookup("example.com")
    second = await provider.lookup("example.com")

    assert first.status is ToolResultStatus.INCONCLUSIVE
    assert first.error is None
    assert first.result is not None and first.result.signals == ["provider_unavailable"]
    assert second.status is ToolResultStatus.INCONCLUSIVE
    assert second.cache.status.value == "hit"
    assert adapter.calls == 1
