from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.agents.tools import (
    CacheMetadata,
    GoogleWebRiskProvider,
    GuardedHttpClient,
    GuardedRedirectResolver,
    NormalizedToolResult,
    ProductionUrlReputationCascade,
    SsrfGuard,
    SsrfPolicy,
    ToolCallError,
    ToolResultStatus,
    UrlReputationFinding,
    UsageMetadata,
    VersionedMemoryCache,
    canonicalize_registrable_domain,
)
from src.models import Verdict

NOW = datetime(2026, 8, 8, tzinfo=UTC)


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def test_shared_canonicalizer_handles_subdomain_idna_and_rejects_non_domains() -> None:
    assert canonicalize_registrable_domain("https://Login.Shop.Example.COM./x") == "example.com"
    assert canonicalize_registrable_domain("a.b.example.co.uk") == "example.co.uk"
    with pytest.raises(ValueError):
        canonicalize_registrable_domain("co.uk")
    with pytest.raises(ValueError):
        canonicalize_registrable_domain("127.0.0.1")


@pytest.mark.asyncio
async def test_guarded_client_stops_stream_without_content_length_at_byte_limit() -> None:
    stream = _ChunkStream([b"1234", b"5678", b"must-not-be-read"])

    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    policy = SsrfPolicy(max_response_bytes=5)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        guarded = GuardedHttpClient(client, SsrfGuard(resolver=resolver, policy=policy))
        with pytest.raises(ToolCallError, match="too large") as caught:
            await guarded.get("https://public.example/")

    assert getattr(caught.value, "error").code == "RESPONSE_TOO_LARGE"
    assert stream.yielded == 2
    assert stream.closed is True


@pytest.mark.asyncio
async def test_versioned_cache_prunes_expired_entries_and_enforces_capacity() -> None:
    current = NOW
    cache: VersionedMemoryCache[str] = VersionedMemoryCache(max_entries=2, clock=lambda: current)
    await cache.put("provider", "v1", "expired", "old", timedelta(seconds=1))
    current += timedelta(seconds=2)
    await cache.put("provider", "v1", "one", "1", timedelta(hours=1))
    assert len(cache._items) == 1

    await cache.put("provider", "v1", "two", "2", timedelta(hours=1))
    await cache.put("provider", "v1", "three", "3", timedelta(hours=1))

    assert len(cache._items) == 2
    assert await cache.get("provider", "v1", "one") is None


@pytest.mark.asyncio
async def test_web_risk_no_hit_is_inconclusive_and_second_lookup_is_memory_hit() -> None:
    calls = 0

    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = GoogleWebRiskProvider("secret", client=client, guard=SsrfGuard(resolver=resolver), clock=lambda: NOW)
        first = await provider.lookup("https://unknown.example/path")
        second = await provider.lookup("https://unknown.example/path")

    assert first.status is ToolResultStatus.INCONCLUSIVE
    assert first.result is not None and first.result.verdict is Verdict.INCONCLUSIVE
    assert second.cache.status.value == "hit"
    assert second.usage.network_calls == 0
    assert calls == 1


class _FixtureProvider:
    def __init__(self, finding: UrlReputationFinding) -> None:
        self.finding = finding

    async def lookup(self, _url: str) -> NormalizedToolResult[UrlReputationFinding]:
        return NormalizedToolResult(
            status=ToolResultStatus.SUCCESS,
            result=self.finding,
            cache=CacheMetadata(status="miss"),
            usage=UsageMetadata(
                usage_ref=f"usage:{self.finding.provider}",
                provider=self.finding.provider,
                provider_version=self.finding.provider_version,
                operation="lookup",
                attempts=1,
                network_calls=1,
                latency_ms=1,
                observed_at=NOW,
            ),
        )

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_high_risk_cascade_escalates_and_normalizes_provider_disagreement() -> None:
    target = "https://conflict.example/login"
    primary = _FixtureProvider(
        UrlReputationFinding(
            provider="google-web-risk",
            provider_version="v1",
            normalized_url=target,
            matched=True,
            verdict=Verdict.MALICIOUS,
            observed_at=NOW,
        )
    )
    secondary = _FixtureProvider(
        UrlReputationFinding(
            provider="virustotal",
            provider_version="v3",
            normalized_url=target,
            matched=True,
            verdict=Verdict.SAFE,
            observed_at=NOW,
        )
    )
    cascade = ProductionUrlReputationCascade(primary, secondary, clock=lambda: NOW)  # type: ignore[arg-type]

    outcome = await cascade.assess(target, high_risk=True)

    assert outcome.result is not None
    assert outcome.result.provider_conflict is True
    assert outcome.result.verdict is Verdict.SUSPICIOUS
    assert outcome.usage.network_calls == 2


@pytest.mark.asyncio
async def test_redirect_resolver_blocks_private_hop_and_detects_loop() -> None:
    async def resolver(host: str, _port: int) -> list[str]:
        return ["127.0.0.1"] if host == "private.example" else ["93.184.216.34"]

    def private_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://private.example/admin"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(private_handler)) as client:
        resolver_adapter = GuardedRedirectResolver(client=client, guard=SsrfGuard(resolver=resolver))
        blocked = await resolver_adapter.resolve("https://public.example/")
    assert blocked.status is ToolResultStatus.BLOCKED
    assert blocked.error is not None and blocked.error.code.value == "SSRF_BLOCKED"

    def loop_handler(request: httpx.Request) -> httpx.Response:
        location = "/next" if request.url.path == "/" else "/"
        return httpx.Response(302, headers={"location": location})

    async with httpx.AsyncClient(transport=httpx.MockTransport(loop_handler)) as client:
        resolver_adapter = GuardedRedirectResolver(client=client, guard=SsrfGuard(resolver=resolver))
        loop = await resolver_adapter.resolve("https://public.example/")
    assert loop.status is ToolResultStatus.FAILED
    assert loop.error is not None and loop.error.code.value == "REDIRECT_LOOP"
