from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from src.agents.tools import (
    CacheMetadata,
    GoogleWebRiskProvider,
    GuardedRedirectResolver,
    NormalizedToolResult,
    ProductionUrlReputationCascade,
    SsrfGuard,
    ToolResultStatus,
    UrlReputationFinding,
    UsageMetadata,
    canonicalize_registrable_domain,
)
from src.models import Verdict

NOW = datetime(2026, 8, 8, tzinfo=UTC)


def test_shared_canonicalizer_handles_subdomain_idna_and_rejects_non_domains() -> None:
    assert canonicalize_registrable_domain("https://Login.Shop.Example.COM./x") == "example.com"
    assert canonicalize_registrable_domain("a.b.example.co.uk") == "example.co.uk"
    with pytest.raises(ValueError):
        canonicalize_registrable_domain("co.uk")
    with pytest.raises(ValueError):
        canonicalize_registrable_domain("127.0.0.1")


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
