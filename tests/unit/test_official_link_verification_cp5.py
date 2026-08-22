from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from src.agents.tools.network import SsrfGuard, SsrfPolicy
from src.security_ai.runtime import TurnExecutionContext
from src.services.official_verification_transport import (
    GuardedHtmlFetcher,
    TavilyWebExtractProvider,
    TavilyWebSearchProvider,
    VerificationTransportLimitation,
    VerificationTransportStatus,
    build_official_verification_providers,
)

PUBLIC_IP = "93.184.216.34"


async def _public_resolver(_host: str, _port: int) -> list[str]:
    return [PUBLIC_IP]


def _context(max_network_units: int = 16) -> TurnExecutionContext:
    return TurnExecutionContext(deadline_seconds=30, max_network_units=max_network_units)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal/computeMetadata/v1",
        "https://public.example:444/admin",
    ],
)
async def test_html_fetch_blocks_private_metadata_and_invalid_ports_before_network(target: str) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<html></html>")

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        fetcher = GuardedHtmlFetcher(client=client, guard=SsrfGuard(resolver=_public_resolver))
        result = await fetcher.fetch(target, execution_context=context)

    assert result.status is VerificationTransportStatus.BLOCKED
    assert result.limitation is VerificationTransportLimitation.SSRF_BLOCKED
    assert result.usage.adapter_attempts == 1
    assert result.usage.network_units == 0
    assert result.tool_calls_used == 1
    assert calls == 0


@pytest.mark.asyncio
async def test_dns_rebinding_is_revalidated_and_blocked_before_second_send() -> None:
    resolutions = 0
    sends = 0

    async def resolver(_host: str, _port: int) -> list[str]:
        nonlocal resolutions
        resolutions += 1
        return [PUBLIC_IP] if resolutions == 1 else ["127.0.0.1"]

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal sends
        sends += 1
        return httpx.Response(302, headers={"location": "/landing"})

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await GuardedHtmlFetcher(
            client=client,
            guard=SsrfGuard(resolver=resolver),
        ).fetch("https://public.example/", execution_context=context)

    assert result.status is VerificationTransportStatus.BLOCKED
    assert result.limitation is VerificationTransportLimitation.SSRF_BLOCKED
    assert resolutions == 2
    assert sends == 1
    assert result.usage.network_units == 1


@pytest.mark.asyncio
async def test_private_redirect_and_redirect_loop_fail_closed_with_per_hop_units() -> None:
    async def resolver(host: str, _port: int) -> list[str]:
        return ["10.0.0.2"] if host == "private.example" else [PUBLIC_IP]

    def private_redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://private.example/internal"})

    private_context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(private_redirect)) as client:
        private = await GuardedHtmlFetcher(
            client=client,
            guard=SsrfGuard(resolver=resolver),
        ).fetch("https://public.example/", execution_context=private_context)

    assert private.status is VerificationTransportStatus.BLOCKED
    assert private.limitation is VerificationTransportLimitation.SSRF_BLOCKED
    assert private.usage.network_units == 1

    def loop(request: httpx.Request) -> httpx.Response:
        location = "/next" if request.url.path == "/" else "/"
        return httpx.Response(302, headers={"location": location})

    loop_context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(loop)) as client:
        looped = await GuardedHtmlFetcher(
            client=client,
            guard=SsrfGuard(resolver=_public_resolver),
        ).fetch("https://public.example/", execution_context=loop_context)

    assert looped.status is VerificationTransportStatus.LIMITED
    assert looped.limitation is VerificationTransportLimitation.REDIRECT_LOOP
    assert looped.usage.network_units == 2


@pytest.mark.asyncio
async def test_html_fetch_enforces_configured_redirect_limit() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        next_hop = int(request.url.path.strip("/") or "0") + 1
        return httpx.Response(302, headers={"location": f"/{next_hop}"})

    context = _context()
    guard = SsrfGuard(
        resolver=_public_resolver,
        policy=SsrfPolicy(max_redirects=1, max_response_bytes=1_000_000),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await GuardedHtmlFetcher(client=client, guard=guard).fetch(
            "https://public.example/",
            execution_context=context,
        )

    assert result.status is VerificationTransportStatus.LIMITED
    assert result.limitation is VerificationTransportLimitation.REDIRECT_LIMIT_EXCEEDED
    assert result.usage.network_units == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "limitation", "status"),
    [
        (
            httpx.Response(429, headers={"content-type": "text/html"}),
            VerificationTransportLimitation.RATE_LIMITED,
            VerificationTransportStatus.LIMITED,
        ),
        (
            httpx.Response(200, headers={"content-type": "application/pdf"}, content=b"pdf"),
            VerificationTransportLimitation.UNSUPPORTED_CONTENT_TYPE,
            VerificationTransportStatus.BLOCKED,
        ),
        (
            httpx.Response(
                200,
                headers={"content-type": "text/html", "content-length": "1000001"},
            ),
            VerificationTransportLimitation.RESPONSE_TOO_LARGE,
            VerificationTransportStatus.LIMITED,
        ),
    ],
)
async def test_html_fetch_normalizes_429_non_html_and_oversized_response(
    response: httpx.Response,
    limitation: VerificationTransportLimitation,
    status: VerificationTransportStatus,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return response

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await GuardedHtmlFetcher(
            client=client,
            guard=SsrfGuard(resolver=_public_resolver),
        ).fetch("https://public.example/", execution_context=context)

    assert result.status is status
    assert result.limitation is limitation
    assert result.document is None
    assert result.usage.network_units == 1


@pytest.mark.asyncio
async def test_html_fetch_timeout_is_bounded_and_normalized() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("fixture timeout", request=request)

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await GuardedHtmlFetcher(
            client=client,
            guard=SsrfGuard(resolver=_public_resolver),
        ).fetch("https://public.example/", execution_context=context)

    assert result.status is VerificationTransportStatus.LIMITED
    assert result.limitation is VerificationTransportLimitation.PROVIDER_TIMEOUT
    assert result.usage.network_units == 1


@pytest.mark.asyncio
async def test_html_fetch_accepts_only_bounded_html_and_counts_every_redirect_hop() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/official"})
        return httpx.Response(
            200,
            headers={"content-type": "application/xhtml+xml; charset=utf-8"},
            content=b"<html><body>official</body></html>",
        )

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await GuardedHtmlFetcher(
            client=client,
            guard=SsrfGuard(resolver=_public_resolver),
        ).fetch("https://public.example/", execution_context=context)

    assert result.status is VerificationTransportStatus.SUCCESS
    assert result.document is not None
    assert result.document.media_type == "application/xhtml+xml"
    assert result.document.body.startswith(b"<html>")
    assert result.document.redirect_chain == [
        "https://public.example/",
        "https://public.example/official",
    ]
    assert result.usage.network_units == 2
    assert calls == 2
    assert "body" not in result.model_dump()["document"]


@pytest.mark.asyncio
async def test_search_request_seventeen_is_not_sent_and_telemetry_separates_attempts() -> None:
    sends = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal sends
        sends += 1
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "title": "Official notice",
                        "url": "https://official.example/notice",
                        "content": "Official announcement",
                        "score": 0.9,
                    }
                ]
            },
        )

    context = _context(max_network_units=16)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = TavilyWebSearchProvider("fixture-key", client=client)
        outcomes = [
            await provider.search_one(f"Example official notice {index}", execution_context=context)
            for index in range(17)
        ]

    assert sends == 16
    assert context.network_units == 16
    assert all(item.tool_calls_used == 1 and item.usage.adapter_attempts == 1 for item in outcomes)
    assert all(item.usage.network_units == 1 for item in outcomes[:16])
    assert outcomes[16].status is VerificationTransportStatus.LIMITED
    assert outcomes[16].limitation is VerificationTransportLimitation.NETWORK_BUDGET_EXHAUSTED
    assert outcomes[16].usage.network_units == 0


@pytest.mark.asyncio
async def test_search_rejects_sensitive_query_before_provider_and_never_fabricates_citation() -> None:
    sends = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal sends
        sends += 1
        return httpx.Response(200, json={"results": []})

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TavilyWebSearchProvider("fixture-key", client=client).search_one(
            "ACME https://secret.example user@example.com OTP=123456",
            execution_context=context,
        )

    assert result.status is VerificationTransportStatus.BLOCKED
    assert result.limitation is VerificationTransportLimitation.INVALID_QUERY
    assert result.usage.network_units == 0
    assert sends == 0
    assert "citation" not in result.model_dump_json().casefold()


@pytest.mark.asyncio
async def test_search_provider_failure_returns_only_normalized_limitation() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"detail": "provider-specific secret detail"})

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TavilyWebSearchProvider("fixture-key", client=client).search_one(
            "Example official announcement",
            execution_context=context,
        )

    assert result.status is VerificationTransportStatus.LIMITED
    assert result.limitation is VerificationTransportLimitation.RATE_LIMITED
    assert result.results == []
    assert "provider-specific" not in result.model_dump_json()
    assert "citation" not in result.model_dump_json().casefold()


@pytest.mark.asyncio
async def test_extract_blocks_private_targets_without_calling_provider() -> None:
    sends = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal sends
        sends += 1
        return httpx.Response(200, json={"results": []})

    async def resolver(host: str, _port: int) -> list[str]:
        return ["127.0.0.1"] if host == "private.example" else [PUBLIC_IP]

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TavilyWebExtractProvider(
            "fixture-key",
            client=client,
            guard=SsrfGuard(resolver=resolver),
        ).extract(
            ["http://private.example/internal"],
            query="Example official notice",
            execution_context=context,
        )

    assert result.status is VerificationTransportStatus.BLOCKED
    assert result.limitation is VerificationTransportLimitation.SSRF_BLOCKED
    assert result.usage.network_units == 0
    assert sends == 0


@pytest.mark.asyncio
async def test_extract_returns_bounded_normalized_document_without_serializing_raw_content() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "url": "https://official.example/notice",
                        "title": "Official notice",
                        "raw_content": "Reviewed official content",
                    }
                ]
            },
        )

    context = _context()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TavilyWebExtractProvider(
            "fixture-key",
            client=client,
            guard=SsrfGuard(resolver=_public_resolver),
        ).extract(
            ["https://official.example/notice"],
            query="Example official notice",
            execution_context=context,
        )

    assert result.status is VerificationTransportStatus.SUCCESS
    assert result.documents[0].content == "Reviewed official content"
    assert result.usage.network_units == 1
    assert "content" not in result.model_dump()["documents"][0]


def test_missing_tavily_keeps_local_registry_path_available() -> None:
    bundle = build_official_verification_providers(SimpleNamespace(tavily_api_key="", provider_timeout_seconds=5))

    assert bundle.search is None
    assert bundle.extract is None
    assert bundle.local_registry_available is True
    assert bundle.limitations == (VerificationTransportLimitation.PROVIDER_UNAVAILABLE,)
