from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from src.agents.tools.errors import ToolCallError, UnsafeUrlError
from src.agents.tools.network import GuardedHttpClient, SsrfGuard
from src.agents.tools.providers import GoogleFactCheckRetriever, GoogleSafeBrowsingScanner
from src.models import ClaimEvidence, Verdict
from src.repositories import JsonFactCheckRepository, SQLiteBlacklistRepository


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
async def test_ssrf_guard_blocks_every_non_global_dns_answer(address):
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8", address]

    with pytest.raises(UnsafeUrlError):
        await SsrfGuard(resolver=resolver).validate("https://example.com/path")


@pytest.mark.asyncio
async def test_guarded_client_revalidates_redirect_target():
    async def resolver(host: str, _port: int) -> list[str]:
        return ["8.8.8.8"] if host == "public.example" else ["127.0.0.1"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://internal.example/admin"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        guarded = GuardedHttpClient(client, SsrfGuard(resolver=resolver))
        with pytest.raises(UnsafeUrlError):
            await guarded.get("https://public.example/")


@pytest.mark.asyncio
async def test_guarded_client_connects_to_the_validated_ip_and_preserves_host():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "93.184.216.34"
        assert request.headers["host"] == "public.example"
        assert request.extensions["sni_hostname"] == b"public.example"
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        guarded = GuardedHttpClient(client, SsrfGuard(resolver=resolver))
        response, _ = await guarded.get("https://public.example/path")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_safe_browsing_no_hit_is_inconclusive():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["key"] == "secret"
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        scanner = GoogleSafeBrowsingScanner("secret", client=client, guard=SsrfGuard(resolver=resolver))
        result = await scanner.scan("https://example.com/")

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.signals == ["no_known_threat_match"]


@pytest.mark.asyncio
async def test_safe_browsing_timeout_is_normalized():
    async def resolver(_host: str, _port: int) -> list[str]:
        return ["8.8.8.8"]

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        scanner = GoogleSafeBrowsingScanner("secret", client=client, guard=SsrfGuard(resolver=resolver))
        with pytest.raises(ToolCallError) as caught:
            await scanner.scan("https://example.com/")

    assert caught.value.error.code == "PROVIDER_TIMEOUT"
    assert caught.value.error.retryable is True


@pytest.mark.asyncio
async def test_fact_check_provider_normalizes_reviews():
    payload = {
        "claims": [
            {
                "text": "claim",
                "claimReview": [
                    {
                        "publisher": {"name": "Verified Source"},
                        "url": "https://fact.example/review",
                        "title": "Review title",
                        "textualRating": "False",
                        "reviewDate": "2026-08-03T13:00:00Z",
                    }
                ],
            }
        ]
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        retriever = GoogleFactCheckRetriever("secret", client=client)
        results = await retriever.search("claim", limit=1)

    assert results[0].source == "Verified Source"
    assert results[0].finding == "False"
    assert results[0].observed_at.tzinfo is UTC


@pytest.mark.asyncio
async def test_blacklist_requires_audited_approval(tmp_path):
    repository = SQLiteBlacklistRepository(tmp_path / "security.db")
    with pytest.raises(PermissionError):
        await repository.add_approved("bad.example", "missing")

    await repository.record_decision(
        decision_id="decision-1",
        reviewer_id="admin-1",
        decision="approved",
        action="add_to_blacklist",
        note="Evidence reviewed",
    )
    await repository.add_approved("BÄD.example.", "decision-1")

    assert await repository.contains("xn--bd-via.example")
    await repository.close()


@pytest.mark.asyncio
async def test_offline_fact_check_repository_is_ranked_and_copied():
    corpus = JsonFactCheckRepository(
        [
            ClaimEvidence(
                source="source",
                title="Cảnh báo phí mở khóa tài khoản",
                url="https://example.com/review",
                finding="Yêu cầu phí mở khóa là giả mạo",
                relevance=1,
                observed_at=datetime(2026, 8, 3, tzinfo=UTC),
            )
        ]
    )
    results = await corpus.search("nộp phí mở khóa tài khoản")

    assert len(results) == 1
    assert 0 < results[0].relevance <= 1
