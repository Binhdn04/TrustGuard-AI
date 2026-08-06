from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.agents.tools.errors import ToolCallError, UnsafeUrlError
from src.agents.tools.network import GuardedHttpClient, SsrfGuard
from src.agents.tools.providers import (
    GoogleFactCheckRetriever,
    GoogleSafeBrowsingScanner,
    map_google_fact_check_rating,
)
from src.agents.tools.rdap import RdapDomainIntelligence
from src.models import ClaimEvidence, ClaimStance, Verdict
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
    assert results[0].stance is ClaimStance.REFUTES


def test_unknown_fact_check_rating_is_not_inferred_from_prose():
    assert map_google_fact_check_rating("Definitely bogus according to this article") is ClaimStance.UNRATED


@pytest.mark.asyncio
async def test_rdap_normalizes_registrable_domain_redaction_and_caches():
    observed_at = datetime(2026, 8, 6, 13, tzinfo=UTC)
    requests: list[str] = []

    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.headers["host"]
        requests.append(host)
        if host == "data.iana.org":
            return httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/"]]]})
        assert host == "rdap.example"
        assert request.url.path == "/domain/example.com"
        return httpx.Response(200, json={
            "events": [
                {"eventAction": "registration", "eventDate": "2026-07-26T13:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2027-07-26T13:00:00Z"},
            ],
            "status": ["active"],
            "remarks": [{"description": ["Registrant data redacted for privacy"]}],
            "entities": [{"vcardArray": ["vcard", [["email", {}, "text", "secret@example.com"]]]}],
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = RdapDomainIntelligence(
            client=client,
            guard=SsrfGuard(resolver=resolver),
            clock=lambda: observed_at,
        )
        first = await adapter.lookup("login.shop.example.com")
        second = await adapter.lookup("example.com")

    assert first == second
    assert first.domain == "example.com"
    assert first.registrar is None
    assert first.privacy_redacted is True
    assert first.signals == ["recent_registration"]
    assert requests == ["data.iana.org", "rdap.example"]


@pytest.mark.asyncio
async def test_rdap_not_found_uses_separate_ttl():
    current = datetime(2026, 8, 6, 13, tzinfo=UTC)
    rdap_calls = 0

    async def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal rdap_calls
        if request.headers["host"] == "data.iana.org":
            return httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/"]]]})
        rdap_calls += 1
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = RdapDomainIntelligence(
            client=client,
            guard=SsrfGuard(resolver=resolver),
            not_found_ttl=timedelta(minutes=5),
            clock=lambda: current,
        )
        assert (await adapter.lookup("missing.com")).signals == ["not_found"]
        assert (await adapter.lookup("missing.com")).signals == ["not_found"]

    assert rdap_calls == 1


def test_rdap_skips_ip_and_public_suffix():
    adapter = RdapDomainIntelligence()
    assert adapter.registrable_domain("127.0.0.1") is None
    assert adapter.registrable_domain("com") is None
    assert adapter.registrable_domain("a.b.example.co.uk") == "example.co.uk"


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
    entry = await repository.get("xn--bd-via.example")
    assert entry is not None
    assert entry.decision_id == "decision-1"
    assert entry.source == "approved-blacklist"
    assert entry.active is True
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
                stance=ClaimStance.REFUTES,
                relevance=1,
                observed_at=datetime(2026, 8, 3, tzinfo=UTC),
            )
        ]
    )
    results = await corpus.search("nộp phí mở khóa tài khoản")

    assert len(results) == 1
    assert 0 < results[0].relevance <= 1
