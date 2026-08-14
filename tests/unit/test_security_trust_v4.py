from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.security_trust import (
    BrandMatcher,
    HttpOfficialSourceSearch,
    OfficialClaimVerifier,
    SecurityTrustService,
)
from src.models import (
    BrandRecordV4,
    OfficialSourceFindingV4,
    OfficialVerificationPurposeV4,
    OfficialVerificationVerdictV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityRiskV4,
    SecurityTriageCreateRequestV4,
    WhitelistRecordV4,
    WhitelistScopeV4,
)
from src.repositories import SQLiteBlacklistRepository
from src.services.security_triage import SecurityTriageScopeService

NOW = datetime(2026, 8, 13, tzinfo=UTC)


def _brand(**updates) -> BrandRecordV4:
    values = {
        "name": "ACME Bank",
        "aliases": ["ACME", "Ngân hàng ACME"],
        "official_domains": ["acme.example"],
        "official_contacts": ["security@acme.example"],
        "provenance": "reviewed corporate registry",
        "effective_from": NOW - timedelta(days=1),
        "reviewer_id": "admin",
        "created_at": NOW,
    }
    values.update(updates)
    return BrandRecordV4(**values)


def _scope(message: str):
    request = SecurityTriageCreateRequestV4(message=message)
    return request, SecurityTriageScopeService().assess(request)


@pytest.mark.parametrize(
    ("message", "signal"),
    [
        ("ACME yêu cầu đăng nhập https://acme.example/login", "official_match"),
        ("Ngân hàng ACME yêu cầu đăng nhập https://acme.example/login", "official_match"),
        ("ACME yêu cầu đăng nhập https://acne.example/login", "lookalike_domain"),
        ("ACME yêu cầu đăng nhập https://xn--acm-7pa.example/login", "homograph_domain"),
        ("ACME yêu cầu đăng nhập https://unrelated.example/login", "domain_mismatch"),
        ("ACME liên hệ security@acme.example để đăng nhập", "official_contact_match"),
    ],
)
def test_brand_matcher_emits_provenanced_signals(message: str, signal: str) -> None:
    request, scoped = _scope(message)
    brand = _brand()
    selected, evidence = BrandMatcher().match(request, scoped, [brand], NOW)
    matched = next(item for item in evidence if item.signal == signal)
    assert selected == brand
    assert matched.provenance_ref == f"brand:{brand.brand_id}:brand-registry-v1"
    if "contact" in signal:
        assert matched.target.startswith("contact:") and "@" not in matched.target


class _Search:
    def __init__(self, findings):
        self.findings = findings
        self.calls = []

    async def search(self, query, *, allowed_domains, max_results):
        self.calls.append((query, tuple(allowed_domains), max_results))
        return self.findings


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("findings", "expected"),
    [
        (
            [
                OfficialSourceFindingV4(
                    source_url="https://acme.example/news", finding="confirmed", title="Offer", observed_at=NOW
                )
            ],
            OfficialVerificationVerdictV4.OFFICIAL_CONFIRMED,
        ),
        (
            [
                OfficialSourceFindingV4(
                    source_url="https://acme.example/news", finding="contradicted", title="Warning", observed_at=NOW
                )
            ],
            OfficialVerificationVerdictV4.OFFICIAL_CONTRADICTED,
        ),
        ([], OfficialVerificationVerdictV4.NOT_FOUND),
    ],
)
async def test_official_verifier_is_domain_and_budget_bounded(findings, expected) -> None:
    search = _Search(findings)
    result, accepted = await OfficialClaimVerifier(search).verify(
        "ACME promotion", OfficialVerificationPurposeV4.VERIFY_OFFICIAL_CAMPAIGN, ["acme.example"]
    )
    assert result.verdict is expected
    assert search.calls == [("ACME promotion", ("acme.example",), 5)]
    assert len(accepted) <= 5


@pytest.mark.asyncio
async def test_http_official_adapter_sends_only_bounded_allowlisted_request() -> None:
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={"findings": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = HttpOfficialSourceSearch("https://verifier.example/check", "secret", client=client)
        assert await adapter.search("ACME offer", allowed_domains=["acme.example"], max_results=50) == []
    assert captured == {
        "query": "ACME offer",
        "allowed_domains": ["acme.example"],
        "max_results": 5,
        "include_raw_content": False,
    }


class _TrustRepository:
    def __init__(self, brands=None, whitelist=None):
        self.brands = brands or []
        self.whitelist = whitelist or []

    async def list_active_brands(self, at):
        del at
        return self.brands

    async def list_active_whitelist(self, at):
        del at
        return self.whitelist


@pytest.mark.asyncio
async def test_official_not_found_is_a_limitation_not_contradiction() -> None:
    search = _Search([])
    request = SecurityTriageCreateRequestV4(
        message="ACME thông báo trúng thưởng", consent={"official_source_lookup": True}
    )
    scoped = await SecurityInvestigationService().investigate(request, SecurityTriageScopeService().assess(request))
    enriched = await SecurityTrustService(
        _TrustRepository(brands=[_brand()]), verifier=OfficialClaimVerifier(search), clock=lambda: NOW
    ).enrich(request, scoped)
    assert any(item.signal == "not_found" for item in enriched.evidence)
    assert any("NOT_FOUND" in item for item in enriched.limitations)
    assert assess_security_risk(enriched).risk is not SecurityRiskV4.MALICIOUS


@pytest.mark.asyncio
async def test_general_fact_request_never_calls_official_verifier() -> None:
    search = _Search([])
    request = SecurityTriageCreateRequestV4(
        message="Tây Ban Nha vô địch World Cup đúng không?", consent={"official_source_lookup": True}
    )
    scoped = SecurityTriageScopeService().assess(request)
    result = await SecurityTrustService(
        _TrustRepository(brands=[_brand()]), verifier=OfficialClaimVerifier(search), clock=lambda: NOW
    ).enrich(request, scoped)
    assert result == scoped
    assert search.calls == []


@pytest.mark.asyncio
async def test_official_lookup_requires_separate_consent_and_rejects_non_official_sources() -> None:
    finding = OfficialSourceFindingV4(
        source_url="https://untrusted.example/promotion",
        finding="contradicted",
        title="Untrusted result",
        observed_at=NOW,
    )
    search = _Search([finding])
    request = SecurityTriageCreateRequestV4(message="ACME thông báo trúng thưởng")
    scoped = await SecurityInvestigationService().investigate(request, SecurityTriageScopeService().assess(request))
    service = SecurityTrustService(
        _TrustRepository(brands=[_brand()]), verifier=OfficialClaimVerifier(search), clock=lambda: NOW
    )
    without_consent = await service.enrich(request, scoped)
    assert search.calls == []
    assert not any(item.type is SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION for item in without_consent.evidence)

    consented = SecurityTriageCreateRequestV4(message=request.message, consent={"official_source_lookup": True})
    enriched = await service.enrich(consented, scoped)
    official = next(item for item in enriched.evidence if item.type is SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION)
    assert official.signal == "insufficient_evidence"
    assert enriched.tool_calls_used == scoped.tool_calls_used + 1


@pytest.mark.asyncio
async def test_whitelist_suppresses_weak_signal_but_not_blacklist() -> None:
    request, scoped = _scope("ACME xem https://acme.example")
    investigated = await SecurityInvestigationService().investigate(request, scoped)
    whitelist = WhitelistRecordV4(
        indicator="acme.example",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="approved registry",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="admin",
        created_at=NOW,
    )
    enriched = await SecurityTrustService(
        _TrustRepository(brands=[_brand()], whitelist=[whitelist]), clock=lambda: NOW
    ).enrich(request, investigated)
    safe = assess_security_risk(enriched)
    assert safe.risk is SecurityRiskV4.SAFE

    blacklist = SecurityEvidenceV4(
        evidence_ref=f"evidence:{'f' * 16}",
        type=SecurityEvidenceTypeV4.BLACKLIST,
        source="approved-blacklist",
        target="acme.example",
        signal="approved_blacklist_hit",
        description="Confirmed compromise.",
        observed_at=NOW,
        confidence=1,
        provenance_ref="decision:1",
    )
    payload = enriched.model_dump()
    payload["evidence"] = [*enriched.evidence, blacklist]
    assert assess_security_risk(type(enriched).model_validate(payload)).risk is SecurityRiskV4.MALICIOUS


@pytest.mark.asyncio
async def test_brand_mismatch_alone_is_low_risk() -> None:
    request, scoped = _scope("ACME xem https://unrelated.example")
    investigated = await SecurityInvestigationService().investigate(request, scoped)
    enriched = await SecurityTrustService(_TrustRepository(brands=[_brand()]), clock=lambda: NOW).enrich(
        request, investigated
    )
    result = assess_security_risk(enriched)
    assert result.risk is SecurityRiskV4.LOW_RISK
    assert result.risk is not SecurityRiskV4.MALICIOUS


@pytest.mark.asyncio
async def test_repository_enforces_effective_interval_and_disable(tmp_path) -> None:
    repository = SQLiteBlacklistRepository(tmp_path / "trust.db")
    active = _brand()
    future = _brand(name="Future", effective_from=NOW + timedelta(days=1))
    await repository.create_brand(active)
    await repository.create_brand(future)
    assert await repository.list_active_brands(NOW) == [active]
    disabled = await repository.disable_brand(str(active.brand_id), "reviewer-2", NOW)
    assert disabled is not None and disabled.lifecycle.value == "disabled"
    assert await repository.list_active_brands(NOW) == []
    active_whitelist = WhitelistRecordV4(
        indicator="acme.example",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="reviewed",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="admin",
        created_at=NOW,
    )
    expired_whitelist = WhitelistRecordV4(
        indicator="expired.example",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="reviewed",
        effective_from=NOW - timedelta(days=2),
        effective_until=NOW - timedelta(days=1),
        reviewer_id="admin",
        created_at=NOW,
    )
    await repository.create_whitelist(active_whitelist)
    await repository.create_whitelist(expired_whitelist)
    assert await repository.list_active_whitelist(NOW) == [active_whitelist]
    disabled_whitelist = await repository.disable_whitelist(str(active_whitelist.whitelist_id), "reviewer-2", NOW)
    assert disabled_whitelist is not None and disabled_whitelist.lifecycle.value == "disabled"
    assert await repository.list_active_whitelist(NOW) == []
    await repository.close()
