from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.security_trust import (
    BrandMatcher,
    SecurityTrustService,
)
from src.models import (
    BrandRecordV4,
    EntityUrlClaimV4,
    EntityUrlRelationshipV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityRiskV4,
    SecurityTriageCreateRequestV4,
    WhitelistRecordV4,
    WhitelistScopeV4,
)
from src.repositories import SQLiteBlacklistRepository
from src.services.platform_wave2 import VersionedSourceRegistry, default_source_policies
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
async def test_unreviewed_claimed_identity_is_visible_and_never_safe() -> None:
    message = "Bệnh viện Đại học Y yêu cầu đăng ký tại https://bachmai.gov.vn/"
    request, scoped = _scope(message)
    context = scoped.security_context.model_copy(update={"claimed_entity": "Bệnh viện Đại học Y"})
    scoped = scoped.model_copy(update={"security_context": context})
    investigated = await SecurityInvestigationService().investigate(request, scoped)

    enriched = await SecurityTrustService(_TrustRepository(), clock=lambda: NOW).enrich(request, investigated)
    result = assess_security_risk(enriched)

    identity = next(item for item in result.evidence if item.signal == "claimed_identity_unverified")
    assert identity.target == "bachmai.gov.vn"
    assert "Bệnh viện Đại học Y" in identity.description
    assert any("exact-resource association" in item for item in result.limitations)
    assert result.risk is SecurityRiskV4.LOW_RISK


@pytest.mark.asyncio
async def test_reviewed_owner_mismatch_overrides_target_whitelist() -> None:
    message = "Bệnh viện Đại học Y thông báo web của bệnh viện là https://bachmai.gov.vn/"
    request, scoped = _scope(message)
    context = scoped.security_context.model_copy(
        update={
            "claimed_entity": "Bệnh viện Đại học Y",
            "entity_url_claims": [
                EntityUrlClaimV4(
                    entity_name="Bệnh viện Đại học Y",
                    url_index=0,
                    relationship=EntityUrlRelationshipV4.CLAIMED_OFFICIAL_SITE,
                    confidence=0.95,
                )
            ],
        }
    )
    scoped = scoped.model_copy(update={"security_context": context})
    investigated = await SecurityInvestigationService().investigate(request, scoped)
    university = _brand(
        name="Bệnh viện Đại học Y",
        aliases=["Đại học Y"],
        official_domains=["daihocy.example"],
    )
    whitelist = WhitelistRecordV4(
        indicator="bachmai.gov.vn",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="approved registry",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="admin",
        created_at=NOW,
    )

    enriched = await SecurityTrustService(
        _TrustRepository(brands=[university], whitelist=[whitelist]),
        source_registry=VersionedSourceRegistry(default_source_policies()),
        clock=lambda: NOW,
    ).enrich(request, investigated)
    result = assess_security_risk(enriched)

    mismatch = next(item for item in result.evidence if item.signal == "entity_target_mismatch")
    assert "Bach Mai Hospital" in mismatch.description
    assert result.risk is SecurityRiskV4.SUSPICIOUS
    assert result.score == 40
    assert result.policy_version == "security-risk-v4"


@pytest.mark.asyncio
async def test_local_entity_linker_detects_reviewed_owner_mismatch_without_ai_offsets() -> None:
    message = (
        "Mọi người nên đăng ký trên app trước khi đến bệnh viện. Hôm nay tôi đi "
        "Bệnh viện Đại học Y vào phòng khám. Web của bệnh viện đây nhé: "
        "https://bachmai.gov.vn/"
    )
    request, scoped = _scope(message)
    assert scoped.security_context.claimed_entity == "Bệnh viện Đại học Y"
    assert scoped.security_context.entity_url_claims[0].url_index == 0
    investigated = await SecurityInvestigationService().investigate(request, scoped)
    university = _brand(
        name="Bệnh viện Đại học Y",
        aliases=["Đại học Y"],
        official_domains=["daihocy.example"],
    )
    whitelist = WhitelistRecordV4(
        indicator="bachmai.gov.vn",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="approved registry",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="admin",
        created_at=NOW,
    )

    enriched = await SecurityTrustService(
        _TrustRepository(brands=[university], whitelist=[whitelist]),
        source_registry=VersionedSourceRegistry(default_source_policies()),
        clock=lambda: NOW,
    ).enrich(request, investigated)
    result = assess_security_risk(enriched)

    assert any(item.signal == "entity_target_mismatch" for item in result.evidence)
    assert result.risk is SecurityRiskV4.SUSPICIOUS
    assert result.score == 40


@pytest.mark.asyncio
async def test_unresolved_entity_url_relation_blocks_safe_even_for_official_target() -> None:
    message = "Bệnh viện Đại học Y xem thông tin tại https://bachmai.gov.vn/"
    request, scoped = _scope(message)
    assert scoped.security_context.claimed_entity == "Bệnh viện Đại học Y"
    assert scoped.security_context.entity_url_claims == []
    investigated = await SecurityInvestigationService().investigate(request, scoped)
    brand = _brand(
        name="Bệnh viện Đại học Y",
        aliases=["Đại học Y"],
        official_domains=["bachmai.gov.vn"],
    )
    whitelist = WhitelistRecordV4(
        indicator="bachmai.gov.vn",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="approved registry",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="admin",
        created_at=NOW,
    )

    enriched = await SecurityTrustService(
        _TrustRepository(brands=[brand], whitelist=[whitelist]),
        clock=lambda: NOW,
    ).enrich(request, investigated)
    result = assess_security_risk(enriched)

    assert any(item.signal == "entity_url_relation_unresolved" for item in result.evidence)
    assert result.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE
    assert result.confidence <= 0.65


@pytest.mark.asyncio
async def test_reference_only_url_does_not_create_an_identity_mismatch() -> None:
    message = "Đại học Y chuyển bệnh nhân sang Bạch Mai, xem https://bachmai.gov.vn/"
    request, scoped = _scope(message)
    context = scoped.security_context.model_copy(
        update={
            "claimed_entity": "Đại học Y",
            "entity_url_claims": [
                EntityUrlClaimV4(
                    entity_name="Đại học Y",
                    url_index=0,
                    relationship=EntityUrlRelationshipV4.REFERENCE_ONLY,
                    confidence=0.95,
                )
            ],
        }
    )
    scoped = scoped.model_copy(update={"security_context": context})
    investigated = await SecurityInvestigationService().investigate(request, scoped)
    whitelist = WhitelistRecordV4(
        indicator="bachmai.gov.vn",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="approved registry",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="admin",
        created_at=NOW,
    )
    enriched = await SecurityTrustService(
        _TrustRepository(
            brands=[_brand(name="Bệnh viện Bạch Mai", official_domains=["bachmai.gov.vn"])], whitelist=[whitelist]
        ),
        clock=lambda: NOW,
    ).enrich(request, investigated)
    result = assess_security_risk(enriched)

    assert all(item.signal != "entity_target_mismatch" for item in result.evidence)
    assert result.risk is SecurityRiskV4.SAFE


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
