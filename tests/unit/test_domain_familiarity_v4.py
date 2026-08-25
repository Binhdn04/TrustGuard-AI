from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.security_trust import SecurityTrustService
from src.agents.tools.domain_familiarity import CloudflareRadarDomainFamiliarityProvider
from src.agents.tools.models import ToolErrorCode
from src.models import (
    BrandRecordV4,
    OfficialIdentityMatchScopeV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityTriageCreateRequestV4,
)
from src.services.official_identity_registry import normalize_official_identity
from src.services.official_verification_coordinator import _local_source
from src.services.security_triage import SecurityTriageScopeService

NOW = datetime(2026, 8, 24, tzinfo=UTC)


@pytest.mark.asyncio
async def test_radar_normalizes_exact_rank_and_caches_result() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.url.params["rankingType"] == "POPULAR"
        return httpx.Response(
            200,
            json={
                "success": True,
                "result": {"details_0": {"rank": 42}, "meta": {"dateRange": [{"endTime": "2026-08-23T00:00:00Z"}]}},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = CloudflareRadarDomainFamiliarityProvider("token", client=client, clock=lambda: NOW)
    first = await provider.lookup("WWW.Example.COM")
    second = await provider.lookup("example.com")
    assert first.result and first.result.popularity_rank == 42
    assert first.result.dataset_window_end == datetime(2026, 8, 23, tzinfo=UTC)
    assert second.cache.status.value == "hit"
    assert second.usage.network_calls == 0
    assert calls == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_radar_no_hit_is_inconclusive_and_rate_limit_is_not_retried() -> None:
    responses = [httpx.Response(200, json={"success": True, "result": {}}), httpx.Response(429)]
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        del request
        response = responses[calls]
        calls += 1
        return response

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = CloudflareRadarDomainFamiliarityProvider("token", client=client, clock=lambda: NOW)
    no_hit = await provider.lookup("unknown.example")
    limited = await provider.lookup("limited.example")
    assert no_hit.status.value == "inconclusive" and no_hit.result and not no_hit.result.matched
    assert limited.error and limited.error.code is ToolErrorCode.RATE_LIMITED and not limited.error.retryable
    assert calls == 2
    await client.aclose()


def test_radar_uses_bucket_without_mistaking_location_rank_for_global_rank() -> None:
    result = CloudflareRadarDomainFamiliarityProvider.normalize_response(
        "example.com",
        {
            "success": True,
            "result": {
                "details_0": {"bucket": "top_10000", "top_locations": [{"rank": 1}]},
                "meta": {"dateRange": []},
            },
        },
        observed_at=NOW,
    )
    assert result.popularity_rank is None
    assert result.popularity_bucket == 10_000


@pytest.mark.asyncio
async def test_radar_timeout_is_normalized_and_three_failures_open_circuit() -> None:
    timeout_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=request)))
    )
    timeout_provider = CloudflareRadarDomainFamiliarityProvider("token", client=timeout_client, clock=lambda: NOW)
    timed_out = await timeout_provider.lookup("timeout.example")
    assert timed_out.error and timed_out.error.code is ToolErrorCode.PROVIDER_TIMEOUT
    await timeout_client.aclose()

    calls = 0

    def fail(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, request=request)

    failure_client = httpx.AsyncClient(transport=httpx.MockTransport(fail))
    provider = CloudflareRadarDomainFamiliarityProvider("token", client=failure_client, clock=lambda: NOW)
    for domain in ("one.example", "two.example", "three.example", "four.example"):
        failed = await provider.lookup(domain)
        assert failed.error and failed.error.code is ToolErrorCode.PROVIDER_ERROR
    assert calls == 3
    assert failed.usage.network_calls == 0
    await failure_client.aclose()


class _Brands:
    def __init__(self, brands):
        self.brands = brands

    async def list_active_brands(self, at):
        del at
        return self.brands

    async def list_active_whitelist(self, at):
        del at
        return []


def _google() -> BrandRecordV4:
    platform = OfficialIdentityV4(
        identity_type=OfficialIdentityTypeV4.DOMAIN,
        canonical_value="forms.google.com",
        display_value="forms.google.com",
        entity_name="Google Forms",
        relationship="platform_service",
        provenance="reviewed Google documentation",
        policy_version="reviewed-platform-familiarity-v1",
        effective_from=NOW - timedelta(days=1),
        reviewed=True,
    )
    return BrandRecordV4(
        name="Google",
        official_domains=["google.com"],
        official_identities=[platform],
        provenance="reviewed Google documentation",
        policy_version="reviewed-platform-familiarity-v1",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="security-admin",
        created_at=NOW,
    )


def test_platform_service_requires_domain_and_is_normalized_to_host_scope() -> None:
    with pytest.raises(ValueError, match="identity_type=domain"):
        OfficialIdentityV4(
            identity_type=OfficialIdentityTypeV4.WEBSITE,
            canonical_value="https://forms.example/",
            display_value="forms.example",
            entity_name="Example Forms",
            relationship="platform_service",
        )
    normalized = normalize_official_identity(
        OfficialIdentityV4(
            identity_type=OfficialIdentityTypeV4.DOMAIN,
            canonical_value="Forms.Example",
            display_value="forms.example",
            entity_name="Example Forms",
            relationship="platform_service",
        ),
        brand_name="Example",
        brand_provenance="authoritative registry",
        brand_policy_version="reviewed-platform-familiarity-v1",
        brand_effective_from=NOW,
    )
    assert normalized.canonical_value == "forms.example"
    assert normalized.match_scope is OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS
    assert normalized.reviewed
    assert _local_source(normalized) is None


class _NeverCalledFamiliarity:
    provider = "never-called"

    def __init__(self) -> None:
        self.calls = 0

    async def lookup(self, domain: str):
        del domain
        self.calls += 1
        raise AssertionError("familiarity provider must not be called")


@pytest.mark.asyncio
async def test_consent_false_and_out_of_scope_make_zero_familiarity_calls() -> None:
    provider = _NeverCalledFamiliarity()
    service = SecurityInvestigationService(
        domain_familiarity=provider,
        domain_familiarity_enabled=True,
    )
    request = SecurityTriageCreateRequestV4(message="Kiểm tra https://example.com")
    result = await service.investigate(request, SecurityTriageScopeService().assess(request))
    step = next(item for item in result.investigation_plan if item.tool.value == "domain_familiarity")
    assert step.status.value == "skipped" and step.status_reason == "consent_required"

    out_of_scope = SecurityTriageCreateRequestV4(message="Ai vô địch giải bóng đá hôm qua?")
    await service.investigate(out_of_scope, SecurityTriageScopeService().assess(out_of_scope))
    assert provider.calls == 0


@pytest.mark.asyncio
async def _specific_platform_identity_wins_parent_and_resource_stays_unverified() -> None:
    request = SecurityTriageCreateRequestV4(message="Kiểm tra https://forms.google.com/d/e/example/viewform")
    scope = SecurityTriageScopeService().assess(request)
    investigated = await SecurityInvestigationService().investigate(request, scope)
    enriched = await SecurityTrustService(
        _Brands([_google()]), domain_familiarity_enabled=True, clock=lambda: NOW
    ).enrich(request, investigated)
    familiarity = next(item for item in enriched.evidence if item.type is SecurityEvidenceTypeV4.DOMAIN_FAMILIARITY)
    assert familiarity.signal == "reviewed_platform_service"
    assert familiarity.domain_familiarity and familiarity.domain_familiarity.shared_platform
    result = assess_security_risk(enriched, familiarity_enforced=True)
    assert result.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE
    assert result.policy_version == "security-risk-v5"
    assert SecurityRecommendedActionV4.PROCEED_WITH_CAUTION in result.recommended_actions


@pytest.mark.asyncio
async def test_neutral_inspection_of_reviewed_first_party_is_safe() -> None:
    request = SecurityTriageCreateRequestV4(message="Mở https://google.com", consent={"external_url_lookup": False})
    scope = SecurityTriageScopeService().assess(request)
    investigated = await SecurityInvestigationService().investigate(request, scope)
    enriched = await SecurityTrustService(
        _Brands([_google()]), domain_familiarity_enabled=True, clock=lambda: NOW
    ).enrich(request, investigated)
    result = assess_security_risk(enriched, familiarity_enforced=True)
    assert result.risk is SecurityRiskV4.SAFE
    assert result.score == 0
    assert result.recommended_actions == [SecurityRecommendedActionV4.ALLOW_OPEN]


@pytest.mark.asyncio
async def test_platform_familiarity_never_overrides_sensitive_context_or_blacklist() -> None:
    request = SecurityTriageCreateRequestV4(
        message="Google Forms yêu cầu đăng nhập và gửi mật khẩu tại https://forms.google.com/d/example"
    )
    investigated = await SecurityInvestigationService().investigate(
        request,
        SecurityTriageScopeService().assess(request),
    )
    enriched = await SecurityTrustService(
        _Brands([_google()]), domain_familiarity_enabled=True, clock=lambda: NOW
    ).enrich(request, investigated)
    sensitive = assess_security_risk(enriched, familiarity_enforced=True)
    assert sensitive.risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE
    assert SecurityRecommendedActionV4.ALLOW_OPEN not in sensitive.recommended_actions

    blacklist = SecurityEvidenceV4(
        evidence_ref="evidence:ffffffffffffffff",
        type=SecurityEvidenceTypeV4.BLACKLIST,
        source="approved-blacklist",
        target="forms.google.com",
        signal="approved_blacklist_hit",
        description="Confirmed malicious target.",
        observed_at=NOW,
        confidence=1,
        provenance_ref="decision:reviewed",
    )
    payload = enriched.model_dump()
    payload["evidence"] = [*enriched.evidence, blacklist]
    malicious = assess_security_risk(type(enriched).model_validate(payload), familiarity_enforced=True)
    assert malicious.risk is SecurityRiskV4.MALICIOUS
