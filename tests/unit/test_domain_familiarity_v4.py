from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.security_trust import SecurityTrustService
from src.agents.tools.domain_familiarity import CloudflareRadarDomainFamiliarityProvider
from src.agents.tools.models import ToolErrorCode
from src.models import (
    AssistantContextV4,
    AssistantProcessingModeV4,
    BrandRecordV4,
    DomainFamiliarityClassificationV4,
    DomainFamiliarityDetailsV4,
    OfficialIdentityMatchScopeV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationToolV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityToolErrorV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import AssistantSynthesis, ModelResponse
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.official_identity_registry import normalize_official_identity
from src.services.official_verification_coordinator import _local_source
from src.services.security_response import (
    GroundedSecurityResponseService,
    SynthesisGroundingFailure,
    check_grounded_ai_response,
    policy_grounded_assistant_response,
)
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


class _RecordingSynthesisModel:
    def __init__(self, summary: str) -> None:
        self.summary = summary
        self.payload: dict[str, object] | None = None

    async def synthesize(self, payload: dict[str, object]) -> ModelResponse[AssistantSynthesis]:
        self.payload = payload
        return ModelResponse(
            output=AssistantSynthesis(summary=self.summary),
            provider="fixture",
            model="fixture-synthesis",
        )


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
async def test_verified_passive_domain_stays_safe_when_semantic_or_provider_enrichment_is_unavailable() -> None:
    """Independent ownership evidence, not provider availability, decides this case."""
    request = SecurityTriageCreateRequestV4(message="Check google.com")
    scope = SecurityTriageScopeService().assess(request)
    investigated = await SecurityInvestigationService().investigate(request, scope)
    enriched = await SecurityTrustService(
        _Brands([_google()]), domain_familiarity_enabled=True, clock=lambda: NOW
    ).enrich(request, investigated)
    degraded = enriched.model_copy(
        update={
            "assistant_context": AssistantContextV4(
                processing_mode=AssistantProcessingModeV4.FALLBACK,
                model_version="unavailable",
            ),
            "errors": [
                SecurityToolErrorV4(
                    tool=SecurityInvestigationToolV4.RDAP,
                    target="google.com",
                    code="PROVIDER_TIMEOUT",
                    message="Provider timed out.",
                    retryable=True,
                    provider="fixture",
                )
            ],
            "limitations": [
                "Không thể xác nhận đầy đủ hành động được yêu cầu.",
                "Không lấy được dữ liệu đăng ký domain từ RDAP; thiếu dữ liệu này không chứng minh domain an toàn.",
            ],
        }
    )

    result = assess_security_risk(degraded, familiarity_enforced=True)

    assert result.risk is SecurityRiskV4.SAFE
    assert result.recommended_actions == [SecurityRecommendedActionV4.ALLOW_OPEN]
    summary = policy_grounded_assistant_response(result).summary.casefold()
    assert "tên miền chính thức" in summary
    assert "cẩn thận" not in summary
    assert "xác minh bằng" not in summary
    cautious_composer_output = AssistantSynthesis(
        summary="Tên miền này có rủi ro thấp; bạn vẫn nên xác minh qua kênh chính thức."
    )
    assert (
        check_grounded_ai_response(result, cautious_composer_output).failure
        is SynthesisGroundingFailure.CAUTION_CONTRADICTS_VERIFIED_PASSIVE_TARGET
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", ["google.com", "youtube.com", "amazon.com", "wikipedia.org"])
@pytest.mark.parametrize("provider_failure", [False, True])
async def test_reviewed_passive_domains_have_one_safe_invariant_regardless_of_enrichment_failure(
    domain: str,
    provider_failure: bool,
) -> None:
    """A reviewed ownership fact must not depend on semantic brand matching.

    These domains intentionally arrive as the same structured truth: only the
    reviewed first-party ownership record is authoritative.  This catches the
    former divergence where a coincidental ``official_match`` produced SAFE,
    while the equivalent domain-familiarity record produced LOW_RISK.
    """
    request = SecurityTriageCreateRequestV4(message=f"Kiểm tra https://{domain}")
    scoped = SecurityTriageScopeService().assess(request)
    investigated = await SecurityInvestigationService().investigate(request, scoped)
    ownership = SecurityEvidenceV4(
        evidence_ref=f"evidence:{hashlib.sha256(domain.encode()).hexdigest()[:16]}",
        type=SecurityEvidenceTypeV4.DOMAIN_FAMILIARITY,
        source="reviewed-domain-registry",
        target=domain,
        signal="reviewed_first_party_domain",
        description="Reviewed first-party ownership.",
        observed_at=NOW,
        confidence=1.0,
        provenance_ref="reviewed:domain-registry-v1",
        domain_familiarity=DomainFamiliarityDetailsV4(
            observed_host=domain,
            registrable_domain=domain,
            classification=DomainFamiliarityClassificationV4.REVIEWED_FIRST_PARTY,
        ),
    )
    updates: dict[str, object] = {"evidence": [*investigated.evidence, ownership]}
    if provider_failure:
        updates.update(
            {
                "assistant_context": AssistantContextV4(
                    processing_mode=AssistantProcessingModeV4.FALLBACK,
                    model_version="unavailable",
                ),
                "errors": [
                    SecurityToolErrorV4(
                        tool=SecurityInvestigationToolV4.RDAP,
                        target=domain,
                        code="PROVIDER_TIMEOUT",
                        message="Provider timed out.",
                        retryable=True,
                        provider="fixture",
                    )
                ],
                "limitations": ["RDAP data unavailable."],
            }
        )

    result = assess_security_risk(investigated.model_copy(update=updates), familiarity_enforced=True)

    assert result.risk is SecurityRiskV4.SAFE
    assert result.recommended_actions == [SecurityRecommendedActionV4.ALLOW_OPEN]
    assert GroundedSecurityResponseService._synthesis_payload(result)["authoritative_security_truth"] == {
        "verified_passive_target": True,
        "credible_malicious_evidence": False,
        "no_risky_requested_action": True,
    }
    accepted = check_grounded_ai_response(
        result,
        AssistantSynthesis(summary="Tên miền này đã được xác minh; bạn có thể mở."),
    )
    assert accepted.response is not None
    assert (
        check_grounded_ai_response(
            result,
            AssistantSynthesis(summary="Tên miền này có rủi ro thấp; hãy xác minh qua kênh chính thức."),
        ).failure
        is SynthesisGroundingFailure.CAUTION_CONTRADICTS_VERIFIED_PASSIVE_TARGET
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", ["youtube.com", "facebook.com", "chatgpt.com"])
@pytest.mark.parametrize(
    ("path", "expected_risk"),
    [("", SecurityRiskV4.SAFE), ("/channel/unreviewed", SecurityRiskV4.INSUFFICIENT_EVIDENCE)],
)
async def test_reviewed_platform_origin_is_safe_but_hosted_resources_are_not(
    domain: str,
    path: str,
    expected_risk: SecurityRiskV4,
) -> None:
    """Platform ownership proves the origin, never arbitrary hosted content."""
    request = SecurityTriageCreateRequestV4(message=f"Kiểm tra https://{domain}{path}")
    scoped = SecurityTriageScopeService().assess(request)
    investigated = await SecurityInvestigationService().investigate(request, scoped)
    platform = SecurityEvidenceV4(
        evidence_ref=f"evidence:{hashlib.sha256((domain + path).encode()).hexdigest()[:16]}",
        type=SecurityEvidenceTypeV4.DOMAIN_FAMILIARITY,
        source="reviewed-domain-registry",
        target=domain,
        signal="reviewed_platform_service",
        description="Reviewed platform service.",
        observed_at=NOW,
        confidence=1.0,
        provenance_ref="reviewed:platform-registry-v1",
        domain_familiarity=DomainFamiliarityDetailsV4(
            observed_host=domain,
            registrable_domain=domain,
            classification=DomainFamiliarityClassificationV4.REVIEWED_PLATFORM_SERVICE,
            platform_name="Reviewed platform",
            shared_platform=True,
        ),
    )

    result = assess_security_risk(
        investigated.model_copy(update={"evidence": [*investigated.evidence, platform]}),
        familiarity_enforced=True,
    )

    assert result.risk is expected_risk
    if not path:
        assert result.recommended_actions == [SecurityRecommendedActionV4.ALLOW_OPEN]
        assert GroundedSecurityResponseService._synthesis_payload(result)["important_uncertainties"] == []
        assert (
            check_grounded_ai_response(
                result,
                AssistantSynthesis(summary="Rủi ro thấp; hãy cẩn thận và xác minh qua kênh chính thức."),
            ).failure
            is SynthesisGroundingFailure.CAUTION_CONTRADICTS_VERIFIED_PASSIVE_TARGET
        )
    else:
        assert SecurityRecommendedActionV4.ALLOW_OPEN not in result.recommended_actions


@pytest.mark.asyncio
async def test_verified_platform_origin_reaches_gpt_and_rejects_cautionary_composition() -> None:
    request = SecurityTriageCreateRequestV4(message="youtube.com")
    investigated = await SecurityInvestigationService().investigate(
        request, SecurityTriageScopeService().assess(request)
    )
    platform = SecurityEvidenceV4(
        evidence_ref="evidence:0123456789abcdef",
        type=SecurityEvidenceTypeV4.DOMAIN_FAMILIARITY,
        source="reviewed-domain-registry",
        target="youtube.com",
        signal="reviewed_platform_service",
        description="Reviewed platform service.",
        observed_at=NOW,
        confidence=1.0,
        provenance_ref="reviewed:platform-registry-v1",
        domain_familiarity=DomainFamiliarityDetailsV4(
            observed_host="youtube.com",
            registrable_domain="youtube.com",
            classification=DomainFamiliarityClassificationV4.REVIEWED_PLATFORM_SERVICE,
            platform_name="YouTube",
            shared_platform=True,
        ),
    )
    result = assess_security_risk(
        investigated.model_copy(update={"evidence": [*investigated.evidence, platform]}),
        familiarity_enforced=True,
    )
    assert result.risk is SecurityRiskV4.SAFE

    valid_model = _RecordingSynthesisModel("Tên miền đã được xác minh; bạn có thể mở.")
    composed = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=valid_model,
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(result)
    assert composed.assistant_response is not None
    assert composed.assistant_response.generation_mode.value == "ai"
    assert valid_model.payload and valid_model.payload["authoritative_security_truth"] == {
        "verified_passive_target": True,
        "credible_malicious_evidence": False,
        "no_risky_requested_action": True,
    }
    assert valid_model.payload["important_uncertainties"] == []

    cautious_model = _RecordingSynthesisModel("Rủi ro thấp; hãy cẩn thận và xác minh qua kênh chính thức.")
    rejected = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=cautious_model,
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(result)
    assert rejected.assistant_response is not None
    assert rejected.assistant_response.generation_mode.value == "policy_grounded"
    assert "rủi ro thấp" not in rejected.assistant_response.summary.casefold()
    assert "cẩn thận" not in rejected.assistant_response.summary.casefold()


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
