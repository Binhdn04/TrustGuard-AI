from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from src.agents.security_risk import assess_security_risk
from src.models import (
    AnalysisStatus,
    AssistantContextV4,
    AssistantProcessingModeV4,
    BrandRecordV4,
    ExposureStateV4,
    IdentityAssociationAssuranceV4,
    IdentityCandidateV4,
    IdentityRelationshipV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    RequestedActionV4,
    ResourceMatchStatusV4,
    ScopeDecisionV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    VerificationStatusV4,
)
from src.security_ai.contracts import AssistantSynthesis, ModelResponse
from src.security_ai.runtime import SecurityAssistantRuntime, TurnExecutionContext
from src.services.official_verification_coordinator import (
    ComparisonDimension,
    ComparisonRelation,
    OfficialLinkVerificationCoordinator,
    VerificationComparisonOutput,
    _resource_endorsement_links,
    apply_official_verification_outcome,
    validate_comparison_output,
)
from src.services.official_verification_transport import (
    ExtractedWebDocument,
    FetchedHtml,
    HtmlFetchEnvelope,
    VerificationTransportLimitation,
    VerificationTransportStatus,
    VerificationTransportUsage,
    WebExtractEnvelope,
    WebSearchEnvelope,
    WebSearchHit,
)
from src.services.platform_wave2 import (
    MemoryWave2Repository,
    SourceRegistryEntry,
    SourceTier,
    VersionedSourceRegistry,
    default_source_policies,
)
from src.services.security_pipeline import SecurityTriagePipeline
from src.services.security_response import (
    GroundedSecurityResponseService,
    SynthesisGroundingFailure,
    check_grounded_ai_response,
    policy_grounded_assistant_response,
)
from src.services.security_triage import SecurityTriageScopeService

NOW = datetime(2026, 8, 20, 12, tzinfo=UTC)
USER_FORM = "https://docs.google.com/forms/d/e/FORM-USER/viewform"
OFFICIAL_JOBS = "https://official.example/jobs"


class _BrandRepository:
    def __init__(self, brands: list[BrandRecordV4]) -> None:
        self.brands = brands
        self.calls = 0
        self.candidates: list[IdentityCandidateV4] = []

    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]:
        assert at.tzinfo is not None
        self.calls += 1
        return self.brands

    async def list_identity_candidates(self) -> list[IdentityCandidateV4]:
        return list(self.candidates)

    async def save_identity_candidate(self, record: IdentityCandidateV4) -> IdentityCandidateV4:
        self.candidates.append(record)
        return record


class _ColdCacheBrandRepository:
    """Production-compatible read path before an observing store is available."""

    def __init__(self, brands: list[BrandRecordV4] | None = None) -> None:
        self.brands = brands or []

    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]:
        assert at.tzinfo is not None
        return list(self.brands)


def _brand() -> BrandRecordV4:
    return BrandRecordV4(
        name="Vingroup",
        aliases=["Vin Group"],
        official_domains=["official.example"],
        provenance="reviewed CP7 fixture",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="network-security-reviewer",
        created_at=NOW - timedelta(days=1),
    )


def _request_scope(
    *,
    user_url: str = USER_FORM,
    official_consent: bool = True,
    external_consent: bool = False,
) -> tuple[SecurityTriageCreateRequestV4, SecurityScopeResponseV4]:
    request = SecurityTriageCreateRequestV4(
        message=f"Vingroup thông báo tuyển dụng, hãy đăng ký tại {user_url}",
        consent={
            "official_source_lookup": official_consent,
            "external_url_lookup": external_consent,
        },
    )
    return request, SecurityTriageScopeService().assess(request)


def _usage(operation: str, *, network_units: int = 1) -> VerificationTransportUsage:
    return VerificationTransportUsage(
        provider="cp7-fake",
        operation=operation,
        adapter_attempts=1,
        network_units=network_units,
        latency_ms=1,
    )


class _SearchProvider:
    def __init__(
        self,
        hits: list[WebSearchHit] | None = None,
        *,
        hits_by_call: list[list[WebSearchHit]] | None = None,
        limitation: VerificationTransportLimitation | None = None,
    ) -> None:
        self.hits = hits or []
        self.hits_by_call = hits_by_call
        self.limitation = limitation
        self.calls: list[tuple[str, int]] = []

    async def search_one(self, query: str, *, execution_context, max_results: int = 5, include_domains=()):
        del include_domains
        self.calls.append((query, max_results))
        execution_context.reserve_network_units()
        if self.limitation is not None:
            return WebSearchEnvelope(
                status=VerificationTransportStatus.LIMITED,
                limitation=self.limitation,
                usage=_usage("search_one"),
            )
        call_index = len(self.calls) - 1
        selected = (
            self.hits_by_call[min(call_index, len(self.hits_by_call) - 1)][:max_results]
            if self.hits_by_call
            else self.hits[:max_results]
        )
        return WebSearchEnvelope(
            status=(VerificationTransportStatus.SUCCESS if selected else VerificationTransportStatus.NO_HIT),
            results=selected,
            usage=_usage("search_one"),
        )


class _HtmlFetcher:
    def __init__(
        self,
        pages: dict[str, str] | None = None,
        *,
        redirects: dict[str, list[str]] | None = None,
        failure: VerificationTransportLimitation | None = None,
    ) -> None:
        self.pages = pages or {}
        self.redirects = redirects or {}
        self.failure = failure
        self.calls: list[str] = []
        self.active = 0
        self.max_active = 0

    async def fetch(self, url: str, *, execution_context):
        self.calls.append(url)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        execution_context.reserve_network_units()
        await asyncio.sleep(0)
        self.active -= 1
        if self.failure is not None:
            return HtmlFetchEnvelope(
                status=VerificationTransportStatus.LIMITED,
                limitation=self.failure,
                usage=_usage("fetch"),
            )
        chain = self.redirects.get(url, [url])
        final_url = chain[-1]
        body = self.pages.get(url, self.pages.get(final_url, "<html><body>Official home</body></html>"))
        return HtmlFetchEnvelope(
            status=VerificationTransportStatus.SUCCESS,
            document=FetchedHtml(
                final_url=final_url,
                redirect_chain=chain,
                media_type="text/html",
                body=body.encode(),
            ),
            usage=_usage("fetch"),
        )


class _ExtractProvider:
    def __init__(self, content: str) -> None:
        self.content = content
        self.calls: list[list[str]] = []

    async def extract(self, urls, *, query: str, execution_context):
        del query
        selected = list(urls)
        self.calls.append(selected)
        execution_context.reserve_network_units()
        return WebExtractEnvelope(
            status=VerificationTransportStatus.SUCCESS,
            documents=[ExtractedWebDocument(url=url, content=self.content) for url in selected],
            usage=_usage("extract"),
        )


def _hit(url: str = OFFICIAL_JOBS, score: float = 0.95) -> WebSearchHit:
    return WebSearchHit(
        title="Official recruitment",
        url=url,
        snippet="Vingroup official recruitment announcement",
        score=score,
    )


def _positive_page(link: str = USER_FORM) -> str:
    return (
        "<html><body><article>Vingroup thông báo tuyển dụng. "
        f"Ứng viên hãy đăng ký và apply tại <a href='{link}'>Application form</a>."
        "</article></body></html>"
    )


@pytest.mark.asyncio
async def test_discovered_official_domain_keeps_sender_and_login_action_unverified_and_cached() -> None:
    target = "https://chinhphu.vn/dang-nhap"
    corroboration = "https://authority.example/government-directory"
    message = f"Chính phủ gửi liên kết {target} và yêu cầu đăng nhập."
    request = SecurityTriageCreateRequestV4(
        message=message,
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    repository = _BrandRepository([])
    search = _SearchProvider([_hit(target), _hit(corroboration)])
    fetcher = _HtmlFetcher(
        {
            target: "<html><body>Cổng thông tin điện tử Chính phủ Việt Nam.</body></html>",
    corroboration: (
        "<html><body>Danh bạ Chính phủ Việt Nam: trang chính thức "
        f"<a href='{target}'>Cổng thông tin</a></body></html>"
    ),
        }
    )
    coordinator = _coordinator(
        repository=repository,
        search=search,
        fetcher=fetcher,
        source_registry=VersionedSourceRegistry([_identity_attestor(host="authority.example")]),
    )

    first = await coordinator.coordinate(request, scope, execution_context=TurnExecutionContext())
    assert first.report is not None
    assert first.report.domain_ownership_verification.status is VerificationStatusV4.VERIFIED
    assert first.report.sender_verification.status is VerificationStatusV4.UNVERIFIED
    assert first.report.action_endorsement_verification.status is VerificationStatusV4.UNVERIFIED
    assert first.report.overall_status is VerificationStatusV4.PARTIALLY_VERIFIED

    staged = apply_official_verification_outcome(scope, first)
    completed = assess_security_risk(staged, official_verification_enforced=True)
    response = policy_grounded_assistant_response(completed)
    assert completed.risk.value == "INSUFFICIENT_EVIDENCE"
    assert completed.policy_version == "security-risk-v7"
    assert {
        item.signal for item in completed.evidence if item.type is SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION
    } == {
        "official_domain_verified",
        "sender_identity_unverified",
        "action_endorsement_unverified",
    }
    assert "chinhphu.vn" in response.summary
    assert "Danh tính người gửi chưa được xác minh riêng." not in response.summary
    assert "mật khẩu hoặc OTP" in response.summary

    search.calls.clear()
    second = await coordinator.coordinate(request, scope, execution_context=TurnExecutionContext())
    assert second.identity_cache_hits > 0
    assert search.calls == []


@pytest.mark.asyncio
async def test_exact_authoritative_source_policy_verifies_unlisted_domain_without_endorsing_login_or_claim() -> None:
    """An exact reviewed ownership record is distinct from campaign endorsement."""
    organization = "Northstar Utilities"
    target = "https://northstar.example/contact"
    request = SecurityTriageCreateRequestV4(
        message=f"{organization} hoàn tiền cho khách hàng; hãy đăng nhập tại {target}",
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    assert scope.security_context is not None
    scope = scope.model_copy(
        update={"security_context": scope.security_context.model_copy(update={"claimed_entity": organization})}
    )
    authoritative_domain = SourceRegistryEntry(
        publisher=organization,
        normalized_pattern="northstar.example",
        tier=SourceTier.A,
        source_type="official_enterprise",
        allowed_operations={"read"},
        policy_version="authoritative-domain-fixture-v1",
        effective_from=NOW - timedelta(days=1),
        default_freshness_seconds=3600,
        reviewer_id="reviewer",
        reviewed_at=NOW - timedelta(hours=1),
    )
    outcome = await _coordinator(
        brands=[],
        source_registry=VersionedSourceRegistry([authoritative_domain]),
        fetcher=_HtmlFetcher({target: f"<html><body>{organization}</body></html>"}),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    report = outcome.report
    association = next(item for item in report.identity_associations if item.canonical_url == target)
    assert association.assurance is IdentityAssociationAssuranceV4.VERIFIED
    assert association.relationship is IdentityRelationshipV4.OFFICIAL_CONTROLLED
    assert report.domain_ownership_verification.status is VerificationStatusV4.VERIFIED
    assert report.claim_verification.status is not VerificationStatusV4.VERIFIED
    assert report.action_endorsement_verification.status is VerificationStatusV4.UNVERIFIED
    assert report.resource_verification.status is VerificationStatusV4.UNVERIFIED

    stale_brand_gap = SecurityEvidenceV4(
        evidence_ref="evidence:1234567890abcdef",
        type=SecurityEvidenceTypeV4.BRAND_MATCH,
        source="brand-registry",
        target="northstar.example",
        signal="claimed_identity_unverified",
        description="Registry has no reviewed identity for this entity.",
        observed_at=NOW,
    )
    reconciled = apply_official_verification_outcome(
        scope.model_copy(
            update={
                "evidence": [stale_brand_gap],
                "limitations": [
                    "Chưa có reviewed identity hoặc exact-resource association để xác nhận quan hệ giữa URL và tổ chức."
                ],
            }
        ),
        outcome,
    )
    assert all("Chưa có reviewed identity hoặc exact-resource" not in item for item in reconciled.limitations)
    assert any(
        item.signal == "official_domain_verified" for item in reconciled.evidence
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "consent",
    [
        {"official_source_lookup": False, "external_url_lookup": True},
        {"official_source_lookup": True, "external_url_lookup": False},
    ],
)
async def test_domain_discovery_requires_both_consents_without_provider_calls(consent) -> None:
    target = "https://chinhphu.vn/dang-nhap"
    request = SecurityTriageCreateRequestV4(
        message=f"Chính phủ yêu cầu đăng nhập tại {target}",
        consent=consent,
    )
    scope = SecurityTriageScopeService().assess(request)
    search = _SearchProvider([_hit(target)])
    fetcher = _HtmlFetcher({target: "<html><body>Chính phủ Việt Nam</body></html>"})

    outcome = await _coordinator(brands=[], search=search, fetcher=fetcher).coordinate(
        request, scope, execution_context=TurnExecutionContext()
    )

    assert outcome.report is not None
    assert outcome.report.domain_ownership_verification.status is VerificationStatusV4.UNVERIFIED
    assert search.calls == []
    assert fetcher.calls == []


def _coordinator(
    *,
    brands: list[BrandRecordV4] | None = None,
    repository: object | None = None,
    search=None,
    fetcher=None,
    extract=None,
    source_registry=None,
) -> OfficialLinkVerificationCoordinator:
    return OfficialLinkVerificationCoordinator(
        repository or _BrandRepository(brands if brands is not None else [_brand()]),
        search=search,
        fetcher=fetcher,
        extract=extract,
        source_registry=source_registry,
        clock=lambda: NOW,
    )


@pytest.mark.asyncio
async def test_verified_report_has_reference_closure_and_stops_early() -> None:
    request, scope = _request_scope()
    search = _SearchProvider([_hit()])
    fetcher = _HtmlFetcher({OFFICIAL_JOBS: _positive_page()})
    outcome = await _coordinator(search=search, fetcher=fetcher).coordinate(
        request,
        scope,
        execution_context=TurnExecutionContext(),
    )

    report = outcome.report
    assert report is not None
    assert report.publisher_verification.status is VerificationStatusV4.VERIFIED
    assert report.claim_verification.status is VerificationStatusV4.VERIFIED
    assert report.resource_verification.status is VerificationStatusV4.VERIFIED
    assert report.resource_verification.match is not None
    assert report.resource_verification.match.status is ResourceMatchStatusV4.EXACT_RESOURCE
    assert report.overall_status is VerificationStatusV4.VERIFIED
    assert outcome.search_attempts == 1
    assert outcome.early_stop_reason == "publisher_claim_exact_resource"
    assert outcome.official_fetches <= 3
    assert fetcher.max_active <= 2
    available = {item.source_ref for item in report.source_refs} | {item.link_ref for item in report.link_refs}
    cited = set(report.publisher_verification.evidence_refs)
    cited.update(report.claim_verification.evidence_refs)
    cited.update(report.resource_verification.evidence_refs)
    assert cited <= available
    assert all(item.source_ref in {source.source_ref for source in report.source_refs} for item in report.link_refs)


@pytest.mark.asyncio
async def test_four_statuses_and_non_applicable_components_follow_fusion_policy() -> None:
    request, scope = _request_scope()
    partial = await _coordinator(
        search=_SearchProvider(),
        fetcher=_HtmlFetcher(),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())
    conflicting = await _coordinator(
        search=_SearchProvider([_hit()]),
        fetcher=_HtmlFetcher(
            {OFFICIAL_JOBS: _positive_page("https://docs.google.com/forms/d/e/FORM-OFFICIAL/viewform")}
        ),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())
    unverified = await _coordinator(brands=[]).coordinate(
        request,
        scope,
        execution_context=TurnExecutionContext(),
    )

    org_only_request = SecurityTriageCreateRequestV4(message="Vingroup có phải tổ chức chính thức không?")
    org_only_scope = SecurityScopeResponseV4(
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        terminal=False,
        next_step="INVESTIGATION",
        scope_reasons=["security_verification_request"],
        security_context={
            "claimed_entity": "Vingroup",
            "scenario": "unknown",
            "urgency": False,
            "credential_request": False,
            "otp_request": False,
            "payment_request": False,
            "personal_information_request": False,
            "potential_threat": "UNDETERMINED_SECURITY_THREAT",
        },
    )
    non_applicable = await _coordinator().coordinate(
        org_only_request,
        org_only_scope,
        execution_context=TurnExecutionContext(),
    )

    assert partial.report is not None
    assert partial.report.overall_status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert partial.report.claim_verification.status is VerificationStatusV4.UNVERIFIED
    assert conflicting.report is not None
    assert conflicting.report.overall_status is VerificationStatusV4.CONFLICTING
    assert conflicting.report.resource_verification.status is VerificationStatusV4.CONFLICTING
    assert unverified.report is not None
    assert unverified.report.overall_status is VerificationStatusV4.UNVERIFIED
    assert non_applicable.report is not None
    assert non_applicable.report.overall_status is VerificationStatusV4.VERIFIED
    assert non_applicable.report.claim_verification.applicable is False
    assert non_applicable.report.resource_verification.applicable is False


@pytest.mark.asyncio
async def test_strong_official_contradiction_stops_search_and_is_conflicting() -> None:
    request, scope = _request_scope()
    search = _SearchProvider([_hit()])
    fetcher = _HtmlFetcher(
        {
            OFFICIAL_JOBS: (
                "<html><body>Vingroup cảnh báo giả mạo: chúng tôi không tuyển dụng và không tổ chức "
                "chương trình này.</body></html>"
            )
        }
    )
    outcome = await _coordinator(search=search, fetcher=fetcher).coordinate(
        request,
        scope,
        execution_context=TurnExecutionContext(),
    )

    assert outcome.report is not None
    assert outcome.report.claim_verification.status is VerificationStatusV4.CONFLICTING
    assert outcome.report.overall_status is VerificationStatusV4.CONFLICTING
    assert outcome.search_attempts == 1
    assert outcome.early_stop_reason == "strong_official_contradiction"


@pytest.mark.asyncio
async def test_claim_time_and_audience_qualifiers_must_match_when_user_supplies_them() -> None:
    request = SecurityTriageCreateRequestV4(
        message=f"Vingroup thông báo tuyển dụng sinh viên năm 2026, hãy đăng ký tại {USER_FORM}",
        consent={"official_source_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    missing = await _coordinator(
        search=_SearchProvider([_hit()]),
        fetcher=_HtmlFetcher({OFFICIAL_JOBS: _positive_page()}),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())
    matching_page = _positive_page().replace(
        "Vingroup thông báo tuyển dụng.",
        "Vingroup thông báo tuyển dụng sinh viên năm 2026.",
    )
    matching = await _coordinator(
        search=_SearchProvider([_hit()]),
        fetcher=_HtmlFetcher({OFFICIAL_JOBS: matching_page}),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert missing.report is not None
    assert missing.report.claim_verification.status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert matching.report is not None
    assert matching.report.claim_verification.status is VerificationStatusV4.VERIFIED


@pytest.mark.asyncio
async def test_consent_matrix_keeps_local_registry_and_blocks_only_external_operations() -> None:
    no_official_request, no_official_scope = _request_scope(
        official_consent=False,
        external_consent=True,
    )
    search = _SearchProvider([_hit()])
    fetcher = _HtmlFetcher({OFFICIAL_JOBS: _positive_page()})
    local_only = await _coordinator(search=search, fetcher=fetcher).coordinate(
        no_official_request,
        no_official_scope,
        execution_context=TurnExecutionContext(),
    )

    short_request, short_scope = _request_scope(
        user_url="https://forms.gle/UserAlias",
        official_consent=True,
        external_consent=False,
    )
    short_fetcher = _HtmlFetcher({OFFICIAL_JOBS: _positive_page("https://bit.ly/OfficialAlias")})
    short = await _coordinator(
        search=_SearchProvider([_hit()]),
        fetcher=short_fetcher,
    ).coordinate(short_request, short_scope, execution_context=TurnExecutionContext())

    assert local_only.report is not None
    assert local_only.report.publisher_verification.status is VerificationStatusV4.VERIFIED
    assert local_only.search_attempts == 0
    assert local_only.official_fetches == 0
    assert search.calls == []
    assert fetcher.calls == []
    assert "official_source_consent_required" in local_only.limitations
    assert short.report is not None
    assert short.report.resource_verification.status is VerificationStatusV4.UNVERIFIED
    assert "external_url_consent_required" in short.limitations
    assert short.outbound_resolutions == 0


@pytest.mark.asyncio
async def test_third_party_redirect_chains_match_with_external_consent() -> None:
    request, scope = _request_scope(
        user_url="https://forms.gle/UserAlias",
        official_consent=True,
        external_consent=True,
    )
    official_short = "https://bit.ly/OfficialAlias"
    final_form = "https://docs.google.com/forms/d/e/FORM-SAME/viewform"
    fetcher = _HtmlFetcher(
        {OFFICIAL_JOBS: _positive_page(official_short)},
        redirects={
            "https://forms.gle/UserAlias": ["https://forms.gle/UserAlias", final_form],
            official_short: [official_short, "https://forms.gle/OfficialAlias", final_form],
        },
    )
    outcome = await _coordinator(
        search=_SearchProvider([_hit()]),
        fetcher=fetcher,
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.resource_verification.status is VerificationStatusV4.VERIFIED
    assert outcome.report.resource_verification.match is not None
    assert outcome.report.resource_verification.match.status is ResourceMatchStatusV4.EXACT_RESOURCE
    assert outcome.outbound_resolutions == 1
    assert official_short in fetcher.calls
    assert "https://forms.gle/UserAlias" in fetcher.calls


@pytest.mark.asyncio
async def test_unlisted_short_link_is_resolved_before_resource_comparison() -> None:
    user_short = "https://unlisted-short.example/UserAlias"
    request, scope = _request_scope(
        user_url=user_short,
        official_consent=True,
        external_consent=True,
    )
    official_short = "https://bit.ly/OfficialAlias"
    final_form = "https://docs.google.com/forms/d/e/FORM-SAME/viewform"
    fetcher = _HtmlFetcher(
        {OFFICIAL_JOBS: _positive_page(official_short)},
        redirects={
            user_short: [user_short, final_form],
            official_short: [official_short, "https://forms.gle/OfficialAlias", final_form],
        },
    )

    outcome = await _coordinator(
        search=_SearchProvider([_hit()]),
        fetcher=fetcher,
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.resource_verification.status is VerificationStatusV4.VERIFIED
    assert outcome.report.resource_verification.match is not None
    assert outcome.report.resource_verification.match.status is ResourceMatchStatusV4.EXACT_RESOURCE
    assert user_short in fetcher.calls


@pytest.mark.asyncio
async def test_reviewed_social_account_post_can_endorse_an_exact_third_party_form() -> None:
    user_form = "https://v.wjx.cn/vm/to3MR3b.aspx"
    social_profile = "https://www.linkedin.com/school/tsinghua-university/"
    social_post = (
        "https://www.linkedin.com/posts/tsinghua-university_ai-highereducation-activity-7484925098416566273-RLNz"
    )
    short_link = "https://bit.ly/4phgUu7"
    brand = BrandRecordV4(
        name="Đại Học Thanh Hoa",
        aliases=["Tsinghua University", "Thanh Hoa University"],
        official_domains=["tsinghua.edu.cn"],
        official_identities=[
            OfficialIdentityV4(
                identity_type=OfficialIdentityTypeV4.SOCIAL_PROFILE,
                canonical_value=social_profile,
                display_value=social_profile,
                entity_name="Đại Học Thanh Hoa",
                provenance="reviewed social identity fixture",
                reviewed=True,
            )
        ],
        provenance="reviewed Tsinghua fixture",
        effective_from=NOW - timedelta(days=1),
        reviewer_id="network-security-reviewer",
        created_at=NOW - timedelta(days=1),
    )
    message = (
        '[Online] Chương Trình Trải Nghiệm "Future Learning With AI" '
        "Do Đại Học Thanh Hoa Tổ Chức 2026 (Miễn Phí Tham Dự) "
        f"Please visit {user_form} to apply."
    )
    request = SecurityTriageCreateRequestV4(
        message=message,
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    fetcher = _HtmlFetcher(
        {
            social_post: (
                "<html><body><article>Tsinghua University School of Education "
                f"invites learners to apply at <a href='{short_link}'>Apply</a>."
                "</article></body></html>"
            )
        },
        redirects={short_link: [short_link, user_form]},
    )

    outcome = await _coordinator(
        brands=[brand],
        search=_SearchProvider([_hit(social_post)]),
        fetcher=fetcher,
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.publisher_verification.status is VerificationStatusV4.VERIFIED
    assert outcome.report.resource_verification.status is VerificationStatusV4.VERIFIED
    assert outcome.report.resource_verification.match is not None
    assert outcome.report.resource_verification.match.status is ResourceMatchStatusV4.EXACT_CANONICAL_URL
    assert short_link in fetcher.calls


@pytest.mark.asyncio
async def test_exact_social_post_cross_linked_by_official_page_can_endorse_third_party_resource() -> None:
    """A first-party source can prove an exact social page, never its whole host."""
    user_short = "https://forms.gle/ApplicantAlias"
    final_form = "https://docs.google.com/forms/d/e/FORM-CROSS-LINK/viewform"
    social_post = "https://www.linkedin.com/posts/vingroup_recruitment-2026"
    official_page = "https://official.example/news/recruitment-2026"
    request, scope = _request_scope(user_url=user_short, official_consent=True, external_consent=True)
    fetcher = _HtmlFetcher(
        {
            official_page: (
                "<html><body>Vingroup thông báo tuyển dụng. "
                f"<a href='{social_post}'>Official announcement</a></body></html>"
            ),
            social_post: (
                "<html><body>Vingroup tuyển dụng. Ứng viên hãy đăng ký tại "
                f"<a href='{final_form}'>Application form</a>.</body></html>"
            ),
        },
        redirects={user_short: [user_short, final_form]},
    )

    outcome = await _coordinator(
        search=_SearchProvider([_hit(official_page)]),
        fetcher=fetcher,
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    report = outcome.report
    assert social_post in fetcher.calls
    assert report.domain_ownership_verification.status is VerificationStatusV4.UNVERIFIED
    assert report.claim_verification.status is VerificationStatusV4.VERIFIED
    assert report.resource_verification.status is VerificationStatusV4.VERIFIED
    assert report.resource_verification.match is not None
    assert report.resource_verification.match.status is ResourceMatchStatusV4.EXACT_RESOURCE
    assert report.action_endorsement_verification.status is VerificationStatusV4.VERIFIED
    assert report.overall_status is VerificationStatusV4.VERIFIED
    social_source = next(source for source in report.source_refs if source.canonical_url == social_post)
    assert social_source.identity is not None
    assert social_source.identity.relationship == "official_cross_link"
    assert social_source.identity.reviewed is False

    completed = assess_security_risk(
        apply_official_verification_outcome(scope, outcome), official_verification_enforced=True
    )
    assert completed.risk is SecurityRiskV4.SAFE
    payload = GroundedSecurityResponseService._synthesis_payload(completed)
    assert payload["verification_state"]["submitted_resource"]["official_association"] == "exact_resource_endorsed"
    assert "Liên kết và thủ tục bạn hỏi đã được nguồn chính thức xác nhận." in (
        policy_grounded_assistant_response(completed).summary
    )


def _identity_attestor(*, host: str) -> SourceRegistryEntry:
    return SourceRegistryEntry(
        publisher="Independent education authority",
        normalized_pattern=host,
        tier=SourceTier.A,
        source_type="academic_institution",
        allowed_operations={"search", "read"},
        policy_version="identity-attestor-v1",
        effective_from=NOW - timedelta(days=1),
        default_freshness_seconds=3600,
        reviewer_id="reviewer",
        reviewed_at=NOW - timedelta(hours=1),
    )


@pytest.mark.asyncio
async def test_absent_organization_establishes_an_ephemeral_domain_from_independent_evidence() -> None:
    organization = "Vingroup"
    official = "https://northstar.example/notices/apply"
    authority = "https://directory.example/organizations/viettel"
    request = SecurityTriageCreateRequestV4(
        message=f"{organization} tuyển sinh, đăng ký tại {official}",
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    assert scope.security_context is not None
    scope = scope.model_copy(update={"security_context": scope.security_context.model_copy(update={"claimed_entity": organization})})
    outcome = await _coordinator(
        brands=[],
        search=_SearchProvider([_hit(official), _hit(authority)]),
        fetcher=_HtmlFetcher(
            {
                official: f"<html><body>{organization} tuyển sinh</body></html>",
                authority: f"<html><body>{organization} official website <a href='https://northstar.example/'>Website</a></body></html>",
            }
        ),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.publisher_verification.reason_code == "publisher_discovered_from_official_evidence"
    assert outcome.report.publisher_verification.identity is not None
    assert outcome.report.publisher_verification.identity.canonical_value == "northstar.example"
    assert outcome.report.domain_ownership_verification.status is VerificationStatusV4.VERIFIED
    assert outcome.report.claim_verification.status is not VerificationStatusV4.VERIFIED
    assert outcome.report.resource_verification.status is VerificationStatusV4.UNVERIFIED


@pytest.mark.asyncio
async def test_social_search_hit_cannot_bootstrap_domain_ownership() -> None:
    """A fetched social post is not a basic-quality independent source."""
    organization = "Vingroup"
    official = "https://vingroup.example/"
    social = "https://facebook.com/vingroup-fans"
    request = SecurityTriageCreateRequestV4(
        message=f"{organization} yêu cầu đăng nhập tại {official}",
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    assert scope.security_context is not None
    scope = scope.model_copy(
        update={"security_context": scope.security_context.model_copy(update={"claimed_entity": organization})}
    )

    outcome = await _coordinator(
        brands=[],
        search=_SearchProvider([_hit(official), _hit(social)]),
        fetcher=_HtmlFetcher(
            {
                official: f"<html><body>{organization}</body></html>",
                social: f"<html><body>{organization} official website <a href='{official}'>Website</a></body></html>",
            }
        ),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.domain_ownership_verification.status is VerificationStatusV4.UNVERIFIED
    assert outcome.report.claim_verification.status is not VerificationStatusV4.VERIFIED
    assert outcome.report.action_endorsement_verification.status is VerificationStatusV4.UNVERIFIED


@pytest.mark.asyncio
async def test_cross_source_bootstraps_unregistered_domain_as_reviewable_source_proposal() -> None:
    """A reviewed attestor can establish a new domain without pre-seeding that domain."""
    organization = "Aurora Holdings"
    official = "https://aurora-holdings.example/"
    authority = "https://registry.example/entities/aurora"
    request = SecurityTriageCreateRequestV4(
        message=f"{organization} yêu cầu đăng nhập tại {official}",
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    assert scope.security_context is not None
    scope = scope.model_copy(
        update={"security_context": scope.security_context.model_copy(update={"claimed_entity": organization})}
    )
    registry = VersionedSourceRegistry([_identity_attestor(host="registry.example")])
    discoveries = MemoryWave2Repository()
    registry.bind_discovery_store(discoveries)

    outcome = await _coordinator(
        brands=[],
        source_registry=registry,
        search=_SearchProvider([_hit(official), _hit(authority)]),
        fetcher=_HtmlFetcher(
            {
                official: f"<html><body>{organization}</body></html>",
                authority: (
                    f"<html><body>{organization} registered website "
                    f"<a href='{official}'>Official website</a></body></html>"
                ),
            }
        ),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.domain_ownership_verification.status is VerificationStatusV4.VERIFIED
    assert outcome.report.claim_verification.status is not VerificationStatusV4.VERIFIED
    assert outcome.report.action_endorsement_verification.status is VerificationStatusV4.UNVERIFIED
    assert registry.matching_entries(official, NOW) == ()

    proposals = await discoveries.list_source_discoveries()
    proposal = next(item for item in proposals if item.domain == "aurora-holdings.example")
    assert proposal.status == "observing"
    assert proposal.publisher == organization
    assert (proposal.extract_success_count, proposal.curated_agreement_count) == (1, 1)


@pytest.mark.asyncio
async def test_reviewed_domain_authenticates_only_its_exact_social_post_and_its_exact_resource_link() -> None:
    organization = "Vingroup"
    official = "https://official.example/notices/apply"
    social_post = "https://www.linkedin.com/posts/northstar-apply-2026"
    user_form = "https://forms.example/northstar-apply"
    request = SecurityTriageCreateRequestV4(
        message=f"{organization} tuyển sinh, đăng ký tại {user_form}",
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    assert scope.security_context is not None
    scope = scope.model_copy(update={"security_context": scope.security_context.model_copy(update={"claimed_entity": organization})})
    outcome = await _coordinator(
        brands=[_brand()],
        search=_SearchProvider([_hit(official)]),
        fetcher=_HtmlFetcher(
            {
                official: f"<html><body>{organization}<a href='{social_post}'>Official social update</a></body></html>",
                social_post: f"<html><body>{organization} tuyển sinh <a href='{user_form}'>Apply</a></body></html>",
            }
        ),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert social_post in [item.canonical_url for item in outcome.report.source_refs]
    assert outcome.report.resource_verification.status is VerificationStatusV4.VERIFIED
    source = next(item for item in outcome.report.source_refs if item.canonical_url == social_post)
    assert source.identity is not None
    assert source.identity.relationship == "official_cross_link"
    assert source.identity.reviewed is False


@pytest.mark.asyncio
async def test_same_name_social_result_is_not_an_identity_without_an_official_outbound_link() -> None:
    organization = "Viettel"
    social_post = "https://www.linkedin.com/posts/northstar-apply-2026"
    request, scope = _request_scope(user_url="https://forms.example/northstar-apply", external_consent=True)
    request = request.model_copy(
        update={"message": f"{organization} tuyển sinh, đăng ký tại https://forms.example/northstar-apply"}
    )
    assert scope.security_context is not None
    scope = scope.model_copy(update={"security_context": scope.security_context.model_copy(update={"claimed_entity": organization})})
    outcome = await _coordinator(
        brands=[],
        search=_SearchProvider([_hit(social_post)]),
        fetcher=_HtmlFetcher({social_post: f"<html><body>{organization} <a href='https://forms.example/northstar-apply'>Apply</a></body></html>"}),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.publisher_verification.status is VerificationStatusV4.UNVERIFIED
    assert social_post not in [item.canonical_url for item in outcome.report.source_refs]


@pytest.mark.asyncio
async def test_unlisted_institutional_search_result_does_not_bootstrap_from_a_raw_search_hit() -> None:
    """A Tavily hit can be fetched, but cannot satisfy independent attestation."""
    message = (
        '[Online] Chương Trình Trải Nghiệm "Future Learning With AI" '
        "Do Đại Học Thanh Hoa Tổ Chức 2026 (Miễn Phí Tham Dự) "
        "Please visit https://v.wjx.cn/vm/to3MR3b.aspx to apply"
    )
    request = SecurityTriageCreateRequestV4(
        message=message,
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    official = "https://www.tsinghua.edu.cn/en"
    fetcher = _HtmlFetcher({official: "<html><body>Tsinghua University</body></html>"})

    outcome = await _coordinator(
        brands=[],
        source_registry=VersionedSourceRegistry(default_source_policies()),
        search=_SearchProvider([_hit(official)]),
        fetcher=fetcher,
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.candidate_count == 0
    assert official in fetcher.calls
    assert outcome.report.publisher_verification.status is VerificationStatusV4.UNVERIFIED
    assert outcome.report.publisher_verification.reason_code == "reviewed_identity_not_found"


@pytest.mark.asyncio
async def test_low_ranked_reviewed_exact_candidate_survives_fetch_budget() -> None:
    exact = "https://official.example/notices/recruitment-2026"
    brand = _brand().model_copy(
        update={
            "official_identities": [
                OfficialIdentityV4(
                    identity_type=OfficialIdentityTypeV4.WEBSITE,
                    canonical_value=exact,
                    display_value=exact,
                    entity_name="Vingroup",
                    provenance="reviewed exact fixture",
                    reviewed=True,
                )
            ]
        }
    )
    request, scope = _request_scope()
    noise = [_hit(f"https://official.example/noise/{index}") for index in range(5)]
    fetcher = _HtmlFetcher({exact: _positive_page()})
    outcome = await _coordinator(brands=[brand], search=_SearchProvider(noise), fetcher=fetcher).coordinate(
        request, scope, execution_context=TurnExecutionContext()
    )

    assert outcome.official_fetches <= 3
    assert exact in fetcher.calls


@pytest.mark.asyncio
async def test_discovered_entity_resource_chain_is_automatically_verified_without_promotion() -> None:
    user_form = "https://v.wjx.cn/vm/to3MR3b.aspx"
    social_post = (
        "https://www.linkedin.com/posts/tsinghua-university_ai-highereducation-activity-7484925098416566273-RLNz"
    )
    short_link = "https://bit.ly/4phgUu7"
    message = (
        '[Online] Chương Trình Trải Nghiệm "Future Learning With AI" '
        "Do Đại Học Thanh Hoa Tổ Chức 2026 (Miễn Phí Tham Dự) "
        f"Please visit {user_form} to apply."
    )
    request = SecurityTriageCreateRequestV4(
        message=message,
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    aggregator = "https://events.example/future-learning-with-ai"
    search = _SearchProvider([_hit(aggregator), _hit(social_post)])
    repository = _BrandRepository([])
    repository.candidates.append(
        IdentityCandidateV4(
            entity_name="Đại Học Thanh Hoa",
            canonical_url=user_form,
            canonical_domain="v.wjx.cn",
            relationship=IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
            assurance=IdentityAssociationAssuranceV4.DISCOVERED,
            confidence=0.35,
            discovered_at=NOW,
            expires_at=NOW + timedelta(days=7),
        )
    )
    fetcher = _HtmlFetcher(
        {
            user_form: (
                "<html><body>Future Learning With AI — Future Education and Learning Team, "
                "School of Education, Tsinghua University.</body></html>"
            ),
            aggregator: (
                "<html><body><article>Đại Học Thanh Hoa tổ chức Future Learning With AI. "
                f"<a href='{user_form}'>Tại đây</a></article></body></html>"
            ),
            social_post: (
                "<html><body><article>Tsinghua University presents "
                "Future Learning With AI. "
                f"<a href='{short_link}'>Apply</a></article></body></html>"
            ),
        },
        redirects={short_link: [short_link, user_form]},
    )

    outcome = await _coordinator(
        repository=repository,
        search=search,
        fetcher=fetcher,
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    association = next(item for item in outcome.report.identity_associations if item.canonical_url == user_form)
    assert association.assurance is IdentityAssociationAssuranceV4.VERIFIED
    assert association.relationship.value == "endorsed_third_party_service"
    assert outcome.report.publisher_verification.status is VerificationStatusV4.UNVERIFIED
    assert outcome.report.resource_verification.status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert outcome.report.resource_verification.reason_code == "discovered_exact_resource_endorsement_chain"
    assert outcome.report.action_endorsement_verification.status is VerificationStatusV4.VERIFIED
    assert outcome.report.action_endorsement_verification.reason_code == "official_exact_resource_action_confirmed"
    assert outcome.report.overall_status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert short_link not in fetcher.calls
    assert social_post in fetcher.calls
    assert aggregator in fetcher.calls
    assert search.calls[0][0].startswith('Đại Học Thanh Hoa "Future Learning With AI"')

    unresolved = SecurityEvidenceV4(
        evidence_ref="evidence:dddddddddddddddd",
        type=SecurityEvidenceTypeV4.BRAND_MATCH,
        source="brand-registry",
        target="v.wjx.cn",
        signal="claimed_identity_unverified",
        description="Chưa xác nhận quan hệ URL.",
        observed_at=NOW,
        confidence=0.5,
    )
    staged = scope.model_copy(
        update={
            "evidence": [unresolved],
            "limitations": [
                "Chưa có reviewed identity hoặc exact-resource association để xác nhận quan hệ giữa URL và tổ chức."
            ],
        }
    )
    reconciled = apply_official_verification_outcome(staged, outcome)
    assert reconciled.evidence[0].description.startswith(
        "Official verification đã xác nhận chuỗi endorsement cho đúng resource"
    )
    assert all("Chưa có reviewed identity hoặc exact-resource" not in item for item in reconciled.limitations)
    assert any("không mở rộng kết quả cho toàn domain" in item for item in reconciled.limitations)
    risk_result = assess_security_risk(reconciled)
    assert "Official verification đã xác nhận chuỗi endorsement" in risk_result.explanation
    assert "Không có reviewed identity để xác nhận domain" not in risk_result.explanation
    assert SecurityRecommendedActionV4.ALLOW_OPEN in risk_result.recommended_actions
    assert SecurityRecommendedActionV4.VERIFY_VIA_OFFICIAL_CHANNEL not in risk_result.recommended_actions

    # This is the real coordinator result: the resource component remains
    # PARTIALLY_VERIFIED because publisher/campaign coverage is separate, but
    # its accepted association must still reach response grounding.
    payload = GroundedSecurityResponseService._synthesis_payload(risk_result)
    assert payload["authoritative_security_truth"]["verified_exact_resource_endorsement"] is True
    assert payload["verification_state"]["submitted_resource"]["official_association"] == "exact_resource_endorsed"
    assert payload["decisive_facts"][0]["category"] == "exact_resource_action_endorsed"
    assert "evidence:dddddddddddddddd" in payload["available_explanation_evidence_refs"]
    raw_gpt_output = AssistantSynthesis(
        summary="The submitted resource could not be verified from an official source."
    )
    assert (
        check_grounded_ai_response(risk_result, raw_gpt_output).failure
        is SynthesisGroundingFailure.CONTRADICTS_VERIFIED_EXACT_RESOURCE_ENDORSEMENT
    )
    fallback = policy_grounded_assistant_response(risk_result).summary
    assert "Tài nguyên bạn gửi đã được nguồn chính thức xác nhận cho quy trình này." in fallback
    assert "Danh tính người gửi chưa được xác minh riêng." in fallback
    assert "Chưa có xác nhận chính thức cho đúng hành động" not in fallback

    natural_reply = AssistantSynthesis(
        summary=(
            "Biểu mẫu này đã được nguồn chính thức của Đại Học Thanh Hoa xác nhận sử dụng. "
            "Tuy nhiên, chưa tìm thấy bằng chứng chính thức xác nhận riêng chương trình Future Learning With AI "
            "hoặc lời mời đăng ký trong tin nhắn này. Vì vậy, link biểu mẫu có cơ sở chính thức nhưng chưa đủ "
            "để xác nhận toàn bộ nội dung tin nhắn."
        )
    )
    natural_check = check_grounded_ai_response(risk_result, natural_reply)
    assert natural_check.failure is None

    class _NaturalSynthesisModel:
        async def synthesize(self, payload):
            del payload
            return ModelResponse(output=natural_reply, provider="test", model="test")

    natural_final = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_NaturalSynthesisModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(risk_result)
    assert natural_final.assistant_response is not None
    assert natural_final.assistant_response.generation_mode.value == "ai"
    assert natural_final.assistant_response.summary == natural_reply.summary

    class _ContradictorySynthesisModel:
        async def synthesize(self, payload):
            del payload
            return ModelResponse(output=raw_gpt_output, provider="test", model="test")

    final = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_ContradictorySynthesisModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(risk_result)
    assert final.assistant_response is not None
    assert final.assistant_response.generation_mode.value == "policy_grounded"
    assert "Tài nguyên bạn gửi đã được nguồn chính thức xác nhận cho quy trình này." in (
        final.assistant_response.summary
    )


@pytest.mark.asyncio
async def test_discovery_fetches_each_claim_frontier_query_before_declaring_no_exact_resource_association() -> None:
    """Equivalent evidence from a later provider result must not depend on ranking."""
    user_form = "https://forms.example/future-learning-2026"
    official_source = "https://events.example/future-learning-with-ai"
    social_source = "https://social.example/posts/future-learning-2026"
    noise = "https://unrelated.example/notice"
    message = f'Đại Học Example tổ chức "Future Learning With AI". Apply at {user_form}.'
    request = SecurityTriageCreateRequestV4(
        message=message,
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    fetcher = _HtmlFetcher(
        {
            official_source: (
                "<html><body>Đại Học Example tổ chức Future Learning With AI. "
                f"<a href='{user_form}'>Apply</a></body></html>"
            ),
            social_source: "<html><body>Future Learning With AI</body></html>",
        }
    )
    search = _SearchProvider(
        hits_by_call=[
            [_hit(noise)],
            [_hit(official_source), _hit(social_source)],
        ]
    )

    outcome = await _coordinator(search=search, fetcher=fetcher).coordinate(
        request, scope, execution_context=TurnExecutionContext()
    )

    assert outcome.report is not None
    association = next(item for item in outcome.report.identity_associations if item.canonical_url == user_form)
    assert association.assurance is IdentityAssociationAssuranceV4.VERIFIED
    assert association.relationship is IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE
    assert len(search.calls) >= 2
    assert official_source in fetcher.calls


def test_neutral_anchor_is_kept_when_it_points_to_the_exact_submitted_resource() -> None:
    target = "https://forms.example/form/abc"
    body = f"<html><body><a href='{target}'>Tại đây</a></body></html>".encode()

    links = _resource_endorsement_links(body, "https://publisher.example/post", {target})

    assert links == [target]


@pytest.mark.asyncio
async def test_provider_fallback_requires_explicit_url_and_caps_components_at_partial() -> None:
    request, scope = _request_scope()
    fetcher = _HtmlFetcher(failure=VerificationTransportLimitation.PROVIDER_ERROR)
    extract = _ExtractProvider(f"Vingroup thông báo tuyển dụng, ứng viên đăng ký tại {USER_FORM}.")
    outcome = await _coordinator(
        search=_SearchProvider([_hit()]),
        fetcher=fetcher,
        extract=extract,
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.claim_verification.status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert outcome.report.resource_verification.status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert outcome.report.overall_status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert extract.calls


@pytest.mark.asyncio
async def test_cache_ignores_superseded_candidate_versions_and_preserves_exact_resource_verification() -> None:
    request, scope = _request_scope()
    repository = _BrandRepository([])
    previous: IdentityCandidateV4 | None = None
    for version in range(1, 26):
        verified = version == 25
        candidate = IdentityCandidateV4(
            entity_name="Vingroup",
            canonical_url=USER_FORM,
            canonical_domain="docs.google.com",
            relationship=IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
            assurance=(
                IdentityAssociationAssuranceV4.VERIFIED if verified else IdentityAssociationAssuranceV4.DISCOVERED
            ),
            confidence=0.7 if verified else 0.35,
            discovered_at=NOW + timedelta(minutes=version),
            verified_at=NOW + timedelta(minutes=version) if verified else None,
            expires_at=NOW + timedelta(days=7),
            version=version,
            supersedes=previous.association_id if previous is not None else None,
        )
        repository.candidates.append(candidate)
        previous = candidate

    outcome = await _coordinator(repository=repository).coordinate(
        request,
        scope,
        execution_context=TurnExecutionContext(),
    )

    assert outcome.report is not None
    assert outcome.report.resource_verification.status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert len(outcome.report.identity_associations) == 1
    assert previous is not None
    assert outcome.report.identity_associations[0].association_id == previous.association_id
    assert outcome.identity_candidate_count == 1
    assert outcome.identity_verified_count == 1
    assert outcome.identity_cache_hits == 1
    assert "identity_cache_hit" in outcome.limitations


@pytest.mark.asyncio
async def test_coordinator_report_never_serializes_raw_html_or_sensitive_url_query() -> None:
    sensitive_url = f"{USER_FORM}?token=fixture-secret&utm_source=mail"
    request, scope = _request_scope(user_url=sensitive_url)
    raw_marker = "RAW-HTML-PRIVATE-MARKER"
    page = _positive_page(sensitive_url).replace("</article>", f" {raw_marker}</article>")
    outcome = await _coordinator(
        search=_SearchProvider([_hit()]),
        fetcher=_HtmlFetcher({OFFICIAL_JOBS: page}),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    serialized = outcome.model_dump_json()
    assert "fixture-secret" not in serialized
    assert "utm_source" not in serialized
    assert raw_marker not in serialized
    assert "<html" not in serialized.casefold()


@pytest.mark.asyncio
async def test_policy_caps_search_candidates_fetch_concurrency_and_outbound_resolution() -> None:
    request, scope = _request_scope(external_consent=True)
    hits = [_hit(f"https://official.example/jobs/{index}", score=1 - index / 10) for index in range(5)]
    links = "".join(f"<a href='https://bit.ly/action-{index}'>Apply {index}</a>" for index in range(5))
    pages = {hit.url: f"<html><body>Vingroup tuyển dụng {links}</body></html>" for hit in hits}
    fetcher = _HtmlFetcher(pages)
    outcome = await _coordinator(search=_SearchProvider(hits), fetcher=fetcher).coordinate(
        request,
        scope,
        execution_context=TurnExecutionContext(),
    )

    assert outcome.search_attempts <= 8
    assert outcome.candidate_count <= 8
    assert outcome.official_fetches == 3
    assert outcome.outbound_resolutions == 3
    assert fetcher.max_active <= 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "limitation",
    [
        None,
        VerificationTransportLimitation.PROVIDER_TIMEOUT,
        VerificationTransportLimitation.PROVIDER_ERROR,
    ],
)
async def test_no_hit_error_and_timeout_do_not_change_existing_risk(limitation) -> None:
    request, scope = _request_scope()
    staged = scope.model_copy(
        update={
            "next_step": "RISK_ASSESSMENT",
            "investigation_status": SecurityInvestigationStatusV4.COMPLETED,
        }
    )
    baseline = assess_security_risk(staged)
    coordinator = _coordinator(search=_SearchProvider(limitation=limitation), fetcher=None)
    enriched = await coordinator.verify(
        request,
        staged,
        execution_context=TurnExecutionContext(),
    )
    after = assess_security_risk(enriched)

    assert after.official_verification is not None
    assert (after.risk, after.score, after.policy_version) == (
        baseline.risk,
        baseline.score,
        baseline.policy_version,
    )


@pytest.mark.asyncio
async def test_identity_discovery_extract_fallback_recovers_blocked_html_fetch() -> None:
    request, scope = _request_scope(external_consent=True)
    extract = _ExtractProvider(f"Vingroup official recruitment {USER_FORM}")
    outcome = await _coordinator(
        brands=[],
        search=_SearchProvider([_hit()]),
        fetcher=_HtmlFetcher(failure=VerificationTransportLimitation.PROVIDER_ERROR),
        extract=extract,
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert extract.calls
    assert "identity_fetch_provider_error" not in outcome.limitations
    assert any(item.canonical_url == OFFICIAL_JOBS for item in outcome.report.identity_associations)


def test_comparison_validator_rejects_fabricated_ids_urls_and_link_roles() -> None:
    valid = VerificationComparisonOutput(
        source_ids=["source:1111111111111111"],
        link_ids=["link:2222222222222222"],
        relation=ComparisonRelation.SUPPORTS,
        matched_dimensions=[ComparisonDimension.ORGANIZATION, ComparisonDimension.TOPIC],
        link_roles={"link:2222222222222222": "application"},
    )
    fabricated = valid.model_copy(update={"source_ids": ["source:aaaaaaaaaaaaaaaa"]})

    assert (
        validate_comparison_output(
            valid,
            available_source_ids={"source:1111111111111111"},
            available_link_ids={"link:2222222222222222"},
        )
        == valid
    )
    assert (
        validate_comparison_output(
            fabricated,
            available_source_ids={"source:1111111111111111"},
            available_link_ids={"link:2222222222222222"},
        )
        is None
    )
    with pytest.raises(ValidationError):
        VerificationComparisonOutput.model_validate(
            {
                "source_ids": ["https://invented.example/source"],
                "link_ids": [],
                "relation": "supports",
                "matched_dimensions": [],
                "link_roles": {},
                "url": "https://invented.example",
            }
        )


@pytest.mark.asyncio
async def test_source_registry_exact_entry_confirms_but_wildcard_only_corroborates() -> None:
    exact = SourceRegistryEntry(
        publisher="Vingroup",
        normalized_pattern="official.example",
        tier=SourceTier.A,
        source_type="official_enterprise",
        allowed_operations={"search", "read"},
        policy_version="source-policy-cp7",
        effective_from=NOW - timedelta(days=1),
        default_freshness_seconds=3600,
        reviewer_id="reviewer",
        reviewed_at=NOW - timedelta(hours=1),
    )
    wildcard = exact.model_copy(update={"normalized_pattern": "*.official.example"})
    wrong_type = exact.model_copy(update={"source_type": "reviewed_news"})
    request, scope = _request_scope(official_consent=False)
    exact_outcome = await _coordinator(source_registry=VersionedSourceRegistry([wildcard, exact])).coordinate(
        request, scope, execution_context=TurnExecutionContext()
    )
    wildcard_outcome = await _coordinator(source_registry=VersionedSourceRegistry([wildcard])).coordinate(
        request, scope, execution_context=TurnExecutionContext()
    )
    wrong_type_outcome = await _coordinator(source_registry=VersionedSourceRegistry([wrong_type])).coordinate(
        request, scope, execution_context=TurnExecutionContext()
    )

    assert exact_outcome.report is not None
    assert exact_outcome.report.publisher_verification.reason_code == "reviewed_registry_and_source_identity"
    assert wildcard_outcome.report is not None
    assert wildcard_outcome.report.publisher_verification.reason_code == "reviewed_exact_identity"
    assert wrong_type_outcome.report is not None
    assert wrong_type_outcome.report.publisher_verification.reason_code == "reviewed_exact_identity"


@pytest.mark.asyncio
async def test_direct_official_cross_link_is_report_scoped_and_never_persisted() -> None:
    request, scope = _request_scope()
    brand = _brand()
    social = "https://www.linkedin.com/company/vingroup/"
    page = _positive_page() + f"<a href='{social}'>Official LinkedIn</a>"
    outcome = await _coordinator(
        brands=[brand],
        search=_SearchProvider([_hit()]),
        fetcher=_HtmlFetcher({OFFICIAL_JOBS: page}),
    ).coordinate(request, scope, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    cross_links = [
        item
        for item in outcome.report.source_refs
        if item.identity is not None and item.identity.relationship == "official_cross_link"
    ]
    assert len(cross_links) == 1
    assert cross_links[0].identity is not None
    assert cross_links[0].identity.reviewed is False
    assert cross_links[0].canonical_url == social
    assert brand.official_identities == []


class _PassthroughUnderstanding:
    async def enrich(self, request, scoped):
        del request
        return scoped


class _MustNotRunCoordinator:
    async def verify(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("recovery-first path invoked official verification")


class _MustNotRunStage:
    async def enrich(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("recovery-first path invoked investigation/trust")

    async def investigate(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("recovery-first path invoked investigation/trust")


class _PassthroughResponse:
    async def enrich(self, scoped):
        return scoped


@pytest.mark.asyncio
async def test_pipeline_never_runs_coordinator_on_recovery_first_incident() -> None:
    request, scoped = _request_scope()
    scoped = scoped.model_copy(
        update={
            "assistant_context": AssistantContextV4(
                processing_mode=AssistantProcessingModeV4.RULES_ONLY,
                exposure_state=ExposureStateV4.CREDENTIAL_SHARED,
                model_version="cp7-fixture",
            )
        }
    )
    pipeline = SecurityTriagePipeline(
        understanding=_PassthroughUnderstanding(),
        investigation=_MustNotRunStage(),
        trust=_MustNotRunStage(),
        responses=_PassthroughResponse(),
        official_verification=_MustNotRunCoordinator(),
    )

    result = await pipeline.process(
        request,
        scoped,
        runtime=SecurityAssistantRuntime(max_retries=0),
    )

    assert result.status is AnalysisStatus.COMPLETED
    assert result.official_verification is None


class _PassthroughInvestigation:
    async def investigate(self, request, scoped, *, runtime):
        del request, runtime
        return scoped.model_copy(
            update={
                "next_step": "RISK_ASSESSMENT",
                "investigation_status": SecurityInvestigationStatusV4.COMPLETED,
            }
        )


class _RecordingTrust:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    async def enrich(self, request, scoped):
        del request
        self.order.append("trust")
        return scoped


class _RecordingCoordinator:
    def __init__(self, coordinator, order: list[str]) -> None:
        self.coordinator = coordinator
        self.order = order

    async def verify(self, *args, **kwargs):
        self.order.append("official_verification")
        return await self.coordinator.verify(*args, **kwargs)


class _RecordingResponse:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    async def enrich(self, scoped):
        assert scoped.official_verification is not None
        assert scoped.risk is not None
        self.order.append("response")
        return scoped


@pytest.mark.asyncio
async def test_shared_pipeline_runs_verification_after_trust_and_before_risk_response() -> None:
    request, scoped = _request_scope(official_consent=False)
    order: list[str] = []
    progress_steps: list[str] = []
    coordinator = _RecordingCoordinator(_coordinator(), order)

    async def progress(step, message, evidence_refs, risk):
        del message, evidence_refs, risk
        progress_steps.append(step)

    pipeline = SecurityTriagePipeline(
        understanding=_PassthroughUnderstanding(),
        investigation=_PassthroughInvestigation(),
        trust=_RecordingTrust(order),
        official_verification=coordinator,
        responses=_RecordingResponse(order),
    )
    result = await pipeline.process(
        request,
        scoped,
        runtime=SecurityAssistantRuntime(max_retries=0),
        progress=progress,
    )

    assert result.official_verification is not None
    assert result.risk is not None
    assert order == ["trust", "official_verification", "response"]
    assert progress_steps == [
        "understanding",
        "investigation",
        "official_link_verification",
        "risk_assessment",
        "assistant_response",
    ]


@pytest.mark.asyncio
async def test_runtime_pipeline_bootstraps_generic_first_party_domain_without_cache_or_attestor() -> None:
    """Cold-cache ownership is usable now; persistence is not a trust prerequisite."""
    organization = "Northstar Institute"
    submitted = "https://northstar.example/vi/contact"
    about = "https://northstar.example/en/about"
    authority = "https://directory.example/entities/northstar"
    raw_hit = "https://untrusted.example/wiki/northstar"
    request = SecurityTriageCreateRequestV4(
        message=f"{organization} hoàn tiền; đăng nhập tại {submitted}",
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scoped = SecurityTriageScopeService().assess(request)
    assert scoped.security_context is not None
    scoped = scoped.model_copy(
        update={"security_context": scoped.security_context.model_copy(update={"claimed_entity": organization})}
    )
    fetcher = _HtmlFetcher(
        {
            submitted: f"<html><body>{organization}</body></html>",
            about: f"<html><body>{organization}</body></html>",
            authority: f"<html><body>{organization} — Website: northstar.example</body></html>",
            raw_hit: f"<html><body>{organization} not affiliated <a href='{submitted}'>link</a></body></html>",
        }
    )
    coordinator = _coordinator(
        repository=_ColdCacheBrandRepository(),
        search=_SearchProvider([_hit(raw_hit), _hit(about), _hit(authority)]),
        fetcher=fetcher,
    )
    pipeline = SecurityTriagePipeline(
        understanding=_PassthroughUnderstanding(),
        investigation=_PassthroughInvestigation(),
        trust=_RecordingTrust([]),
        official_verification=coordinator,
        responses=_PassthroughResponse(),
    )

    result = await pipeline.process(request, scoped, runtime=SecurityAssistantRuntime(max_retries=0))

    assert result.official_verification is not None
    report = result.official_verification
    assert report.domain_ownership_verification.status is VerificationStatusV4.VERIFIED
    assert report.claim_verification.status is not VerificationStatusV4.VERIFIED
    assert report.action_endorsement_verification.status is VerificationStatusV4.UNVERIFIED
    assert not any(item.assurance is IdentityAssociationAssuranceV4.CONFLICTING for item in report.identity_associations)
    assert any(
        item.signal == "official_domain_verified" and item.target == "northstar.example"
        for item in result.evidence
    )
    assert (
        "Chưa có reviewed identity hoặc exact-resource association để xác nhận quan hệ giữa URL và tổ chức."
        not in result.limitations
    )
    assert fetcher.calls[:3] == [submitted, about, authority]


@pytest.mark.asyncio
async def test_generic_editorial_scam_warning_does_not_negate_host_bound_ownership() -> None:
    """Only a relation-specific statement about the candidate host can conflict."""
    organization = "Northstar Institute"
    submitted = "https://northstar.example/contact"
    about = "https://northstar.example/about"
    directory = "https://directory.example/entities/northstar"
    request = SecurityTriageCreateRequestV4(
        message=f"{organization} hoàn 20 triệu cho khách hàng. Đăng nhập tại {submitted}",
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scoped = SecurityTriageScopeService().assess(request)
    assert scoped.security_context is not None
    scoped = scoped.model_copy(
        update={"security_context": scoped.security_context.model_copy(update={"claimed_entity": organization})}
    )
    outcome = await _coordinator(
        brands=[],
        search=_SearchProvider([_hit(about), _hit(directory)]),
        fetcher=_HtmlFetcher(
            {
                submitted: f"<html><body>{organization}</body></html>",
                about: f"<html><body>{organization} parent company information</body></html>",
                directory: (
                    f"<html><body>Editorial scam warning for contributors. {organization}. "
                    f"Website: <a href='{submitted}'>northstar.example</a>.</body></html>"
                ),
            }
        ),
    ).coordinate(request, scoped, execution_context=TurnExecutionContext())

    assert outcome.report is not None
    assert outcome.report.domain_ownership_verification.status is VerificationStatusV4.VERIFIED
    assert outcome.report.claim_verification.status is VerificationStatusV4.UNVERIFIED
    assert outcome.report.action_endorsement_verification.status is VerificationStatusV4.UNVERIFIED
    assert any(
        item.canonical_domain == "northstar.example"
        and item.relationship is IdentityRelationshipV4.OFFICIAL_CONTROLLED
        and item.assurance is IdentityAssociationAssuranceV4.VERIFIED
        for item in outcome.report.identity_associations
    )
    assert all(
        observation.family.value != "explicit_ownership_conflict"
        for observation in outcome.report.identity_evidence
    )


@pytest.mark.asyncio
async def test_runtime_pipeline_bootstraps_generic_third_party_exact_resource_without_cache() -> None:
    """A self-identifying hosted form is not thereby an owned publisher domain."""
    organization = "Northstar Institute"
    submitted = "https://forms.example/apply/future-learning"
    provenance = "https://events.example/future-learning"
    request = SecurityTriageCreateRequestV4(
        message=f'{organization} presents "Future Learning With AI"; apply at {submitted}',
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scoped = SecurityTriageScopeService().assess(request)
    assert scoped.security_context is not None
    scoped = scoped.model_copy(
        update={"security_context": scoped.security_context.model_copy(update={"claimed_entity": organization})}
    )
    coordinator = _coordinator(
        repository=_ColdCacheBrandRepository(),
        search=_SearchProvider([_hit(provenance)]),
        fetcher=_HtmlFetcher(
            {
                submitted: f"<html><body>{organization} — Future Learning With AI</body></html>",
                provenance: (
                    f"<html><body>{organization} presents Future Learning With AI. "
                    f"<a href='{submitted}'>Apply</a></body></html>"
                ),
            }
        ),
    )
    pipeline = SecurityTriagePipeline(
        understanding=_PassthroughUnderstanding(),
        investigation=_PassthroughInvestigation(),
        trust=_RecordingTrust([]),
        official_verification=coordinator,
        responses=_PassthroughResponse(),
    )

    result = await pipeline.process(request, scoped, runtime=SecurityAssistantRuntime(max_retries=0))

    assert result.official_verification is not None
    report = result.official_verification
    # The provenance-search edge must retain the entity/campaign query.  The
    # submitted third-party host is checked on the separate exact-resource
    # edge; putting it into this query caused relevant official sources to be
    # omitted by query-sensitive providers.
    assert coordinator._search is not None
    assert coordinator._search.calls[0][0] == 'Northstar Institute "Future Learning With AI"'
    assert result.security_context is not None
    assert result.security_context.urls == [submitted]
    assert report.intent.requested_action is not None
    assert report.intent.action_url_indices == [0]
    association = next(item for item in report.identity_associations if item.canonical_url == submitted)
    assert association.relationship is IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE
    assert association.assurance is IdentityAssociationAssuranceV4.VERIFIED
    assert report.domain_ownership_verification.status is VerificationStatusV4.UNVERIFIED
    assert report.resource_verification.status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert report.action_endorsement_verification.status is VerificationStatusV4.VERIFIED
    assert report.sender_verification.status is VerificationStatusV4.UNVERIFIED
    assert report.claim_verification.status is VerificationStatusV4.UNVERIFIED
    assert result.risk is not SecurityRiskV4.SAFE
    payload = GroundedSecurityResponseService._synthesis_payload(result)
    assert payload["authoritative_security_truth"]["verified_exact_resource_endorsement"] is True
    assert payload["verification_state"]["submitted_resource"]["official_association"] == "exact_resource_endorsed"
    assert payload["verification_state"]["domain_ownership"] == "UNVERIFIED"
    assert payload["verification_state"]["sender_identity"] == "UNVERIFIED"


@pytest.mark.asyncio
async def test_bare_url_keeps_official_report_none() -> None:
    request = SecurityTriageCreateRequestV4(
        message="https://example.test/application",
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    outcome = await _coordinator(search=_SearchProvider([_hit()]), fetcher=_HtmlFetcher()).coordinate(
        request,
        scope,
        execution_context=TurnExecutionContext(),
    )

    assert outcome.report is None
    assert outcome.adapter_attempts == 0


@pytest.mark.asyncio
async def test_official_domain_identity_does_not_endorse_an_arbitrary_passport_resource() -> None:
    target = "https://dichvucong.bocongan.gov.vn/?home=1"
    authority = "https://authority.example/government-directory"
    message = f"Cán bộ phường hướng dẫn tôi vào\n{target} để làm hộ chiếu"
    request = SecurityTriageCreateRequestV4(
        message=message,
        consent={"official_source_lookup": True, "external_url_lookup": True},
    )
    scope = SecurityTriageScopeService().assess(request)
    coordinator = _coordinator(
        repository=_BrandRepository([]),
        search=_SearchProvider([_hit(target), _hit(authority)]),
        source_registry=VersionedSourceRegistry([_identity_attestor(host="authority.example")]),
        fetcher=_HtmlFetcher(
            {
                target: (
                    "<html><body>dichvucong.bocongan.gov.vn — Cổng dịch vụ công hướng dẫn làm hộ chiếu.</body></html>"
                ),
                authority: (
                    "<html><body>Danh bạ dịch vụ công chính thức: "
                    f"<a href='{target}'>dichvucong.bocongan.gov.vn</a> làm hộ chiếu.</body></html>"
                ),
            }
        ),
    )

    outcome = await coordinator.coordinate(request, scope, execution_context=TurnExecutionContext())
    assert outcome.report is not None
    report = outcome.report
    assert scope.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert scope.security_context is not None
    assert scope.security_context.requested_action is RequestedActionV4.APPLY_FOR_PASSPORT
    assert report.publisher_verification.status is VerificationStatusV4.VERIFIED
    assert report.domain_ownership_verification.status is VerificationStatusV4.VERIFIED
    assert report.resource_verification.status is VerificationStatusV4.UNVERIFIED
    assert report.action_endorsement_verification.status is VerificationStatusV4.UNVERIFIED
    assert report.sender_verification.status is VerificationStatusV4.UNVERIFIED

    completed = assess_security_risk(
        apply_official_verification_outcome(scope, outcome),
        official_verification_enforced=True,
    )
    assert completed.risk.value == "INSUFFICIENT_EVIDENCE"
    assert completed.recommended_actions != [SecurityRecommendedActionV4.ALLOW_OPEN]

    rendered_response = policy_grounded_assistant_response(completed).summary
    assert "chưa có đủ dữ liệu" in rendered_response.casefold()
