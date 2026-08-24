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
    ResourceMatchStatusV4,
    ScopeDecisionV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    VerificationStatusV4,
)
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
from src.services.platform_wave2 import SourceRegistryEntry, SourceTier, VersionedSourceRegistry
from src.services.security_pipeline import SecurityTriagePipeline
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
        limitation: VerificationTransportLimitation | None = None,
    ) -> None:
        self.hits = hits or []
        self.limitation = limitation
        self.calls: list[tuple[str, int]] = []

    async def search_one(self, query: str, *, execution_context, max_results: int = 5):
        self.calls.append((query, max_results))
        execution_context.reserve_network_units()
        if self.limitation is not None:
            return WebSearchEnvelope(
                status=VerificationTransportStatus.LIMITED,
                limitation=self.limitation,
                usage=_usage("search_one"),
            )
        selected = self.hits[:max_results]
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


def _coordinator(
    *,
    brands: list[BrandRecordV4] | None = None,
    repository: _BrandRepository | None = None,
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

    assert outcome.search_attempts <= 4
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
