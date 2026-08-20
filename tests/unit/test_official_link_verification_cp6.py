from __future__ import annotations

import pytest

from src.models import (
    OfficialIdentityMatchScopeV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    ResourceMatchStatusV4,
    ResourceTypeV4,
    VerificationStatusV4,
)
from src.services.official_resource_identity import (
    FinalPageIdentityStatus,
    LinkEvidenceStrength,
    LinkExtractionMethod,
    OfficialHtmlLinkExtractor,
    UrlNormalizationError,
    extract_provider_fallback_link,
    identify_resource,
    identify_resource_chain,
    match_resource_chains,
    match_resources,
    normalize_verification_url,
)
from src.services.official_verification_transport import (
    ExtractedWebDocument,
    FetchedHtml,
    VerificationTransportLimitation,
)


def _domain_identity(domain: str = "official.example") -> OfficialIdentityV4:
    return OfficialIdentityV4(
        identity_type=OfficialIdentityTypeV4.PRIMARY_WEBSITE,
        canonical_value=domain,
        display_value=domain,
        entity_name="Example University",
        match_scope=OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS,
        provenance="reviewed fixture",
        reviewed=True,
    )


def _url_identity(url: str) -> OfficialIdentityV4:
    return OfficialIdentityV4(
        identity_type=OfficialIdentityTypeV4.SOCIAL_PROFILE,
        canonical_value=url,
        display_value=url,
        entity_name="Example University",
        provenance="reviewed fixture",
        reviewed=True,
    )


def _html_document(
    body: str,
    *,
    final_url: str = "https://official.example/notices/recruitment",
    redirect_chain: list[str] | None = None,
) -> FetchedHtml:
    return FetchedHtml(
        final_url=final_url,
        redirect_chain=redirect_chain or [final_url],
        media_type="text/html",
        body=body.encode(),
    )


@pytest.mark.parametrize(
    "raw_url",
    [
        "javascript:alert(1)",
        "data:text/html,unsafe",
        "mailto:security@example.com",
        "https://user:password@official.example/form",
        "https://official.example/%zz",
    ],
)
def test_url_normalization_rejects_unsafe_href_shapes(raw_url: str) -> None:
    with pytest.raises(UrlNormalizationError):
        normalize_verification_url(raw_url)


def test_url_representations_preserve_fetch_semantics_and_bound_persisted_values() -> None:
    raw = (
        "https://official.example/Form/%7eStep%2fOne?"
        "b=2&a=first&a=second&utm_source=mail&token=fixture-secret&X-Amz-Signature=signed"
    )

    normalized = normalize_verification_url(raw)

    assert normalized.fetch_url == raw
    assert normalized.display_url == ("https://official.example/Form/~Step%2FOne?b=2&a=first&a=second")
    assert normalized.canonical_url == ("https://official.example/Form/~Step%2FOne?a=first&a=second&b=2")
    assert "fixture-secret" not in normalized.model_dump_json()
    assert "signed" not in normalized.model_dump_json()
    assert "fetch_url" not in normalized.model_dump()


def test_html_parser_uses_first_valid_base_and_resolves_relative_and_protocol_relative_links() -> None:
    html = """
    <html><head>
      <base href="javascript:ignored">
      <base href="/applications/">
      <base href="https://attacker.example/ignored/">
    </head><body>
      <p>Apply with OTP: 123456 and user@example.com
        <a href="form?id=FORM-1&utm_source=mail">Apply now</a>
      </p>
      <a href="//cdn.official.example/files/guide.pdf">Guide</a>
      <a href="mailto:team@official.example">Email</a>
      <a href="https://user:password@official.example/private">Credential URL</a>
    </body></html>
    """

    result = OfficialHtmlLinkExtractor().extract(
        _html_document(html),
        accepted_identities=[_domain_identity()],
    )

    assert result.identity_assessment.status is FinalPageIdentityStatus.ACCEPTED
    assert [item.canonical_url for item in result.links] == [
        "https://official.example/applications/form?id=FORM-1",
        "https://cdn.official.example/files/guide.pdf",
    ]
    assert result.links[0].anchor_text == "Apply now"
    assert "123456" not in (result.links[0].context_text or "")
    assert "user@example.com" not in (result.links[0].context_text or "")
    assert result.links[0].extraction_method is LinkExtractionMethod.HTML_ANCHOR
    assert result.links[0].evidence_strength is LinkEvidenceStrength.DIRECT_OFFICIAL_PAGE
    serialized = result.model_dump(mode="json")
    assert all("fetch_url" not in item for item in serialized["links"])
    assert "<html" not in result.model_dump_json().casefold()


def test_malformed_html_is_deterministic_deduped_and_text_is_bounded() -> None:
    long_anchor = "A" * 300
    long_context = "context " * 200
    html = (
        f"<div>{long_context}<a href='/form?b=2&a=1'>{long_anchor}"
        "<a href='/form?a=1&b=2'>duplicate canonical"
        "<a href='/second'>second"
    )
    identity = _domain_identity()

    first = OfficialHtmlLinkExtractor().extract(
        _html_document(html),
        accepted_identities=[identity],
    )
    second = OfficialHtmlLinkExtractor().extract(
        _html_document(html),
        accepted_identities=[identity],
    )

    assert first == second
    assert len(first.links) == 2
    assert len(first.links[0].anchor_text or "") == 200
    assert len(first.links[0].context_text or "") <= 500
    assert first.source_ref.startswith("source:")
    assert all(item.source_ref == first.source_ref for item in first.links)
    assert all(len(item.content_hash) == 64 for item in first.links)


def test_redirected_final_page_is_reclassified_before_content_is_trusted() -> None:
    result = OfficialHtmlLinkExtractor().extract(
        _html_document(
            "<a href='https://forms.example/apply'>Apply</a>",
            final_url="https://attacker.example/copied-official-page",
            redirect_chain=[
                "https://official.example/notices/recruitment",
                "https://attacker.example/copied-official-page",
            ],
        ),
        accepted_identities=[_domain_identity()],
    )

    assert result.identity_assessment.status is FinalPageIdentityStatus.REJECTED
    assert result.identity_assessment.reason_code == "redirected_outside_reviewed_identity"
    assert result.links == []
    assert result.maximum_status is VerificationStatusV4.UNVERIFIED
    assert result.limitation == "final_page_identity_not_accepted"


def test_html_extraction_is_bounded_to_fifty_unique_links() -> None:
    html = "".join(f"<a href='/resource/{index}'>Resource {index}</a>" for index in range(60))

    result = OfficialHtmlLinkExtractor().extract(
        _html_document(html),
        accepted_identities=[_domain_identity()],
    )

    assert len(result.links) == 50
    assert result.links[0].canonical_url.endswith("/resource/0")
    assert result.links[-1].canonical_url.endswith("/resource/49")


def test_linkedin_bitly_forms_gle_google_forms_chain_matches_by_provider_id() -> None:
    linkedin = "https://www.linkedin.com/company/example-university/"
    extracted = OfficialHtmlLinkExtractor().extract(
        _html_document(
            "<article>Recruitment <a href='https://bit.ly/example-apply'>Apply</a></article>",
            final_url=linkedin,
        ),
        accepted_identities=[_url_identity(linkedin)],
    )
    official_chain = [
        extracted.links[0].fetch_url,
        "https://forms.gle/ShortAlias",
        "https://docs.google.com/forms/d/e/FORM-ABC/viewform?usp=sf_link",
    ]
    user_chain = [
        "https://forms.gle/UserAlias",
        "https://docs.google.com/forms/d/e/FORM-ABC/viewform?usp=sharing",
    ]

    matched = match_resource_chains(user_chain, official_chain)

    assert identify_resource("https://bit.ly/example-apply") is None
    assert identify_resource("https://forms.gle/ShortAlias") is None
    assert matched.status is ResourceMatchStatusV4.EXACT_RESOURCE
    assert matched.reason_code == "same_provider_resource_id"
    assert matched.user_resource is not None
    assert matched.user_resource.resource_type is ResourceTypeV4.GOOGLE_FORM
    assert matched.user_resource.resource_id == "FORM-ABC"


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (
            "https://forms.office.com/r/MICROSOFT-ID",
            "https://forms.microsoft.com/Pages/ResponsePage.aspx?id=MICROSOFT-ID&origin=lprLink",
        ),
        (
            "https://forms.microsoft.com/e/MICROSOFT-ID",
            "https://forms.office.com/Pages/ResponsePage.aspx?id=MICROSOFT-ID",
        ),
        (
            "https://forms.cloud.microsoft/r/MICROSOFT-ID",
            "https://forms.office.com/Pages/ResponsePage.aspx?id=MICROSOFT-ID",
        ),
    ],
)
def test_microsoft_forms_aliases_match_by_provider_id(left: str, right: str) -> None:
    matched = match_resources(identify_resource(left), identify_resource(right))

    assert matched.status is ResourceMatchStatusV4.EXACT_RESOURCE
    assert matched.user_resource is not None
    assert matched.user_resource.resource_type is ResourceTypeV4.MICROSOFT_FORM


def test_different_forms_and_same_domain_different_paths_never_match() -> None:
    different_google_forms = match_resources(
        identify_resource("https://docs.google.com/forms/d/e/FORM-ONE/viewform"),
        identify_resource("https://docs.google.com/forms/d/e/FORM-TWO/viewform"),
    )
    same_domain_different_resource = match_resources(
        identify_resource("https://files.example/download/one"),
        identify_resource("https://files.example/download/two"),
    )
    unresolved_shortener = match_resources(
        identify_resource_chain(["https://bit.ly/unresolved"]),
        identify_resource("https://docs.google.com/forms/d/e/FORM-ONE/viewform"),
    )

    assert different_google_forms.status is ResourceMatchStatusV4.DIFFERENT_RESOURCE
    assert same_domain_different_resource.status is ResourceMatchStatusV4.DIFFERENT_RESOURCE
    assert same_domain_different_resource.reason_code == "different_canonical_url"
    assert unresolved_shortener.status is ResourceMatchStatusV4.UNRESOLVED


def test_generic_resource_matches_only_exact_canonical_url_not_raw_query_order() -> None:
    matched = match_resources(
        identify_resource("https://files.example/download?id=1&b=2&utm_source=mail"),
        identify_resource("https://files.example/download?b=2&id=1"),
    )
    percent_encoded_google = match_resources(
        identify_resource("https://docs.google.com/forms/u/0/d/e/FORM-%41/viewform"),
        identify_resource("https://docs.google.com/forms/d/e/FORM-A/viewform"),
    )

    assert matched.status is ResourceMatchStatusV4.EXACT_CANONICAL_URL
    assert percent_encoded_google.status is ResourceMatchStatusV4.EXACT_RESOURCE


def test_provider_fallback_requires_explicit_url_and_caps_evidence_at_partial() -> None:
    candidate = "https://forms.example/apply?id=FORM-1&token=fixture-secret"
    document = ExtractedWebDocument(
        url="https://official.example/notices/recruitment",
        title="Recruitment",
        content=f"The application is available at {candidate} for this intake.",
    )

    result = extract_provider_fallback_link(
        document,
        candidate,
        accepted_identities=[_domain_identity()],
        direct_fetch_limitation=VerificationTransportLimitation.PROVIDER_ERROR,
    )

    assert len(result.links) == 1
    assert result.maximum_status is VerificationStatusV4.PARTIALLY_VERIFIED
    assert result.links[0].evidence_strength is LinkEvidenceStrength.PROVIDER_FALLBACK_PARTIAL
    assert result.links[0].display_url == "https://forms.example/apply?id=FORM-1"
    serialized = result.model_dump_json()
    assert "fixture-secret" not in serialized
    assert candidate not in serialized


def test_provider_fallback_rejects_non_explicit_candidate_and_security_block() -> None:
    document = ExtractedWebDocument(
        url="https://official.example/notices/recruitment",
        content="Apply using the form linked from the announcement.",
    )
    missing = extract_provider_fallback_link(
        document,
        "https://forms.example/apply",
        accepted_identities=[_domain_identity()],
        direct_fetch_limitation=VerificationTransportLimitation.PROVIDER_ERROR,
    )
    blocked = extract_provider_fallback_link(
        document.model_copy(update={"content": "https://forms.example/apply"}),
        "https://forms.example/apply",
        accepted_identities=[_domain_identity()],
        direct_fetch_limitation=VerificationTransportLimitation.SSRF_BLOCKED,
    )

    assert missing.links == []
    assert missing.limitation == "candidate_not_explicit_in_provider_extract"
    assert blocked.links == []
    assert blocked.limitation == "direct_failure_not_fallback_eligible"
    assert blocked.maximum_status is VerificationStatusV4.UNVERIFIED
