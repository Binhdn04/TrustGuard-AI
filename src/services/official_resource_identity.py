from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from enum import StrEnum
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from pydantic import Field, model_validator

from src.agents.tools.models import ToolContractModel
from src.models import (
    OfficialIdentityMatchScopeV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    ResourceIdentityV4,
    ResourceMatchStatusV4,
    ResourceMatchV4,
    ResourceTypeV4,
    VerificationStatusV4,
)
from src.services.official_verification_transport import (
    ExtractedWebDocument,
    FetchedHtml,
    VerificationTransportLimitation,
)

_MAX_URL_LENGTH = 4096
_MAX_PERSISTED_URL_LENGTH = 2048
_MAX_LINKS = 50
_MAX_ANCHOR_LENGTH = 200
_MAX_CONTEXT_LENGTH = 500
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_FORBIDDEN_SCHEMES = frozenset({"javascript", "data", "mailto"})
_TRACKING_QUERY_KEYS = frozenset(
    {
        "_hsenc",
        "_hsmi",
        "dclid",
        "fbclid",
        "gclid",
        "igshid",
        "mc_cid",
        "mc_eid",
        "mkt_tok",
        "msclkid",
        "origin",
        "rb_clickid",
        "s_cid",
        "usp",
        "vero_conv",
        "vero_id",
        "yclid",
    }
)
_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "code",
        "credential",
        "jwt",
        "otp",
        "passcode",
        "passwd",
        "password",
        "secret",
        "signature",
        "token",
        "x-amz-credential",
        "x-amz-signature",
    }
)
_SENSITIVE_QUERY_SUFFIXES = (
    "_api_key",
    "_credential",
    "_otp",
    "_passcode",
    "_passwd",
    "_password",
    "_secret",
    "_signature",
    "_token",
)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
_LABELED_SECRET_RE = re.compile(r"(?i)\b(?:otp|password|passcode|token|secret|api[_ -]?key|credential)\s*[:=]?\s*\S+")
_PERCENT_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_INVALID_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_GOOGLE_FORM_PATH_RE = re.compile(
    r"^/forms/(?:u/\d+/)?d/(?:e/)?([^/]+)(?:/|$)",
    re.IGNORECASE,
)
_MICROSOFT_FORM_PATH_RE = re.compile(r"^/(?:r|e)/([^/?#]+)(?:/|$)", re.IGNORECASE)
_REDIRECT_ONLY_HOSTS = frozenset({"bit.ly", "bitly.com", "forms.gle", "aka.ms"})
_DIRECT_FALLBACK_LIMITATIONS = frozenset(
    {
        VerificationTransportLimitation.PROVIDER_TIMEOUT,
        VerificationTransportLimitation.RATE_LIMITED,
        VerificationTransportLimitation.PROVIDER_ERROR,
        VerificationTransportLimitation.RESPONSE_TOO_LARGE,
        VerificationTransportLimitation.UNSUPPORTED_CONTENT_TYPE,
    }
)


class UrlNormalizationError(ValueError):
    pass


class LinkExtractionMethod(StrEnum):
    HTML_ANCHOR = "html_anchor"
    PROVIDER_EXPLICIT_URL = "provider_explicit_url"


class LinkEvidenceStrength(StrEnum):
    DIRECT_OFFICIAL_PAGE = "direct_official_page"
    PROVIDER_FALLBACK_PARTIAL = "provider_fallback_partial"


class FinalPageIdentityStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


class VerificationUrl(ToolContractModel):
    fetch_url: str = Field(max_length=_MAX_URL_LENGTH, exclude=True, repr=False)
    display_url: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)
    canonical_url: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)
    match_key: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)


class FinalPageIdentityAssessment(ToolContractModel):
    status: FinalPageIdentityStatus
    final_display_url: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)
    final_canonical_url: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)
    reason_code: str = Field(pattern=r"^[a-z0-9_]+$")
    identity_id: str | None = None


class ExtractedOfficialLink(ToolContractModel):
    link_ref: str = Field(pattern=r"^link:[a-f0-9]{16}$")
    source_ref: str = Field(pattern=r"^source:[a-f0-9]{16}$")
    fetch_url: str = Field(max_length=_MAX_URL_LENGTH, exclude=True, repr=False)
    display_url: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)
    canonical_url: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)
    anchor_text: str | None = Field(default=None, max_length=_MAX_ANCHOR_LENGTH)
    context_text: str | None = Field(default=None, max_length=_MAX_CONTEXT_LENGTH)
    extraction_method: LinkExtractionMethod
    evidence_strength: LinkEvidenceStrength
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    resource: ResourceIdentityV4 | None = None


class OfficialPageExtraction(ToolContractModel):
    source_ref: str = Field(pattern=r"^source:[a-f0-9]{16}$")
    source_display_url: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)
    source_canonical_url: str = Field(max_length=_MAX_PERSISTED_URL_LENGTH)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    identity_assessment: FinalPageIdentityAssessment
    links: list[ExtractedOfficialLink] = Field(default_factory=list, max_length=_MAX_LINKS)
    maximum_status: VerificationStatusV4
    limitation: str | None = Field(default=None, pattern=r"^[a-z0-9_]+$")

    @model_validator(mode="after")
    def validate_trust_boundary(self) -> OfficialPageExtraction:
        if self.identity_assessment.status is not FinalPageIdentityStatus.ACCEPTED and self.links:
            raise ValueError("unaccepted final page identity cannot yield trusted links")
        if self.links and self.limitation is not None:
            raise ValueError("successful link extraction cannot contain a limitation")
        if not self.links and self.limitation is None:
            raise ValueError("empty link extraction requires a limitation")
        return self


def _is_sensitive_query_key(key: str) -> bool:
    folded = key.casefold().replace("-", "_")
    return (
        folded.startswith("utm_")
        or folded in _TRACKING_QUERY_KEYS
        or folded in _SENSITIVE_QUERY_KEYS
        or folded.endswith(_SENSITIVE_QUERY_SUFFIXES)
    )


def _normalize_percent_encoding(value: str, *, safe: str) -> str:
    if _INVALID_PERCENT_RE.search(value):
        raise UrlNormalizationError("URL contains an invalid percent escape")

    def replace(match: re.Match[str]) -> str:
        byte = int(match.group(1), 16)
        character = chr(byte)
        return character if character in _UNRESERVED else f"%{byte:02X}"

    normalized = _PERCENT_ESCAPE_RE.sub(replace, value)
    return quote(normalized, safe=f"{safe}%")


def _bounded_url(value: str) -> str:
    if len(value) > _MAX_PERSISTED_URL_LENGTH:
        raise UrlNormalizationError("normalized URL exceeds the persisted boundary")
    return value


def normalize_verification_url(raw_url: str, *, base_url: str | None = None) -> VerificationUrl:
    candidate = raw_url.strip()
    if not candidate or len(candidate) > _MAX_URL_LENGTH:
        raise UrlNormalizationError("URL is empty or too long")
    if base_url is not None:
        candidate = urljoin(base_url, candidate)
    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.casefold()
        if scheme in _FORBIDDEN_SCHEMES or scheme not in {"http", "https"}:
            raise UrlNormalizationError("only absolute HTTP(S) URLs are accepted")
        if parsed.username is not None or parsed.password is not None:
            raise UrlNormalizationError("URLs containing credentials are rejected")
        if not parsed.hostname:
            raise UrlNormalizationError("URL host is required")
        host = parsed.hostname.encode("idna").decode("ascii").casefold().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, UrlNormalizationError):
            raise
        raise UrlNormalizationError("URL is malformed") from exc

    default_port = (scheme == "http" and port in {None, 80}) or (scheme == "https" and port in {None, 443})
    display_host = f"[{host}]" if ":" in host else host
    authority = display_host if default_port else f"{display_host}:{port}"
    fetch_path = parsed.path or "/"
    fetch_url = urlunsplit((scheme, authority, fetch_path, parsed.query, ""))

    canonical_path = _normalize_percent_encoding(fetch_path, safe="/:@-._~!$&'()*+,;=")
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
    persisted_pairs = [(key, value) for key, value in query_pairs if not _is_sensitive_query_key(key)]
    display_query = urlencode(persisted_pairs, doseq=True)
    canonical_query = urlencode(sorted(persisted_pairs), doseq=True)
    display_url = _bounded_url(urlunsplit((scheme, authority, canonical_path, display_query, "")))
    canonical_url = _bounded_url(urlunsplit((scheme, authority, canonical_path, canonical_query, "")))
    return VerificationUrl(
        fetch_url=fetch_url,
        display_url=display_url,
        canonical_url=canonical_url,
        match_key=f"url-v1:{canonical_url}",
    )


def _safe_text(value: str, maximum: int) -> str | None:
    cleaned = " ".join(value.split())
    cleaned = _URL_RE.sub("[redacted-url]", cleaned)
    cleaned = _EMAIL_RE.sub("[redacted-email]", cleaned)
    cleaned = _LABELED_SECRET_RE.sub("[redacted-secret]", cleaned)
    bounded = cleaned[:maximum].strip()
    return bounded or None


def _hash(value: str | bytes) -> str:
    payload = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _reference(prefix: str, value: str) -> str:
    return f"{prefix}:{_hash(value)[:16]}"


def _identity_url(identity: OfficialIdentityV4) -> VerificationUrl | None:
    candidate = identity.canonical_value
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        return normalize_verification_url(candidate)
    except UrlNormalizationError:
        return None


def assess_final_page_identity(
    final_url: str,
    accepted_identities: Sequence[OfficialIdentityV4],
) -> FinalPageIdentityAssessment:
    normalized = normalize_verification_url(final_url)
    final = urlsplit(normalized.canonical_url)
    reviewed = [identity for identity in accepted_identities if identity.reviewed]
    if not reviewed:
        return FinalPageIdentityAssessment(
            status=FinalPageIdentityStatus.UNRESOLVED,
            final_display_url=normalized.display_url,
            final_canonical_url=normalized.canonical_url,
            reason_code="no_reviewed_identity",
        )

    for identity in reviewed:
        identity_url = _identity_url(identity)
        if identity_url is None:
            continue
        expected = urlsplit(identity_url.canonical_url)
        host_scoped = identity.match_scope is OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS or (
            identity.identity_type in {OfficialIdentityTypeV4.PRIMARY_WEBSITE, OfficialIdentityTypeV4.DOMAIN}
        )
        if host_scoped and (final.hostname == expected.hostname or final.hostname.endswith(f".{expected.hostname}")):
            return FinalPageIdentityAssessment(
                status=FinalPageIdentityStatus.ACCEPTED,
                final_display_url=normalized.display_url,
                final_canonical_url=normalized.canonical_url,
                reason_code="reviewed_host_identity",
                identity_id=str(identity.identity_id),
            )
        final_without_query = urlunsplit((final.scheme, final.netloc, final.path, "", ""))
        expected_without_query = urlunsplit((expected.scheme, expected.netloc, expected.path, "", ""))
        if final_without_query == expected_without_query:
            return FinalPageIdentityAssessment(
                status=FinalPageIdentityStatus.ACCEPTED,
                final_display_url=normalized.display_url,
                final_canonical_url=normalized.canonical_url,
                reason_code="reviewed_exact_url_identity",
                identity_id=str(identity.identity_id),
            )

    return FinalPageIdentityAssessment(
        status=FinalPageIdentityStatus.REJECTED,
        final_display_url=normalized.display_url,
        final_canonical_url=normalized.canonical_url,
        reason_code="redirected_outside_reviewed_identity",
    )


def identify_resource(url: str) -> ResourceIdentityV4 | None:
    try:
        normalized = normalize_verification_url(url)
    except UrlNormalizationError:
        return None
    parsed = urlsplit(normalized.canonical_url)
    host = (parsed.hostname or "").casefold()
    path = parsed.path or "/"
    if host in _REDIRECT_ONLY_HOSTS:
        return None

    if host in {"docs.google.com", "forms.google.com"}:
        match = _GOOGLE_FORM_PATH_RE.match(path)
        if match:
            resource_id = match.group(1)
            return ResourceIdentityV4(
                resource_type=ResourceTypeV4.GOOGLE_FORM,
                provider="google_forms",
                resource_id=resource_id,
                canonical_url=normalized.canonical_url,
                match_key=f"google-forms-v1:{resource_id}",
            )

    if host in {"forms.cloud.microsoft", "forms.office.com", "forms.microsoft.com"}:
        match = _MICROSOFT_FORM_PATH_RE.match(path)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        resource_id = match.group(1) if match else query.get("id")
        if resource_id:
            return ResourceIdentityV4(
                resource_type=ResourceTypeV4.MICROSOFT_FORM,
                provider="microsoft_forms",
                resource_id=resource_id,
                canonical_url=normalized.canonical_url,
                match_key=f"microsoft-forms-v1:{resource_id}",
            )

    return ResourceIdentityV4(
        resource_type=ResourceTypeV4.URL,
        canonical_url=normalized.canonical_url,
        match_key=normalized.match_key,
    )


def identify_resource_chain(redirect_chain: Sequence[str]) -> ResourceIdentityV4 | None:
    if not redirect_chain:
        return None
    return identify_resource(redirect_chain[-1])


def match_resources(
    user_resource: ResourceIdentityV4 | None,
    official_resource: ResourceIdentityV4 | None,
) -> ResourceMatchV4:
    if user_resource is None or official_resource is None:
        return ResourceMatchV4(
            status=ResourceMatchStatusV4.UNRESOLVED,
            user_resource=user_resource,
            official_resource=official_resource,
            reason_code="redirect_chain_unresolved",
        )
    provider_identity = (
        user_resource.provider is not None
        and official_resource.provider is not None
        and user_resource.resource_id is not None
        and official_resource.resource_id is not None
    )
    if provider_identity and user_resource.provider == official_resource.provider:
        same_resource = user_resource.resource_id == official_resource.resource_id
        return ResourceMatchV4(
            status=(
                ResourceMatchStatusV4.EXACT_RESOURCE if same_resource else ResourceMatchStatusV4.DIFFERENT_RESOURCE
            ),
            user_resource=user_resource,
            official_resource=official_resource,
            reason_code=("same_provider_resource_id" if same_resource else "different_provider_resource_id"),
        )
    if user_resource.canonical_url == official_resource.canonical_url:
        return ResourceMatchV4(
            status=ResourceMatchStatusV4.EXACT_CANONICAL_URL,
            user_resource=user_resource,
            official_resource=official_resource,
            reason_code="same_canonical_url",
        )
    return ResourceMatchV4(
        status=ResourceMatchStatusV4.DIFFERENT_RESOURCE,
        user_resource=user_resource,
        official_resource=official_resource,
        reason_code="different_canonical_url",
    )


def match_resource_chains(
    user_redirect_chain: Sequence[str],
    official_redirect_chain: Sequence[str],
) -> ResourceMatchV4:
    return match_resources(
        identify_resource_chain(user_redirect_chain),
        identify_resource_chain(official_redirect_chain),
    )


class OfficialHtmlLinkExtractor:
    def extract(
        self,
        document: FetchedHtml,
        *,
        accepted_identities: Sequence[OfficialIdentityV4],
    ) -> OfficialPageExtraction:
        assessment = assess_final_page_identity(document.final_url, accepted_identities)
        content_hash = _hash(document.body)
        source_ref = _reference(
            "source",
            f"{assessment.final_canonical_url}|{content_hash}",
        )
        if assessment.status is not FinalPageIdentityStatus.ACCEPTED:
            return OfficialPageExtraction(
                source_ref=source_ref,
                source_display_url=assessment.final_display_url,
                source_canonical_url=assessment.final_canonical_url,
                content_hash=content_hash,
                identity_assessment=assessment,
                maximum_status=VerificationStatusV4.UNVERIFIED,
                limitation="final_page_identity_not_accepted",
            )

        soup = BeautifulSoup(document.body, "html.parser")
        base_url = document.final_url
        for base in soup.find_all("base", href=True):
            href = base.get("href")
            if not isinstance(href, str):
                continue
            try:
                base_url = normalize_verification_url(href, base_url=document.final_url).fetch_url
                break
            except UrlNormalizationError:
                continue

        links: list[ExtractedOfficialLink] = []
        seen: set[str] = set()
        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href")
            if not isinstance(href, str):
                continue
            try:
                normalized = normalize_verification_url(href, base_url=base_url)
            except UrlNormalizationError:
                continue
            if normalized.canonical_url in seen:
                continue
            seen.add(normalized.canonical_url)
            occurrence = len(links)
            parent_text = anchor.parent.get_text(" ", strip=True) if anchor.parent is not None else ""
            links.append(
                ExtractedOfficialLink(
                    link_ref=_reference(
                        "link",
                        f"{source_ref}|{normalized.canonical_url}|{occurrence}",
                    ),
                    source_ref=source_ref,
                    fetch_url=normalized.fetch_url,
                    display_url=normalized.display_url,
                    canonical_url=normalized.canonical_url,
                    anchor_text=_safe_text(anchor.get_text(" ", strip=True), _MAX_ANCHOR_LENGTH),
                    context_text=_safe_text(parent_text, _MAX_CONTEXT_LENGTH),
                    extraction_method=LinkExtractionMethod.HTML_ANCHOR,
                    evidence_strength=LinkEvidenceStrength.DIRECT_OFFICIAL_PAGE,
                    content_hash=content_hash,
                    resource=identify_resource(normalized.fetch_url),
                )
            )
            if len(links) == _MAX_LINKS:
                break

        return OfficialPageExtraction(
            source_ref=source_ref,
            source_display_url=assessment.final_display_url,
            source_canonical_url=assessment.final_canonical_url,
            content_hash=content_hash,
            identity_assessment=assessment,
            links=links,
            maximum_status=VerificationStatusV4.VERIFIED,
            limitation=None if links else "no_valid_outbound_links",
        )


def extract_provider_fallback_link(
    document: ExtractedWebDocument,
    candidate_url: str,
    *,
    accepted_identities: Sequence[OfficialIdentityV4],
    direct_fetch_limitation: VerificationTransportLimitation,
) -> OfficialPageExtraction:
    assessment = assess_final_page_identity(document.url, accepted_identities)
    content_hash = _hash(document.content)
    source_ref = _reference("source", f"{assessment.final_canonical_url}|{content_hash}")

    limitation: str | None = None
    candidate: VerificationUrl | None = None
    if direct_fetch_limitation not in _DIRECT_FALLBACK_LIMITATIONS:
        limitation = "direct_failure_not_fallback_eligible"
    elif assessment.status is not FinalPageIdentityStatus.ACCEPTED:
        limitation = "final_page_identity_not_accepted"
    else:
        try:
            candidate = normalize_verification_url(candidate_url)
        except UrlNormalizationError:
            limitation = "fallback_candidate_invalid"

    matched_url: re.Match[str] | None = None
    if limitation is None and candidate is not None:
        for match in _URL_RE.finditer(document.content):
            literal = match.group(0).rstrip(".,);]}")
            try:
                extracted = normalize_verification_url(literal)
            except UrlNormalizationError:
                continue
            if extracted.canonical_url == candidate.canonical_url:
                matched_url = match
                break
        if matched_url is None:
            limitation = "candidate_not_explicit_in_provider_extract"

    links: list[ExtractedOfficialLink] = []
    if limitation is None and candidate is not None and matched_url is not None:
        context_start = max(0, matched_url.start() - 200)
        context_end = min(len(document.content), matched_url.end() + 200)
        links.append(
            ExtractedOfficialLink(
                link_ref=_reference("link", f"{source_ref}|{candidate.canonical_url}|provider"),
                source_ref=source_ref,
                fetch_url=candidate.fetch_url,
                display_url=candidate.display_url,
                canonical_url=candidate.canonical_url,
                context_text=_safe_text(
                    document.content[context_start:context_end],
                    _MAX_CONTEXT_LENGTH,
                ),
                extraction_method=LinkExtractionMethod.PROVIDER_EXPLICIT_URL,
                evidence_strength=LinkEvidenceStrength.PROVIDER_FALLBACK_PARTIAL,
                content_hash=content_hash,
                resource=identify_resource(candidate.fetch_url),
            )
        )

    return OfficialPageExtraction(
        source_ref=source_ref,
        source_display_url=assessment.final_display_url,
        source_canonical_url=assessment.final_canonical_url,
        content_hash=content_hash,
        identity_assessment=assessment,
        links=links,
        maximum_status=(VerificationStatusV4.PARTIALLY_VERIFIED if links else VerificationStatusV4.UNVERIFIED),
        limitation=limitation,
    )


__all__ = [
    "ExtractedOfficialLink",
    "FinalPageIdentityAssessment",
    "FinalPageIdentityStatus",
    "LinkEvidenceStrength",
    "LinkExtractionMethod",
    "OfficialHtmlLinkExtractor",
    "OfficialPageExtraction",
    "UrlNormalizationError",
    "VerificationUrl",
    "assess_final_page_identity",
    "extract_provider_fallback_link",
    "identify_resource",
    "identify_resource_chain",
    "match_resource_chains",
    "match_resources",
    "normalize_verification_url",
]
