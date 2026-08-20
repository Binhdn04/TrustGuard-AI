from __future__ import annotations

import asyncio
import hashlib
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
from pydantic import Field, model_validator

from src.agents.tools.models import ToolContractModel
from src.models import (
    BrandRecordV4,
    ClaimVerificationV4,
    LinkRoleV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    OfficialLinkReferenceV4,
    OfficialLinkVerificationReportV4,
    OfficialSourceReferenceV4,
    PublisherVerificationV4,
    ResourceIdentityV4,
    ResourceMatchStatusV4,
    ResourceMatchV4,
    ResourceVerificationV4,
    ScopeDecisionV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    VerificationStatusV4,
    VerificationTopicV4,
)
from src.security_ai.runtime import TurnExecutionContext
from src.services.official_identity_registry import (
    BrandResolutionStatus,
    OfficialIdentityRegistry,
    SourceIdentityAssessment,
)
from src.services.official_resource_identity import (
    ExtractedOfficialLink,
    FinalPageIdentityStatus,
    LinkEvidenceStrength,
    OfficialHtmlLinkExtractor,
    OfficialPageExtraction,
    UrlNormalizationError,
    assess_final_page_identity,
    extract_provider_fallback_link,
    identify_resource,
    identify_resource_chain,
    match_resources,
    normalize_verification_url,
)
from src.services.official_verification_intent import (
    GroundedVerificationIntent,
    OfficialVerificationQueryBuilder,
    VerificationQuery,
    build_grounded_verification_intent,
)
from src.services.official_verification_transport import (
    GuardedHtmlFetcher,
    VerificationTransportLimitation,
    VerificationTransportStatus,
    WebExtractProvider,
    WebSearchProvider,
)

_MAX_SEARCH_ATTEMPTS = 4
_MAX_SEARCH_RESULTS = 5
_MAX_CANDIDATES = 8
_MAX_OFFICIAL_FETCHES = 3
_MAX_FETCH_CONCURRENCY = 2
_MAX_OUTBOUND_RESOLUTIONS = 3
_MAX_USER_ACTION_URLS = 3
_MAX_VISIBLE_TEXT = 100_000
_SOCIAL_HOSTS = frozenset(
    {
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "youtube.com",
    }
)
_IDENTITY_CONFIRMING_SOURCE_TYPES = frozenset(
    {
        "academic_institution",
        "financial_institution",
        "government",
        "government_health",
        "government_or_official",
        "healthcare_provider",
        "international_organization",
        "official_enterprise",
        "sports_governing_body",
    }
)
_FALLBACK_ELIGIBLE = frozenset(
    {
        VerificationTransportLimitation.PROVIDER_TIMEOUT,
        VerificationTransportLimitation.RATE_LIMITED,
        VerificationTransportLimitation.PROVIDER_ERROR,
        VerificationTransportLimitation.RESPONSE_TOO_LARGE,
        VerificationTransportLimitation.UNSUPPORTED_CONTENT_TYPE,
    }
)

_TOPIC_TERMS: dict[VerificationTopicV4, tuple[str, ...]] = {
    VerificationTopicV4.RECRUITMENT: ("tuyen dung", "recruitment", "career", "job opening"),
    VerificationTopicV4.PROMOTION: ("khuyen mai", "promotion", "giveaway", "prize"),
    VerificationTopicV4.EVENT: ("su kien", "event", "conference", "workshop"),
    VerificationTopicV4.COURSE: ("khoa hoc", "course", "training", "program"),
    VerificationTopicV4.SURVEY: ("khao sat", "survey", "questionnaire"),
    VerificationTopicV4.ACCOUNT: ("tai khoan", "account", "sign in", "login"),
    VerificationTopicV4.PAYMENT: ("thanh toan", "payment", "fee"),
    VerificationTopicV4.CHARITY: ("tu thien", "charity", "donation"),
    VerificationTopicV4.INVESTMENT: ("dau tu", "investment", "investor"),
    VerificationTopicV4.GENERAL_NOTICE: ("thong bao", "announcement", "notice"),
    VerificationTopicV4.UNKNOWN: (),
}
_ACTION_TERMS = {
    "login": ("dang nhap", "login", "sign in"),
    "share_otp": ("otp", "verification code"),
    "share_credentials": ("credential", "password", "dang nhap"),
    "transfer_money": ("chuyen tien", "transfer"),
    "pay_fee": ("dong phi", "payment", "fee"),
    "provide_personal_information": ("thong tin ca nhan", "personal information"),
    "open_link": ("mo lien ket", "open link"),
    "install_app": ("cai ung dung", "install", "download"),
    "share_screen": ("chia se man hinh", "share screen"),
    "scan_qr": ("quet ma", "scan qr"),
    "submit_form": ("gui bieu mau", "submit", "form"),
    "register_or_apply": ("dang ky", "ung tuyen", "register", "apply", "application"),
    "download_file": ("tai tep", "download", "file"),
}
_CONTRADICTION_TERMS = (
    "canh bao gia mao",
    "khong co chuong trinh",
    "khong lien quan",
    "khong to chuc",
    "khong tuyen dung",
    "fake announcement",
    "fraudulent",
    "not affiliated",
    "not recruiting",
    "scam warning",
)
_QUALIFIER_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_TIME_QUALIFIER_RE = re.compile(r"\b(?:20\d{2}|\d{1,2}[/-]\d{1,2}[/-]20\d{2}|thang\s+\d{1,2})\b")
_AUDIENCE_QUALIFIERS = (
    "customer",
    "employee",
    "fresh graduate",
    "khach hang",
    "nhan vien",
    "sinh vien",
    "student",
)
_ROLE_TERMS: tuple[tuple[LinkRoleV4, tuple[str, ...]], ...] = (
    (LinkRoleV4.APPLICATION, ("apply", "application", "career", "job", "ung-tuyen")),
    (LinkRoleV4.REGISTRATION, ("register", "registration", "dang-ky", "event")),
    (LinkRoleV4.FORM, ("form", "survey", "khao-sat")),
    (LinkRoleV4.DOWNLOAD, ("download", ".pdf", ".doc", ".zip", "tai-tep")),
    (LinkRoleV4.LOGIN, ("login", "signin", "sign-in", "dang-nhap")),
    (LinkRoleV4.PAYMENT, ("payment", "pay", "checkout", "thanh-toan")),
    (LinkRoleV4.CONTACT, ("contact", "lien-he")),
)
_ACTION_ROLES = {
    "login": frozenset({LinkRoleV4.LOGIN}),
    "transfer_money": frozenset({LinkRoleV4.PAYMENT}),
    "pay_fee": frozenset({LinkRoleV4.PAYMENT}),
    "install_app": frozenset({LinkRoleV4.DOWNLOAD}),
    "submit_form": frozenset({LinkRoleV4.FORM, LinkRoleV4.APPLICATION, LinkRoleV4.REGISTRATION}),
    "register_or_apply": frozenset({LinkRoleV4.APPLICATION, LinkRoleV4.REGISTRATION, LinkRoleV4.FORM}),
    "download_file": frozenset({LinkRoleV4.DOWNLOAD}),
}


class OfficialBrandRepository(Protocol):
    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]: ...


class ReviewedSourceRegistry(Protocol):
    def matching_entries(self, url: str, at: datetime) -> Sequence[object]: ...


class ComparisonRelation(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    INSUFFICIENT = "insufficient"


class ComparisonDimension(StrEnum):
    ORGANIZATION = "organization"
    TOPIC = "topic"
    ACTION = "action"
    TIME = "time"
    AUDIENCE = "audience"


class VerificationComparisonOutput(ToolContractModel):
    source_ids: list[str] = Field(default_factory=list, max_length=20)
    link_ids: list[str] = Field(default_factory=list, max_length=50)
    relation: ComparisonRelation
    matched_dimensions: list[ComparisonDimension] = Field(default_factory=list, max_length=5)
    link_roles: dict[str, LinkRoleV4] = Field(default_factory=dict, max_length=50)

    @model_validator(mode="after")
    def validate_id_shapes(self) -> VerificationComparisonOutput:
        if any(re.fullmatch(r"source:[a-f0-9]{16}", value) is None for value in self.source_ids):
            raise ValueError("comparison source IDs must be bounded source refs")
        if any(re.fullmatch(r"link:[a-f0-9]{16}", value) is None for value in self.link_ids):
            raise ValueError("comparison link IDs must be bounded link refs")
        if set(self.link_roles) - set(self.link_ids):
            raise ValueError("comparison link roles require returned link IDs")
        return self


def validate_comparison_output(
    output: VerificationComparisonOutput,
    *,
    available_source_ids: set[str],
    available_link_ids: set[str],
) -> VerificationComparisonOutput | None:
    if set(output.source_ids) - available_source_ids:
        return None
    if set(output.link_ids) - available_link_ids:
        return None
    if set(output.link_roles) - available_link_ids:
        return None
    return output


class OfficialVerificationCoordinatorOutcome(ToolContractModel):
    report: OfficialLinkVerificationReportV4 | None = None
    adapter_attempts: int = Field(default=0, ge=0)
    search_attempts: int = Field(default=0, ge=0, le=_MAX_SEARCH_ATTEMPTS)
    candidate_count: int = Field(default=0, ge=0, le=_MAX_CANDIDATES)
    official_fetches: int = Field(default=0, ge=0, le=_MAX_OFFICIAL_FETCHES)
    outbound_resolutions: int = Field(default=0, ge=0, le=_MAX_OUTBOUND_RESOLUTIONS)
    early_stop_reason: str | None = Field(default=None, pattern=r"^[a-z0-9_]+$")
    limitations: list[str] = Field(default_factory=list, max_length=50)


@dataclass(frozen=True, slots=True)
class _Candidate:
    fetch_url: str
    canonical_url: str
    identity: OfficialIdentityV4


@dataclass(frozen=True, slots=True)
class _PageEvidence:
    extraction: OfficialPageExtraction
    visible_text: str


@dataclass(frozen=True, slots=True)
class _LinkEvidence:
    extracted: ExtractedOfficialLink
    public: OfficialLinkReferenceV4


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _fold(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    return " ".join(
        "".join(character for character in decomposed if not unicodedata.combining(character)).replace("đ", "d").split()
    )


def _ref(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode()).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _identity_url(identity: OfficialIdentityV4) -> str | None:
    candidate = identity.canonical_value
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        return normalize_verification_url(candidate).fetch_url
    except UrlNormalizationError:
        return None


def _local_source(identity: OfficialIdentityV4) -> OfficialSourceReferenceV4 | None:
    candidate = _identity_url(identity)
    if candidate is None:
        return None
    normalized = normalize_verification_url(candidate)
    source_ref = _ref("source", str(identity.identity_id), identity.policy_version)
    linked_identity = identity.model_copy(update={"source_ref": source_ref})
    return OfficialSourceReferenceV4(
        source_ref=source_ref,
        identity=linked_identity,
        display_url=normalized.display_url,
        canonical_url=normalized.canonical_url,
    )


def _link_role(link: ExtractedOfficialLink) -> LinkRoleV4:
    host = (urlsplit(link.canonical_url).hostname or "").casefold()
    if any(host == social or host.endswith(f".{social}") for social in _SOCIAL_HOSTS):
        return LinkRoleV4.SOCIAL_PROFILE
    haystack = _fold(
        " ".join(
            filter(
                None,
                (link.anchor_text, link.context_text, urlsplit(link.canonical_url).path),
            )
        )
    )
    for role, terms in _ROLE_TERMS:
        if any(term in haystack for term in terms):
            return role
    return LinkRoleV4.OTHER


def _role_is_relevant(role: LinkRoleV4, intent: GroundedVerificationIntent) -> bool:
    action = intent.contract.requested_action
    if action is None:
        return False
    allowed = _ACTION_ROLES.get(action.value)
    if allowed is None:
        return action.value == "open_link" or role is LinkRoleV4.OTHER
    return role in allowed


def _visible_html_text(body: bytes) -> str:
    soup = BeautifulSoup(body, "html.parser")
    for element in soup(["script", "style", "noscript"]):
        element.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())[:_MAX_VISIBLE_TEXT]


def _claim_dimensions(
    intent: GroundedVerificationIntent,
    page: _PageEvidence,
    qualifiers: Sequence[str] = (),
) -> tuple[bool, bool, bool, bool]:
    text = _fold(page.visible_text)
    contradiction = any(term in text for term in _CONTRADICTION_TERMS)
    topic = intent.contract.topic
    if topic is None:
        claim_tokens = {token for token in _fold(intent.contract.claim_summary or "").split() if len(token) >= 4}
        topic_match = bool(claim_tokens) and len(claim_tokens & set(text.split())) >= min(2, len(claim_tokens))
    else:
        topic_match = any(term in text for term in _TOPIC_TERMS[topic])
    action = intent.contract.requested_action
    action_match = action is None or any(term in text for term in _ACTION_TERMS[action.value])
    if action is not None and not action_match:
        action_match = any(_role_is_relevant(_link_role(link), intent) for link in page.extraction.links)
    qualifiers_match = all(qualifier in text for qualifier in qualifiers)
    return topic_match, action_match, qualifiers_match, contradiction


def _claim_qualifiers(message: str) -> tuple[str, ...]:
    without_urls = _QUALIFIER_URL_RE.sub(" ", message)
    folded = _fold(without_urls)
    qualifiers = list(_TIME_QUALIFIER_RE.findall(folded))
    qualifiers.extend(term for term in _AUDIENCE_QUALIFIERS if term in folded)
    return tuple(dict.fromkeys(qualifiers))


class OfficialLinkVerificationCoordinator:
    policy_version = "official-link-verification-v1"

    def __init__(
        self,
        brand_repository: OfficialBrandRepository,
        *,
        search: WebSearchProvider | None = None,
        extract: WebExtractProvider | None = None,
        fetcher: GuardedHtmlFetcher | None = None,
        source_registry: ReviewedSourceRegistry | None = None,
        identity_registry: OfficialIdentityRegistry | None = None,
        query_builder: OfficialVerificationQueryBuilder | None = None,
        html_extractor: OfficialHtmlLinkExtractor | None = None,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self._brands = brand_repository
        self._search = search
        self._extract = extract
        self._fetcher = fetcher
        self._source_registry = source_registry
        self._identities = identity_registry or OfficialIdentityRegistry()
        self._queries = query_builder or OfficialVerificationQueryBuilder()
        self._html = html_extractor or OfficialHtmlLinkExtractor()
        self._clock = clock

    async def verify(
        self,
        request: SecurityTriageCreateRequestV4,
        scope: SecurityScopeResponseV4,
        *,
        execution_context: TurnExecutionContext,
    ) -> SecurityScopeResponseV4:
        outcome = await self.coordinate(request, scope, execution_context=execution_context)
        if outcome.report is None:
            return scope
        return scope.model_copy(
            update={
                "official_verification": outcome.report,
                "limitations": _unique([*scope.limitations, *outcome.limitations]),
                "tool_calls_used": scope.tool_calls_used + outcome.adapter_attempts,
            }
        )

    async def coordinate(
        self,
        request: SecurityTriageCreateRequestV4,
        scope: SecurityScopeResponseV4,
        *,
        execution_context: TurnExecutionContext,
    ) -> OfficialVerificationCoordinatorOutcome:
        if scope.scope_decision is not ScopeDecisionV4.IN_SCOPE or scope.security_context is None:
            return OfficialVerificationCoordinatorOutcome()
        intent = build_grounded_verification_intent(
            request.message,
            scope.security_context,
            scope.assistant_context,
        )
        if intent is None:
            return OfficialVerificationCoordinatorOutcome()

        now = self._clock()
        brands = await self._brands.list_active_brands(now)
        resolution = self._identities.resolve(
            intent.contract.organization_name or request.message,
            brands,
            now,
        )
        brand = resolution.brand if resolution.status is BrandResolutionStatus.RESOLVED else None
        identities = tuple(identity for identity in resolution.identities if identity.reviewed)
        limitations: list[str] = []
        local_sources = [source for identity in identities if (source := _local_source(identity)) is not None]
        publisher = self._publisher_component(
            intent,
            resolution.status,
            brand,
            identities,
            local_sources,
            now,
        )
        user_urls = self._action_urls(intent, scope)
        pages: list[_PageEvidence] = []
        candidates: list[_Candidate] = []
        candidate_keys: set[str] = set()
        fetch_cursor = 0
        official_fetches = 0
        search_attempts = 0
        adapter_attempts = 0
        early_stop_reason: str | None = None
        claim_qualifiers = _claim_qualifiers(request.message)

        def add_candidate(url: str) -> None:
            if len(candidates) >= _MAX_CANDIDATES:
                return
            try:
                normalized = normalize_verification_url(url)
            except UrlNormalizationError:
                return
            if normalized.canonical_url in candidate_keys:
                return
            for identity in identities:
                try:
                    assessment = assess_final_page_identity(url, [identity])
                except UrlNormalizationError:
                    continue
                if assessment.status is FinalPageIdentityStatus.ACCEPTED:
                    candidate_keys.add(normalized.canonical_url)
                    candidates.append(_Candidate(normalized.fetch_url, normalized.canonical_url, identity))
                    return

        local_candidate_urls = [value for identity in identities if (value := _identity_url(identity)) is not None]
        queries = self._queries.build(intent)
        online_verification_needed = (
            intent.contract.claim_summary is not None or intent.contract.topic is not None or bool(user_urls)
        )

        async def fetch_next_batch(query: VerificationQuery | None) -> None:
            nonlocal fetch_cursor, official_fetches, adapter_attempts
            remaining = _MAX_OFFICIAL_FETCHES - official_fetches
            batch = candidates[fetch_cursor : fetch_cursor + min(_MAX_FETCH_CONCURRENCY, remaining)]
            fetch_cursor += len(batch)
            if not batch:
                return
            results = await asyncio.gather(
                *(
                    self._fetch_candidate(
                        candidate,
                        intent,
                        user_urls,
                        query,
                        execution_context,
                    )
                    for candidate in batch
                )
            )
            official_fetches += len(batch)
            for page, calls, page_limitations in results:
                adapter_attempts += calls
                limitations.extend(page_limitations)
                if page is not None:
                    pages.append(page)

        if identities and online_verification_needed and request.consent.official_source_lookup:
            if self._search is not None and queries:
                for index, query in enumerate(queries[:_MAX_SEARCH_ATTEMPTS]):
                    result = await self._search.search_one(
                        query.text,
                        execution_context=execution_context,
                        max_results=_MAX_SEARCH_RESULTS,
                    )
                    search_attempts += 1
                    adapter_attempts += result.tool_calls_used
                    if result.status is VerificationTransportStatus.SUCCESS:
                        for hit in result.results[:_MAX_SEARCH_RESULTS]:
                            add_candidate(hit.url)
                    elif result.limitation is not None:
                        limitations.append(f"search_{result.limitation.value}")
                    if index == 0:
                        for url in local_candidate_urls:
                            add_candidate(url)
                    await fetch_next_batch(query)
                    early_stop_reason = self._early_stop_reason(
                        intent,
                        publisher,
                        pages,
                        user_urls,
                        claim_qualifiers,
                    )
                    if early_stop_reason is not None or official_fetches >= _MAX_OFFICIAL_FETCHES:
                        break
            else:
                if self._search is None:
                    limitations.append("official_web_search_unavailable")
                for url in local_candidate_urls:
                    add_candidate(url)

            while (
                early_stop_reason is None
                and official_fetches < _MAX_OFFICIAL_FETCHES
                and fetch_cursor < len(candidates)
            ):
                await fetch_next_batch(queries[0] if queries else None)
                early_stop_reason = self._early_stop_reason(
                    intent,
                    publisher,
                    pages,
                    user_urls,
                    claim_qualifiers,
                )
        elif identities and online_verification_needed:
            limitations.append("official_source_consent_required")

        source_refs, link_evidence = self._public_evidence(
            brand,
            identities,
            local_sources,
            pages,
        )
        claim, strong_contradiction = self._claim_component(
            intent,
            publisher,
            pages,
            claim_qualifiers,
        )
        if strong_contradiction and early_stop_reason is None:
            early_stop_reason = "strong_official_contradiction"
        resource, resource_calls, outbound_resolutions, resource_limitations = await self._resource_component(
            intent,
            user_urls,
            link_evidence,
            request.consent.external_url_lookup,
            execution_context,
        )
        adapter_attempts += resource_calls
        limitations.extend(resource_limitations)
        report = self._report(
            intent,
            publisher,
            claim,
            resource,
            source_refs,
            [item.public for item in link_evidence],
            limitations,
        )
        self._validate_reference_closure(report)
        return OfficialVerificationCoordinatorOutcome(
            report=report,
            adapter_attempts=adapter_attempts,
            search_attempts=search_attempts,
            candidate_count=len(candidates),
            official_fetches=official_fetches,
            outbound_resolutions=outbound_resolutions,
            early_stop_reason=early_stop_reason,
            limitations=_unique(limitations)[:50],
        )

    def _publisher_component(
        self,
        intent: GroundedVerificationIntent,
        resolution_status: BrandResolutionStatus,
        brand: BrandRecordV4 | None,
        identities: Sequence[OfficialIdentityV4],
        local_sources: Sequence[OfficialSourceReferenceV4],
        at: datetime,
    ) -> PublisherVerificationV4:
        if intent.contract.organization_name is None:
            return PublisherVerificationV4(
                applicable=False,
                status=None,
                reason_code="no_organization_dimension",
            )
        if resolution_status is BrandResolutionStatus.AMBIGUOUS:
            return PublisherVerificationV4(
                applicable=True,
                status=VerificationStatusV4.UNVERIFIED,
                reason_code="ambiguous_registry_identity",
            )
        if brand is None or not identities or not local_sources:
            return PublisherVerificationV4(
                applicable=True,
                status=VerificationStatusV4.UNVERIFIED,
                reason_code="reviewed_identity_not_found",
            )

        exact_source = False
        if self._source_registry is not None:
            for identity in identities:
                candidate = _identity_url(identity)
                if candidate is None:
                    continue
                for entry in self._source_registry.matching_entries(candidate, at):
                    source_type = str(getattr(entry, "source_type", "")).casefold()
                    if source_type not in _IDENTITY_CONFIRMING_SOURCE_TYPES:
                        continue
                    if (
                        self._identities.assess_source_entry(identity, brand, entry, at)
                        is SourceIdentityAssessment.CONFIRMS_IDENTITY
                    ):
                        exact_source = True
                        break
                if exact_source:
                    break
        selected_source = local_sources[0]
        return PublisherVerificationV4(
            applicable=True,
            status=VerificationStatusV4.VERIFIED,
            reason_code=("reviewed_registry_and_source_identity" if exact_source else "reviewed_exact_identity"),
            evidence_refs=[selected_source.source_ref],
            identity=selected_source.identity,
        )

    @staticmethod
    def _action_urls(
        intent: GroundedVerificationIntent,
        scope: SecurityScopeResponseV4,
    ) -> list[str]:
        context = scope.security_context
        if context is None:
            return []
        return [
            context.urls[index]
            for index in intent.contract.action_url_indices[:_MAX_USER_ACTION_URLS]
            if index < len(context.urls)
        ]

    async def _fetch_candidate(
        self,
        candidate: _Candidate,
        intent: GroundedVerificationIntent,
        user_urls: Sequence[str],
        query: VerificationQuery | None,
        execution_context: TurnExecutionContext,
    ) -> tuple[_PageEvidence | None, int, list[str]]:
        if self._fetcher is None:
            return None, 0, ["official_fetch_unavailable"]
        fetched = await self._fetcher.fetch(candidate.fetch_url, execution_context=execution_context)
        calls = fetched.tool_calls_used
        if fetched.status is VerificationTransportStatus.SUCCESS and fetched.document is not None:
            extraction = self._html.extract(
                fetched.document,
                accepted_identities=[candidate.identity],
            )
            if extraction.identity_assessment.status is not FinalPageIdentityStatus.ACCEPTED:
                return None, calls, ["final_page_identity_not_accepted"]
            return _PageEvidence(extraction, _visible_html_text(fetched.document.body)), calls, []

        limitation = fetched.limitation
        limitations = [f"official_fetch_{limitation.value}"] if limitation is not None else ["official_fetch_failed"]
        if limitation not in _FALLBACK_ELIGIBLE or self._extract is None or not user_urls:
            return None, calls, limitations
        fallback_query = query.text if query is not None else self._fallback_query(intent)
        extracted = await self._extract.extract(
            [candidate.fetch_url],
            query=fallback_query,
            execution_context=execution_context,
        )
        calls += extracted.tool_calls_used
        if extracted.status is not VerificationTransportStatus.SUCCESS:
            if extracted.limitation is not None:
                limitations.append(f"extract_{extracted.limitation.value}")
            return None, calls, limitations
        for document in extracted.documents:
            fallback_links: list[ExtractedOfficialLink] = []
            first: OfficialPageExtraction | None = None
            for user_url in user_urls:
                outcome = extract_provider_fallback_link(
                    document,
                    user_url,
                    accepted_identities=[candidate.identity],
                    direct_fetch_limitation=limitation,
                )
                if outcome.links:
                    first = first or outcome
                    fallback_links.extend(outcome.links)
            if first is not None:
                merged = first.model_copy(
                    update={
                        "links": list({item.link_ref: item for item in fallback_links}.values()),
                        "limitation": None,
                    }
                )
                return _PageEvidence(merged, document.content), calls, limitations
        limitations.append("provider_fallback_no_explicit_url")
        return None, calls, limitations

    @staticmethod
    def _fallback_query(intent: GroundedVerificationIntent) -> str:
        return " ".join(
            filter(
                None,
                (
                    intent.contract.organization_name,
                    intent.contract.topic.value if intent.contract.topic is not None else None,
                    "official",
                ),
            )
        )[:300]

    @staticmethod
    def _early_stop_reason(
        intent: GroundedVerificationIntent,
        publisher: PublisherVerificationV4,
        pages: Sequence[_PageEvidence],
        user_urls: Sequence[str],
        qualifiers: Sequence[str],
    ) -> str | None:
        for page in pages:
            topic, action, qualifiers_match, contradiction = _claim_dimensions(intent, page, qualifiers)
            if contradiction:
                return "strong_official_contradiction"
            if publisher.status is not VerificationStatusV4.VERIFIED or not (topic and action and qualifiers_match):
                continue
            for link in page.extraction.links:
                if not _role_is_relevant(_link_role(link), intent):
                    continue
                for user_url in user_urls:
                    match = match_resources(identify_resource(user_url), link.resource)
                    if match.status in {
                        ResourceMatchStatusV4.EXACT_RESOURCE,
                        ResourceMatchStatusV4.EXACT_CANONICAL_URL,
                    }:
                        return "publisher_claim_exact_resource"
        return None

    @staticmethod
    def _public_evidence(
        brand: BrandRecordV4 | None,
        identities: Sequence[OfficialIdentityV4],
        local_sources: Sequence[OfficialSourceReferenceV4],
        pages: Sequence[_PageEvidence],
    ) -> tuple[list[OfficialSourceReferenceV4], list[_LinkEvidence]]:
        by_identity = {str(identity.identity_id): identity for identity in identities}
        # Keep the publisher-cited local identity first, then every fetched
        # page cited by link refs. Additional registry descriptors are appended
        # only after reference closure has been secured within the public cap.
        sources = {local_sources[0].source_ref: local_sources[0]} if local_sources else {}
        links: dict[str, _LinkEvidence] = {}
        for page in pages:
            extraction = page.extraction
            identity_id = extraction.identity_assessment.identity_id
            identity = by_identity.get(identity_id or "")
            linked_identity = identity.model_copy(update={"source_ref": extraction.source_ref}) if identity else None
            sources[extraction.source_ref] = OfficialSourceReferenceV4(
                source_ref=extraction.source_ref,
                identity=linked_identity,
                display_url=extraction.source_display_url,
                canonical_url=extraction.source_canonical_url,
                content_hash=extraction.content_hash,
            )
        for page in pages:
            extraction = page.extraction
            for extracted in extraction.links:
                role = _link_role(extracted)
                public = OfficialLinkReferenceV4(
                    link_ref=extracted.link_ref,
                    source_ref=extracted.source_ref,
                    role=role,
                    display_url=extracted.display_url,
                    canonical_url=extracted.canonical_url,
                    resource=extracted.resource,
                )
                links[public.link_ref] = _LinkEvidence(extracted, public)
                host = (urlsplit(extracted.canonical_url).hostname or "").casefold()
                if brand is not None and any(host == social or host.endswith(f".{social}") for social in _SOCIAL_HOSTS):
                    cross_source_ref = _ref(
                        "source",
                        extraction.source_ref,
                        extracted.canonical_url,
                        "official_cross_link",
                    )
                    cross_identity = OfficialIdentityV4(
                        identity_type=OfficialIdentityTypeV4.SOCIAL_PROFILE,
                        canonical_value=extracted.canonical_url,
                        display_value=extracted.display_url,
                        entity_name=brand.name,
                        relationship="official_cross_link",
                        provenance=f"cross-link:{extraction.source_ref}",
                        policy_version="official-identity-cross-link-v1",
                        reviewed=False,
                        source_ref=cross_source_ref,
                    )
                    sources[cross_source_ref] = OfficialSourceReferenceV4(
                        source_ref=cross_source_ref,
                        identity=cross_identity,
                        display_url=extracted.display_url,
                        canonical_url=extracted.canonical_url,
                    )
        for source in local_sources[1:]:
            sources.setdefault(source.source_ref, source)
        return list(sources.values())[:20], list(links.values())[:50]

    @staticmethod
    def _claim_component(
        intent: GroundedVerificationIntent,
        publisher: PublisherVerificationV4,
        pages: Sequence[_PageEvidence],
        qualifiers: Sequence[str],
    ) -> tuple[ClaimVerificationV4, bool]:
        applicable = intent.contract.claim_summary is not None or intent.contract.topic is not None
        if not applicable:
            return (
                ClaimVerificationV4(
                    applicable=False,
                    status=None,
                    reason_code="no_claim_dimension",
                ),
                False,
            )
        if publisher.status is not VerificationStatusV4.VERIFIED:
            return (
                ClaimVerificationV4(
                    applicable=True,
                    status=VerificationStatusV4.UNVERIFIED,
                    reason_code="publisher_not_verified",
                    topic=intent.contract.topic,
                ),
                False,
            )

        supporting: list[_PageEvidence] = []
        partial: list[_PageEvidence] = []
        contradicting: list[_PageEvidence] = []
        for page in pages:
            topic, action, qualifiers_match, contradiction = _claim_dimensions(intent, page, qualifiers)
            if contradiction:
                contradicting.append(page)
            elif topic and action and qualifiers_match:
                supporting.append(page)
            elif topic or action:
                partial.append(page)
        if contradicting:
            refs = [page.extraction.source_ref for page in contradicting]
            refs.extend(page.extraction.source_ref for page in supporting)
            return (
                ClaimVerificationV4(
                    applicable=True,
                    status=VerificationStatusV4.CONFLICTING,
                    reason_code=("official_sources_disagree" if supporting else "strong_official_contradiction"),
                    evidence_refs=_unique(refs),
                    topic=intent.contract.topic,
                ),
                True,
            )
        if supporting:
            fallback_only = all(
                page.extraction.maximum_status is VerificationStatusV4.PARTIALLY_VERIFIED for page in supporting
            )
            return (
                ClaimVerificationV4(
                    applicable=True,
                    status=(
                        VerificationStatusV4.PARTIALLY_VERIFIED if fallback_only else VerificationStatusV4.VERIFIED
                    ),
                    reason_code=(
                        "provider_fallback_claim_match" if fallback_only else "official_claim_dimensions_match"
                    ),
                    evidence_refs=[page.extraction.source_ref for page in supporting],
                    topic=intent.contract.topic,
                ),
                False,
            )
        if partial:
            return (
                ClaimVerificationV4(
                    applicable=True,
                    status=VerificationStatusV4.PARTIALLY_VERIFIED,
                    reason_code="official_claim_dimensions_incomplete",
                    evidence_refs=[page.extraction.source_ref for page in partial],
                    topic=intent.contract.topic,
                ),
                False,
            )
        return (
            ClaimVerificationV4(
                applicable=True,
                status=VerificationStatusV4.UNVERIFIED,
                reason_code="official_claim_evidence_not_found",
                topic=intent.contract.topic,
            ),
            False,
        )

    async def _resource_component(
        self,
        intent: GroundedVerificationIntent,
        user_urls: Sequence[str],
        links: Sequence[_LinkEvidence],
        external_consent: bool,
        execution_context: TurnExecutionContext,
    ) -> tuple[ResourceVerificationV4, int, int, list[str]]:
        if not user_urls:
            return (
                ResourceVerificationV4(
                    applicable=False,
                    status=None,
                    reason_code="no_user_action_url",
                ),
                0,
                0,
                [],
            )
        relevant = [item for item in links if _role_is_relevant(item.public.role, intent)][:_MAX_OUTBOUND_RESOLUTIONS]
        if not relevant:
            return (
                ResourceVerificationV4(
                    applicable=True,
                    status=VerificationStatusV4.UNVERIFIED,
                    reason_code="official_action_link_not_found",
                ),
                0,
                0,
                [],
            )

        calls = 0
        outbound_resolutions = 0
        limitations: list[str] = []

        async def resolve(url: str, current: ResourceIdentityV4 | None, *, outbound: bool) -> ResourceIdentityV4 | None:
            nonlocal calls, outbound_resolutions
            if current is not None:
                return current
            if not external_consent:
                limitations.append("external_url_consent_required")
                return None
            if self._fetcher is None:
                limitations.append("external_redirect_resolver_unavailable")
                return None
            if outbound:
                outbound_resolutions += 1
            fetched = await self._fetcher.fetch(url, execution_context=execution_context)
            calls += fetched.tool_calls_used
            if fetched.status is VerificationTransportStatus.SUCCESS and fetched.document is not None:
                return identify_resource_chain(fetched.document.redirect_chain)
            if fetched.limitation is not None:
                limitations.append(f"external_resolve_{fetched.limitation.value}")
            return None

        user_resources = [
            await resolve(url, identify_resource(url), outbound=False) for url in user_urls[:_MAX_USER_ACTION_URLS]
        ]
        exact: tuple[ResourceMatchV4, str, LinkEvidenceStrength] | None = None
        different: tuple[ResourceMatchV4, str, LinkEvidenceStrength] | None = None
        unresolved: tuple[ResourceMatchV4, str, LinkEvidenceStrength] | None = None
        for link in relevant:
            official_resource = await resolve(
                link.extracted.fetch_url,
                link.extracted.resource,
                outbound=True,
            )
            for user_resource in user_resources:
                match = match_resources(user_resource, official_resource)
                row = (match, link.public.link_ref, link.extracted.evidence_strength)
                if match.status in {
                    ResourceMatchStatusV4.EXACT_RESOURCE,
                    ResourceMatchStatusV4.EXACT_CANONICAL_URL,
                }:
                    exact = row
                    break
                if match.status is ResourceMatchStatusV4.DIFFERENT_RESOURCE:
                    different = different or row
                else:
                    unresolved = unresolved or row
            if exact is not None:
                break

        selected = exact or different or unresolved
        if selected is None:
            return (
                ResourceVerificationV4(
                    applicable=True,
                    status=VerificationStatusV4.UNVERIFIED,
                    reason_code="resource_chain_unresolved",
                ),
                calls,
                outbound_resolutions,
                _unique(limitations),
            )
        match, link_ref, strength = selected
        if exact is not None:
            fallback = strength is LinkEvidenceStrength.PROVIDER_FALLBACK_PARTIAL
            return (
                ResourceVerificationV4(
                    applicable=True,
                    status=(VerificationStatusV4.PARTIALLY_VERIFIED if fallback else VerificationStatusV4.VERIFIED),
                    reason_code=("provider_fallback_exact_resource" if fallback else "official_exact_resource"),
                    evidence_refs=[link_ref],
                    match=match,
                ),
                calls,
                outbound_resolutions,
                _unique(limitations),
            )
        if different is not None:
            return (
                ResourceVerificationV4(
                    applicable=True,
                    status=VerificationStatusV4.CONFLICTING,
                    reason_code="official_link_points_to_different_resource",
                    evidence_refs=[link_ref],
                    match=match,
                ),
                calls,
                outbound_resolutions,
                _unique(limitations),
            )
        return (
            ResourceVerificationV4(
                applicable=True,
                status=VerificationStatusV4.UNVERIFIED,
                reason_code="resource_chain_unresolved",
                evidence_refs=[link_ref],
                match=match,
            ),
            calls,
            outbound_resolutions,
            _unique(limitations),
        )

    @staticmethod
    def _report(
        intent: GroundedVerificationIntent,
        publisher: PublisherVerificationV4,
        claim: ClaimVerificationV4,
        resource: ResourceVerificationV4,
        sources: Sequence[OfficialSourceReferenceV4],
        links: Sequence[OfficialLinkReferenceV4],
        limitations: Sequence[str],
    ) -> OfficialLinkVerificationReportV4:
        statuses = [
            component.status
            for component in (publisher, claim, resource)
            if component.applicable and component.status is not None
        ]
        if VerificationStatusV4.CONFLICTING in statuses:
            overall = VerificationStatusV4.CONFLICTING
            reason = "applicable_component_conflicting"
        elif statuses and all(status is VerificationStatusV4.VERIFIED for status in statuses):
            overall = VerificationStatusV4.VERIFIED
            reason = "all_applicable_components_verified"
        elif any(
            status in {VerificationStatusV4.VERIFIED, VerificationStatusV4.PARTIALLY_VERIFIED} for status in statuses
        ):
            overall = VerificationStatusV4.PARTIALLY_VERIFIED
            reason = "applicable_components_partial"
        else:
            overall = VerificationStatusV4.UNVERIFIED
            reason = "applicable_evidence_insufficient"
        return OfficialLinkVerificationReportV4(
            intent=intent.contract,
            publisher_verification=publisher,
            claim_verification=claim,
            resource_verification=resource,
            overall_status=overall,
            reason_code=reason,
            source_refs=list(sources)[:20],
            link_refs=list(links)[:50],
            limitations=_unique(list(limitations))[:50],
        )

    @staticmethod
    def _validate_reference_closure(report: OfficialLinkVerificationReportV4) -> None:
        available = {source.source_ref for source in report.source_refs}
        available.update(link.link_ref for link in report.link_refs)
        cited = set(report.publisher_verification.evidence_refs)
        cited.update(report.claim_verification.evidence_refs)
        cited.update(report.resource_verification.evidence_refs)
        if cited - available:
            raise ValueError("official verification evidence-reference closure failed")
        source_ids = {source.source_ref for source in report.source_refs}
        if any(link.source_ref not in source_ids for link in report.link_refs):
            raise ValueError("official link reference cites an unavailable source")


__all__ = [
    "ComparisonDimension",
    "ComparisonRelation",
    "OfficialLinkVerificationCoordinator",
    "OfficialVerificationCoordinatorOutcome",
    "VerificationComparisonOutput",
    "validate_comparison_output",
]
