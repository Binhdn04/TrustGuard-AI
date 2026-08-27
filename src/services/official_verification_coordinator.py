from __future__ import annotations

import asyncio
import hashlib
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from pydantic import Field, model_validator

from src.agents.tools.models import ToolContractModel
from src.models import (
    BrandRecordV4,
    ClaimVerificationV4,
    IdentityAssociationAssuranceV4,
    IdentityAssociationV4,
    IdentityCandidateV4,
    IdentityEvidenceFamilyV4,
    IdentityEvidenceObservationV4,
    IdentityRelationshipV4,
    LinkRoleV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    OfficialLinkReferenceV4,
    OfficialLinkVerificationReportV4,
    OfficialSourceReferenceV4,
    OfficialVerificationComponentV4,
    PublisherVerificationV4,
    RequestedActionV4,
    ResourceIdentityV4,
    ResourceMatchStatusV4,
    ResourceMatchV4,
    ResourceVerificationV4,
    ScopeDecisionV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    VerificationStatusV4,
    VerificationTopicV4,
)
from src.security_ai.runtime import TurnExecutionContext
from src.services.official_evidence_planner import EvidenceRetrievalPlanner, RetrievalDirection
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
        "threads.com",
        "twitter.com",
        "x.com",
        "youtube.com",
    }
)
_SHORT_LINK_HOSTS = frozenset(
    {
        "bit.ly",
        "forms.gle",
        "lnkd.in",
        "t.co",
        "tinyurl.com",
    }
)
_KNOWN_OUTBOUND_REDIRECTS = frozenset(
    {
        ("l.facebook.com", "/l.php"),
        ("www.linkedin.com", "/redir/redirect"),
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
    "apply_for_passport": ("lam ho chieu", "xin ho chieu", "cap ho chieu", "passport"),
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
# Domain ownership conflicts need a stricter predicate than a claim conflict.
# A general site warning (for example, Wikipedia's editing scam warning) says
# nothing about the organization-to-domain edge being evaluated.
_OWNERSHIP_CONFLICT_TERMS = (
    "not affiliated",
    "unaffiliated",
    "not related",
    "not owned by",
    "does not own",
    "khong lien quan",
    "khong phai",
    "khong thuoc",
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

    async def list_identity_candidates(self) -> list[IdentityCandidateV4]: ...

    async def save_identity_candidate(self, record: IdentityCandidateV4) -> IdentityCandidateV4: ...


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
    identity_candidate_count: int = Field(default=0, ge=0, le=20)
    identity_verified_count: int = Field(default=0, ge=0, le=20)
    identity_conflicting_count: int = Field(default=0, ge=0, le=20)
    identity_cache_hits: int = Field(default=0, ge=0, le=20)


_UNREVIEWED_IDENTITY_LIMITATION = (
    "Chưa có reviewed identity hoặc exact-resource association để xác nhận quan hệ giữa URL và tổ chức."
)
_SCOPED_RESOURCE_LIMITATION = (
    "Publisher/domain identity chưa được review; official verification đã xác nhận đúng resource được gửi "
    "và không mở rộng kết quả cho toàn domain."
)


def _current_identity_candidate_versions(
    records: Sequence[IdentityCandidateV4],
) -> list[IdentityCandidateV4]:
    """Return the current candidate in each repository version chain."""
    superseded_ids = {item.supersedes for item in records if item.supersedes is not None}
    current = [item for item in records if item.association_id not in superseded_ids]
    latest_by_key: dict[tuple[str, str, IdentityRelationshipV4], IdentityCandidateV4] = {}
    for item in current:
        key = (_fold(item.entity_name), item.canonical_domain.casefold(), item.relationship)
        previous = latest_by_key.get(key)
        if previous is None or (item.version, item.discovered_at) > (previous.version, previous.discovered_at):
            latest_by_key[key] = item
    return list(latest_by_key.values())


def apply_official_verification_outcome(
    scope: SecurityScopeResponseV4,
    outcome: OfficialVerificationCoordinatorOutcome,
) -> SecurityScopeResponseV4:
    """Merge a visible report and reconcile stale domain-level wording."""
    report = outcome.report
    if report is None:
        return scope
    context = scope.security_context
    submitted_urls = {
        canonical
        for url in (context.urls if context is not None else [])
        if (canonical := _canonical_discovery_url(url)) is not None
    }
    verified_associations = verified_exact_resource_endorsement_associations(report, submitted_urls)
    verified_resource_hosts = {item.canonical_domain for item in verified_associations}
    ownership_refs = set(report.domain_ownership_verification.evidence_refs)
    verified_ownership_hosts = {
        item.canonical_domain
        for item in report.identity_associations
        if item.assurance is IdentityAssociationAssuranceV4.VERIFIED
        and item.relationship is IdentityRelationshipV4.OFFICIAL_CONTROLLED
        and bool(set(item.evidence_refs) & ownership_refs)
        and any(
            (urlsplit(url).hostname or "").casefold() == item.canonical_domain
            or (urlsplit(url).hostname or "").casefold().endswith(f".{item.canonical_domain}")
            for url in submitted_urls
        )
    }
    evidence = list(scope.evidence)
    if verified_resource_hosts or verified_ownership_hosts:
        evidence = [
            item.model_copy(
                update={
                    "description": (
                        f"Official verification đã xác nhận tên miền {item.target} thuộc tổ chức được nêu. "
                        "Xác nhận ownership này không tự xác nhận claim hoặc hành động trong tin nhắn."
                        if item.target in verified_ownership_hosts
                        else "Official verification đã xác nhận chuỗi endorsement cho đúng resource đã gửi trên "
                        f"{item.target}. Publisher/domain identity chưa được review; kết quả không áp dụng "
                        "cho resource khác trên cùng domain."
                    )
                }
            )
            if item.signal in {"claimed_identity_unverified", "entity_target_unverified"}
            and item.target in (verified_resource_hosts | verified_ownership_hosts)
            else item
            for item in evidence
        ]
    limitations = [
        item
        for item in [*scope.limitations, *outcome.limitations]
        if not ((verified_resource_hosts or verified_ownership_hosts) and item == _UNREVIEWED_IDENTITY_LIMITATION)
    ]
    if verified_resource_hosts and report.publisher_verification.status is VerificationStatusV4.UNVERIFIED:
        limitations.append(_SCOPED_RESOURCE_LIMITATION)

    verification_evidence: list[SecurityEvidenceV4] = []
    ownership = report.domain_ownership_verification
    sender = report.sender_verification
    action = report.action_endorsement_verification
    verified_domain = next(
        (
            item.canonical_domain
            for item in report.identity_associations
            if item.assurance is IdentityAssociationAssuranceV4.VERIFIED
            and item.relationship is IdentityRelationshipV4.OFFICIAL_CONTROLLED
            and bool(set(item.evidence_refs) & set(ownership.evidence_refs))
        ),
        None,
    )
    projected = (
        (
            ownership,
            "official_domain_verified",
            verified_domain,
            (
                f"Tên miền {verified_domain} đã được xác minh thuộc quyền kiểm soát chính thức của "
                f"{report.intent.organization_name}."
                if verified_domain
                else "Quan hệ sở hữu tên miền chính thức đã được xác minh."
            ),
            VerificationStatusV4.VERIFIED,
        ),
        (
            sender,
            "sender_identity_unverified",
            report.intent.organization_name,
            "Tin nhắn không cung cấp bằng chứng xác thực đủ để xác nhận danh tính người gửi.",
            VerificationStatusV4.UNVERIFIED,
        ),
        (
            action,
            "action_endorsement_unverified",
            report.intent.requested_action.value if report.intent.requested_action else None,
            "Nguồn chính thức chưa xác nhận đúng yêu cầu hành động hoặc tài nguyên đăng nhập trong tin nhắn.",
            VerificationStatusV4.UNVERIFIED,
        ),
    )
    for component, signal, target, description, expected_status in projected:
        if component.applicable and component.status is expected_status:
            verification_evidence.append(
                SecurityEvidenceV4(
                    evidence_ref=_ref("evidence", report.policy_version, signal, target or "unknown"),
                    type=SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION,
                    source="official_verification",
                    target=target,
                    signal=signal,
                    description=description,
                    observed_at=scope.created_at,
                    confidence=1.0 if expected_status is VerificationStatusV4.VERIFIED else None,
                )
            )
    known_refs = {item.evidence_ref for item in evidence}
    evidence.extend(item for item in verification_evidence if item.evidence_ref not in known_refs)
    return scope.model_copy(
        update={
            "official_verification": report,
            "evidence": evidence,
            "limitations": _unique(limitations),
            "tool_calls_used": scope.tool_calls_used + outcome.adapter_attempts,
        }
    )


def verified_exact_resource_endorsement_associations(
    report: OfficialLinkVerificationReportV4,
    submitted_resources: Sequence[str],
) -> list[IdentityAssociationV4]:
    """Return accepted official endorsement chains for the exact submitted resource.

    This deliberately establishes neither publisher/domain ownership nor a
    SAFE verdict. The association is authoritative only when it is VERIFIED,
    carries provenance evidence, and matches both the report's exact-resource
    match and a canonical resource submitted in this request.
    """
    match = report.resource_verification.match
    user_resource = match.user_resource if match is not None else None
    if (
        match is None
        or user_resource is None
        or not user_resource.canonical_url
        or match.status
        not in {ResourceMatchStatusV4.EXACT_RESOURCE, ResourceMatchStatusV4.EXACT_CANONICAL_URL}
    ):
        return []
    user_canonical = _canonical_discovery_url(user_resource.canonical_url)
    # ``user_resource`` is the coordinator's canonical identity for a
    # submitted URL, including a guarded redirect destination. The original
    # input can therefore differ from this canonical URL (for example, a
    # short link); requiring an input URL prevents detached reports from
    # gaining this meaning while preserving the resolved submitted resource.
    if user_canonical is None or not submitted_resources:
        return []
    return [
        association
        for association in report.identity_associations
        if association.assurance is IdentityAssociationAssuranceV4.VERIFIED
        and association.relationship is IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE
        and association.canonical_url == user_canonical
        and bool(association.evidence_refs)
    ]


def has_verified_exact_resource_endorsement(
    report: OfficialLinkVerificationReportV4 | None,
    submitted_resources: Sequence[str],
) -> bool:
    """Whether an accepted official provenance chain endorses this request's resource."""
    if report is None:
        return False
    if verified_exact_resource_endorsement_associations(report, submitted_resources):
        return True
    match = report.resource_verification.match
    user_resource = match.user_resource if match is not None else None
    if (
        match is None
        or user_resource is None
        or not user_resource.canonical_url
        or match.status
        not in {ResourceMatchStatusV4.EXACT_RESOURCE, ResourceMatchStatusV4.EXACT_CANONICAL_URL}
        or report.resource_verification.status is not VerificationStatusV4.VERIFIED
        or not report.resource_verification.evidence_refs
    ):
        return False
    user_canonical = _canonical_discovery_url(user_resource.canonical_url)
    return user_canonical is not None and bool(submitted_resources)


def has_verified_exact_resource_action_endorsement(
    report: OfficialLinkVerificationReportV4 | None,
    submitted_resources: Sequence[str],
) -> bool:
    """Whether an exact-resource endorsement also covers the requested action.

    This is independent of publisher/domain ownership: an organization can
    endorse a specific third-party workflow without owning that platform.
    """
    return bool(
        report is not None
        and report.intent.requested_action is not None
        and report.action_endorsement_verification.status is VerificationStatusV4.VERIFIED
        and has_verified_exact_resource_endorsement(report, submitted_resources)
    )


@dataclass(frozen=True, slots=True)
class _Candidate:
    fetch_url: str
    canonical_url: str
    priority: tuple[int, int, str]
    # ``identity`` is a fetch-time capability.  For a cross-link it is an
    # ephemeral exact-URL identity derived from a reviewed source, never a
    # reviewed identity for the social account or its host.
    identity: OfficialIdentityV4
    source_identity: OfficialIdentityV4


@dataclass(frozen=True, slots=True)
class _PageEvidence:
    extraction: OfficialPageExtraction
    visible_text: str
    source_identity: OfficialIdentityV4


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
    if identity.relationship == "platform_service":
        return None
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


def _canonical_discovery_url(url: str) -> str | None:
    try:
        normalized = normalize_verification_url(url).canonical_url
    except UrlNormalizationError:
        return None
    parsed = urlsplit(normalized)
    # Query data is unnecessary for identity candidates and may contain secrets.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _entity_appears(entity: str, text: str) -> bool:
    folded_text = _fold(text)
    tokens = [token for token in _fold(entity).split() if len(token) >= 3]
    return bool(tokens) and sum(token in folded_text for token in set(tokens)) >= min(2, len(set(tokens)))


def _entity_self_identified(entity: str, text: str) -> bool:
    """Require an exact normalized organization phrase for a root identity.

    This deliberately does not reuse the token-overlap matcher used for claim
    relevance: a name-like fragment is supporting evidence, never a domain
    ownership anchor.
    """
    candidate = _fold(entity)
    return bool(candidate) and re.search(rf"(?<!\\w){re.escape(candidate)}(?!\\w)", _fold(text)) is not None


def _links_to_host(text: str, source_url: str, target_host: str) -> bool:
    """Find an exact host declaration on an independently fetched source.

    An HTML anchor remains the normal path.  Some authoritative listings and
    extracted filings, however, expose the registered website as labelled
    text rather than a clickable link (for example, ``Website: example.com``).
    That is still a domain-specific ownership edge after the caller has
    independently established the source entity and host separation.  A bare
    domain mention is deliberately not enough: it needs a website/official
    site label and an exact host boundary.
    """
    soup = BeautifulSoup(text, "html.parser")
    for anchor in soup.find_all("a", href=True):
        try:
            link = normalize_verification_url(str(anchor["href"]), base_url=source_url)
        except UrlNormalizationError:
            continue
        host = (urlsplit(link.canonical_url).hostname or "").casefold()
        if host == target_host:
            return True
    visible = " ".join(soup.get_text(" ", strip=True).split())
    escaped_host = re.escape(target_host.casefold())
    return bool(
        re.search(
            rf"(?:website|web\s*site|official\s+(?:website|site)|trang\s+web(?:\s+chinh\s+thuc)?)"
            rf"\s*(?::|[-–—|])?\s*(?:https?://)?(?:www\.)?{escaped_host}(?=$|[/?#\s,;.)])",
            _fold(visible),
        )
    )


def _has_explicit_ownership_conflict(text: str, target_host: str) -> bool:
    """Return only a host-bound statement that negates an ownership relation.

    Claim-level warning words are intentionally insufficient: third-party
    pages frequently contain generic anti-scam or editorial boilerplate while
    also correctly listing an organization's website.
    """
    visible = " ".join(BeautifulSoup(text, "html.parser").get_text(" ", strip=True).split())
    folded_host = re.escape(target_host.casefold())
    host_pattern = rf"(?:https?://)?(?:www\.)?{folded_host}(?=$|[/?#\s,;.)])"
    for sentence in re.split(r"[.!?;]+|\n+", _fold(visible)):
        if re.search(host_pattern, sentence) and any(term in sentence for term in _OWNERSHIP_CONFLICT_TERMS):
            return True
    return False


def _links_to_exact_resource(text: str, source_url: str, target_urls: set[str]) -> bool:
    """Whether fetched provenance points to one exact submitted resource."""
    soup = BeautifulSoup(text, "html.parser")
    for anchor in soup.find_all("a", href=True):
        try:
            link = normalize_verification_url(str(anchor["href"]), base_url=source_url)
        except UrlNormalizationError:
            continue
        canonical = _canonical_discovery_url(link.canonical_url)
        if canonical in target_urls:
            return True
    return False


def _grounded_claim_appears(intent: GroundedVerificationIntent, text: str) -> bool:
    claim = " ".join(_fold(intent.contract.claim_summary or "").split())
    tokens = {token for token in claim.split() if len(token) >= 4}
    if len(tokens) < 2 or len(claim) < 8:
        return False
    return claim in " ".join(_fold(text).split())


def _resource_endorsement_links(
    body: bytes,
    base_url: str,
    requested_targets: set[str],
) -> list[str]:
    """Select bounded action/short links from an entity-bearing discovery page."""
    soup = BeautifulSoup(body, "html.parser")
    ranked: list[tuple[int, str]] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        raw = str(anchor.get("href", "")).strip()
        absolute = urljoin(base_url, raw)
        canonical = _canonical_discovery_url(absolute)
        if canonical is None or canonical in seen:
            continue
        host = (urlsplit(canonical).hostname or "").casefold()
        path = urlsplit(canonical).path.casefold()
        text = _fold(f"{anchor.get_text(' ', strip=True)} {urlsplit(canonical).path}")
        is_short = host in _SHORT_LINK_HOSTS
        is_known_redirect = any(
            host == redirect_host and path.startswith(redirect_path)
            for redirect_host, redirect_path in _KNOWN_OUTBOUND_REDIRECTS
        )
        is_exact_target = canonical in requested_targets
        is_action = any(term in text for terms in _ACTION_TERMS.values() for term in terms)
        if not is_exact_target and not is_short and not is_known_redirect and not is_action:
            continue
        seen.add(canonical)
        ranked.append((0 if is_exact_target else (1 if is_short or is_known_redirect else 2), absolute))
    ranked.sort(key=lambda item: item[0])
    return [url for _, url in ranked[:_MAX_OUTBOUND_RESOLUTIONS]]


def _identity_observation(
    family: IdentityEvidenceFamilyV4,
    canonical_url: str,
    content_hash: str,
    now: datetime,
) -> IdentityEvidenceObservationV4:
    canonical = _canonical_discovery_url(canonical_url)
    if canonical is None:  # pragma: no cover - callers only pass guarded URLs
        raise ValueError("identity evidence requires a public canonical URL")
    host = (urlsplit(canonical).hostname or "").casefold()
    return IdentityEvidenceObservationV4(
        evidence_ref=_ref("identity-evidence", family.value, host, canonical, content_hash),
        family=family,
        source_host=host,
        canonical_url=canonical,
        content_hash=content_hash,
        observed_at=now,
    )


class OfficialLinkVerificationCoordinator:
    policy_version = "official-link-verification-v2"

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
        return apply_official_verification_outcome(scope, outcome)

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
        platform_identities = tuple(identity for identity in identities if identity.relationship == "platform_service")
        verifiable_identities = tuple(
            identity for identity in identities if identity.relationship != "platform_service"
        )
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
        identity_associations: list[IdentityAssociationV4] = []
        identity_evidence: list[IdentityEvidenceObservationV4] = []
        # Search is discovery-only until an association passes the independent
        # identity-evidence rule below.  Keep its URLs so the discovery phase
        # can inspect them without treating the provider result as identity.
        discovery_seed_urls: list[str] = []

        def enqueue(candidate: _Candidate) -> None:
            """Keep the bounded, unfetched queue ordered by provenance value."""
            nonlocal candidates
            candidates.append(candidate)
            candidates[fetch_cursor:] = sorted(candidates[fetch_cursor:], key=lambda item: item.priority)
            if len(candidates) > _MAX_CANDIDATES:
                removed = candidates.pop()
                candidate_keys.discard(removed.canonical_url)

        def add_candidate(url: str, *, title: str = "") -> None:
            try:
                normalized = normalize_verification_url(url)
            except UrlNormalizationError:
                return
            if normalized.canonical_url in candidate_keys:
                return
            for platform_identity in platform_identities:
                try:
                    platform_assessment = assess_final_page_identity(url, [platform_identity])
                except UrlNormalizationError:
                    continue
                if platform_assessment.status is FinalPageIdentityStatus.ACCEPTED:
                    # A more-specific reviewed shared platform must not inherit
                    # first-party source status from a broader parent domain.
                    return
            for identity in verifiable_identities:
                try:
                    assessment = assess_final_page_identity(url, [identity])
                except UrlNormalizationError:
                    continue
                if assessment.status is FinalPageIdentityStatus.ACCEPTED:
                    candidate_keys.add(normalized.canonical_url)
                    enqueue(
                        _Candidate(
                            normalized.fetch_url,
                            normalized.canonical_url,
                            (
                                5 if normalized.fetch_url == _identity_url(identity) else 10,
                                0 if _fold(title) == _fold(intent.contract.claim_summary or "") else 1,
                                normalized.canonical_url,
                            ),
                            identity,
                            identity,
                        )
                    )
                    return
        def add_exact_cross_link_candidate(link: ExtractedOfficialLink, page: _PageEvidence) -> None:
            """Continue one exact social URL explicitly linked by an accepted source.

            This grants no host-wide or account-wide identity.  Redirects and
            sibling pages still fail the normal final-page identity check.
            """
            if _link_role(link) is not LinkRoleV4.SOCIAL_PROFILE:
                return
            if link.canonical_url in candidate_keys:
                return
            try:
                normalized = normalize_verification_url(link.fetch_url)
            except UrlNormalizationError:
                return
            trusted_identity = OfficialIdentityV4(
                identity_type=OfficialIdentityTypeV4.SOCIAL_PROFILE,
                canonical_value=normalized.canonical_url,
                display_value=normalized.display_url,
                entity_name=page.source_identity.entity_name,
                relationship="official_cross_link_exact",
                provenance=f"exact-cross-link:{link.link_ref}",
                policy_version="official-identity-cross-link-v1",
                reviewed=True,
            )
            source_identity = trusted_identity.model_copy(
                update={"relationship": "official_cross_link", "reviewed": False}
            )
            candidate_keys.add(normalized.canonical_url)
            enqueue(
                _Candidate(
                    normalized.fetch_url,
                    normalized.canonical_url,
                    (0, 0, normalized.canonical_url),
                    trusted_identity,
                    source_identity,
                )
            )

        local_candidate_urls = [
            value for identity in verifiable_identities if (value := _identity_url(identity)) is not None
        ]
        # Discovery is driven by missing evidence edges, never by increasingly
        # paraphrased searches.  Query text is merely the transport for a
        # selected edge and is bounded by the planner.
        planner = EvidenceRetrievalPlanner(
            entity=brand.name if brand is not None else (intent.contract.organization_name or ""),
            campaign=intent.contract.claim_summary or "",
            resource_url=user_urls[0] if user_urls else "",
            normalized_entity=(intent.derived_organizations[0].value if intent.derived_organizations else ""),
            normalized_topic=(intent.contract.topic.value if intent.contract.topic is not None else ""),
        )
        queries: list[VerificationQuery] = []
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
                    # A source may prove that this exact social post/page is
                    # official.  Follow only that exact link; do not infer an
                    # identity from its display name, platform, or host.
                    for link in page.extraction.links:
                        add_exact_cross_link_candidate(link, page)

        # Reviewed identities enter the continuation queue immediately.
        # Registry misses use the separate two-consent evidence-discovery path
        # below; source policy can corroborate an attestor there, never admit
        # the candidate organization/domain by itself.
        for url in local_candidate_urls:
            add_candidate(url)
        if verifiable_identities and online_verification_needed and request.consent.official_source_lookup:
            if self._search is not None:
                while search_attempts < _MAX_SEARCH_ATTEMPTS:
                    frontier = planner.next_frontier()
                    if frontier is None:
                        break
                    if frontier.direction is RetrievalDirection.SOURCE_CENTRIC:
                        # Candidate material must be extracted before another
                        # search can be justified.
                        break
                    gained = False
                    frontier_early_stop: str | None = None
                    for text in frontier.queries:
                        query = VerificationQuery(
                            query_id=f"frontier:{frontier.edge.value}:{hashlib.sha256(text.encode()).hexdigest()[:16]}",
                            text=text,
                            source_fields=(frontier.edge.value,),
                            derivations=(f"evidence_{frontier.direction.value}",),
                        )
                        queries.append(query)
                        result = await self._search.search_one(
                            query.text, execution_context=execution_context, max_results=_MAX_SEARCH_RESULTS
                        )
                        search_attempts += 1
                        adapter_attempts += result.tool_calls_used
                        if result.status is VerificationTransportStatus.SUCCESS:
                            urls = [
                                canonical for hit in result.results[:_MAX_SEARCH_RESULTS]
                                if (canonical := _canonical_discovery_url(hit.url)) is not None
                            ]
                            gained = planner.observe_candidates(urls) or gained
                            for hit in result.results[:_MAX_SEARCH_RESULTS]:
                                canonical = _canonical_discovery_url(hit.url)
                                if canonical is not None and canonical not in discovery_seed_urls:
                                    discovery_seed_urls.append(canonical)
                                add_candidate(hit.url, title=hit.title)
                        elif result.limitation is not None:
                            limitations.append(f"search_{result.limitation.value}")
                        if gained:
                            # Candidate URLs are not verification evidence.
                            # Fetch them before deciding whether this frontier
                            # has supplied enough support to skip its next,
                            # non-equivalent query.
                            await fetch_next_batch(query)
                            frontier_early_stop = self._early_stop_reason(
                                intent,
                                publisher,
                                pages,
                                user_urls,
                                claim_qualifiers,
                            )
                            if frontier_early_stop is not None:
                                break
                    planner.complete_frontier(frontier, new_evidence=gained)
                    if frontier_early_stop is not None:
                        early_stop_reason = frontier_early_stop
                        break
                    if planner.stop_reason is not None:
                        early_stop_reason = planner.stop_reason
                        break
            else:
                if self._search is None:
                    limitations.append("official_web_search_unavailable")

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
        elif verifiable_identities and online_verification_needed:
            limitations.append("official_source_consent_required")

        discovery_needed = (
            early_stop_reason != "strong_official_contradiction"
            and (
                resolution.status in {BrandResolutionStatus.NOT_FOUND, BrandResolutionStatus.AMBIGUOUS}
                or not identities
                or bool(user_urls)
            )
        )
        if discovery_needed:
            (
                identity_associations,
                identity_evidence,
                discovery_searches,
                discovery_fetches,
                discovery_calls,
                discovery_limitations,
            ) = await self._discover_identity_associations(
                intent,
                user_urls,
                verifiable_identities,
                pages,
                now,
                official_consent=request.consent.official_source_lookup,
                external_consent=request.consent.external_url_lookup,
                search_cap=max(0, _MAX_SEARCH_ATTEMPTS - search_attempts),
                fetch_cap=max(0, _MAX_OFFICIAL_FETCHES - official_fetches),
                candidate_seed_urls=discovery_seed_urls,
                execution_context=execution_context,
            )
            search_attempts += discovery_searches
            official_fetches += discovery_fetches
            adapter_attempts += discovery_calls
            limitations.extend(discovery_limitations)
            if early_stop_reason is None and "identity_consecutive_retrievals_no_new_evidence" in discovery_limitations:
                early_stop_reason = "consecutive_retrievals_no_new_evidence"

        discovered_publisher = next(
            (
                item
                for item in identity_associations
                if item.assurance is IdentityAssociationAssuranceV4.VERIFIED
                and item.relationship is IdentityRelationshipV4.OFFICIAL_CONTROLLED
            ),
            None,
        )
        if discovered_publisher is not None and publisher.status is not VerificationStatusV4.VERIFIED:
            publisher = PublisherVerificationV4(
                applicable=True,
                status=VerificationStatusV4.VERIFIED,
                reason_code="publisher_discovered_from_official_evidence",
                evidence_refs=discovered_publisher.evidence_refs,
                identity=OfficialIdentityV4(
                    identity_type=OfficialIdentityTypeV4.DOMAIN,
                    canonical_value=discovered_publisher.canonical_domain,
                    display_value=discovered_publisher.canonical_domain,
                    entity_name=discovered_publisher.entity_name,
                    match_scope="host_and_subdomains",
                    relationship="discovered_official_control",
                    provenance="independent official-source identity evidence",
                    policy_version="identity-discovery-v2",
                    effective_from=discovered_publisher.verified_at,
                    reviewed=False,
                ),
            )

        source_refs, link_evidence = self._public_evidence(
            brand,
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
        resource = self._resource_from_identity_associations(
            resource,
            user_urls,
            identity_associations,
        )
        adapter_attempts += resource_calls
        limitations.extend(resource_limitations)
        action_evidence_refs = [
            page.extraction.source_ref for page in pages if _claim_dimensions(intent, page, claim_qualifiers)[1]
        ]
        action_evidence_refs.extend(
            item.evidence_ref
            for item in identity_evidence
            if item.family is IdentityEvidenceFamilyV4.ACTION_ENDORSEMENT
        )
        reviewed_ownership: dict[str, list[str]] = {}
        for identity in verifiable_identities:
            identity_url = _identity_url(identity)
            if identity_url is None:
                continue
            identity_host = (urlsplit(identity_url).hostname or "").casefold()
            matching_refs = [
                source.source_ref
                for source in local_sources
                if source.identity is not None and source.identity.identity_id == identity.identity_id
            ]
            if identity_host and matching_refs:
                reviewed_ownership[identity_host] = matching_refs
        report = self._report(
            intent,
            publisher,
            claim,
            resource,
            source_refs,
            [item.public for item in link_evidence],
            limitations,
            identity_associations,
            identity_evidence,
            user_urls=user_urls,
            official_source_consent=request.consent.official_source_lookup,
            external_url_consent=request.consent.external_url_lookup,
            action_evidence_refs=action_evidence_refs,
            reviewed_ownership=reviewed_ownership,
        )
        self._validate_reference_closure(report)
        reported_associations = report.identity_associations
        return OfficialVerificationCoordinatorOutcome(
            report=report,
            adapter_attempts=adapter_attempts,
            search_attempts=search_attempts,
            candidate_count=len(candidates),
            official_fetches=official_fetches,
            outbound_resolutions=outbound_resolutions,
            early_stop_reason=early_stop_reason,
            limitations=_unique(limitations)[:50],
            identity_candidate_count=len(reported_associations),
            identity_verified_count=sum(
                item.assurance is IdentityAssociationAssuranceV4.VERIFIED for item in reported_associations
            ),
            identity_conflicting_count=sum(
                item.assurance
                in {
                    IdentityAssociationAssuranceV4.CONFLICTING,
                    IdentityAssociationAssuranceV4.CONFIRMED_MISMATCH,
                }
                for item in reported_associations
            ),
            identity_cache_hits=(len(reported_associations) if "identity_cache_hit" in limitations else 0),
        )

    async def _discover_identity_associations(
        self,
        intent: GroundedVerificationIntent,
        user_urls: Sequence[str],
        identities: Sequence[OfficialIdentityV4],
        reviewed_pages: Sequence[_PageEvidence],
        now: datetime,
        *,
        official_consent: bool,
        external_consent: bool,
        search_cap: int,
        fetch_cap: int,
        candidate_seed_urls: Sequence[str] = (),
        execution_context: TurnExecutionContext,
    ) -> tuple[list[IdentityAssociationV4], list[IdentityEvidenceObservationV4], int, int, int, list[str]]:
        requested_url_map = {
            canonical: url for url in user_urls if (canonical := _canonical_discovery_url(url)) is not None
        }
        requested_targets = set(requested_url_map)
        first_target = next(iter(sorted(requested_targets)), None)
        entity = intent.contract.organization_name or (
            (urlsplit(first_target).hostname or "").casefold() if first_target else None
        )
        if entity is None:
            return [], [], 0, 0, 0, []
        cached: list[IdentityCandidateV4] = []
        stale_found = False
        list_candidates = getattr(self._brands, "list_identity_candidates", None)
        if list_candidates is not None:
            candidate_records = _current_identity_candidate_versions(
                [item for item in await list_candidates() if _fold(item.entity_name) == _fold(entity)]
            )
            stale_found = any(
                item.assurance
                in {
                    IdentityAssociationAssuranceV4.DISCOVERED,
                    IdentityAssociationAssuranceV4.VERIFIED,
                    IdentityAssociationAssuranceV4.CONFLICTING,
                }
                and (item.expires_at is None or item.expires_at <= now)
                for item in candidate_records
            )
            cached = [
                item
                for item in candidate_records
                if (
                    item.assurance
                    in {
                        IdentityAssociationAssuranceV4.CONFIRMED_MISMATCH,
                        IdentityAssociationAssuranceV4.REJECTED,
                        IdentityAssociationAssuranceV4.PROMOTED,
                    }
                    or (
                        item.assurance
                        in {
                            IdentityAssociationAssuranceV4.DISCOVERED,
                            IdentityAssociationAssuranceV4.VERIFIED,
                            IdentityAssociationAssuranceV4.CONFLICTING,
                        }
                        and item.expires_at is not None
                        and now < item.expires_at
                    )
                )
            ]
        cache_complete_assurances = {
            IdentityAssociationAssuranceV4.CONFIRMED_MISMATCH,
            IdentityAssociationAssuranceV4.REJECTED,
            IdentityAssociationAssuranceV4.PROMOTED,
            IdentityAssociationAssuranceV4.VERIFIED,
            IdentityAssociationAssuranceV4.CONFLICTING,
        }
        completed_cached_urls = {item.canonical_url for item in cached if item.assurance in cache_complete_assurances}
        if cached and (
            (requested_targets and requested_targets <= completed_cached_urls)
            or (not requested_targets and bool(completed_cached_urls))
        ):
            visible_cached = (
                cached
                if official_consent and external_consent
                else [item for item in cached if item.relationship is not IdentityRelationshipV4.OFFICIAL_CONTROLLED]
            )
            visible_urls = {
                item.canonical_url for item in visible_cached if item.assurance in cache_complete_assurances
            }
            if visible_cached and (
                (requested_targets and requested_targets <= visible_urls) or (not requested_targets and visible_urls)
            ):
                return (
                    list(visible_cached),
                    [obs for item in visible_cached for obs in item.observations],
                    0,
                    0,
                    0,
                    ["identity_cache_hit"],
                )

        if not official_consent or not external_consent:
            consent_limitations = []
            if not official_consent:
                consent_limitations.append("official_source_consent_required")
            if not external_consent:
                consent_limitations.append("external_url_consent_required")
            if stale_found:
                consent_limitations.insert(0, "identity_stale_revalidation")
            return [], [], 0, 0, 0, consent_limitations

        direct_associations: list[IdentityCandidateV4] = []
        for target in requested_targets:
            target_host = (urlsplit(target).hostname or "").casefold()
            for page in reviewed_pages:
                source_host = (urlsplit(page.extraction.source_canonical_url).hostname or "").casefold()
                if source_host == target_host or not any(
                    _canonical_discovery_url(link.canonical_url) == target for link in page.extraction.links
                ):
                    continue
                direct_observations = [
                    _identity_observation(
                        IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT,
                        page.extraction.source_canonical_url,
                        page.extraction.content_hash,
                        now,
                    ),
                    _identity_observation(
                        IdentityEvidenceFamilyV4.TARGET_RESOURCE_MATCH,
                        target,
                        hashlib.sha256(target.encode()).hexdigest(),
                        now,
                    ),
                ]
                association = self._association_from_observations(
                    entity,
                    target,
                    IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
                    direct_observations,
                    now,
                )
                direct_associations.append(
                    IdentityCandidateV4(**association.model_dump(), observations=direct_observations)
                )
                break
        if direct_associations and requested_targets <= {item.canonical_url for item in direct_associations}:
            save = getattr(self._brands, "save_identity_candidate", None)
            stored = [await save(item) for item in direct_associations] if save is not None else direct_associations
            return list(stored), [obs for item in stored for obs in item.observations], 0, 0, 0, []

        if not official_consent:
            stale = ["identity_stale_revalidation"] if stale_found else []
            return [], [], 0, 0, 0, [*stale, "official_source_consent_required"]
        # The submitted URL is already a consent-scoped discovery candidate.
        # Do not abandon its guarded fetch merely because optional web search
        # is unavailable; otherwise direct authoritative domain evidence can
        # never be reconciled in deployments without a search provider.
        if self._search is None and not candidate_seed_urls and not requested_targets:
            stale = ["identity_stale_revalidation"] if stale_found else []
            return [], [], 0, 0, 0, [*stale, "official_web_search_unavailable"]

        candidate_urls: list[str] = list(sorted(requested_targets)) if external_consent else []
        identity_candidate_urls: set[str] = set()
        authority_candidate_urls: set[str] = set()
        target_host = (urlsplit(first_target).hostname or "").casefold() if first_target is not None else ""
        planner = EvidenceRetrievalPlanner(
            # Keep claim discovery independent from the submitted host.  The
            # exact-resource edge has its own resource-centric query; adding a
            # third-party host here makes the official provenance search miss
            # otherwise relevant entity/campaign pages.
            entity=entity,
            campaign=intent.contract.claim_summary or "",
            resource_url=first_target or "",
            normalized_entity=(intent.derived_organizations[0].value if intent.derived_organizations else ""),
            normalized_topic=(intent.contract.topic.value if intent.contract.topic is not None else ""),
        )
        for candidate in candidate_seed_urls:
            if candidate in requested_targets and not external_consent:
                continue
            if candidate not in candidate_urls:
                candidate_urls.append(candidate)
                planner.observe_candidates([candidate])
        searches = calls = fetches = 0
        limitations: list[str] = ["identity_stale_revalidation"] if stale_found else []
        last_query = entity
        while (
            self._search is not None
            and searches < min(search_cap, _MAX_SEARCH_ATTEMPTS)
            and len(candidate_urls) < _MAX_CANDIDATES
        ):
            frontier = planner.next_frontier()
            if frontier is None:
                if planner.stop_reason is not None:
                    limitations.append(f"identity_{planner.stop_reason}")
                break
            if frontier.direction is RetrievalDirection.SOURCE_CENTRIC:
                # Fetch and extract useful candidates before considering a new
                # search.  Search results are evidence material, not rejects.
                break
            gained = False
            for query in frontier.queries:
                last_query = query
                result = await self._search.search_one(
                    query, execution_context=execution_context, max_results=_MAX_SEARCH_RESULTS
                )
                searches += 1
                calls += result.tool_calls_used
                if result.status is VerificationTransportStatus.SUCCESS:
                    urls = [
                        canonical for hit in result.results
                        if (canonical := _canonical_discovery_url(hit.url)) is not None
                    ]
                    gained = planner.observe_candidates(urls) or gained
                    for canonical in urls:
                        if canonical not in candidate_urls:
                            candidate_urls.append(canonical)
                        if len(candidate_urls) >= _MAX_CANDIDATES:
                            break
                elif result.limitation is not None:
                    limitations.append(f"identity_search_{result.limitation.value}")
                if searches >= min(search_cap, _MAX_SEARCH_ATTEMPTS) or len(candidate_urls) >= _MAX_CANDIDATES:
                    break
            planner.complete_frontier(frontier, new_evidence=gained)

        # Candidate discovery normally stops to fetch material after the first
        # useful query.  For ownership, reserve one distinct lookup for a
        # source that can explicitly associate the submitted host with the
        # entity.  This is not evidence by itself; it merely prevents an
        # encyclopedia-heavy result page from starving the cross-source edge.
        if self._search is not None and target_host and searches < min(search_cap, _MAX_SEARCH_ATTEMPTS):
            # Keep the entity-to-site edge independent from claim recall. A
            # campaign query can return many topical articles and otherwise
            # starve the organization identity evidence under the fetch cap.
            identity_query = entity
            last_query = identity_query
            result = await self._search.search_one(
                identity_query,
                execution_context=execution_context,
                max_results=_MAX_SEARCH_RESULTS,
            )
            searches += 1
            calls += result.tool_calls_used
            if result.status is VerificationTransportStatus.SUCCESS:
                for hit in result.results:
                    canonical = _canonical_discovery_url(hit.url)
                    if canonical is not None:
                        identity_candidate_urls.add(canonical)
                        if canonical not in candidate_urls:
                            candidate_urls.append(canonical)
            elif result.limitation is not None:
                limitations.append(f"identity_entity_search_{result.limitation.value}")

        if self._search is not None and target_host and searches < min(search_cap, _MAX_SEARCH_ATTEMPTS):
            authority_query = f'{entity} "{target_host}" registry'
            last_query = authority_query
            result = await self._search.search_one(
                authority_query,
                execution_context=execution_context,
                max_results=_MAX_SEARCH_RESULTS,
            )
            searches += 1
            calls += result.tool_calls_used
            if result.status is VerificationTransportStatus.SUCCESS:
                for hit in result.results:
                    canonical = _canonical_discovery_url(hit.url)
                    if canonical is not None:
                        authority_candidate_urls.add(canonical)
                        if canonical not in candidate_urls:
                            candidate_urls.append(canonical)
                    if len(candidate_urls) >= _MAX_CANDIDATES:
                        break
            elif result.limitation is not None:
                limitations.append(f"identity_authority_search_{result.limitation.value}")

        # A user target is only fetched under its separate consent. Search candidates
        # are fetched under official-source consent and every redirect remains guarded.
        fetch_urls: list[str] = []
        if external_consent:
            for url in requested_url_map.values():
                if url not in fetch_urls:
                    fetch_urls.append(url)
        target_hosts = {(urlsplit(url).hostname or "").casefold() for url in requested_targets}

        def fetch_priority(url: str) -> tuple[int, str]:
            host = (urlsplit(url).hostname or "").casefold()
            if host in target_hosts:
                return (0, url)
            if any(host.endswith(f".{target_host}") for target_host in target_hosts):
                # A same-site page can provide the entity self-identification
                # half of ownership proof even when the submitted path blocks
                # automated fetching.
                return (1, url)
            canonical = _canonical_discovery_url(url)
            if canonical in identity_candidate_urls:
                return (2, url)
            if canonical in authority_candidate_urls:
                return (3, url)
            if self._is_basic_independent_identity_source(url, now):
                return (4, url)
            return (5, url)

        ordered_candidates = sorted(
            (url for url in candidate_urls if url not in requested_targets and url not in fetch_urls),
            key=fetch_priority,
        )
        # One same-site page is enough to obtain self-identification. Reserve
        # the remaining bounded fetches for an independent identity source.
        same_site = [
            url
            for url in ordered_candidates
            if any(
                (host := (urlsplit(url).hostname or "").casefold()) == target_host
                or host.endswith(f".{target_host}")
                for target_host in target_hosts
            )
        ]
        same_site_keys = set(same_site)
        fetch_urls.extend([*same_site[:1], *(url for url in ordered_candidates if url not in same_site_keys)])
        fetched_pages: dict[str, tuple[str, str, str]] = {}
        discovery_endorsements: dict[str, list[IdentityEvidenceObservationV4]] = {}
        pending_endorsements: dict[str, list[tuple[str, str]]] = {}
        if self._fetcher is not None:
            fetch_cursor = 0
            while fetch_cursor < len(fetch_urls) and fetches < fetch_cap:
                url = fetch_urls[fetch_cursor]
                fetch_cursor += 1
                fetched = await self._fetcher.fetch(url, execution_context=execution_context)
                fetches += 1
                calls += fetched.tool_calls_used
                if fetched.status is VerificationTransportStatus.SUCCESS and fetched.document is not None:
                    canonical = _canonical_discovery_url(fetched.document.final_url)
                    if canonical:
                        text = (
                            _visible_html_text(fetched.document.body)
                            + " "
                            + fetched.document.body.decode("utf-8", errors="ignore")[:_MAX_VISIBLE_TEXT]
                        )
                        fetched_pages[canonical] = (
                            text,
                            hashlib.sha256(fetched.document.body).hexdigest(),
                            (urlsplit(canonical).hostname or "").casefold(),
                        )
                        requested_key = _canonical_discovery_url(url)
                        if canonical in requested_targets and requested_key is not None:
                            for source_url, source_hash in pending_endorsements.get(requested_key, []):
                                discovery_endorsements.setdefault(canonical, []).append(
                                    _identity_observation(
                                        IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT,
                                        source_url,
                                        source_hash,
                                        now,
                                    )
                                )
                        if _entity_appears(entity, text) or _grounded_claim_appears(intent, text):
                            for outbound in reversed(
                                _resource_endorsement_links(
                                    fetched.document.body,
                                    fetched.document.final_url,
                                    requested_targets,
                                )
                            ):
                                outbound_key = _canonical_discovery_url(outbound)
                                if outbound_key is None:
                                    continue
                                if outbound_key in requested_targets:
                                    discovery_endorsements.setdefault(outbound_key, []).append(
                                        _identity_observation(
                                            IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT,
                                            canonical,
                                            fetched_pages[canonical][1],
                                            now,
                                        )
                                    )
                                    continue
                                pending_endorsements.setdefault(outbound_key, []).append(
                                    (canonical, fetched_pages[canonical][1])
                                )
                                if outbound_key not in {_canonical_discovery_url(item) for item in fetch_urls}:
                                    # Resolve evidence-bearing links before unrelated
                                    # search hits while staying inside the same fetch cap.
                                    fetch_urls.insert(fetch_cursor, outbound)
                elif fetched.limitation is not None:
                    recovered = False
                    if fetched.limitation in _FALLBACK_ELIGIBLE and self._extract is not None:
                        extracted = await self._extract.extract(
                            [url],
                            query=last_query,
                            execution_context=execution_context,
                        )
                        calls += extracted.tool_calls_used
                        if extracted.status is VerificationTransportStatus.SUCCESS:
                            requested_key = _canonical_discovery_url(url)
                            for document in extracted.documents:
                                canonical = _canonical_discovery_url(document.url)
                                if canonical is None:
                                    continue
                                fetched_pages[canonical] = (
                                    document.content,
                                    hashlib.sha256(document.content.encode()).hexdigest(),
                                    (urlsplit(canonical).hostname or "").casefold(),
                                )
                                recovered = True
                                if canonical in requested_targets and requested_key is not None:
                                    for source_url, source_hash in pending_endorsements.get(requested_key, []):
                                        discovery_endorsements.setdefault(canonical, []).append(
                                            _identity_observation(
                                                IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT,
                                                source_url,
                                                source_hash,
                                                now,
                                            )
                                        )
                        elif extracted.limitation is not None:
                            limitations.append(f"identity_extract_{extracted.limitation.value}")
                        else:
                            limitations.append("identity_extract_no_hit")
                    if not recovered:
                        limitations.append(f"identity_fetch_{fetched.limitation.value}")
        else:
            limitations.append("official_fetch_unavailable")

        associations: list[IdentityAssociationV4] = []
        observations: list[IdentityEvidenceObservationV4] = []
        for canonical in candidate_urls:
            host = (urlsplit(canonical).hostname or "").casefold()
            if not self._is_root_identity_candidate(canonical, now):
                continue
            candidate_observations: list[IdentityEvidenceObservationV4] = []
            page = fetched_pages.get(canonical)
            exact_resource_endorsed = canonical in discovery_endorsements
            if page is not None and _entity_self_identified(entity, page[0]):
                # A page hosted on the candidate domain identifying the named
                # organization establishes the domain-to-entity edge. Generic
                # mentions of a corporate hierarchy on that page cannot turn
                # its host into a different "parent organization" identity.
                candidate_observations.append(
                    _identity_observation(
                        IdentityEvidenceFamilyV4.ENTITY_SELF_IDENTIFICATION,
                        canonical,
                        page[1],
                        now,
                    )
                )
                # A reviewed exact source-policy entry is authoritative
                # ownership evidence even when this organization has not yet
                # been added to the brand registry. It is deliberately bound
                # to both the exact host and the entity name; a wildcard,
                # search hit, or a page merely mentioning the entity cannot
                # take this path.
                if self._is_direct_authoritative_domain_identity(canonical, entity, now):
                    candidate_observations.append(
                        _identity_observation(
                            IdentityEvidenceFamilyV4.AUTHORITATIVE_DOMAIN_ATTESTATION,
                            canonical,
                            page[1],
                            now,
                        )
                    )
            for source_url, (text, content_hash, source_host) in fetched_pages.items():
                if source_host == host or source_url == canonical:
                    continue
                if _links_to_host(text, source_url, host) and _entity_self_identified(entity, text):
                    # An independently fetched page that points to the exact
                    # submitted resource proves the narrower endorsement path.
                    # Do not inflate that provenance into control of the whole
                    # third-party host merely because the target page repeats
                    # the entity's name.
                    if (
                        exact_resource_endorsed
                        and _links_to_exact_resource(text, source_url, requested_targets)
                        and not self._is_authoritative_identity_attestor(source_url, now)
                    ):
                        continue
                    # Search hits only nominate URLs; fetched content from an
                    # independent source that passes the existing basic source
                    # checks may corroborate this exact hostname.  Reviewed
                    # attestor policy can still prioritize a source, but is
                    # not a prerequisite for ownership bootstrap.
                    if (
                        self._is_basic_independent_identity_source(source_url, now)
                        and _has_explicit_ownership_conflict(text, host)
                    ):
                        candidate_observations.append(
                            _identity_observation(
                                IdentityEvidenceFamilyV4.EXPLICIT_OWNERSHIP_CONFLICT, source_url, content_hash, now
                            )
                        )
                    elif self._is_basic_independent_identity_source(source_url, now):
                        candidate_observations.append(
                            _identity_observation(
                                IdentityEvidenceFamilyV4.INDEPENDENT_ENTITY_LINK,
                                source_url,
                                content_hash,
                                now,
                            )
                        )
            association = self._association_from_observations(
                entity,
                canonical,
                IdentityRelationshipV4.OFFICIAL_CONTROLLED,
                candidate_observations,
                now,
            )
            associations.append(association)
            observations.extend(candidate_observations)

        # Exact links from a reviewed identity are an endorsement anchor. Trust is
        # intentionally scoped to the exact resource, never the partner domain.
        reviewed_hosts = {
            (urlsplit(_identity_url(identity) or "").hostname or "").casefold() for identity in identities
        }
        for user_url in user_urls:
            canonical = _canonical_discovery_url(user_url)
            if canonical is None:
                continue
            # A root-domain association is stronger and semantically distinct
            # from an endorsed third-party resource.  Never overwrite it just
            # because the submitted URL happens to be on the official host.
            if any(
                item.assurance is IdentityAssociationAssuranceV4.VERIFIED
                and item.relationship is IdentityRelationshipV4.OFFICIAL_CONTROLLED
                and (urlsplit(canonical).hostname or "").casefold() == item.canonical_domain
                for item in associations
            ):
                continue
            anchor: list[IdentityEvidenceObservationV4] = []
            for page in reviewed_pages:
                if any(_canonical_discovery_url(link.canonical_url) == canonical for link in page.extraction.links):
                    anchor.append(
                        _identity_observation(
                            IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT,
                            page.extraction.source_canonical_url,
                            page.extraction.content_hash,
                            now,
                        )
                    )
            anchor.extend(discovery_endorsements.get(canonical, []))
            target = fetched_pages.get(canonical)
            if (
                target is not None
                and (_entity_appears(entity, target[0]) or _grounded_claim_appears(intent, target[0]))
                and (urlsplit(canonical).hostname or "").casefold() not in reviewed_hosts
            ):
                anchor.append(
                    _identity_observation(IdentityEvidenceFamilyV4.TARGET_RESOURCE_MATCH, canonical, target[1], now)
                )
            if any(item.family is IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT for item in anchor):
                association = self._association_from_observations(
                    entity,
                    canonical,
                    IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
                    anchor,
                    now,
                )
                associations = [item for item in associations if item.canonical_url != canonical]
                associations.append(association)
                observations.extend(anchor)

        action = intent.contract.requested_action
        if action is not None:
            action_observations: list[IdentityEvidenceObservationV4] = []
            for canonical, (text, content_hash, _source_host) in fetched_pages.items():
                if any(term in _fold(text) for term in _ACTION_TERMS[action.value]):
                    action_observations.append(
                        _identity_observation(
                            IdentityEvidenceFamilyV4.ACTION_ENDORSEMENT,
                            canonical,
                            content_hash,
                            now,
                        )
                    )
            observations.extend(action_observations)
            if action_observations:
                associations = [
                    item.model_copy(
                        update={
                            "evidence_refs": _unique(
                                [
                                    *item.evidence_refs,
                                    *[
                                        observation.evidence_ref
                                        for observation in action_observations
                                        if observation.source_host == item.canonical_domain
                                        or observation.source_host.endswith(f".{item.canonical_domain}")
                                    ],
                                ]
                            )
                        }
                    )
                    for item in associations
                ]

        save = getattr(self._brands, "save_identity_candidate", None)
        if save is not None:
            stored_associations: list[IdentityAssociationV4] = []
            by_ref = {item.evidence_ref: item for item in observations}
            for association in associations:
                candidate = IdentityCandidateV4(
                    **association.model_dump(),
                    observations=[by_ref[ref] for ref in association.evidence_refs if ref in by_ref],
                )
                stored_associations.append(await save(candidate))
            associations = stored_associations
        await self._observe_authoritative_domain_bootstraps(entity, associations)
        return (
            associations[:20],
            list({item.evidence_ref: item for item in observations}.values())[:50],
            searches,
            fetches,
            calls,
            _unique(limitations),
        )

    async def _observe_authoritative_domain_bootstraps(
        self,
        entity: str,
        associations: Sequence[IdentityAssociationV4],
    ) -> None:
        """Queue, but never activate, a source-policy proposal from cross-source ownership proof.

        A newly established domain remains an ephemeral identity candidate.  We
        only feed it into the separate source-discovery review queue after the
        exact entity phrase on the candidate host and an independent fetched
        source's exact link have already produced a verified association.
        This deliberately excludes self-identification, search rank and
        claim/action/resource endorsements from source-policy bootstrap.
        """
        observe = getattr(self._source_registry, "observe_discovery", None)
        if observe is None:
            return
        for association in associations:
            families = (
                {item.family for item in association.observations}
                if isinstance(association, IdentityCandidateV4)
                else set()
            )
            # Associations returned from the coordinator are normally
            # IdentityCandidateV4 records.  Keep the guard robust for a
            # repository adapter that returns the base association model.
            if not families:
                continue
            if (
                association.assurance is not IdentityAssociationAssuranceV4.VERIFIED
                or association.relationship is not IdentityRelationshipV4.OFFICIAL_CONTROLLED
                or not {
                    IdentityEvidenceFamilyV4.ENTITY_SELF_IDENTIFICATION,
                    IdentityEvidenceFamilyV4.INDEPENDENT_ENTITY_LINK,
                } <= families
            ):
                continue
            claim_hash = hashlib.sha256(
                f"{_fold(entity)}\0{association.canonical_domain}".encode()
            ).hexdigest()
            observed = observe(
                url=association.canonical_url,
                publisher=entity,
                event="extract",
                claim_hash=claim_hash,
            )
            if hasattr(observed, "__await__"):
                await observed
            observed = observe(
                url=association.canonical_url,
                publisher=entity,
                event="comparison",
                claim_hash=claim_hash,
                agrees_with_curated=True,
            )
            if hasattr(observed, "__await__"):
                await observed

    def _is_root_identity_candidate(self, url: str, at: datetime) -> bool:
        """Reject hosts that cannot establish an organization root by themselves."""
        host = (urlsplit(url).hostname or "").casefold().rstrip(".")
        if not host or any(host == value or host.endswith(f".{value}") for value in (*_SOCIAL_HOSTS, *_SHORT_LINK_HOSTS)):
            return False
        if self._source_registry is None:
            return True
        # An explicit reviewed deny is a veto, not a reason to fall back to
        # provider-derived identity evidence.
        return not any(
            getattr(entry, "explicit_deny", False)
            for entry in self._source_registry.matching_entries(url, at)
        )

    def _is_basic_independent_identity_source(self, url: str, at: datetime) -> bool:
        """Apply the existing root-source checks to fetched corroboration.

        This intentionally does not require an attestor policy.  A search hit
        remains only a candidate: it must be fetched, name the exact entity,
        and contain an exact-host anchor before it can be used.
        """
        return self._is_root_identity_candidate(url, at)

    def _is_authoritative_identity_attestor(self, url: str, at: datetime) -> bool:
        """Accept a reviewed policy only for the independent attestor host.

        The policy does not name or approve the candidate organization/domain;
        it merely constrains which external sources are eligible to corroborate
        a new identity.
        """
        if self._source_registry is None:
            return False
        for entry in self._source_registry.matching_entries(url, at):
            source_type = str(getattr(entry, "source_type", "")).casefold()
            effective_from = getattr(entry, "effective_from", None)
            effective_to = getattr(entry, "effective_to", None)
            reviewed_at = getattr(entry, "reviewed_at", None)
            operations = set(getattr(entry, "allowed_operations", set()))
            if (
                source_type in _IDENTITY_CONFIRMING_SOURCE_TYPES
                and not getattr(entry, "explicit_deny", False)
                and getattr(entry, "active", False)
                and effective_from is not None
                and effective_from <= at
                and (effective_to is None or at < effective_to)
                and reviewed_at is not None
                and reviewed_at <= at
                and "read" in operations
            ):
                return True
        return False

    def _is_direct_authoritative_domain_identity(self, url: str, entity: str, at: datetime) -> bool:
        """Whether a reviewed exact source policy independently binds entity to host.

        This is intentionally narrower than an attestor policy: it accepts
        only an exact host entry whose reviewed publisher matches the claimed
        entity. The fetched page must still self-identify that entity before
        this evidence is emitted. It establishes domain ownership only, never
        campaign, resource, sender, or requested-action endorsement.
        """
        if self._source_registry is None:
            return False
        host = (urlsplit(url).hostname or "").casefold().rstrip(".")
        if not host:
            return False
        for entry in self._source_registry.matching_entries(url, at):
            source_type = str(getattr(entry, "source_type", "")).casefold()
            effective_from = getattr(entry, "effective_from", None)
            effective_to = getattr(entry, "effective_to", None)
            reviewed_at = getattr(entry, "reviewed_at", None)
            operations = set(getattr(entry, "allowed_operations", set()))
            if (
                str(getattr(entry, "normalized_pattern", "")).casefold().rstrip(".") == host
                and source_type in _IDENTITY_CONFIRMING_SOURCE_TYPES
                and not getattr(entry, "explicit_deny", False)
                and getattr(entry, "active", False)
                and effective_from is not None
                and effective_from <= at
                and (effective_to is None or at < effective_to)
                and reviewed_at is not None
                and reviewed_at <= at
                and "read" in operations
                and _fold(str(getattr(entry, "publisher", ""))) == _fold(entity)
            ):
                return True
        return False

    @staticmethod
    def _identity_discovery_queries(
        intent: GroundedVerificationIntent,
        *,
        fallback_entity: str = "",
    ) -> list[str]:
        organization = intent.contract.organization_name or fallback_entity
        claim = intent.contract.claim_summary or ""
        values: list[str] = []
        if organization and claim:
            values.append(f'{organization} "{claim}"')
        values.append(organization)
        for item in intent.derived_organizations:
            values.append(f'{item.value} "{claim}"' if claim else item.value)
        queries: list[str] = []
        for value in values:
            bounded = " ".join(value.split())[:200]
            if bounded and bounded.casefold() not in {item.casefold() for item in queries}:
                queries.append(bounded)
        return queries[:3]

    @staticmethod
    def _association_from_observations(
        entity: str,
        canonical_url: str,
        relationship: IdentityRelationshipV4,
        observations: Sequence[IdentityEvidenceObservationV4],
        now: datetime,
    ) -> IdentityAssociationV4:
        families = {item.family for item in observations}
        hosts = {item.source_host for item in observations}
        required = {
            IdentityRelationshipV4.OFFICIAL_CONTROLLED: (
                {IdentityEvidenceFamilyV4.ENTITY_SELF_IDENTIFICATION},
                {IdentityEvidenceFamilyV4.INDEPENDENT_ENTITY_LINK},
            ),
            IdentityRelationshipV4.PARENT_ORGANIZATION: (
                {IdentityEvidenceFamilyV4.PARENT_DECLARATION},
                {
                    IdentityEvidenceFamilyV4.CANDIDATE_CORROBORATION,
                    IdentityEvidenceFamilyV4.INDEPENDENT_ENTITY_LINK,
                },
            ),
            IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE: (
                {IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT},
                {IdentityEvidenceFamilyV4.TARGET_RESOURCE_MATCH},
            ),
        }[relationship]
        target_host = (urlsplit(canonical_url).hostname or "").casefold()
        external_endorsement_hosts = {
            item.source_host
            for item in observations
            if item.family is IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT and item.source_host != target_host
        }
        fully_corroborated = len(hosts) >= 2 and bool(families & required[0]) and bool(families & required[1])
        direct_authoritative_ownership = (
            relationship is IdentityRelationshipV4.OFFICIAL_CONTROLLED
            and IdentityEvidenceFamilyV4.ENTITY_SELF_IDENTIFICATION in families
            and IdentityEvidenceFamilyV4.AUTHORITATIVE_DOMAIN_ATTESTATION in families
        )
        verified = (
            bool(external_endorsement_hosts)
            if relationship is IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE
            else fully_corroborated or direct_authoritative_ownership
        )
        conflicting = IdentityEvidenceFamilyV4.EXPLICIT_OWNERSHIP_CONFLICT in families
        return IdentityAssociationV4(
            entity_name=entity,
            canonical_url=canonical_url,
            canonical_domain=(urlsplit(canonical_url).hostname or "").casefold(),
            relationship=relationship,
            assurance=(
                IdentityAssociationAssuranceV4.CONFLICTING
                if conflicting
                else (
                    IdentityAssociationAssuranceV4.VERIFIED if verified else IdentityAssociationAssuranceV4.DISCOVERED
                )
            ),
            confidence=(
                0.9
                if conflicting
                else (0.85 if fully_corroborated or direct_authoritative_ownership else (0.7 if verified else 0.35))
            ),
            evidence_refs=[item.evidence_ref for item in observations],
            discovered_at=now,
            verified_at=now if verified or conflicting else None,
            expires_at=now + timedelta(days=7),
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
            return _PageEvidence(
                extraction,
                _visible_html_text(fetched.document.body),
                candidate.source_identity,
            ), calls, []

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
                return _PageEvidence(merged, document.content, candidate.source_identity), calls, limitations
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
        local_sources: Sequence[OfficialSourceReferenceV4],
        pages: Sequence[_PageEvidence],
    ) -> tuple[list[OfficialSourceReferenceV4], list[_LinkEvidence]]:
        # Keep the publisher-cited local identity first, then every fetched
        # page cited by link refs. Additional registry descriptors are appended
        # only after reference closure has been secured within the public cap.
        sources = {local_sources[0].source_ref: local_sources[0]} if local_sources else {}
        links: dict[str, _LinkEvidence] = {}
        for page in pages:
            extraction = page.extraction
            linked_identity = page.source_identity.model_copy(update={"source_ref": extraction.source_ref})
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
        if intent.contract.requested_action is RequestedActionV4.OPEN_LINK:
            # "Open this link" identifies a target to inspect, not an
            # official workflow with a canonical outbound destination.  A
            # publisher page can contain many unrelated links; comparing any
            # one of them with the submitted URL would turn an otherwise
            # verified domain (for example, a provider homepage) into a false
            # resource conflict.
            return (
                ResourceVerificationV4(
                    applicable=True,
                    status=VerificationStatusV4.UNVERIFIED,
                    reason_code="generic_open_link_not_resource_comparable",
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

        user_resources = []
        for url in user_urls[:_MAX_USER_ACTION_URLS]:
            direct_resource = identify_resource(url)
            # Provider-specific identities (for example a Google Form URL)
            # are already stable. A generic URL can instead be an unlisted
            # shortener, so resolve it under the existing consent, SSRF, and
            # per-turn call limits before comparing it to an official link.
            user_resources.append(
                await resolve(
                    url,
                    direct_resource if direct_resource is not None and direct_resource.provider is not None else None,
                    outbound=False,
                )
            )
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
    def _resource_from_identity_associations(
        current: ResourceVerificationV4,
        user_urls: Sequence[str],
        associations: Sequence[IdentityAssociationV4],
    ) -> ResourceVerificationV4:
        """Expose a verified discovery chain without claiming a reviewed publisher."""
        if current.status in {VerificationStatusV4.VERIFIED, VerificationStatusV4.CONFLICTING}:
            return current
        requested = {_canonical_discovery_url(url): url for url in user_urls}
        requested.pop(None, None)
        association = next(
            (
                item
                for item in associations
                if item.assurance is IdentityAssociationAssuranceV4.VERIFIED
                and item.relationship is IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE
                and item.canonical_url in requested
            ),
            None,
        )
        if association is None:
            return current
        submitted = requested.get(association.canonical_url) or next(
            url
            for url in requested.values()
            if (urlsplit(url).hostname or "").casefold() == association.canonical_domain
            or (urlsplit(url).hostname or "").casefold().endswith(f".{association.canonical_domain}")
        )
        match = match_resources(
            identify_resource(submitted),
            identify_resource(association.canonical_url),
        )
        return ResourceVerificationV4(
            applicable=True,
            status=VerificationStatusV4.PARTIALLY_VERIFIED,
            reason_code="discovered_exact_resource_endorsement_chain",
            evidence_refs=association.evidence_refs,
            match=match,
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
        identity_associations: Sequence[IdentityAssociationV4] = (),
        identity_evidence: Sequence[IdentityEvidenceObservationV4] = (),
        *,
        user_urls: Sequence[str] = (),
        official_source_consent: bool = False,
        external_url_consent: bool = False,
        action_evidence_refs: Sequence[str] = (),
        reviewed_ownership: dict[str, list[str]] | None = None,
    ) -> OfficialLinkVerificationReportV4:
        action_hosts = {(urlsplit(url).hostname or "").casefold() for url in user_urls}
        reviewed_owner = next(
            (
                (domain, refs)
                for domain, refs in (reviewed_ownership or {}).items()
                if any(host == domain or host.endswith(f".{domain}") for host in action_hosts)
            ),
            None,
        )
        ownership = OfficialVerificationComponentV4(
            applicable=bool(user_urls),
            status=(
                VerificationStatusV4.VERIFIED
                if reviewed_owner is not None
                else VerificationStatusV4.UNVERIFIED
                if user_urls
                else None
            ),
            reason_code=(
                "reviewed_domain_ownership_verified"
                if reviewed_owner is not None
                else "ownership_consent_required"
                if user_urls and not (official_source_consent and external_url_consent)
                else "ownership_evidence_insufficient"
                if user_urls
                else "not_applicable"
            ),
            evidence_refs=reviewed_owner[1] if reviewed_owner is not None else [],
        )
        if ownership.applicable and official_source_consent and external_url_consent:
            verified = next(
                (
                    item
                    for item in identity_associations
                    if item.relationship is IdentityRelationshipV4.OFFICIAL_CONTROLLED
                    and item.assurance is IdentityAssociationAssuranceV4.VERIFIED
                    and any(
                        host == item.canonical_domain or host.endswith(f".{item.canonical_domain}")
                        for host in action_hosts
                    )
                ),
                None,
            )
            if verified is not None:
                ownership = ownership.model_copy(
                    update={
                        "status": VerificationStatusV4.VERIFIED,
                        "reason_code": "independent_domain_ownership_verified",
                        "evidence_refs": verified.evidence_refs,
                    }
                )
        sender = OfficialVerificationComponentV4(
            applicable=intent.contract.requested_action is not None,
            status=(VerificationStatusV4.UNVERIFIED if intent.contract.requested_action is not None else None),
            reason_code=("message_sender_not_authenticated" if intent.contract.requested_action else "not_applicable"),
        )
        action = OfficialVerificationComponentV4(
            applicable=intent.contract.requested_action is not None,
            status=(VerificationStatusV4.UNVERIFIED if intent.contract.requested_action is not None else None),
            reason_code=("official_action_not_confirmed" if intent.contract.requested_action else "not_applicable"),
        )
        action_targets = {_canonical_discovery_url(url) for url in user_urls}
        exact_resource_action_endorsed = bool(
            action.applicable
            and action_evidence_refs
            and any(
                association.assurance is IdentityAssociationAssuranceV4.VERIFIED
                and association.relationship is IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE
                and association.canonical_url in action_targets
                and bool(association.evidence_refs)
                for association in identity_associations
            )
        )
        if (
            action.applicable
            and action_evidence_refs
            and (
                (
                    resource.status is VerificationStatusV4.VERIFIED
                    and (not claim.applicable or claim.status is VerificationStatusV4.VERIFIED)
                )
                or exact_resource_action_endorsed
            )
        ):
            action = action.model_copy(
                update={
                    "status": VerificationStatusV4.VERIFIED,
                    "reason_code": (
                        "official_exact_resource_action_confirmed"
                        if exact_resource_action_endorsed
                        else "official_action_and_resource_confirmed"
                    ),
                    "evidence_refs": list(
                        dict.fromkeys([*claim.evidence_refs, *resource.evidence_refs, *action_evidence_refs])
                    ),
                }
            )
        statuses = [
            component.status
            for component in (publisher, claim, resource, action)
            if component.applicable and component.status is not None
        ]
        if not intent.contract.action_url_indices and sender.applicable:
            statuses.append(sender.status)
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
            schema_version="official-link-verification-v4",
            intent=intent.contract,
            publisher_verification=publisher,
            claim_verification=claim,
            resource_verification=resource,
            domain_ownership_verification=ownership,
            sender_verification=sender,
            action_endorsement_verification=action,
            overall_status=overall,
            reason_code=reason,
            source_refs=list(sources)[:20],
            link_refs=list(links)[:50],
            limitations=_unique(list(limitations))[:50],
            identity_associations=list(identity_associations)[:20],
            identity_evidence=list(identity_evidence)[:50],
            policy_version="official-link-verification-v4",
        )

    @staticmethod
    def _validate_reference_closure(report: OfficialLinkVerificationReportV4) -> None:
        available = {source.source_ref for source in report.source_refs}
        available.update(link.link_ref for link in report.link_refs)
        available.update(item.evidence_ref for item in report.identity_evidence)
        cited = set(report.publisher_verification.evidence_refs)
        cited.update(report.claim_verification.evidence_refs)
        cited.update(report.resource_verification.evidence_refs)
        cited.update(report.domain_ownership_verification.evidence_refs)
        cited.update(report.sender_verification.evidence_refs)
        cited.update(report.action_endorsement_verification.evidence_refs)
        if cited - available:
            raise ValueError("official verification evidence-reference closure failed")
        source_ids = {source.source_ref for source in report.source_refs}
        if any(link.source_ref not in source_ids for link in report.link_refs):
            raise ValueError("official link reference cites an unavailable source")
        identity_refs = {item.evidence_ref for item in report.identity_evidence}
        cited_identity_refs = {
            evidence_ref for association in report.identity_associations for evidence_ref in association.evidence_refs
        }
        if cited_identity_refs - identity_refs:
            raise ValueError("identity association evidence-reference closure failed")


__all__ = [
    "ComparisonDimension",
    "ComparisonRelation",
    "OfficialLinkVerificationCoordinator",
    "OfficialVerificationCoordinatorOutcome",
    "apply_official_verification_outcome",
    "has_verified_exact_resource_action_endorsement",
    "has_verified_exact_resource_endorsement",
    "verified_exact_resource_endorsement_associations",
    "VerificationComparisonOutput",
    "validate_comparison_output",
]
