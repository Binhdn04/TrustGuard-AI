from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from src.agents.nodes.planning import step_id_for
from src.agents.nodes.rules import normalize_url
from src.agents.tools.domains import canonicalize_registrable_domain
from src.models import (
    BrandRecordV4,
    DomainFamiliarityClassificationV4,
    DomainFamiliarityDetailsV4,
    EntityUrlRelationshipV4,
    InvestigationStepV4,
    OfficialIdentityMatchScopeV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityInvestigationStepStatusV4,
    SecurityInvestigationToolV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    WhitelistRecordV4,
    WhitelistScopeV4,
)
from src.services.official_identity_registry import (
    BrandResolutionStatus,
    OfficialIdentityRegistry,
    runtime_official_identities,
)

_EMAIL_RE = re.compile(r"(?<![\w.+-])([\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])")


class SecurityTrustRepository(Protocol):
    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]: ...
    async def list_active_whitelist(self, at: datetime) -> list[WhitelistRecordV4]: ...


class ReviewedSourceIdentityRegistry(Protocol):
    def matching_entries(self, url: str, at: datetime) -> Sequence[object]: ...


def _fold(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    return " ".join("".join(char for char in decomposed if not unicodedata.combining(char)).split())


def _ref(kind: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join((kind, *values)).encode()).hexdigest()[:16]
    return f"evidence:{digest}"


def _evidence(
    kind: SecurityEvidenceTypeV4,
    source: str,
    signal: str,
    description: str,
    observed_at: datetime,
    *,
    target: str | None = None,
    confidence: float | None = None,
    provenance_ref: str | None = None,
    domain_familiarity: DomainFamiliarityDetailsV4 | None = None,
) -> SecurityEvidenceV4:
    return SecurityEvidenceV4(
        evidence_ref=_ref(kind.value, source, target or "", signal),
        type=kind,
        source=source,
        target=target,
        signal=signal,
        description=description,
        observed_at=observed_at,
        confidence=confidence,
        provenance_ref=provenance_ref,
        domain_familiarity=domain_familiarity,
    )


def _is_domain_or_subdomain(observed: str, official: str) -> bool:
    return observed == official or observed.endswith(f".{official}")


def canonical_whitelist_url(value: str) -> str | None:
    normalized = normalize_url(value)
    if normalized is None:
        return None
    parsed = urlsplit(normalized)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for index, left_char in enumerate(left, start=1):
        current = [index]
        for other_index, right_char in enumerate(right, start=1):
            current.append(
                min(current[-1] + 1, previous[other_index] + 1, previous[other_index - 1] + (left_char != right_char))
            )
        previous = current
    return previous[-1]


def _brand_for_message(
    message: str,
    claimed_entity: str | None,
    brands: list[BrandRecordV4],
    observed_at: datetime,
) -> BrandRecordV4 | None:
    registry = OfficialIdentityRegistry()
    if claimed_entity:
        resolution = registry.resolve(claimed_entity, brands, observed_at)
        if resolution.status is BrandResolutionStatus.RESOLVED:
            return resolution.brand
        if resolution.status is BrandResolutionStatus.AMBIGUOUS:
            return None
    resolution = registry.resolve(message, brands, observed_at)
    return resolution.brand if resolution.status is BrandResolutionStatus.RESOLVED else None


def _target_owner(
    url: str,
    brands: list[BrandRecordV4],
    observed_at: datetime,
    source_registry: ReviewedSourceIdentityRegistry | None,
) -> tuple[str, str] | None:
    host = (urlsplit(url).hostname or "").casefold().rstrip(".")
    brand_owners: dict[str, tuple[str, str]] = {}
    for brand in brands:
        for identity in runtime_official_identities(brand, observed_at):
            if identity.relationship == "platform_service":
                continue
            candidate = canonical_whitelist_url(identity.canonical_value)
            identity_host = (urlsplit(candidate or f"//{identity.canonical_value}").hostname or "").casefold()
            matched = (
                identity.match_scope is OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS
                and _is_domain_or_subdomain(host, identity_host)
            ) or (
                identity.match_scope is OfficialIdentityMatchScopeV4.EXACT and candidate == canonical_whitelist_url(url)
            )
            if matched:
                brand_owners[_fold(brand.name)] = (brand.name, f"brand:{brand.brand_id}:{brand.policy_version}")
    if len(brand_owners) == 1:
        return next(iter(brand_owners.values()))
    if len(brand_owners) > 1:
        return None
    source_owners: dict[str, tuple[str, str]] = {}
    if source_registry is not None:
        for entry in source_registry.matching_entries(url, observed_at):
            pattern = getattr(entry, "normalized_pattern", "")
            publisher = getattr(entry, "publisher", "")
            if (
                publisher
                and pattern
                and not pattern.startswith("*.")
                and not getattr(entry, "explicit_deny", False)
                and pattern.casefold().rstrip(".") == host
            ):
                source_id = getattr(entry, "source_id", "reviewed")
                policy = getattr(entry, "policy_version", "source-registry")
                source_owners[_fold(publisher)] = (publisher, f"source:{source_id}:{policy}")
    return next(iter(source_owners.values())) if len(source_owners) == 1 else None


def _reviewed_familiarity_evidence(
    urls: list[str],
    brands: list[BrandRecordV4],
    observed_at: datetime,
) -> list[SecurityEvidenceV4]:
    evidence: list[SecurityEvidenceV4] = []
    for url in urls:
        host = (urlsplit(url).hostname or "").casefold().rstrip(".")
        if not host:
            continue
        matches: list[tuple[int, BrandRecordV4, OfficialIdentityV4]] = []
        for brand in brands:
            for identity in runtime_official_identities(brand, observed_at):
                if not identity.reviewed or identity.identity_type not in {
                    OfficialIdentityTypeV4.PRIMARY_WEBSITE,
                    OfficialIdentityTypeV4.DOMAIN,
                }:
                    continue
                identity_host = identity.canonical_value.casefold().rstrip(".")
                if identity.match_scope is OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS:
                    matched = _is_domain_or_subdomain(host, identity_host)
                else:
                    matched = host == identity_host
                if matched:
                    matches.append((len(identity_host.split(".")), brand, identity))
        if not matches:
            continue
        _, brand, identity = max(matches, key=lambda item: item[0])
        is_platform = identity.relationship == "platform_service"
        classification = (
            DomainFamiliarityClassificationV4.REVIEWED_PLATFORM_SERVICE
            if is_platform
            else DomainFamiliarityClassificationV4.REVIEWED_FIRST_PARTY
        )
        signal = "reviewed_platform_service" if is_platform else "reviewed_first_party_domain"
        try:
            registrable = canonicalize_registrable_domain(host)
        except ValueError:
            continue
        details = DomainFamiliarityDetailsV4(
            observed_host=host,
            registrable_domain=registrable,
            classification=classification,
            platform_name=identity.entity_name if is_platform else None,
            shared_platform=is_platform,
        )
        evidence.append(
            _evidence(
                SecurityEvidenceTypeV4.DOMAIN_FAMILIARITY,
                "brand-registry",
                signal,
                (
                    f"{host} là dịch vụ nền tảng đã được review của {identity.entity_name}; "
                    "nền tảng quen thuộc không bảo chứng publisher hoặc nội dung cụ thể."
                    if is_platform
                    else f"{host} khớp domain first-party đã được review của {brand.name}."
                ),
                observed_at,
                target=host,
                confidence=1.0,
                provenance_ref=f"brand:{brand.brand_id}:{identity.policy_version}",
                domain_familiarity=details,
            )
        )
    return evidence


class BrandMatcher:
    def __init__(self, source_registry: ReviewedSourceIdentityRegistry | None = None) -> None:
        self._source_registry = source_registry

    def match(
        self,
        request: SecurityTriageCreateRequestV4,
        scope: SecurityScopeResponseV4,
        brands: list[BrandRecordV4],
        observed_at: datetime,
    ) -> tuple[BrandRecordV4 | None, list[SecurityEvidenceV4]]:
        context = scope.security_context
        if context is None:
            return None, []
        brand = _brand_for_message(request.message, context.claimed_entity, brands, observed_at)
        claims_by_index = {item.url_index: item for item in context.entity_url_claims}
        if brand is None and not claims_by_index:
            if not context.claimed_entity:
                return None, []
            evidence = []
            for url in context.urls:
                host = (urlsplit(url).hostname or "").casefold()
                evidence.append(
                    _evidence(
                        SecurityEvidenceTypeV4.BRAND_MATCH,
                        "brand-registry",
                        "claimed_identity_unverified",
                        (
                            f"Chưa có reviewed identity hoặc exact-resource association để xác nhận quan hệ "
                            f"giữa URL trên {host} và tổ chức {context.claimed_entity}; domain có thể là nền "
                            "tảng bên thứ ba và không được mặc định là tài sản của tổ chức."
                        ),
                        observed_at,
                        target=host,
                        confidence=0.5,
                        provenance_ref="brand-registry:review-required",
                    )
                )
            return None, evidence
        evidence: list[SecurityEvidenceV4] = []
        provenance = f"brand:{brand.brand_id}:{brand.policy_version}" if brand else "brand-registry:unresolved"
        identities = runtime_official_identities(brand, observed_at) if brand else ()
        official_domains = {
            item.canonical_value
            for item in identities
            if item.match_scope is OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS
        }
        exact_urls = {
            canonical_whitelist_url(item.canonical_value)
            for item in identities
            if item.match_scope is OfficialIdentityMatchScopeV4.EXACT and "://" in item.canonical_value
        }
        for url_index, url in enumerate(context.urls):
            host = (urlsplit(url).hostname or "").casefold()
            exact_url = canonical_whitelist_url(url)
            claim = claims_by_index.get(url_index)
            owner = _target_owner(url, brands, observed_at, self._source_registry) if claim else None
            evidence_provenance = provenance
            if context.claimed_entity and claim is None:
                evidence.append(
                    _evidence(
                        SecurityEvidenceTypeV4.BRAND_MATCH,
                        "local-entity-linker",
                        "entity_url_relation_unresolved",
                        (
                            f"Nội dung có nhắc {context.claimed_entity} và domain {host}, nhưng chưa có "
                            "quan hệ entity-URL được grounded."
                        ),
                        observed_at,
                        target=host,
                        confidence=0.5,
                        provenance_ref="local-entity-linker:v1",
                    )
                )
            if claim and claim.relationship is EntityUrlRelationshipV4.REFERENCE_ONLY:
                continue
            if exact_url in exact_urls or any(_is_domain_or_subdomain(host, official) for official in official_domains):
                signal, confidence = "official_match", 1.0
            elif claim and owner is not None and _fold(claim.entity_name) != _fold(owner[0]):
                signal, confidence = "entity_target_mismatch", 1.0
                evidence_provenance = f"{provenance}|{owner[1]}"
            elif host.startswith("xn--") or ".xn--" in host:
                signal, confidence = "homograph_domain", 0.9
            elif any(
                _distance(host.split(".")[0], official.split(".")[0]) <= 2
                or host.split(".")[0].startswith(f"{official.split('.')[0]}-")
                for official in official_domains
            ):
                signal, confidence = "lookalike_domain", 0.85
            elif brand is not None:
                signal, confidence = "domain_mismatch", 0.7
            else:
                signal, confidence = "entity_target_unverified", 0.5
            evidence.append(
                _evidence(
                    SecurityEvidenceTypeV4.BRAND_MATCH,
                    "brand-registry",
                    signal,
                    (
                        f"Domain thuộc reviewed identity của {owner[0]} nhưng nội dung gắn domain với "
                        f"{claim.entity_name}; kết quả={signal}."
                        if signal == "entity_target_mismatch" and owner is not None and claim is not None
                        else f"Domain được đối chiếu với registry của {brand.name if brand else context.claimed_entity}; kết quả={signal}."
                    ),
                    observed_at,
                    target=host,
                    confidence=confidence,
                    provenance_ref=evidence_provenance,
                )
            )
        official_contacts = {_fold(item) for item in brand.official_contacts} if brand else set()
        for contact in _EMAIL_RE.findall(request.message):
            digest_target = f"contact:{hashlib.sha256(contact.casefold().encode()).hexdigest()[:16]}"
            signal = "official_contact_match" if _fold(contact) in official_contacts else "contact_mismatch"
            evidence.append(
                _evidence(
                    SecurityEvidenceTypeV4.BRAND_MATCH,
                    "brand-registry",
                    signal,
                    f"Contact được đối chiếu với registry của {brand.name if brand else context.claimed_entity}; kết quả={signal}.",
                    observed_at,
                    target=digest_target,
                    confidence=1.0 if signal == "official_contact_match" else 0.7,
                    provenance_ref=provenance,
                )
            )
        return brand, evidence


class SecurityTrustService:
    def __init__(
        self,
        repository: SecurityTrustRepository,
        *,
        matcher: BrandMatcher | None = None,
        source_registry: ReviewedSourceIdentityRegistry | None = None,
        domain_familiarity_enabled: bool = False,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self._repository = repository
        self._matcher = matcher or BrandMatcher(source_registry)
        self._clock = clock
        self._domain_familiarity_enabled = domain_familiarity_enabled

    async def enrich(
        self, request: SecurityTriageCreateRequestV4, scope: SecurityScopeResponseV4
    ) -> SecurityScopeResponseV4:
        if scope.security_context is None:
            return scope
        now = self._clock()
        plan = list(scope.investigation_plan)
        trust_indexes = [
            index
            for index, step in enumerate(plan)
            if step.tool
            in {
                SecurityInvestigationToolV4.BRAND_MATCH,
                SecurityInvestigationToolV4.WHITELIST_LOOKUP,
            }
        ]
        # A completed planner with no trust candidates intentionally selected a
        # context-only route (for example payment/OTP without a URL).
        if not trust_indexes and scope.investigation_status is not SecurityInvestigationStatusV4.NOT_STARTED:
            return scope

        if not trust_indexes:  # compatibility for callers that invoke trust directly
            brand_placeholder = self._local_plan(scope, None)[0].model_copy(
                update={"status": SecurityInvestigationStepStatusV4.PENDING, "status_reason": None}
            )
            plan.append(brand_placeholder)
            for step in self._local_plan(scope, None)[1:]:
                plan.append(step.model_copy(update={"status": SecurityInvestigationStepStatusV4.PENDING}))

        brand_indexes = [
            index
            for index, step in enumerate(plan)
            if step.tool is SecurityInvestigationToolV4.BRAND_MATCH
            and step.status is SecurityInvestigationStepStatusV4.PENDING
        ]
        whitelist_indexes = [
            index
            for index, step in enumerate(plan)
            if step.tool is SecurityInvestigationToolV4.WHITELIST_LOOKUP
            and step.status is SecurityInvestigationStepStatusV4.PENDING
        ]
        brands = await self._repository.list_active_brands(now) if brand_indexes else []
        brand, evidence = self._matcher.match(request, scope, brands, now) if brand_indexes else (None, [])
        if brand_indexes and self._domain_familiarity_enabled:
            evidence.extend(_reviewed_familiarity_evidence(scope.security_context.urls, brands, now))
        for index in brand_indexes:
            plan[index] = plan[index].model_copy(
                update={
                    "status": SecurityInvestigationStepStatusV4.COMPLETED,
                    "status_reason": "match_completed" if brand else "no_brand_match",
                }
            )
        if whitelist_indexes:
            whitelist = await self._repository.list_active_whitelist(now)
            evidence.extend(self._whitelist_evidence(request, scope, whitelist, now))
            for index in whitelist_indexes:
                plan[index] = plan[index].model_copy(
                    update={
                        "status": SecurityInvestigationStepStatusV4.COMPLETED,
                        "status_reason": "lookup_completed",
                    }
                )

        payload = scope.model_dump()
        payload["evidence"] = list({item.evidence_ref: item for item in [*scope.evidence, *evidence]}.values())
        payload["investigation_plan"] = plan
        limitation_messages: list[str] = []
        if any(item.signal in {"claimed_identity_unverified", "entity_target_unverified"} for item in evidence):
            limitation_messages.append(
                "Chưa có reviewed identity hoặc exact-resource association để xác nhận quan hệ giữa URL và tổ chức."
            )
        if any(item.signal == "entity_url_relation_unresolved" for item in evidence):
            limitation_messages.append(
                "Chưa xác nhận được quan hệ giữa domain và tổ chức được nhắc đến trong nội dung."
            )
        if limitation_messages:
            payload["limitations"] = list(
                dict.fromkeys(
                    [
                        *scope.limitations,
                        *limitation_messages,
                    ]
                )
            )
        return SecurityScopeResponseV4.model_validate(payload)

    def _local_plan(self, scope: SecurityScopeResponseV4, brand: BrandRecordV4 | None) -> list[InvestigationStepV4]:
        context = scope.security_context
        assert context is not None
        steps = [
            InvestigationStepV4(
                step_id=step_id_for(SecurityInvestigationToolV4.BRAND_MATCH.value, "message"),
                tool=SecurityInvestigationToolV4.BRAND_MATCH,
                target="message",
                reason_code="claimed_entity_or_alias_check",
                status=SecurityInvestigationStepStatusV4.COMPLETED,
                status_reason="match_completed" if brand else "no_brand_match",
            )
        ]
        for url in context.urls:
            host = (urlsplit(url).hostname or "").casefold()
            steps.append(
                InvestigationStepV4(
                    step_id=step_id_for(SecurityInvestigationToolV4.WHITELIST_LOOKUP.value, host),
                    tool=SecurityInvestigationToolV4.WHITELIST_LOOKUP,
                    target=host,
                    reason_code="trust_indicator_lookup",
                    status=SecurityInvestigationStepStatusV4.COMPLETED,
                    status_reason="lookup_completed",
                )
            )
        return steps

    def _whitelist_evidence(
        self,
        request: SecurityTriageCreateRequestV4,
        scope: SecurityScopeResponseV4,
        records: list[WhitelistRecordV4],
        observed_at: datetime,
    ) -> list[SecurityEvidenceV4]:
        context = scope.security_context
        assert context is not None
        domains = {(urlsplit(url).hostname or "").casefold() for url in context.urls}
        urls = {canonical_whitelist_url(url) for url in context.urls}
        contacts = {item.casefold() for item in _EMAIL_RE.findall(request.message)}
        evidence: list[SecurityEvidenceV4] = []
        for record in records:
            matched = (
                (record.scope is WhitelistScopeV4.DOMAIN and record.indicator in domains)
                or (record.scope is WhitelistScopeV4.URL and canonical_whitelist_url(record.indicator) in urls)
                or (record.scope is WhitelistScopeV4.CONTACT and record.indicator.casefold() in contacts)
            )
            if not matched:
                continue
            target = record.indicator
            if record.scope is not WhitelistScopeV4.DOMAIN:
                target = f"target:{hashlib.sha256(record.indicator.encode()).hexdigest()[:16]}"
            evidence.append(
                _evidence(
                    SecurityEvidenceTypeV4.WHITELIST,
                    "approved-whitelist",
                    "approved_whitelist",
                    f"Indicator khớp whitelist policy {record.policy_version}.",
                    observed_at,
                    target=target,
                    confidence=1.0,
                    provenance_ref=f"whitelist:{record.whitelist_id}:{record.policy_version}",
                )
            )
        return evidence


__all__ = [
    "BrandMatcher",
    "SecurityTrustService",
    "canonical_whitelist_url",
]
