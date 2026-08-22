from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit
from uuid import NAMESPACE_URL, uuid5

from src.agents.nodes.rules import normalize_url
from src.models import (
    BrandRecordV4,
    OfficialIdentityMatchScopeV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    TrustLifecycleV4,
)
from src.repositories.blacklist import normalize_domain


class BrandResolutionStatus(StrEnum):
    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    NOT_FOUND = "not_found"


class BrandResolutionMatch(StrEnum):
    EXACT_CANONICAL_NAME = "exact_canonical_name"
    EXACT_ALIAS = "exact_alias"
    BOUNDED_PHRASE = "bounded_phrase"


class SourceIdentityAssessment(StrEnum):
    CONFIRMS_IDENTITY = "confirms_identity"
    CORROBORATES = "corroborates"
    NO_MATCH = "no_match"


class ReviewedSourceEntry(Protocol):
    publisher: str
    normalized_pattern: str
    active: bool
    explicit_deny: bool
    effective_from: datetime
    effective_to: datetime | None
    reviewed_at: datetime


@dataclass(frozen=True, slots=True)
class BrandIdentityResolution:
    status: BrandResolutionStatus
    match: BrandResolutionMatch | None = None
    brand: BrandRecordV4 | None = None
    identities: tuple[OfficialIdentityV4, ...] = ()
    candidate_brand_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status is BrandResolutionStatus.RESOLVED and self.brand is None:
            raise ValueError("resolved identity requires a brand")
        if self.status is not BrandResolutionStatus.RESOLVED and (self.brand or self.identities):
            raise ValueError("unresolved identity cannot create an implicit allowlist")


def _fold(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    folded = "".join(char for char in decomposed if not unicodedata.combining(char))
    return " ".join(folded.replace("đ", "d").split())


def _is_bounded_phrase(phrase: str, value: str) -> bool:
    return bool(phrase) and re.search(rf"(?<!\w){re.escape(phrase)}(?!\w)", value) is not None


def _identity_host(identity: OfficialIdentityV4) -> str | None:
    if identity.identity_type in {
        OfficialIdentityTypeV4.PRIMARY_WEBSITE,
        OfficialIdentityTypeV4.DOMAIN,
    }:
        return identity.canonical_value.casefold().rstrip(".")
    if identity.identity_type in {
        OfficialIdentityTypeV4.WEBSITE,
        OfficialIdentityTypeV4.CAREERS_PAGE,
        OfficialIdentityTypeV4.SOCIAL_PROFILE,
    }:
        return (urlsplit(identity.canonical_value).hostname or "").casefold().rstrip(".") or None
    return None


def normalize_official_identity(
    identity: OfficialIdentityV4,
    *,
    brand_name: str,
    brand_provenance: str,
    brand_policy_version: str,
    brand_effective_from: datetime,
) -> OfficialIdentityV4:
    """Normalize an admin-reviewed identity without accepting discovered network values."""
    identity_type = identity.identity_type
    canonical = identity.canonical_value
    match_scope = identity.match_scope
    relationship = identity.relationship

    if identity_type in {
        OfficialIdentityTypeV4.PRIMARY_WEBSITE,
        OfficialIdentityTypeV4.DOMAIN,
    }:
        canonical = normalize_domain(canonical)
        match_scope = OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS
        if identity_type is OfficialIdentityTypeV4.PRIMARY_WEBSITE and relationship == "primary":
            relationship = "primary_website"
    elif identity_type in {
        OfficialIdentityTypeV4.WEBSITE,
        OfficialIdentityTypeV4.CAREERS_PAGE,
        OfficialIdentityTypeV4.SOCIAL_PROFILE,
    }:
        candidate = canonical if "://" in canonical else f"https://{canonical}"
        parsed_candidate = urlsplit(candidate)
        if parsed_candidate.username or parsed_candidate.password:
            raise ValueError("official identity URLs cannot contain credentials")
        normalized = normalize_url(candidate)
        if normalized is None:
            raise ValueError("official identity URL is invalid")
        parsed = urlsplit(normalized)
        canonical = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        match_scope = OfficialIdentityMatchScopeV4.EXACT
        if relationship == "primary":
            relationship = {
                OfficialIdentityTypeV4.WEBSITE: "official_website",
                OfficialIdentityTypeV4.CAREERS_PAGE: "careers",
                OfficialIdentityTypeV4.SOCIAL_PROFILE: "official_social",
            }[identity_type]
    elif identity_type is OfficialIdentityTypeV4.SUB_ORGANIZATION:
        canonical = " ".join(canonical.split())
        match_scope = OfficialIdentityMatchScopeV4.BOUNDED_PHRASE
        if relationship == "primary":
            relationship = "sub_organization"

    payload = identity.model_dump()
    payload.update(
        {
            "canonical_value": canonical,
            "entity_name": identity.entity_name or brand_name,
            "match_scope": match_scope,
            "relationship": relationship,
            "provenance": (brand_provenance if identity.provenance == "unversioned_contract" else identity.provenance),
            "policy_version": (
                brand_policy_version if identity.policy_version == "official-identity-v1" else identity.policy_version
            ),
            "effective_from": identity.effective_from or brand_effective_from,
            "reviewed": True,
        }
    )
    return OfficialIdentityV4.model_validate(payload)


def runtime_official_identities(
    brand: BrandRecordV4,
    at: datetime,
) -> tuple[OfficialIdentityV4, ...]:
    """Read explicit identities and project legacy official_domains as primary websites."""
    explicit = list(brand.official_identities)
    explicit_keys = {(item.identity_type, item.canonical_value.casefold()) for item in explicit}
    for domain in brand.official_domains:
        canonical_domain = normalize_domain(domain)
        key = (OfficialIdentityTypeV4.PRIMARY_WEBSITE, canonical_domain)
        if key in explicit_keys:
            continue
        explicit.append(
            OfficialIdentityV4(
                identity_id=uuid5(
                    NAMESPACE_URL,
                    f"brand:{brand.brand_id}:primary-website:{canonical_domain}",
                ),
                identity_type=OfficialIdentityTypeV4.PRIMARY_WEBSITE,
                canonical_value=canonical_domain,
                display_value=domain,
                entity_name=brand.name,
                match_scope=OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS,
                relationship="primary_website",
                provenance=brand.provenance,
                policy_version=brand.policy_version,
                effective_from=brand.effective_from,
                effective_until=brand.effective_until,
                reviewed=True,
            )
        )

    effective_versions = [
        item
        for item in explicit
        if item.effective_from is None or item.effective_from <= at
        if item.effective_until is None or at < item.effective_until
    ]
    superseded = {item.supersedes for item in effective_versions if item.supersedes is not None}
    return tuple(
        item
        for item in effective_versions
        if item.lifecycle is TrustLifecycleV4.ACTIVE and item.identity_id not in superseded
    )


def active_brand_versions(brands: Sequence[BrandRecordV4], at: datetime) -> list[BrandRecordV4]:
    effective = [
        item
        for item in brands
        if item.effective_from <= at and (item.effective_until is None or at < item.effective_until)
    ]
    superseded = {item.supersedes for item in effective if item.supersedes is not None}
    return [item for item in effective if item.lifecycle is TrustLifecycleV4.ACTIVE and item.brand_id not in superseded]


class OfficialIdentityRegistry:
    def resolve(
        self,
        organization_name: str,
        brands: Sequence[BrandRecordV4],
        at: datetime,
    ) -> BrandIdentityResolution:
        folded = _fold(organization_name)
        active = active_brand_versions(brands, at)
        canonical = [item for item in active if _fold(item.name) == folded]
        result = self._select(canonical, BrandResolutionMatch.EXACT_CANONICAL_NAME, at)
        if result is not None:
            return result

        aliases = [item for item in active if folded in {_fold(alias) for alias in item.aliases}]
        result = self._select(aliases, BrandResolutionMatch.EXACT_ALIAS, at)
        if result is not None:
            return result

        phrases = [
            item
            for item in active
            if any(
                _is_bounded_phrase(candidate, folded)
                for candidate in {
                    _fold(item.name),
                    *(_fold(alias) for alias in item.aliases),
                    *(
                        _fold(identity.canonical_value)
                        for identity in runtime_official_identities(item, at)
                        if identity.identity_type is OfficialIdentityTypeV4.SUB_ORGANIZATION
                    ),
                    *(
                        _fold(identity.entity_name)
                        for identity in runtime_official_identities(item, at)
                        if identity.identity_type is OfficialIdentityTypeV4.SUB_ORGANIZATION
                    ),
                }
            )
        ]
        result = self._select(phrases, BrandResolutionMatch.BOUNDED_PHRASE, at)
        if result is not None:
            return result
        return BrandIdentityResolution(status=BrandResolutionStatus.NOT_FOUND)

    @staticmethod
    def _select(
        matches: Sequence[BrandRecordV4],
        match: BrandResolutionMatch,
        at: datetime,
    ) -> BrandIdentityResolution | None:
        if not matches:
            return None
        if len(matches) > 1:
            return BrandIdentityResolution(
                status=BrandResolutionStatus.AMBIGUOUS,
                match=match,
                candidate_brand_ids=tuple(sorted(str(item.brand_id) for item in matches)),
            )
        brand = matches[0]
        return BrandIdentityResolution(
            status=BrandResolutionStatus.RESOLVED,
            match=match,
            brand=brand,
            identities=runtime_official_identities(brand, at),
            candidate_brand_ids=(str(brand.brand_id),),
        )

    def assess_source_entry(
        self,
        identity: OfficialIdentityV4,
        brand: BrandRecordV4,
        entry: object,
        at: datetime,
    ) -> SourceIdentityAssessment:
        """Only exact, entity-bound, reviewed source entries can confirm an identity."""
        host = _identity_host(identity)
        pattern = getattr(entry, "normalized_pattern", "").casefold().rstrip(".")
        if not identity.reviewed or not host or not pattern or getattr(entry, "explicit_deny", False):
            return SourceIdentityAssessment.NO_MATCH
        if not getattr(entry, "active", False):
            return SourceIdentityAssessment.NO_MATCH
        effective_from = getattr(entry, "effective_from", None)
        effective_to = getattr(entry, "effective_to", None)
        if effective_from is None or effective_from > at or (effective_to is not None and at >= effective_to):
            return SourceIdentityAssessment.NO_MATCH
        suffix = pattern.removeprefix("*.")
        if host != suffix and not host.endswith(f".{suffix}"):
            return SourceIdentityAssessment.NO_MATCH

        reviewed_at = getattr(entry, "reviewed_at", None)
        publisher = _fold(getattr(entry, "publisher", ""))
        entity_names = {_fold(brand.name), _fold(identity.entity_name), *(_fold(alias) for alias in brand.aliases)}
        exact_entity_bound = (
            not pattern.startswith("*.")
            and host == pattern
            and reviewed_at is not None
            and reviewed_at <= at
            and publisher in entity_names
        )
        return (
            SourceIdentityAssessment.CONFIRMS_IDENTITY if exact_entity_bound else SourceIdentityAssessment.CORROBORATES
        )


__all__ = [
    "BrandIdentityResolution",
    "BrandResolutionMatch",
    "BrandResolutionStatus",
    "OfficialIdentityRegistry",
    "SourceIdentityAssessment",
    "active_brand_versions",
    "normalize_official_identity",
    "runtime_official_identities",
]
