from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from src.agents.nodes.planning import step_id_for
from src.agents.nodes.rules import normalize_url
from src.models import (
    BrandRecordV4,
    InvestigationStepV4,
    OfficialIdentityMatchScopeV4,
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


class BrandMatcher:
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
        if brand is None:
            return None, []
        evidence: list[SecurityEvidenceV4] = []
        provenance = f"brand:{brand.brand_id}:{brand.policy_version}"
        identities = runtime_official_identities(brand, observed_at)
        official_domains = {
            item.canonical_value
            for item in identities
            if item.match_scope is OfficialIdentityMatchScopeV4.HOST_AND_SUBDOMAINS
        }
        exact_urls = {
            canonical_whitelist_url(item.canonical_value)
            for item in identities
            if item.match_scope is OfficialIdentityMatchScopeV4.EXACT
            and "://" in item.canonical_value
        }
        for url in context.urls:
            host = (urlsplit(url).hostname or "").casefold()
            exact_url = canonical_whitelist_url(url)
            if exact_url in exact_urls or any(
                _is_domain_or_subdomain(host, official) for official in official_domains
            ):
                signal, confidence = "official_match", 1.0
            elif host.startswith("xn--") or ".xn--" in host:
                signal, confidence = "homograph_domain", 0.9
            elif any(
                _distance(host.split(".")[0], official.split(".")[0]) <= 2
                or host.split(".")[0].startswith(f"{official.split('.')[0]}-")
                for official in official_domains
            ):
                signal, confidence = "lookalike_domain", 0.85
            else:
                signal, confidence = "domain_mismatch", 0.7
            evidence.append(
                _evidence(
                    SecurityEvidenceTypeV4.BRAND_MATCH,
                    "brand-registry",
                    signal,
                    f"Domain được đối chiếu với registry của {brand.name}; kết quả={signal}.",
                    observed_at,
                    target=host,
                    confidence=confidence,
                    provenance_ref=provenance,
                )
            )
        official_contacts = {_fold(item) for item in brand.official_contacts}
        for contact in _EMAIL_RE.findall(request.message):
            digest_target = f"contact:{hashlib.sha256(contact.casefold().encode()).hexdigest()[:16]}"
            signal = "official_contact_match" if _fold(contact) in official_contacts else "contact_mismatch"
            evidence.append(
                _evidence(
                    SecurityEvidenceTypeV4.BRAND_MATCH,
                    "brand-registry",
                    signal,
                    f"Contact được đối chiếu với registry của {brand.name}; kết quả={signal}.",
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
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self._repository = repository
        self._matcher = matcher or BrandMatcher()
        self._clock = clock

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
