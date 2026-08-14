from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

import httpx

from src.agents.nodes.planning import step_id_for
from src.agents.nodes.rules import normalize_url
from src.models import (
    BrandRecordV4,
    InvestigationStepV4,
    OfficialSourceFindingV4,
    OfficialVerificationPurposeV4,
    OfficialVerificationResultV4,
    OfficialVerificationVerdictV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityInvestigationStepStatusV4,
    SecurityInvestigationToolV4,
    SecurityScenarioV4,
    SecurityScopeResponseV4,
    SecurityToolErrorV4,
    SecurityTriageCreateRequestV4,
    WhitelistRecordV4,
    WhitelistScopeV4,
)
from src.repositories.blacklist import normalize_domain

_EMAIL_RE = re.compile(r"(?<![\w.+-])([\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])")


class SecurityTrustRepository(Protocol):
    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]: ...
    async def list_active_whitelist(self, at: datetime) -> list[WhitelistRecordV4]: ...


class OfficialSourceSearch(Protocol):
    async def search(
        self, query: str, *, allowed_domains: Sequence[str], max_results: int
    ) -> list[OfficialSourceFindingV4]: ...


class HttpOfficialSourceSearch:
    """Adapter for a purpose-built verifier; returned URLs are still allowlist-filtered locally."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        *,
        timeout: float = 10,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def search(
        self, query: str, *, allowed_domains: Sequence[str], max_results: int
    ) -> list[OfficialSourceFindingV4]:
        response = await self._client.post(
            self._endpoint,
            headers={"Authorization": f"Bearer {self._api_key}"} if self._api_key else {},
            json={
                "query": query,
                "allowed_domains": list(allowed_domains),
                "max_results": min(max_results, OfficialClaimVerifier.MAX_SOURCES),
                "include_raw_content": False,
            },
        )
        response.raise_for_status()
        payload = response.json()
        rows = payload.get("findings", []) if isinstance(payload, dict) else []
        return [OfficialSourceFindingV4.model_validate(item) for item in rows[:max_results]]

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


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


def _brand_for_message(message: str, claimed_entity: str | None, brands: list[BrandRecordV4]) -> BrandRecordV4 | None:
    folded_message = _fold(message)
    folded_entity = _fold(claimed_entity) if claimed_entity else None
    for brand in brands:
        names = {_fold(brand.name), *(_fold(alias) for alias in brand.aliases)}
        if folded_entity in names or any(
            re.search(rf"(?<!\w){re.escape(name)}(?!\w)", folded_message) for name in names
        ):
            return brand
    return None


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
        brand = _brand_for_message(request.message, context.claimed_entity, brands)
        if brand is None:
            return None, []
        evidence: list[SecurityEvidenceV4] = []
        provenance = f"brand:{brand.brand_id}:{brand.policy_version}"
        official_domains = {normalize_domain(item) for item in brand.official_domains}
        for url in context.urls:
            host = (urlsplit(url).hostname or "").casefold()
            if any(_is_domain_or_subdomain(host, official) for official in official_domains):
                signal, confidence = "official_match", 1.0
            elif host.startswith("xn--") or ".xn--" in host:
                signal, confidence = "homograph_domain", 0.9
            elif any(_distance(host.split(".")[0], official.split(".")[0]) <= 2 for official in official_domains):
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


class OfficialClaimVerifier:
    MAX_CLAIMS_PER_CASE = 1
    MAX_SEARCH_QUERIES = 2
    MAX_SOURCES = 5

    def __init__(self, search: OfficialSourceSearch | None = None) -> None:
        self._search = search

    async def verify(
        self,
        claim: str,
        purpose: OfficialVerificationPurposeV4,
        allowed_domains: Sequence[str],
    ) -> tuple[OfficialVerificationResultV4, list[OfficialSourceFindingV4]]:
        domains = tuple(dict.fromkeys(normalize_domain(item) for item in allowed_domains))
        if not domains or self._search is None:
            return OfficialVerificationResultV4(
                verdict=OfficialVerificationVerdictV4.INSUFFICIENT_EVIDENCE,
                purpose=purpose,
                sources_checked=0,
                search_queries_used=0,
            ), []
        findings = await self._search.search(claim, allowed_domains=domains, max_results=self.MAX_SOURCES)
        accepted: list[OfficialSourceFindingV4] = []
        for finding in findings[: self.MAX_SOURCES]:
            host = (urlsplit(finding.source_url).hostname or "").casefold()
            if any(_is_domain_or_subdomain(host, domain) for domain in domains):
                accepted.append(finding)
        if any(item.finding == "contradicted" for item in accepted):
            verdict = OfficialVerificationVerdictV4.OFFICIAL_CONTRADICTED
        elif any(item.finding == "confirmed" for item in accepted):
            verdict = OfficialVerificationVerdictV4.OFFICIAL_CONFIRMED
        elif findings:
            verdict = OfficialVerificationVerdictV4.INSUFFICIENT_EVIDENCE
        else:
            verdict = OfficialVerificationVerdictV4.NOT_FOUND
        refs = [_ref("official", item.source_url, item.finding) for item in accepted]
        return OfficialVerificationResultV4(
            verdict=verdict,
            purpose=purpose,
            sources_checked=len(accepted),
            search_queries_used=1,
            evidence_refs=refs,
        ), accepted

    async def aclose(self) -> None:
        close = getattr(self._search, "aclose", None) or getattr(self._search, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result


def _purpose(scope: SecurityScopeResponseV4) -> OfficialVerificationPurposeV4:
    context = scope.security_context
    assert context is not None
    if context.scenario is SecurityScenarioV4.RECRUITMENT:
        return OfficialVerificationPurposeV4.VERIFY_RECRUITMENT_PROGRAM
    if context.scenario is SecurityScenarioV4.PROMOTION_PRIZE:
        return OfficialVerificationPurposeV4.VERIFY_OFFICIAL_CAMPAIGN
    if context.urls:
        return OfficialVerificationPurposeV4.VERIFY_OFFICIAL_DOMAIN
    return OfficialVerificationPurposeV4.VERIFY_BRAND_ANNOUNCEMENT


class SecurityTrustService:
    def __init__(
        self,
        repository: SecurityTrustRepository,
        *,
        matcher: BrandMatcher | None = None,
        verifier: OfficialClaimVerifier | None = None,
        max_external_calls: int = 8,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self._repository = repository
        self._matcher = matcher or BrandMatcher()
        self._verifier = verifier or OfficialClaimVerifier()
        self._clock = clock
        self._max_external_calls = max_external_calls

    async def enrich(
        self, request: SecurityTriageCreateRequestV4, scope: SecurityScopeResponseV4
    ) -> SecurityScopeResponseV4:
        if scope.security_context is None:
            return scope
        now = self._clock()
        brands = await self._repository.list_active_brands(now)
        whitelist = await self._repository.list_active_whitelist(now)
        brand, evidence = self._matcher.match(request, scope, brands, now)
        evidence.extend(self._whitelist_evidence(request, scope, whitelist, now))
        limitations = list(scope.limitations)
        errors = list(scope.errors)
        plan = list(scope.investigation_plan)
        plan.extend(self._local_plan(scope, brand))
        official_step = InvestigationStepV4(
            step_id=step_id_for(SecurityInvestigationToolV4.OFFICIAL_CLAIM_VERIFIER.value, "official-sources"),
            tool=SecurityInvestigationToolV4.OFFICIAL_CLAIM_VERIFIER,
            target="official-sources",
            reason_code="official_verification_requested",
            status=SecurityInvestigationStepStatusV4.SKIPPED,
            status_reason="consent_required",
        )
        official_calls = 0
        trust_partial = False
        if request.consent.official_source_lookup:
            if brand is None:
                limitations.append("Không có brand registry phù hợp để giới hạn official-source lookup.")
                official_step = official_step.model_copy(update={"status_reason": "brand_registry_required"})
            elif scope.tool_calls_used >= self._max_external_calls:
                limitations.append("Official-source lookup bị bỏ qua vì đã hết external-call budget.")
                official_step = official_step.model_copy(update={"status_reason": "budget_exhausted"})
            else:
                provider_failed = False
                try:
                    result, findings = await self._verifier.verify(
                        request.message, _purpose(scope), brand.official_domains
                    )
                except Exception:
                    provider_failed = True
                    trust_partial = True
                    result, findings = (
                        OfficialVerificationResultV4(
                            verdict=OfficialVerificationVerdictV4.INSUFFICIENT_EVIDENCE,
                            purpose=_purpose(scope),
                            sources_checked=0,
                            search_queries_used=0,
                        ),
                        [],
                    )
                    limitations.append("Official-source lookup không hoàn tất.")
                    errors.append(
                        SecurityToolErrorV4(
                            tool=SecurityInvestigationToolV4.OFFICIAL_CLAIM_VERIFIER,
                            target="official-sources",
                            code="PROVIDER_ERROR",
                            message="Official-source provider failed.",
                            retryable=True,
                            provider="official-source-search",
                        )
                    )
                official_calls = result.search_queries_used
                official_step = official_step.model_copy(
                    update={
                        "status": (
                            SecurityInvestigationStepStatusV4.FAILED
                            if provider_failed
                            else SecurityInvestigationStepStatusV4.COMPLETED
                            if official_calls
                            else SecurityInvestigationStepStatusV4.SKIPPED
                        ),
                        "status_reason": (
                            "tool_failed"
                            if provider_failed
                            else "tool_completed"
                            if official_calls
                            else "not_configured"
                        ),
                    }
                )
                evidence.extend(self._official_evidence(result, findings, brand, now))
                if result.verdict is OfficialVerificationVerdictV4.NOT_FOUND:
                    limitations.append("Official source không tìm thấy thông tin; NOT_FOUND không phải là phủ định.")
                elif result.verdict is OfficialVerificationVerdictV4.INSUFFICIENT_EVIDENCE:
                    limitations.append("Official-source evidence chưa đủ để kết luận.")
        plan.append(official_step)
        payload = scope.model_dump()
        payload["evidence"] = list({item.evidence_ref: item for item in [*scope.evidence, *evidence]}.values())
        payload["limitations"] = list(dict.fromkeys(limitations))
        payload["errors"] = errors
        payload["investigation_plan"] = plan
        payload["tool_calls_used"] = scope.tool_calls_used + official_calls
        if trust_partial:
            payload["investigation_status"] = SecurityInvestigationStatusV4.PARTIAL
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

    def _official_evidence(
        self,
        result: OfficialVerificationResultV4,
        findings: list[OfficialSourceFindingV4],
        brand: BrandRecordV4,
        observed_at: datetime,
    ) -> list[SecurityEvidenceV4]:
        target = canonical_whitelist_url(findings[0].source_url) if findings else brand.official_domains[0]
        return [
            _evidence(
                SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION,
                "official-claim-verifier",
                result.verdict.value.casefold(),
                f"Official verification cho {brand.name}: {result.verdict.value}; sources={result.sources_checked}.",
                observed_at,
                target=target,
                confidence=1.0 if result.sources_checked else 0.0,
                provenance_ref=f"brand:{brand.brand_id}:{brand.policy_version}",
            )
        ]

    async def aclose(self) -> None:
        await self._verifier.aclose()


__all__ = [
    "BrandMatcher",
    "HttpOfficialSourceSearch",
    "OfficialClaimVerifier",
    "OfficialSourceSearch",
    "SecurityTrustService",
    "canonical_whitelist_url",
]
