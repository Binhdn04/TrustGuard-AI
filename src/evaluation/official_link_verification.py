from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import fmean
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.agents.security_risk import assess_security_risk
from src.models import (
    BrandRecordV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    RequestedActionV4,
    ResourceMatchStatusV4,
    ScopeDecisionV4,
    SecurityInvestigationStatusV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    VerificationStatusV4,
)
from src.security_ai.contracts import (
    SemanticActionKind,
    SemanticActionMention,
    SemanticDirection,
    SemanticInteractionType,
    SemanticModality,
    SemanticParticipant,
    SemanticSensitiveObject,
    SemanticStance,
    Understanding,
    UnderstandingSourceSpan,
)
from src.security_ai.runtime import BudgetExceededError, TurnExecutionContext
from src.services.official_resource_identity import UrlNormalizationError, normalize_verification_url
from src.services.official_verification_coordinator import OfficialLinkVerificationCoordinator
from src.services.official_verification_transport import (
    FetchedHtml,
    HtmlFetchEnvelope,
    VerificationTransportLimitation,
    VerificationTransportStatus,
    VerificationTransportUsage,
    WebSearchEnvelope,
    WebSearchHit,
)
from src.services.security_span_candidates import generate_semantic_span_candidates
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_understanding import merge_semantic_understanding

SECURITY_V4_V2_DATASET_VERSION = "security-v4-v2"
REQUIRED_CATEGORIES = frozenset(
    {
        "hard_social_short_form",
        "verified",
        "partially_verified",
        "unverified_no_hit",
        "conflicting",
        "non_applicable",
        "out_of_scope",
        "consent_denied",
        "ssrf_redirect",
        "provider_timeout",
        "budget_exhaustion",
        "prompt_injection",
    }
)
NOW = datetime(2026, 8, 20, 12, tzinfo=UTC)
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


class EvaluationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IdentityFixture(EvaluationModel):
    identity_type: OfficialIdentityTypeV4
    value: str = Field(min_length=1, max_length=2048)
    relationship: str = Field(default="primary", pattern=r"^[a-z0-9_]+$")


class SearchHitFixture(EvaluationModel):
    url: str = Field(min_length=1, max_length=2048)
    title: str = "Official announcement"
    snippet: str = "Official source"
    score: float = Field(default=0.95, ge=0, le=1)


class ExpectedFixture(EvaluationModel):
    scope_decision: ScopeDecisionV4
    overall_status: VerificationStatusV4 | None = None
    publisher_status: VerificationStatusV4 | None = None
    claim_status: VerificationStatusV4 | None = None
    resource_status: VerificationStatusV4 | None = None
    publisher_applicable: bool | None = None
    claim_applicable: bool | None = None
    resource_applicable: bool | None = None
    resource_match_status: ResourceMatchStatusV4 | None = None
    required_limitations: list[str] = Field(default_factory=list)
    query_contains: list[str] = Field(default_factory=list)
    max_adapter_attempts: int = Field(default=20, ge=0)
    not_found: bool = False
    ssrf_case: bool = False
    budget_case: bool = False

    @model_validator(mode="after")
    def validate_scope(self) -> ExpectedFixture:
        if self.scope_decision is not ScopeDecisionV4.IN_SCOPE and self.overall_status is not None:
            raise ValueError("out-of-scope cases cannot require a verification report")
        return self


class OfficialVerificationEvaluationCase(EvaluationModel):
    dataset_version: Literal["security-v4-v2"]
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    category: str
    message: str = Field(min_length=1)
    consent: dict[str, bool] = Field(default_factory=dict)
    semantic_claimed_entity: str | None = None
    organization_only_context: bool = False
    official_source_kind: Literal["social_announcement"] | None = None
    brand_name: str | None = None
    brand_aliases: list[str] = Field(default_factory=list)
    identities: list[IdentityFixture] = Field(default_factory=list)
    search_status: Literal["success", "no_hit", "provider_timeout", "provider_error"] = "success"
    search_hit_query_contains: str | None = None
    search_hits: list[SearchHitFixture] = Field(default_factory=list)
    pages: dict[str, str] = Field(default_factory=dict)
    redirects: dict[str, list[str]] = Field(default_factory=dict)
    blocked_urls: list[str] = Field(default_factory=list)
    fetch_limitation: VerificationTransportLimitation | None = None
    max_network_units: int = Field(default=16, ge=0)
    estimated_cost_usd_per_attempt: float = Field(default=0.001, ge=0, le=0.05)
    expected: ExpectedFixture

    @model_validator(mode="after")
    def validate_fixture_mode(self) -> OfficialVerificationEvaluationCase:
        if self.organization_only_context and self.category != "non_applicable":
            raise ValueError("organization_only_context is reserved for the non_applicable fusion case")
        if self.category == "hard_social_short_form":
            if self.official_source_kind != "social_announcement":
                raise ValueError("the hard case must identify an official social announcement")
            social_announcement_fixture = any(
                "social" in hit.title.casefold() and "announcement" in hit.title.casefold() for hit in self.search_hits
            )
            if not social_announcement_fixture:
                raise ValueError("the hard case must include a labeled social-announcement search result")
        return self


class OfficialVerificationCaseResult(EvaluationModel):
    id: str
    category: str
    scope_decision: ScopeDecisionV4
    overall_status: VerificationStatusV4 | None
    publisher_status: VerificationStatusV4 | None
    claim_status: VerificationStatusV4 | None
    resource_status: VerificationStatusV4 | None
    resource_match_status: ResourceMatchStatusV4 | None
    risk: SecurityRiskV4 | None
    adapter_attempts: int
    network_units: int
    estimated_cost_usd: float
    latency_ms: float
    queries: list[str]
    limitations: list[str]
    scope_pass: bool
    component_checks: int
    component_correct: int
    resource_match_pass: bool | None
    reference_closure_pass: bool
    fabricated_ref_count: int
    fabricated_url_count: int
    query_pass: bool
    bounded_pass: bool


def _usage(operation: str, *, network_units: int) -> VerificationTransportUsage:
    return VerificationTransportUsage(
        provider="security-v4-v2-offline",
        operation=operation,
        adapter_attempts=1,
        network_units=network_units,
        latency_ms=0.1,
    )


class _BrandRepository:
    def __init__(self, brands: list[BrandRecordV4]) -> None:
        self.brands = brands
        self.calls = 0

    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]:
        assert at.tzinfo is not None
        self.calls += 1
        return self.brands


class _SearchProvider:
    def __init__(self, case: OfficialVerificationEvaluationCase) -> None:
        self.case = case
        self.queries: list[str] = []

    async def search_one(self, query: str, *, execution_context: TurnExecutionContext, max_results: int = 5):
        self.queries.append(query)
        try:
            execution_context.reserve_network_units()
        except BudgetExceededError:
            return WebSearchEnvelope(
                status=VerificationTransportStatus.LIMITED,
                limitation=VerificationTransportLimitation.NETWORK_BUDGET_EXHAUSTED,
                usage=_usage("search_one", network_units=0),
            )
        execution_context.record_external_cost(self.case.estimated_cost_usd_per_attempt)
        limitation = {
            "provider_timeout": VerificationTransportLimitation.PROVIDER_TIMEOUT,
            "provider_error": VerificationTransportLimitation.PROVIDER_ERROR,
        }.get(self.case.search_status)
        if limitation is not None:
            return WebSearchEnvelope(
                status=VerificationTransportStatus.LIMITED,
                limitation=limitation,
                usage=_usage("search_one", network_units=1),
            )
        query_gate = self.case.search_hit_query_contains
        selected = (
            self.case.search_hits[:max_results]
            if self.case.search_status == "success"
            and (query_gate is None or query_gate.casefold() in query.casefold())
            else []
        )
        if not selected:
            return WebSearchEnvelope(
                status=VerificationTransportStatus.NO_HIT,
                usage=_usage("search_one", network_units=1),
            )
        return WebSearchEnvelope(
            status=VerificationTransportStatus.SUCCESS,
            results=[WebSearchHit(**item.model_dump()) for item in selected],
            usage=_usage("search_one", network_units=1),
        )


class _HtmlFetcher:
    def __init__(self, case: OfficialVerificationEvaluationCase) -> None:
        self.case = case
        self.calls: list[str] = []

    async def fetch(self, url: str, *, execution_context: TurnExecutionContext) -> HtmlFetchEnvelope:
        self.calls.append(url)
        try:
            execution_context.reserve_network_units()
        except BudgetExceededError:
            return HtmlFetchEnvelope(
                status=VerificationTransportStatus.LIMITED,
                limitation=VerificationTransportLimitation.NETWORK_BUDGET_EXHAUSTED,
                usage=_usage("fetch", network_units=0),
            )
        execution_context.record_external_cost(self.case.estimated_cost_usd_per_attempt)
        if url in self.case.blocked_urls:
            return HtmlFetchEnvelope(
                status=VerificationTransportStatus.BLOCKED,
                limitation=VerificationTransportLimitation.SSRF_BLOCKED,
                usage=_usage("fetch", network_units=1),
            )
        if self.case.fetch_limitation is not None:
            return HtmlFetchEnvelope(
                status=(
                    VerificationTransportStatus.BLOCKED
                    if self.case.fetch_limitation is VerificationTransportLimitation.SSRF_BLOCKED
                    else VerificationTransportStatus.LIMITED
                ),
                limitation=self.case.fetch_limitation,
                usage=_usage("fetch", network_units=1),
            )
        chain = self.case.redirects.get(url, [url])
        final_url = chain[-1]
        page = self.case.pages.get(url, self.case.pages.get(final_url))
        if page is None:
            return HtmlFetchEnvelope(
                status=VerificationTransportStatus.LIMITED,
                limitation=VerificationTransportLimitation.PROVIDER_UNAVAILABLE,
                usage=_usage("fetch", network_units=1),
            )
        await asyncio.sleep(0)
        return HtmlFetchEnvelope(
            status=VerificationTransportStatus.SUCCESS,
            document=FetchedHtml(
                final_url=final_url,
                redirect_chain=chain,
                media_type="text/html",
                body=page.encode(),
            ),
            usage=_usage("fetch", network_units=1),
        )


def _brands(case: OfficialVerificationEvaluationCase) -> list[BrandRecordV4]:
    if case.brand_name is None:
        return []
    identities = [
        OfficialIdentityV4(
            identity_id=uuid5(NAMESPACE_URL, f"{case.id}:{item.identity_type}:{item.value}"),
            identity_type=item.identity_type,
            canonical_value=item.value,
            display_value=item.value,
            entity_name=case.brand_name,
            relationship=item.relationship,
            provenance=f"dataset:{SECURITY_V4_V2_DATASET_VERSION}:{case.id}",
            effective_from=NOW - timedelta(days=1),
            reviewed=True,
        )
        for item in case.identities
    ]
    domains = [item.value for item in case.identities if item.identity_type is OfficialIdentityTypeV4.DOMAIN]
    return [
        BrandRecordV4(
            brand_id=uuid5(NAMESPACE_URL, f"{case.id}:brand"),
            name=case.brand_name,
            aliases=case.brand_aliases,
            official_domains=domains,
            official_identities=identities,
            provenance=f"dataset:{SECURITY_V4_V2_DATASET_VERSION}:{case.id}",
            effective_from=NOW - timedelta(days=1),
            reviewer_id="security-v4-v2-reviewer",
            created_at=NOW - timedelta(days=1),
        )
    ]


def _semantic_scope(case: OfficialVerificationEvaluationCase, scoped):
    entity = case.semantic_claimed_entity
    if entity is None:
        return scoped
    if case.organization_only_context:
        return SecurityScopeResponseV4(
            scope_decision=ScopeDecisionV4.IN_SCOPE,
            terminal=False,
            next_step="INVESTIGATION",
            scope_reasons=["security_verification_request"],
            security_context={
                "claimed_entity": entity,
                "scenario": "unknown",
                "urgency": False,
                "credential_request": False,
                "otp_request": False,
                "payment_request": False,
                "personal_information_request": False,
                "potential_threat": "UNDETERMINED_SECURITY_THREAT",
            },
        )
    start = case.message.casefold().find(entity.casefold())
    if start < 0:
        raise ValueError(f"semantic entity is not grounded in message: {case.id}")
    action_mentions: list[SemanticActionMention] = []
    if scoped.security_context and scoped.security_context.requested_action is not None:
        candidates = generate_semantic_span_candidates(case.message)
        action_span = next(
            (item for item in candidates if item.kind == "action_phrase"),
            next(item for item in candidates if item.kind == "full_message"),
        )
        action_kind, sensitive_object, interaction_type = _fixture_action_mention(
            scoped.security_context.requested_action
        )
        action_mentions.append(
            SemanticActionMention(
                action_kind=action_kind,
                sensitive_object=sensitive_object,
                actor=SemanticParticipant.SENDER,
                recipient=SemanticParticipant.USER,
                direction=SemanticDirection.TO_USER,
                modality=SemanticModality.REQUESTED,
                stance=SemanticStance.ASSERTED,
                interaction_type=interaction_type,
                span_ids=[action_span.span_id],
                confidence=0.95,
            )
        )
    output = Understanding(
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        claimed_entity=entity,
        action_mentions=action_mentions,
        field_confidences={"scope_decision": 0.95, "claimed_entity": 0.95},
        source_spans=[UnderstandingSourceSpan(field_name="claimed_entity", start=start, end=start + len(entity))],
    )
    return merge_semantic_understanding(
        case.message,
        scoped,
        output,
        model_version="security-v4-v2-semantic-fixture",
    )


def _fixture_action_mention(
    action: RequestedActionV4,
) -> tuple[SemanticActionKind, SemanticSensitiveObject, SemanticInteractionType]:
    if action is RequestedActionV4.SHARE_OTP:
        return SemanticActionKind.DISCLOSE, SemanticSensitiveObject.OTP, SemanticInteractionType.DISCLOSURE
    if action is RequestedActionV4.SHARE_CREDENTIALS:
        return SemanticActionKind.DISCLOSE, SemanticSensitiveObject.CREDENTIALS, SemanticInteractionType.DISCLOSURE
    if action is RequestedActionV4.PROVIDE_PERSONAL_INFORMATION:
        return (
            SemanticActionKind.DISCLOSE,
            SemanticSensitiveObject.PERSONAL_INFORMATION,
            SemanticInteractionType.DISCLOSURE,
        )
    if action in {RequestedActionV4.TRANSFER_MONEY, RequestedActionV4.PAY_FEE}:
        return (
            SemanticActionKind.TRANSFER_MONEY,
            SemanticSensitiveObject.MONEY,
            SemanticInteractionType.ROUTINE_WORKFLOW,
        )
    return SemanticActionKind(action.value), SemanticSensitiveObject.UNKNOWN, SemanticInteractionType.ROUTINE_WORKFLOW


def _allowed_urls(case: OfficialVerificationEvaluationCase) -> set[str]:
    raw = set(_URL_RE.findall(case.message))
    raw.update(item.value for item in case.identities if "://" in item.value)
    raw.update(item.url for item in case.search_hits)
    raw.update(case.pages)
    for page in case.pages.values():
        raw.update(_URL_RE.findall(page))
    for source, chain in case.redirects.items():
        raw.add(source)
        raw.update(chain)
    allowed: set[str] = set()
    for value in raw:
        try:
            normalized = normalize_verification_url(value.rstrip(".,)"))
        except UrlNormalizationError:
            continue
        allowed.update({normalized.display_url, normalized.canonical_url, normalized.fetch_url})
    for identity in case.identities:
        if identity.identity_type in {OfficialIdentityTypeV4.DOMAIN, OfficialIdentityTypeV4.PRIMARY_WEBSITE}:
            try:
                normalized = normalize_verification_url(f"https://{identity.value}")
            except UrlNormalizationError:
                continue
            allowed.update({normalized.display_url, normalized.canonical_url, normalized.fetch_url})
    return allowed


def _component_values(report) -> list[tuple[bool, VerificationStatusV4 | None]]:
    if report is None:
        return []
    return [
        (report.publisher_verification.applicable, report.publisher_verification.status),
        (report.claim_verification.applicable, report.claim_verification.status),
        (report.resource_verification.applicable, report.resource_verification.status),
    ]


async def evaluate_case(case: OfficialVerificationEvaluationCase) -> OfficialVerificationCaseResult:
    started = time.perf_counter()
    request = SecurityTriageCreateRequestV4(message=case.message, consent=case.consent)
    scoped = _semantic_scope(case, SecurityTriageScopeService().assess(request))
    search = _SearchProvider(case)
    fetcher = _HtmlFetcher(case)
    context = TurnExecutionContext(
        deadline_seconds=30,
        max_network_units=case.max_network_units,
        max_estimated_cost_usd=0.05,
    )
    outcome = await OfficialLinkVerificationCoordinator(
        _BrandRepository(_brands(case)),
        search=search,
        fetcher=fetcher,
        clock=lambda: NOW,
    ).coordinate(request, scoped, execution_context=context)
    report = outcome.report
    staged = scoped.model_copy(
        update={
            "official_verification": report,
            "limitations": list(dict.fromkeys([*scoped.limitations, *outcome.limitations])),
            "investigation_status": SecurityInvestigationStatusV4.COMPLETED
            if scoped.scope_decision is ScopeDecisionV4.IN_SCOPE
            else scoped.investigation_status,
            "next_step": "RISK_ASSESSMENT" if scoped.scope_decision is ScopeDecisionV4.IN_SCOPE else scoped.next_step,
        }
    )
    risk_result = (
        assess_security_risk(staged, official_verification_enforced=True)
        if scoped.scope_decision is ScopeDecisionV4.IN_SCOPE
        else staged
    )

    expected = case.expected
    actual_components = _component_values(report)
    expected_components = [
        (expected.publisher_applicable, expected.publisher_status),
        (expected.claim_applicable, expected.claim_status),
        (expected.resource_applicable, expected.resource_status),
    ]
    component_checks = component_correct = 0
    for actual, wanted in zip(actual_components, expected_components, strict=False):
        wanted_applicable, wanted_status = wanted
        if wanted_applicable is not None:
            component_checks += 1
            component_correct += actual[0] is wanted_applicable
        if wanted_status is not None:
            component_checks += 1
            component_correct += actual[1] is wanted_status

    available_sources = {item.source_ref for item in report.source_refs} if report else set()
    available_links = {item.link_ref for item in report.link_refs} if report else set()
    available_refs = available_sources | available_links
    cited_refs: set[str] = set()
    if report:
        for component in (report.publisher_verification, report.claim_verification, report.resource_verification):
            cited_refs.update(component.evidence_refs)
    fabricated_refs = cited_refs - available_refs
    if report:
        fabricated_refs.update(item.source_ref for item in report.link_refs if item.source_ref not in available_sources)

    returned_urls: set[str] = set()
    if report:
        for source in report.source_refs:
            returned_urls.update({source.display_url, source.canonical_url})
        for link in report.link_refs:
            returned_urls.update({link.display_url, link.canonical_url})
        match = report.resource_verification.match
        if match:
            for resource in (match.user_resource, match.official_resource):
                if resource and resource.canonical_url:
                    returned_urls.add(resource.canonical_url)
    fabricated_urls = returned_urls - _allowed_urls(case)
    match_status = report.resource_verification.match.status if report and report.resource_verification.match else None
    resource_match_pass = (
        match_status is expected.resource_match_status if expected.resource_match_status is not None else None
    )
    limitations = list(dict.fromkeys([*outcome.limitations, *(report.limitations if report else [])]))
    bounded_pass = outcome.adapter_attempts <= expected.max_adapter_attempts
    if expected.budget_case:
        bounded_pass = bounded_pass and report is not None and "search_network_budget_exhausted" in limitations

    return OfficialVerificationCaseResult(
        id=case.id,
        category=case.category,
        scope_decision=scoped.scope_decision,
        overall_status=report.overall_status if report else None,
        publisher_status=report.publisher_verification.status if report else None,
        claim_status=report.claim_verification.status if report else None,
        resource_status=report.resource_verification.status if report else None,
        resource_match_status=match_status,
        risk=risk_result.risk,
        adapter_attempts=outcome.adapter_attempts,
        network_units=context.network_units,
        estimated_cost_usd=round(context.estimated_cost_usd, 6),
        latency_ms=round((time.perf_counter() - started) * 1000, 3),
        queries=search.queries,
        limitations=limitations,
        scope_pass=scoped.scope_decision is expected.scope_decision,
        component_checks=component_checks,
        component_correct=component_correct,
        resource_match_pass=resource_match_pass,
        reference_closure_pass=not fabricated_refs,
        fabricated_ref_count=len(fabricated_refs),
        fabricated_url_count=len(fabricated_urls),
        query_pass=all(
            any(term.casefold() in query.casefold() for query in search.queries) for term in expected.query_contains
        ),
        bounded_pass=bounded_pass and all(item in limitations for item in expected.required_limitations),
    )


def load_evaluation_set(path: str | Path) -> list[OfficialVerificationEvaluationCase]:
    source = Path(path)
    cases = [
        OfficialVerificationEvaluationCase.model_validate_json(line)
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not cases or len({case.id for case in cases}) != len(cases):
        raise ValueError("security-v4-v2 requires non-empty unique case IDs")
    missing = REQUIRED_CATEGORIES - {case.category for case in cases}
    if missing:
        raise ValueError("security-v4-v2 is missing categories: " + ", ".join(sorted(missing)))
    return cases


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 1.0


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)] if ordered else 0.0


async def evaluate_set(
    cases: list[OfficialVerificationEvaluationCase], *, dataset_path: str | Path
) -> dict[str, object]:
    results = [await evaluate_case(case) for case in cases]
    expected_by_id = {case.id: case.expected for case in cases}
    component_checks = sum(item.component_checks for item in results)
    component_correct = sum(item.component_correct for item in results)
    labeled_resource = [item for item in results if item.resource_match_pass is not None]
    out_of_scope = [item for item in results if expected_by_id[item.id].scope_decision is not ScopeDecisionV4.IN_SCOPE]
    not_found = [item for item in results if expected_by_id[item.id].not_found]
    ssrf = [item for item in results if expected_by_id[item.id].ssrf_case]
    official_reports = [item for item in results if item.overall_status is not None]
    metrics = {
        "case_count": len(results),
        "scope_accuracy": _ratio(sum(item.scope_pass for item in results), len(results)),
        "component_status_accuracy": _ratio(component_correct, component_checks),
        "labeled_resource_match_precision": _ratio(
            sum(item.resource_match_pass is True for item in labeled_resource), len(labeled_resource)
        ),
        "evidence_reference_closure_rate": _ratio(
            sum(item.reference_closure_pass for item in official_reports), len(official_reports)
        ),
        "grounded_explanation_rate": _ratio(
            sum(item.reference_closure_pass for item in official_reports), len(official_reports)
        ),
        "fabricated_ref_count": sum(item.fabricated_ref_count for item in results),
        "fabricated_url_count": sum(item.fabricated_url_count for item in results),
        "oos_provider_network_ai_calls": sum(item.adapter_attempts + item.network_units for item in out_of_scope),
        "not_found_to_malicious_count": sum(item.risk is SecurityRiskV4.MALICIOUS for item in not_found),
        "ssrf_bypass_count": sum(
            not any(value.endswith("ssrf_blocked") for value in item.limitations) for item in ssrf
        ),
        "max_estimated_cost_usd_per_analysis": max((item.estimated_cost_usd for item in results), default=0),
        "mean_latency_ms": round(fmean(item.latency_ms for item in results), 3),
        "p95_latency_ms": round(_percentile([item.latency_ms for item in results], 0.95), 3),
    }
    gates = {
        "oos_zero_calls": metrics["oos_provider_network_ai_calls"] == 0,
        "zero_fabricated_refs": metrics["fabricated_ref_count"] == 0,
        "zero_fabricated_urls": metrics["fabricated_url_count"] == 0,
        "evidence_reference_closure": metrics["evidence_reference_closure_rate"] == 1,
        "resource_match_precision": metrics["labeled_resource_match_precision"] == 1,
        "not_found_not_malicious": metrics["not_found_to_malicious_count"] == 0,
        "ssrf_zero_bypass": metrics["ssrf_bypass_count"] == 0,
        "scope_accuracy": metrics["scope_accuracy"] >= 0.95,
        "component_status_accuracy": metrics["component_status_accuracy"] >= 0.90,
        "grounded_explanations": metrics["grounded_explanation_rate"] == 1,
        "provider_cost": metrics["max_estimated_cost_usd_per_analysis"] <= 0.05,
        "p95_latency": metrics["p95_latency_ms"] <= 30_000,
        "case_expectations": all(
            item.scope_pass
            and item.component_correct == item.component_checks
            and item.resource_match_pass is not False
            and item.query_pass
            and item.bounded_pass
            and item.overall_status is expected_by_id[item.id].overall_status
            for item in results
        ),
    }
    source = Path(dataset_path)
    return {
        "dataset_version": SECURITY_V4_V2_DATASET_VERSION,
        "dataset_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "evaluation_profile": "offline_deterministic_official_link_verification",
        "threshold_profile": "official-link-verification-release-gates-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metrics": metrics,
        "gates": gates,
        "passed": all(gates.values()),
        "limitations": [
            "Offline fakes exercise production scope, intent, coordinator, fusion and risk code but do not replace hosted OIDC, PostgreSQL, Redis, worker, provider, load or backup/restore evidence."
        ],
        "cases": [item.model_dump(mode="json") for item in results],
    }


def write_report(report: dict[str, object], output: str | Path) -> None:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "REQUIRED_CATEGORIES",
    "SECURITY_V4_V2_DATASET_VERSION",
    "OfficialVerificationEvaluationCase",
    "evaluate_case",
    "evaluate_set",
    "load_evaluation_set",
    "write_report",
]
