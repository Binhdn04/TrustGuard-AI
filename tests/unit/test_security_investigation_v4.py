from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest

from src.agents.security_investigation import (
    SecurityInvestigationService,
    build_security_investigation_plan,
)
from src.agents.tools import (
    CacheMetadata,
    CacheStatus,
    DnsResolutionEnvelope,
    DnsResolutionError,
    DnsResolutionResult,
    FakeBlacklistRepository,
    NormalizedToolError,
    NormalizedToolResult,
    RedirectResolutionResult,
    RedirectResolutionStatus,
    SafeDnsEvidenceResolver,
    SsrfGuard,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UrlReputationCascadeResult,
    UrlReputationFinding,
    UsageMetadata,
)
from src.models import (
    DomainIntelligenceResult,
    SecurityEvidenceTypeV4,
    SecurityInvestigationStepStatusV4,
    SecurityInvestigationToolV4,
    SecurityTriageCreateRequestV4,
    Verdict,
)
from src.services.security_triage import SecurityTriageScopeService

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _request(message: str, *, consent: bool = False) -> SecurityTriageCreateRequestV4:
    return SecurityTriageCreateRequestV4(
        message=message,
        consent={"external_url_lookup": consent},
    )


def _scope(request: SecurityTriageCreateRequestV4):
    return SecurityTriageScopeService().assess(request)


def _usage(tool: ToolName | str, suffix: str = "1") -> UsageMetadata:
    tool_value = tool.value if isinstance(tool, ToolName) else tool
    return UsageMetadata(
        usage_ref=f"usage:test:{tool_value}:{suffix}",
        provider=f"fixture-{tool_value}",
        provider_version="v1",
        operation=tool_value,
        attempts=1,
        network_calls=1,
        latency_ms=1,
        observed_at=NOW,
    )


def _success(tool: ToolName, result: Any, suffix: str = "1") -> NormalizedToolResult[Any]:
    return NormalizedToolResult(
        status=ToolResultStatus.SUCCESS,
        result=result,
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="fixture"),
        usage=_usage(tool, suffix),
    )


def _failure(
    tool: ToolName,
    code: ToolErrorCode,
    *,
    retryable: bool,
    suffix: str = "1",
) -> NormalizedToolResult[Any]:
    return NormalizedToolResult(
        status=ToolResultStatus.FAILED,
        error=NormalizedToolError(
            tool=tool,
            code=code,
            message="fixture provider failure",
            retryable=retryable,
            provider=f"fixture-{tool.value}",
        ),
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="fixture"),
        usage=_usage(tool, suffix),
    )


class _Dns:
    def __init__(self, *results: NormalizedToolResult[Any], delay: float = 0) -> None:
        self.results = list(results)
        self.delay = delay
        self.calls: list[str] = []

    async def resolve(self, target: str) -> NormalizedToolResult[Any]:
        self.calls.append(target)
        if self.delay:
            await asyncio.sleep(self.delay)
        index = min(len(self.calls) - 1, len(self.results) - 1)
        return self.results[index]


class _Redirect:
    def __init__(self, result: NormalizedToolResult[Any]) -> None:
        self.result = result
        self.calls: list[str] = []

    async def resolve(self, target: str) -> NormalizedToolResult[Any]:
        self.calls.append(target)
        return self.result


class _Rdap:
    def __init__(self, result: NormalizedToolResult[Any]) -> None:
        self.result = result
        self.calls: list[str] = []

    async def lookup(self, target: str) -> NormalizedToolResult[Any]:
        self.calls.append(target)
        return self.result


class _Reputation:
    def __init__(self, result: NormalizedToolResult[Any]) -> None:
        self.result = result
        self.calls: list[str] = []
        self.high_risk_calls: list[bool] = []

    async def assess(self, target: str, *, high_risk: bool = False) -> NormalizedToolResult[Any]:
        self.calls.append(target)
        self.high_risk_calls.append(high_risk)
        return self.result


def _dns_success(url: str = "https://example.com/login") -> NormalizedToolResult[Any]:
    return DnsResolutionEnvelope(
        status=ToolResultStatus.SUCCESS,
        result=DnsResolutionResult(
            normalized_url=url,
            domain="example.com",
            address_count=1,
            ipv4_count=1,
            ipv6_count=0,
            observed_at=NOW,
        ),
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="fixture"),
        usage=_usage("dns"),
    )


def _dns_failure(*, retryable: bool) -> DnsResolutionEnvelope:
    return DnsResolutionEnvelope(
        status=ToolResultStatus.FAILED,
        error=DnsResolutionError(
            code=ToolErrorCode.PROVIDER_TIMEOUT,
            message="fixture provider failure",
            retryable=retryable,
            provider="fixture-dns",
        ),
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="fixture"),
        usage=_usage("dns"),
    )


def test_planner_is_deterministic_and_uses_only_context_derived_targets() -> None:
    request = _request("Kiểm tra https://example.com/login", consent=True)
    context = _scope(request).security_context
    assert context is not None

    first = build_security_investigation_plan(context, external_url_lookup=True)
    second = build_security_investigation_plan(context, external_url_lookup=True)

    assert first == second
    assert {step.target for step in first} <= {"message", "https://example.com/login", "example.com"}
    assert all("fact_check" not in step.tool.value for step in first)

    no_url = _scope(_request("HR yêu cầu tôi đóng phí hồ sơ")).security_context
    assert no_url is not None
    assert [step.tool for step in build_security_investigation_plan(no_url, external_url_lookup=True)] == [
        SecurityInvestigationToolV4.SECURITY_CONTEXT_ANALYSIS
    ]


@pytest.mark.asyncio
async def test_no_consent_runs_local_rules_and_never_calls_external_tools() -> None:
    request = _request("Đăng nhập https://tést.example/login để xác minh")
    dns = _Dns(_dns_success("https://xn--tst-bma.example/login"))
    service = SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        dns=dns,
        redirect=_Redirect(_dns_success()),
        rdap=_Rdap(_dns_success()),
        reputation=_Reputation(_dns_success()),
    )

    result = await service.investigate(request, _scope(request))

    assert dns.calls == []
    assert result.tool_calls_used == 0
    signals = {item.signal for item in result.evidence}
    assert {"punycode_domain", "credential_path"} <= signals
    external = {
        step.tool: step.status
        for step in result.investigation_plan
        if step.tool
        in {
            SecurityInvestigationToolV4.DNS,
            SecurityInvestigationToolV4.REDIRECT_RESOLVER,
            SecurityInvestigationToolV4.RDAP,
            SecurityInvestigationToolV4.URL_REPUTATION,
        }
    }
    assert set(external.values()) == {SecurityInvestigationStepStatusV4.SKIPPED}
    assert any("consent" in item.casefold() for item in result.limitations)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    ["http://127.0.0.1/login", "http://localhost/login", "http://metadata.google.internal/computeMetadata/v1/"],
)
async def test_private_local_and_metadata_targets_short_circuit_before_network(target: str) -> None:
    request = _request(f"Kiểm tra link đăng nhập {target}", consent=True)
    dns = _Dns(_dns_success(target))
    result = await SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        dns=dns,
    ).investigate(request, _scope(request))

    assert dns.calls == []
    assert result.tool_calls_used == 0
    assert any(item.signal == "ssrf_blocked" for item in result.evidence)
    assert any(step.status_reason == "ssrf_short_circuit" for step in result.investigation_plan)


@pytest.mark.asyncio
async def test_blacklist_hit_has_provenance_and_short_circuits_network() -> None:
    request = _request("Kiểm tra https://bad.example/login", consent=True)
    dns = _Dns(_dns_success("https://bad.example/login"))
    result = await SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(["bad.example"]),
        dns=dns,
    ).investigate(request, _scope(request))

    assert dns.calls == []
    blacklist = next(item for item in result.evidence if item.type is SecurityEvidenceTypeV4.BLACKLIST)
    assert blacklist.provenance_ref == "decision:fixture-approved"
    assert any(step.status_reason == "blacklist_short_circuit" for step in result.investigation_plan)


@pytest.mark.asyncio
async def test_safe_dns_adapter_reports_counts_and_blocks_private_resolution() -> None:
    async def public_resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

    async def private_resolver(_host: str, _port: int) -> list[str]:
        return ["10.0.0.7"]

    public = await SafeDnsEvidenceResolver(SsrfGuard(resolver=public_resolver)).resolve("https://example.com/")
    private = await SafeDnsEvidenceResolver(SsrfGuard(resolver=private_resolver)).resolve("https://example.com/")

    assert public.result is not None
    assert (public.result.address_count, public.result.ipv4_count, public.result.ipv6_count) == (2, 1, 1)
    assert private.status is ToolResultStatus.BLOCKED
    assert private.error is not None and private.error.code is ToolErrorCode.SSRF_BLOCKED


@pytest.mark.asyncio
async def test_external_evidence_keeps_redirect_rdap_and_reputation_no_hit_inconclusive() -> None:
    url = "https://example.com/login"
    request = _request(f"Kiểm tra {url}", consent=True)
    redirect = _Redirect(
        _success(
            ToolName.REDIRECT_RESOLVER,
            RedirectResolutionResult(
                normalized_url=url,
                final_url="https://example.com/final",
                redirect_chain=[url, "https://example.com/final"],
                status=RedirectResolutionStatus.RESOLVED,
                signals=["cross_path_redirect"],
                observed_at=NOW,
            ),
        )
    )
    rdap = _Rdap(
        _success(
            ToolName.RDAP,
            DomainIntelligenceResult(
                provider="fixture-rdap",
                domain="example.com",
                signals=["service_unavailable"],
                observed_at=NOW,
            ),
        )
    )
    reputation = _Reputation(
        NormalizedToolResult(
            status=ToolResultStatus.INCONCLUSIVE,
            result=UrlReputationCascadeResult(
                normalized_url=url,
                findings=[
                    UrlReputationFinding(
                        provider="fixture-reputation",
                        provider_version="v1",
                        normalized_url=url,
                        matched=False,
                        verdict=Verdict.INCONCLUSIVE,
                        observed_at=NOW,
                    )
                ],
                verdict=Verdict.INCONCLUSIVE,
                provider_conflict=False,
                policy_version="fixture-policy-v1",
            ),
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="fixture"),
            usage=_usage(ToolName.URL_REPUTATION),
        )
    )
    ledger = FakeBlacklistRepository()
    result = await SecurityInvestigationService(
        blacklist=ledger,
        dns=_Dns(_dns_success()),
        redirect=redirect,
        rdap=rdap,
        reputation=reputation,
        execution_ledger=ledger,
    ).investigate(request, _scope(request))

    assert result.tool_calls_used == 4
    assert redirect.calls == [url]
    assert rdap.calls == ["example.com"]
    assert reputation.calls == [url]
    assert reputation.high_risk_calls == [True]
    assert len(ledger.tool_executions) == 4
    assert set(ledger.tool_executions.values()) == {"completed"}
    assert all(key[2].startswith("target:") and url not in key[2] for key in ledger.tool_executions)
    types = {item.type for item in result.evidence}
    assert {
        SecurityEvidenceTypeV4.DNS,
        SecurityEvidenceTypeV4.REDIRECT,
        SecurityEvidenceTypeV4.RDAP,
        SecurityEvidenceTypeV4.URL_REPUTATION,
    } <= types
    assert any("no-hit" in item for item in result.limitations)
    assert any("không công bố dịch vụ RDAP" in item for item in result.limitations)
    assert result.errors == []


def test_reputation_evidence_preserves_conflict_and_independent_hit_count() -> None:
    url = "https://example.com/login"
    request = _request(f"Kiểm tra {url}", consent=True)
    context = _scope(request).security_context
    assert context is not None
    step = next(
        item
        for item in build_security_investigation_plan(context, external_url_lookup=True)
        if item.tool is SecurityInvestigationToolV4.URL_REPUTATION
    )
    cascade = UrlReputationCascadeResult(
        normalized_url=url,
        findings=[
            UrlReputationFinding(
                provider="provider-one",
                provider_version="v1",
                normalized_url=url,
                matched=True,
                verdict=Verdict.MALICIOUS,
                observed_at=NOW,
            ),
            UrlReputationFinding(
                provider="provider-two",
                provider_version="v1",
                normalized_url=url,
                matched=True,
                verdict=Verdict.MALICIOUS,
                observed_at=NOW,
            ),
            UrlReputationFinding(
                provider="provider-three",
                provider_version="v1",
                normalized_url=url,
                matched=True,
                verdict=Verdict.SAFE,
                observed_at=NOW,
            ),
        ],
        verdict=Verdict.MALICIOUS,
        provider_conflict=True,
        policy_version="fixture-policy-v1",
    )
    envelope = _success(ToolName.URL_REPUTATION, cascade)

    evidence, limitations = SecurityInvestigationService()._provider_evidence(step, envelope)

    assert limitations == []
    assert evidence[0].signal == "malicious+provider_conflict+corroborated_provider_hit"


def test_http_error_redirect_evidence_keeps_the_known_destination_distinct_from_retrieval() -> None:
    url = "https://portal.northstar.example/contact"
    context = _scope(_request(f"Kiểm tra {url}", consent=True)).security_context
    assert context is not None
    step = next(
        item
        for item in build_security_investigation_plan(context, external_url_lookup=True)
        if item.tool is SecurityInvestigationToolV4.REDIRECT_RESOLVER
    )
    envelope = NormalizedToolResult(
        status=ToolResultStatus.INCONCLUSIVE,
        result=RedirectResolutionResult(
            normalized_url=url,
            final_url=url,
            redirect_chain=[url],
            status=RedirectResolutionStatus.UNRESOLVED,
            signals=["http_404"],
            http_status_code=404,
            observed_at=NOW,
        ),
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="fixture"),
        usage=_usage(ToolName.REDIRECT_RESOLVER),
    )

    evidence, limitations = SecurityInvestigationService()._provider_evidence(step, envelope)

    assert limitations == []
    assert evidence[0].signal == "redirect_resolution_inconclusive+http_404"
    assert "redirect_destination_unresolved" not in evidence[0].signal


@pytest.mark.asyncio
async def test_retry_is_bounded_and_counts_each_attempt_against_budget() -> None:
    request = _request("Kiểm tra https://example.com/login", consent=True)
    dns = _Dns(
        _dns_failure(retryable=True),
        _dns_success(),
    )
    result = await SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        dns=dns,
        max_external_calls=2,
        max_retries=1,
    ).investigate(request, _scope(request))

    assert len(dns.calls) == 2
    assert result.tool_calls_used == 2
    dns_step = next(step for step in result.investigation_plan if step.tool is SecurityInvestigationToolV4.DNS)
    assert dns_step.status is SecurityInvestigationStepStatusV4.COMPLETED


@pytest.mark.asyncio
async def test_budget_exhaustion_skips_remaining_external_steps() -> None:
    request = _request("Kiểm tra https://example.com/login", consent=True)
    result = await SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        dns=_Dns(_dns_success()),
        redirect=_Redirect(_dns_success()),
        max_external_calls=1,
    ).investigate(request, _scope(request))

    assert result.tool_calls_used == 1
    assert any(step.status_reason == "budget_exhausted" for step in result.investigation_plan)
    assert any("ngân sách" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_deadline_exhaustion_is_bounded_and_recorded() -> None:
    request = _request("Kiểm tra https://example.com/login", consent=True)
    result = await SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        dns=_Dns(_dns_success(), delay=0.02),
        deadline_seconds=0.001,
    ).investigate(request, _scope(request))

    assert result.tool_calls_used == 1
    assert any(step.status_reason == "deadline_exhausted" for step in result.investigation_plan)
    assert any("thời gian" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_provider_timeout_is_exposed_as_normalized_error() -> None:
    request = _request("Kiểm tra https://example.com/login", consent=True)
    result = await SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        dns=_Dns(_dns_failure(retryable=True)),
        max_retries=0,
    ).investigate(request, _scope(request))

    assert result.errors[0].code == "PROVIDER_TIMEOUT"
    assert result.errors[0].retryable is True
    assert result.errors[0].provider == "fixture-dns"
