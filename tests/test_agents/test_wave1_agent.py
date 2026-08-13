from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from src.agents.contracts import CachedReputationEvidence, ProvisionalWarning
from src.agents.graph import build_graph
from src.agents.nodes.provisional import build_provisional_warning
from src.agents.seams import ProvisionalWarningSink
from src.agents.tools.fakes import FakeBlacklistRepository
from src.agents.tools.models import (
    CacheMetadata,
    CacheStatus,
    NormalizedToolResult,
    RedirectResolutionResult,
    RedirectResolutionStatus,
    ToolResultStatus,
    UsageMetadata,
)
from src.models import InvestigationStepStatus, InvestigationTool, UrlScanResult, Verdict


class RecordingWarningSink(ProvisionalWarningSink):
    def __init__(self) -> None:
        self.items: list[ProvisionalWarning] = []

    async def emit(self, warning: ProvisionalWarning) -> None:
        self.items.append(warning)


class SlowScanner:
    provider = "slow-fixture"

    def __init__(self) -> None:
        self.cancelled = False

    async def scan(self, normalized_url: str) -> UrlScanResult:
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return UrlScanResult(
            provider=self.provider,
            normalized_url=normalized_url,
            verdict=Verdict.INCONCLUSIVE,
            redirect_chain=[],
            signals=["no_hit"],
            observed_at=datetime.now(UTC),
        )


class RecordingScanner:
    provider = "recording-fixture"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def scan(self, normalized_url: str) -> UrlScanResult:
        self.calls.append(normalized_url)
        return UrlScanResult(
            provider=self.provider,
            normalized_url=normalized_url,
            verdict=Verdict.INCONCLUSIVE,
            redirect_chain=[],
            signals=["no_hit"],
            observed_at=datetime.now(UTC),
        )


class MixedSpeedScanner(RecordingScanner):
    async def scan(self, normalized_url: str) -> UrlScanResult:
        if "slow" in normalized_url:
            await asyncio.sleep(1)
        return await super().scan(normalized_url)


class FixtureRedirectResolver:
    provider = "fixture-redirect"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def resolve(self, normalized_url: str):
        self.calls.append(normalized_url)
        now = datetime.now(UTC)
        return NormalizedToolResult(
            status=ToolResultStatus.SUCCESS,
            result=RedirectResolutionResult(
                normalized_url=normalized_url,
                final_url="https://landing.example/",
                redirect_chain=[normalized_url, "https://landing.example/"],
                status=RedirectResolutionStatus.RESOLVED,
                observed_at=now,
            ),
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="fixture"),
            usage=UsageMetadata(
                usage_ref="usage:redirect:fixture",
                provider=self.provider,
                provider_version="v1",
                operation="resolve_redirects",
                attempts=1,
                network_calls=2,
                latency_ms=1,
                estimated_cost_usd=0.001,
                observed_at=now,
            ),
        )


@pytest.mark.asyncio
async def test_local_provisional_warning_is_emitted_then_replaced_by_final() -> None:
    sink = RecordingWarningSink()
    graph = build_graph(provisional_warning_sink=sink)

    result = await graph.ainvoke({"message": "Mở https://example.com/login để xác minh", "consent_to_scan_urls": False})

    assert len(sink.items) == 1
    assert sink.items[0].is_provisional is True
    assert sink.items[0].evidence_refs[0].startswith("evidence:sha256:")
    assert result["active_warning"] == "final"
    assert result["provisional_warning"] is None


def test_provisional_warning_accepts_only_unexpired_decisive_cache_entry() -> None:
    now = datetime(2026, 8, 8, tzinfo=UTC)

    def cached(expires_at: datetime) -> CachedReputationEvidence:
        return CachedReputationEvidence(
            finding=UrlScanResult(
                provider="fixture-cache",
                normalized_url="https://bad.example/",
                verdict=Verdict.MALICIOUS,
                redirect_chain=[],
                signals=["known_threat"],
                observed_at=now - timedelta(minutes=1),
            ),
            usage_ref="usage:reputation:cache-hit",
            expires_at=expires_at,
        )

    expired = build_provisional_warning(
        {"cached_reputation_evidence": [cached(now)]},
        lambda: now,
    )
    valid = build_provisional_warning(
        {"cached_reputation_evidence": [cached(now + timedelta(minutes=5))]},
        lambda: now,
    )

    assert expired["provisional_warning"] is None
    assert valid["provisional_warning"].evidence_refs == ["usage:reputation:cache-hit"]


@pytest.mark.asyncio
async def test_deadline_cancels_inflight_provider_and_falls_back() -> None:
    scanner = SlowScanner()
    started_at = datetime.now(UTC)
    graph = build_graph(
        url_scanner=scanner,
        blacklist=FakeBlacklistRepository(),
        progress_clock=lambda: started_at,
    )

    result = await graph.ainvoke(
        {
            "message": "Kiểm tra https://unknown.example/",
            "consent_to_scan_urls": True,
            "deadline_at": started_at + timedelta(milliseconds=20),
        }
    )

    step = next(item for item in result["investigation_plan"] if item.tool is InvestigationTool.URL_SCANNER)
    assert scanner.cancelled is True
    assert step.status is InvestigationStepStatus.FAILED
    assert any(error.code == "PROVIDER_TIMEOUT" for error in result["errors"])
    assert result["verdict"] is Verdict.INCONCLUSIVE


@pytest.mark.asyncio
async def test_concurrent_tools_share_deadline_without_discarding_fast_result() -> None:
    scanner = MixedSpeedScanner()
    started_at = datetime.now(UTC)
    graph = build_graph(
        url_scanner=scanner,
        blacklist=FakeBlacklistRepository(),
        progress_clock=lambda: started_at,
    )

    result = await graph.ainvoke(
        {
            "message": "Kiểm tra https://fast.example/ và https://slow.example/",
            "consent_to_scan_urls": True,
            "deadline_at": started_at + timedelta(milliseconds=30),
        }
    )

    steps = {item.target: item for item in result["investigation_plan"] if item.tool is InvestigationTool.URL_SCANNER}
    assert steps["https://fast.example/"].status is InvestigationStepStatus.COMPLETED
    assert steps["https://slow.example/"].status is InvestigationStepStatus.FAILED
    assert [item.normalized_url for item in result["url_findings"]] == ["https://fast.example/"]


@pytest.mark.asyncio
async def test_redirect_is_routed_before_reputation_and_records_usage() -> None:
    resolver = FixtureRedirectResolver()
    graph = build_graph(redirect_resolver=resolver, blacklist=FakeBlacklistRepository())

    result = await graph.ainvoke({"message": "Kiểm tra https://short.example/", "consent_to_scan_urls": True})

    redirect = next(item for item in result["investigation_plan"] if item.tool is InvestigationTool.REDIRECT_RESOLVER)
    reputation = next(item for item in result["investigation_plan"] if item.tool is InvestigationTool.URL_SCANNER)
    assert resolver.calls == ["https://short.example/"]
    assert redirect.status is InvestigationStepStatus.COMPLETED
    assert redirect.step_id in reputation.depends_on
    assert result["tool_usage_refs"] == ["usage:redirect:fixture"]
    assert result["tool_cost_used_usd"] == pytest.approx(0.001)


@pytest.mark.asyncio
async def test_llm_budget_zero_never_invokes_model() -> None:
    class Llm:
        calls = 0

        def with_structured_output(self, _schema):
            self.calls += 1
            raise AssertionError("LLM must not be constructed after budget gate")

    llm = Llm()
    result = await build_graph(llm=llm).ainvoke(
        {
            "message": "Nội dung cần kiểm tra",
            "consent_to_scan_urls": False,
            "max_llm_calls": 0,
        }
    )

    assert llm.calls == 0
    assert result["verdict"] is Verdict.INCONCLUSIVE
    assert any("budget" in item for item in result["limitations"])


@pytest.mark.asyncio
async def test_resume_with_terminal_plan_does_not_duplicate_tool_call() -> None:
    scanner = RecordingScanner()
    graph = build_graph(url_scanner=scanner, blacklist=FakeBlacklistRepository())
    initial = await graph.ainvoke({"message": "Kiểm tra https://unknown.example/", "consent_to_scan_urls": True})

    resumed = await graph.ainvoke(initial)

    assert scanner.calls == ["https://unknown.example/"]
    url_step = next(item for item in resumed["investigation_plan"] if item.tool is InvestigationTool.URL_SCANNER)
    assert url_step.status is InvestigationStepStatus.COMPLETED


@pytest.mark.asyncio
async def test_zero_tool_cost_budget_skips_external_work() -> None:
    scanner = RecordingScanner()
    graph = build_graph(url_scanner=scanner, blacklist=FakeBlacklistRepository())

    result = await graph.ainvoke(
        {
            "message": "Kiểm tra https://unknown.example/",
            "consent_to_scan_urls": True,
            "max_tool_cost_usd": 0,
        }
    )

    assert scanner.calls == []
    url_step = next(item for item in result["investigation_plan"] if item.tool is InvestigationTool.URL_SCANNER)
    assert url_step.status is InvestigationStepStatus.SKIPPED
    assert any("ngân sách" in item for item in result["limitations"])
