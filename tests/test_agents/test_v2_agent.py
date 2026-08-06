import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from src.agents.graph import build_graph
from src.agents.nodes.planning import ensure_step, transition_step
from src.agents.nodes.risk import assess_risk
from src.agents.tools.errors import ToolCallError
from src.agents.tools.fakes import FakeBlacklistRepository
from src.models import (
    ClaimEvidence,
    ClaimStance,
    DomainIntelligenceResult,
    InvestigationStepStatus,
    InvestigationTool,
    UrlScanResult,
    Verdict,
)

NOW = datetime(2026, 8, 6, tzinfo=UTC)


class RecordingScanner:
    def __init__(self, barrier: asyncio.Event | None = None) -> None:
        self.calls: list[str] = []
        self.barrier = barrier

    async def scan(self, url: str) -> UrlScanResult:
        self.calls.append(url)
        if self.barrier is not None:
            self.barrier.set()
            await asyncio.sleep(0)
        return UrlScanResult(
            provider="fake-reputation",
            normalized_url=url,
            verdict=Verdict.INCONCLUSIVE,
            redirect_chain=[],
            signals=["no_hit"],
            observed_at=NOW,
        )


class RecordingDomainIntelligence:
    def __init__(self, scanner_started: asyncio.Event | None = None) -> None:
        self.calls: list[str] = []
        self.scanner_started = scanner_started
        self.overlapped = False

    async def lookup(self, domain: str) -> DomainIntelligenceResult:
        self.calls.append(domain)
        self.overlapped = self.scanner_started is not None and self.scanner_started.is_set()
        return DomainIntelligenceResult(
            provider="fake-rdap",
            domain=domain,
            registered_at=NOW - timedelta(days=10),
            expires_at=None,
            registrar=None,
            country=None,
            status=[],
            privacy_redacted=False,
            signals=["new_domain"],
            observed_at=NOW,
        )


class RetryOnceScanner(RecordingScanner):
    def __init__(self) -> None:
        super().__init__()
        self.active_calls = 0
        self.max_active_calls = 0

    async def scan(self, url: str) -> UrlScanResult:
        self.calls.append(url)
        self.active_calls += 1
        self.max_active_calls = max(self.max_active_calls, self.active_calls)
        try:
            await asyncio.sleep(0)
            if len(self.calls) == 1:
                raise ToolCallError("url_scanner", "PROVIDER_TIMEOUT", "Timed out", retryable=True)
            return UrlScanResult(
                provider="fake-reputation",
                normalized_url=url,
                verdict=Verdict.INCONCLUSIVE,
                redirect_chain=[],
                signals=["no_hit"],
                observed_at=NOW,
            )
        finally:
            self.active_calls -= 1


def test_step_transition_is_idempotent_and_terminal() -> None:
    plan = []
    step = ensure_step(
        plan,
        tool=InvestigationTool.URL_SCANNER,
        target="https://example.com/",
        reason_code="url_reputation_needed",
    )

    plan = transition_step(plan, step.step_id, InvestigationStepStatus.RUNNING)
    plan = transition_step(plan, step.step_id, InvestigationStepStatus.COMPLETED)
    plan = transition_step(plan, step.step_id, InvestigationStepStatus.COMPLETED)
    plan = transition_step(plan, step.step_id, InvestigationStepStatus.FAILED)

    assert plan[0].status is InvestigationStepStatus.COMPLETED


@pytest.mark.asyncio
async def test_retry_returns_running_step_to_pending_without_overlap() -> None:
    scanner = RetryOnceScanner()
    graph = build_graph(url_scanner=scanner, blacklist=FakeBlacklistRepository())

    result = await graph.ainvoke(
        {
            "message": "Kiểm tra https://unknown.example/login",
            "consent_to_scan_urls": True,
            "max_tool_retries": 1,
        }
    )

    scanner_step = next(step for step in result["investigation_plan"] if step.tool is InvestigationTool.URL_SCANNER)
    assert len(scanner.calls) == 2
    assert scanner.max_active_calls == 1
    assert scanner_step.status is InvestigationStepStatus.COMPLETED


def test_rdap_signal_is_capped_and_cannot_be_malicious_alone() -> None:
    result = assess_risk(
        {
            "domain_findings": [
                DomainIntelligenceResult(
                    provider="fake-rdap",
                    domain="new.example",
                    registered_at=NOW - timedelta(days=1),
                    expires_at=None,
                    registrar=None,
                    country=None,
                    status=[],
                    privacy_redacted=False,
                    signals=["new_domain", "recent_registration"],
                    observed_at=NOW,
                )
            ],
            "evidence": [],
            "normalized_urls": ["https://new.example/"],
        }
    )

    assert result["risk_score"] == 20
    assert result["verdict"] is Verdict.INCONCLUSIVE


def test_rdap_privacy_redaction_does_not_increase_risk() -> None:
    result = assess_risk(
        {
            "domain_findings": [
                DomainIntelligenceResult(
                    provider="fake-rdap",
                    domain="redacted.example",
                    registered_at=None,
                    expires_at=None,
                    registrar=None,
                    country=None,
                    status=[],
                    privacy_redacted=True,
                    signals=["privacy_redacted"],
                    observed_at=NOW,
                )
            ],
            "evidence": [],
            "normalized_urls": ["https://redacted.example/"],
        }
    )

    assert result["risk_score"] == 0
    assert result["verdict"] is Verdict.INCONCLUSIVE


def test_claim_scoring_uses_stance_not_finding_keywords() -> None:
    common = {
        "source": "fact-check",
        "title": "Review",
        "url": "https://fact.example/review",
        "relevance": 0.9,
        "observed_at": NOW,
    }
    unrated = assess_risk(
        {
            "claim_findings": [
                ClaimEvidence(
                    **common,
                    finding="Bác bỏ, sai sự thật, không đúng.",
                    stance=ClaimStance.UNRATED,
                )
            ],
            "evidence": [],
            "claims": ["claim"],
        }
    )
    refuted = assess_risk(
        {
            "claim_findings": [
                ClaimEvidence(
                    **common,
                    finding="Provider rating in another language.",
                    stance=ClaimStance.REFUTES,
                )
            ],
            "evidence": [],
            "claims": ["claim"],
        }
    )

    assert unrated["risk_score"] == 0
    assert refuted["risk_score"] == 70
    assert refuted["verdict"] is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_no_consent_creates_no_external_work() -> None:
    scanner = RecordingScanner()
    domain = RecordingDomainIntelligence()
    graph = build_graph(
        url_scanner=scanner,
        domain_intelligence=domain,
        blacklist=FakeBlacklistRepository(),
    )

    result = await graph.ainvoke({"message": "Kiểm tra https://unknown.example/login", "consent_to_scan_urls": False})

    assert scanner.calls == []
    assert domain.calls == []
    external = [
        step
        for step in result["investigation_plan"]
        if step.tool in {InvestigationTool.URL_SCANNER, InvestigationTool.DOMAIN_INTELLIGENCE}
    ]
    assert external and all(step.status is InvestigationStepStatus.SKIPPED for step in external)


@pytest.mark.asyncio
async def test_approved_blacklist_hit_stops_paid_url_and_domain_work() -> None:
    scanner = RecordingScanner()
    domain = RecordingDomainIntelligence()
    graph = build_graph(
        url_scanner=scanner,
        domain_intelligence=domain,
        blacklist=FakeBlacklistRepository(["known-bad.example"]),
    )

    result = await graph.ainvoke({"message": "Kiểm tra https://known-bad.example/login", "consent_to_scan_urls": True})

    assert scanner.calls == []
    assert domain.calls == []
    assert any(item.type.value == "blacklist" for item in result["evidence"])


@pytest.mark.asyncio
async def test_reputation_and_rdap_run_after_gate_and_can_overlap() -> None:
    scanner_started = asyncio.Event()
    scanner = RecordingScanner(scanner_started)
    domain = RecordingDomainIntelligence(scanner_started)
    graph = build_graph(
        url_scanner=scanner,
        domain_intelligence=domain,
        blacklist=FakeBlacklistRepository(),
    )

    result = await graph.ainvoke({"message": "Kiểm tra https://unknown.example/login", "consent_to_scan_urls": True})

    assert scanner.calls == ["https://unknown.example/login"]
    assert domain.calls == ["unknown.example"]
    assert domain.overlapped is True
    external = [
        step
        for step in result["investigation_plan"]
        if step.tool in {InvestigationTool.URL_SCANNER, InvestigationTool.DOMAIN_INTELLIGENCE}
    ]
    assert all(step.status is InvestigationStepStatus.COMPLETED for step in external)
