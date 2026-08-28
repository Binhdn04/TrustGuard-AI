from __future__ import annotations

from time import perf_counter

import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.models import AnalysisStatus, SecurityInvestigationStatusV4, SecurityTriageCreateRequestV4
from src.security_ai.runtime import (
    BudgetExceededError,
    SecurityAssistantRuntime,
    TurnBudget,
    TurnExecutionContext,
)
from src.services.security_pipeline import SecurityTriagePipeline
from src.services.security_progress import SecurityProgressUpdate
from src.services.security_triage import SecurityTriageScopeService


class PassthroughUnderstanding:
    def __init__(self) -> None:
        self.calls = 0

    async def enrich(self, request, scoped):
        del request
        self.calls += 1
        return scoped


class MustNotRun:
    async def enrich(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("terminal scope resolved a later pipeline stage")


class PassthroughInvestigation:
    async def investigate(self, request, scoped, *, runtime):
        del request, runtime
        return scoped.model_copy(
            update={
                "next_step": "RISK_ASSESSMENT",
                "investigation_status": SecurityInvestigationStatusV4.COMPLETED,
            }
        )


class PassthroughTrust:
    async def enrich(self, request, scoped):
        del request
        return scoped


class PassthroughResponse:
    async def enrich(self, scoped):
        return scoped


@pytest.mark.asyncio
async def test_inline_and_worker_pipeline_construction_have_result_and_event_parity() -> None:
    request = SecurityTriageCreateRequestV4(message="https://example.test/login")
    scoped = SecurityTriageScopeService().assess(request)
    investigation = PassthroughInvestigation()
    worker_events: list[str] = []

    async def resolve_investigation():
        return investigation

    async def record_progress(update: SecurityProgressUpdate):
        worker_events.append(f"{update.stage.value}.{update.state.value}")

    inline = SecurityTriagePipeline(
        understanding=PassthroughUnderstanding(),
        investigation_resolver=resolve_investigation,
        trust=PassthroughTrust(),
        responses=PassthroughResponse(),
    )
    worker = SecurityTriagePipeline(
        understanding=PassthroughUnderstanding(),
        investigation=investigation,
        trust=PassthroughTrust(),
        responses=PassthroughResponse(),
    )

    inline_result = await inline.process(request, scoped, runtime=SecurityAssistantRuntime())
    worker_result = await worker.process(
        request,
        scoped.model_copy(update={"status": AnalysisStatus.RUNNING}),
        runtime=SecurityAssistantRuntime(),
        progress=record_progress,
    )

    assert inline_result.model_dump(exclude={"completed_at"}) == worker_result.model_dump(exclude={"completed_at"})
    assert worker_events == [
        "understanding.started",
        "understanding.completed",
        "scope_gate.completed",
        "investigation.started",
        "investigation.completed",
        "risk_assessment.started",
        "risk_assessment.completed",
        "assistant_response.started",
        "assistant_response.completed",
    ]


@pytest.mark.asyncio
async def test_terminal_scope_completes_without_resolving_investigation_or_memory() -> None:
    request = SecurityTriageCreateRequestV4(message="World Cup co dung khong?")
    scoped = SecurityTriageScopeService().assess(request)
    understanding = PassthroughUnderstanding()
    resolved: list[str] = []

    async def resolve_investigation():
        resolved.append("investigation")
        raise AssertionError("out-of-scope turn resolved investigation")

    async def resolve_memory():
        resolved.append("memory")
        raise AssertionError("out-of-scope turn resolved memory")

    pipeline = SecurityTriagePipeline(
        understanding=understanding,
        investigation_resolver=resolve_investigation,
        trust=MustNotRun(),
        responses=MustNotRun(),
        memory_lookup_resolver=resolve_memory,
    )

    result = await pipeline.process(request, scoped, runtime=SecurityAssistantRuntime())

    assert understanding.calls == 1
    assert resolved == []
    assert result.status is AnalysisStatus.COMPLETED
    assert result.completed_at is not None
    assert result.tool_calls_used == 0


def test_turn_execution_context_owns_shared_ai_network_deadline_and_cost_budgets() -> None:
    assert TurnExecutionContext().max_network_units == 16

    ai_budget = TurnBudget(max_calls=3, cost_usd=0.01)
    context = TurnExecutionContext(
        deadline_seconds=30,
        max_network_units=2,
        max_estimated_cost_usd=0.05,
        ai_budget=ai_budget,
    )
    runtime = SecurityAssistantRuntime(
        budget=TurnBudget(max_calls=1),
        execution_context=context,
        turn_started_at=context.started_at,
    )

    assert runtime.budget is ai_budget
    assert runtime.execution_context is context
    assert 0 < context.remaining_seconds <= 30

    context.reserve_network_units(2)
    with pytest.raises(BudgetExceededError, match="turn_network_budget_exhausted"):
        context.reserve_network_units()

    context.record_external_cost(0.02)
    assert context.estimated_cost_usd == pytest.approx(0.03)
    assert context.cost_budget_exhausted is False


class MustNotCallDns:
    provider = "must-not-call-dns"

    def __init__(self) -> None:
        self.calls = 0

    async def resolve(self, target):
        del target
        self.calls += 1
        raise AssertionError("external provider started after the end-to-end deadline")


class EmptyBlacklist:
    async def get(self, target):
        del target
        return None


@pytest.mark.asyncio
async def test_investigation_uses_remaining_end_to_end_deadline() -> None:
    request = SecurityTriageCreateRequestV4(
        message="https://example.test/login",
        consent={"external_url_lookup": True},
    )
    scoped = SecurityTriageScopeService().assess(request)
    dns = MustNotCallDns()
    context = TurnExecutionContext(
        deadline_seconds=0.01,
        started_at=perf_counter() - 1,
    )
    runtime = SecurityAssistantRuntime(
        execution_context=context,
        turn_started_at=context.started_at,
    )

    result = await SecurityInvestigationService(blacklist=EmptyBlacklist(), dns=dns).investigate(
        request,
        scoped,
        runtime=runtime,
    )

    assert dns.calls == 0
    assert result.tool_calls_used == 0
    assert "Đã hết thời gian dành cho investigation tools." in result.limitations
