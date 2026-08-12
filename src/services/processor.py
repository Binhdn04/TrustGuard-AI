from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

from src.agents.contracts import LiveStepTransition, ProvisionalWarning
from src.agents.graph import close_graph_resources
from src.models import (
    AnalysisCreateRequest,
    AnalysisResponse,
    AnalysisStatus,
    InvestigationStep,
    ToolError,
)

ProgressCallback = Callable[[InvestigationStep], Awaitable[None]]
ProvisionalCallback = Callable[[ProvisionalWarning], Awaitable[None]]


class _CallbackProgressSink:
    def __init__(self, callback: ProgressCallback | None) -> None:
        self._callback = callback
        self.emitted: set[tuple[str, str]] = set()

    async def emit(self, transition: LiveStepTransition) -> None:
        self.emitted.add((transition.step_id, transition.status.value))
        if self._callback is not None:
            await self._callback(
                InvestigationStep(
                    step_id=transition.step_id,
                    tool=transition.tool,
                    target=transition.target,
                    reason_code=transition.reason_code,
                    depends_on=transition.depends_on,
                    status=transition.status,
                )
            )


class _CallbackProvisionalSink:
    def __init__(self, callback: ProvisionalCallback | None) -> None:
        self._callback = callback

    async def emit(self, warning: ProvisionalWarning) -> None:
        if self._callback is not None:
            await self._callback(warning)


@dataclass(slots=True)
class ProcessedAnalysis:
    """Internal processor result; tool errors remain private persistence data."""

    response: AnalysisResponse
    errors: list[ToolError]
    usage_records: list[Any] = field(default_factory=list)


class AnalysisGraph(Protocol):
    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]: ...


class LangGraphAnalysisProcessor:
    """Translate between the HTTP analysis contract and the LangGraph state."""

    def __init__(
        self,
        graph: AnalysisGraph,
        *,
        max_tool_calls: int = 6,
        deadline_seconds: float = 30,
        max_tool_cost_usd: float = 0.05,
    ) -> None:
        self._graph = graph
        self._max_tool_calls = max_tool_calls
        self._deadline_seconds = deadline_seconds
        self._max_tool_cost_usd = max_tool_cost_usd

    async def process(
        self,
        analysis_id: UUID,
        request: AnalysisCreateRequest,
        created_at: datetime,
        progress: ProgressCallback | None = None,
        provisional: ProvisionalCallback | None = None,
    ) -> ProcessedAnalysis:
        progress_sink = _CallbackProgressSink(progress)
        state = await self._graph.ainvoke(
            {
                "analysis_id": str(analysis_id),
                "message": request.message,
                "consent_to_scan_urls": request.consent_to_scan_urls,
                "consent_to_capture_screenshot": bool(getattr(request, "consent_to_capture_screenshot", False)),
                "max_tool_calls": self._max_tool_calls,
                "deadline_at": datetime.now(UTC) + timedelta(seconds=self._deadline_seconds),
                "max_tool_cost_usd": self._max_tool_cost_usd,
                "runtime_progress_sink": progress_sink,
                "runtime_provisional_sink": _CallbackProvisionalSink(provisional),
            }
        )
        plan = [step.model_copy(deep=True) for step in state.get("investigation_plan", [])]
        if progress is not None:
            for step in plan:
                marker = (step.step_id, step.status.value)
                if marker not in progress_sink.emitted:
                    await progress(step.model_copy(deep=True))
        response = AnalysisResponse(
            analysis_id=analysis_id,
            status=AnalysisStatus.COMPLETED,
            input_type=state["input_type"],
            normalized_urls=list(state.get("normalized_urls", [])),
            claims=list(state.get("claims", [])),
            investigation_plan=plan,
            risk_score=state["risk_score"],
            risk_level=state["risk_level"],
            verdict=state["verdict"],
            recommended_action=state["recommended_action"],
            confidence=state["confidence"],
            fact_check_basis=state.get("fact_check_basis", "inconclusive"),
            fact_check_confidence=state.get("fact_check_confidence"),
            summary=state["summary"],
            reasons=list(state.get("reasons", [])),
            evidence=list(state.get("evidence", [])),
            examined_evidence=list(state.get("examined_evidence", [])),
            limitations=list(state.get("limitations", [])),
            case_status=state["case_status"],
            scoring_version=state["scoring_version"],
            created_at=created_at,
            completed_at=datetime.now(UTC),
        )
        return ProcessedAnalysis(
            response=response,
            errors=list(state.get("errors", [])),
            usage_records=list(state.get("usage_records", [])),
        )

    async def aclose(self) -> None:
        await close_graph_resources(self._graph)
