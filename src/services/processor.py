from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from src.agents.graph import close_graph_resources
from src.models import (
    AnalysisCreateRequest,
    AnalysisResponse,
    AnalysisStatus,
    InvestigationStep,
    ToolError,
)

ProgressCallback = Callable[[InvestigationStep], Awaitable[None]]


@dataclass(slots=True)
class ProcessedAnalysis:
    """Internal processor result; tool errors remain private persistence data."""

    response: AnalysisResponse
    errors: list[ToolError]


class AnalysisGraph(Protocol):
    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]: ...


class LangGraphAnalysisProcessor:
    """Translate between the HTTP analysis contract and the LangGraph state."""

    def __init__(self, graph: AnalysisGraph, *, max_tool_calls: int = 6) -> None:
        self._graph = graph
        self._max_tool_calls = max_tool_calls

    async def process(
        self,
        analysis_id: UUID,
        request: AnalysisCreateRequest,
        created_at: datetime,
        progress: ProgressCallback | None = None,
    ) -> ProcessedAnalysis:
        state = await self._graph.ainvoke(
            {
                "analysis_id": str(analysis_id),
                "message": request.message,
                "consent_to_scan_urls": request.consent_to_scan_urls,
                "consent_to_capture_screenshot": bool(getattr(request, "consent_to_capture_screenshot", False)),
                "max_tool_calls": self._max_tool_calls,
            }
        )
        plan = [step.model_copy(deep=True) for step in state.get("investigation_plan", [])]
        if progress is not None:
            for step in plan:
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
            summary=state["summary"],
            reasons=list(state.get("reasons", [])),
            evidence=list(state.get("evidence", [])),
            limitations=list(state.get("limitations", [])),
            case_status=state["case_status"],
            scoring_version=state["scoring_version"],
            created_at=created_at,
            completed_at=datetime.now(UTC),
        )
        return ProcessedAnalysis(response=response, errors=list(state.get("errors", [])))

    async def aclose(self) -> None:
        await close_graph_resources(self._graph)
