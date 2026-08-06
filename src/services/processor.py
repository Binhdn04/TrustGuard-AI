from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from src.agents.graph import close_graph_resources
from src.models import AnalysisCreateRequest, AnalysisResponse, AnalysisStatus


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
    ) -> AnalysisResponse:
        state = await self._graph.ainvoke(
            {
                "analysis_id": str(analysis_id),
                "message": request.message,
                "consent_to_scan_urls": request.consent_to_scan_urls,
                "max_tool_calls": self._max_tool_calls,
            }
        )
        return AnalysisResponse(
            analysis_id=analysis_id,
            status=AnalysisStatus.COMPLETED,
            input_type=state["input_type"],
            normalized_urls=list(state.get("normalized_urls", [])),
            claims=list(state.get("claims", [])),
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

    async def aclose(self) -> None:
        await close_graph_resources(self._graph)
