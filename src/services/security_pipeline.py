from __future__ import annotations

from collections.abc import Awaitable, Callable

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.security_trust import SecurityTrustService
from src.agents.tools.security_memory import SecurityMemoryLookupTool
from src.models import (
    ExposureStateV4,
    ScopeDecisionV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_conversation_policy import is_incident_exposure
from src.services.security_response import GroundedSecurityResponseService
from src.services.security_understanding import SecuritySemanticUnderstandingService

ProgressCallback = Callable[
    [str, str, list[str], SecurityRiskV4 | None],
    Awaitable[None],
]


class SecurityTriagePipeline:
    """Shared inline/worker pipeline for one immutable Security v4 turn."""

    def __init__(
        self,
        *,
        understanding: SecuritySemanticUnderstandingService,
        investigation: SecurityInvestigationService,
        trust: SecurityTrustService,
        responses: GroundedSecurityResponseService,
        memory_lookup: SecurityMemoryLookupTool | None = None,
    ) -> None:
        self._understanding = understanding
        self._investigation = investigation
        self._trust = trust
        self._responses = responses
        self._memory_lookup = memory_lookup

    async def process(
        self,
        request: SecurityTriageCreateRequestV4,
        scoped: SecurityScopeResponseV4,
        *,
        runtime: SecurityAssistantRuntime,
        progress: ProgressCallback | None = None,
        owner_id: str | None = None,
    ) -> SecurityScopeResponseV4:
        scoped = await self._understanding.enrich(request, scoped)
        if progress is not None:
            await progress("understanding", "Đã hợp nhất ngữ cảnh rule và AI.", [], None)
        if scoped.scope_decision is not ScopeDecisionV4.IN_SCOPE:
            return scoped

        exposure = (
            scoped.assistant_context.exposure_state
            if scoped.assistant_context is not None
            else ExposureStateV4.UNKNOWN
        )
        if is_incident_exposure(exposure):
            if self._memory_lookup is not None and owner_id is not None:
                scoped = await self._memory_lookup.enrich(scoped, owner_id=owner_id)
            scoped = assess_security_risk(
                scoped,
                memory_enabled=bool(self._memory_lookup and self._memory_lookup.enabled and owner_id),
            )
            if progress is not None:
                await progress("incident_response", "Đã ưu tiên hướng dẫn khôi phục tức thời.", [], scoped.risk)
        else:
            scoped = await self._investigation.investigate(request, scoped, runtime=runtime)
            if progress is not None:
                await progress(
                    "investigation",
                    "Đã hoàn tất kế hoạch điều tra được policy kiểm soát.",
                    [item.evidence_ref for item in scoped.evidence],
                    None,
                )
            scoped = await self._trust.enrich(request, scoped)
            if self._memory_lookup is not None and owner_id is not None:
                scoped = await self._memory_lookup.enrich(scoped, owner_id=owner_id)
                if progress is not None:
                    refs = [
                        item.evidence_ref for item in scoped.evidence if item.type.value == "reviewed_security_memory"
                    ]
                    await progress(
                        "security_memory_lookup",
                        "Đã đối chiếu Security Memory được reviewer phê duyệt.",
                        refs,
                        None,
                    )
            scoped = assess_security_risk(
                scoped,
                memory_enabled=bool(self._memory_lookup and self._memory_lookup.enabled and owner_id),
            )
            if progress is not None:
                await progress(
                    "risk_assessment",
                    "Đã tính risk bằng policy xác định.",
                    list(scoped.explanation_evidence_refs),
                    scoped.risk,
                )
        scoped = await self._responses.enrich(scoped)
        if progress is not None:
            await progress(
                "assistant_response",
                "Đã tạo phản hồi trợ lý có kiểm tra grounding.",
                list(scoped.explanation_evidence_refs),
                scoped.risk,
            )
        return scoped


__all__ = ["SecurityTriagePipeline"]
