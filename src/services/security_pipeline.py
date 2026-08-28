from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_risk import assess_security_risk
from src.agents.security_trust import SecurityTrustService
from src.agents.tools.security_memory import SecurityMemoryLookupTool
from src.models import (
    AnalysisStatus,
    AssistantProcessingModeV4,
    ExposureStateV4,
    ScopeDecisionV4,
    SecurityInvestigationStatusV4,
    SecurityInvestigationStepStatusV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
)
from src.observability.langfuse import get_langfuse_observability
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.official_verification_coordinator import OfficialLinkVerificationCoordinator
from src.services.official_verification_rollout import OfficialVerificationRolloutStage
from src.services.security_conversation_policy import is_incident_exposure
from src.services.security_progress import SecurityProgressMessageCode, SecurityProgressUpdate
from src.services.security_response import GroundedSecurityResponseService
from src.services.security_understanding import SecuritySemanticUnderstandingService

ProgressCallback = Callable[[SecurityProgressUpdate], Awaitable[None]]

logger = logging.getLogger("trustguard.official_verification")
InvestigationResolver = Callable[[], Awaitable[SecurityInvestigationService]]
MemoryLookupResolver = Callable[[], Awaitable[SecurityMemoryLookupTool]]


async def _emit(progress: ProgressCallback | None, message_code: SecurityProgressMessageCode) -> None:
    if progress is not None:
        await progress(SecurityProgressUpdate.for_message_code(message_code))


class SecurityTriagePipeline:
    """Shared inline/worker pipeline for one immutable Security v4 turn."""

    def __init__(
        self,
        *,
        understanding: SecuritySemanticUnderstandingService,
        investigation: SecurityInvestigationService | None = None,
        investigation_resolver: InvestigationResolver | None = None,
        trust: SecurityTrustService,
        responses: GroundedSecurityResponseService,
        official_verification: OfficialLinkVerificationCoordinator | None = None,
        official_verification_rollout: OfficialVerificationRolloutStage | None = None,
        memory_lookup: SecurityMemoryLookupTool | None = None,
        memory_lookup_resolver: MemoryLookupResolver | None = None,
        familiarity_enforced: bool = False,
    ) -> None:
        if (investigation is None) == (investigation_resolver is None):
            raise ValueError("provide exactly one investigation service or resolver")
        if memory_lookup is not None and memory_lookup_resolver is not None:
            raise ValueError("provide at most one memory lookup service or resolver")
        if official_verification is not None and official_verification_rollout is not None:
            raise ValueError("provide either the CP7 coordinator or the rollout stage, not both")
        self._understanding = understanding
        self._investigation = investigation
        self._investigation_resolver = investigation_resolver
        self._trust = trust
        self._responses = responses
        self._official_verification = official_verification
        self._official_verification_rollout = official_verification_rollout
        self._memory_lookup = memory_lookup
        self._memory_lookup_resolver = memory_lookup_resolver
        self._familiarity_enforced = familiarity_enforced

    async def process(
        self,
        request: SecurityTriageCreateRequestV4,
        scoped: SecurityScopeResponseV4,
        *,
        runtime: SecurityAssistantRuntime,
        progress: ProgressCallback | None = None,
        owner_id: str | None = None,
    ) -> SecurityScopeResponseV4:
        observability = get_langfuse_observability()
        await _emit(progress, SecurityProgressMessageCode.UNDERSTANDING_STARTED)
        with observability.observation(
            "understand-security-context",
            input={"initial_scope": scoped.scope_decision.value},
        ) as observation:
            scoped = await self._understanding.enrich(request, scoped)
            if observation is not None:
                observation.update(
                    output={
                        "status": "completed",
                        "scope": scoped.scope_decision.value,
                        "scenario": scoped.security_context.scenario.value if scoped.security_context else None,
                        "semantic_processing_mode": (
                            scoped.assistant_context.processing_mode.value if scoped.assistant_context else "rules_only"
                        ),
                        "semantic_fields": (
                            sorted(scoped.assistant_context.field_confidences)
                            if scoped.assistant_context is not None
                            else []
                        ),
                    }
                )
        await _emit(
            progress,
            SecurityProgressMessageCode.UNDERSTANDING_DEGRADED
            if scoped.assistant_context is not None
            and scoped.assistant_context.processing_mode is AssistantProcessingModeV4.FALLBACK
            else SecurityProgressMessageCode.UNDERSTANDING_COMPLETED,
        )
        await _emit(progress, SecurityProgressMessageCode.SCOPE_GATE_COMPLETED)
        if scoped.scope_decision is not ScopeDecisionV4.IN_SCOPE:
            # Legacy test/dry-run response doubles may intentionally omit the
            # composer. Production always supplies GroundedSecurityResponseService.
            compose_terminal = getattr(self._responses, "enrich_terminal", None)
            if compose_terminal is not None:
                await _emit(progress, SecurityProgressMessageCode.ASSISTANT_RESPONSE_STARTED)
                scoped = await compose_terminal(scoped)
                await _emit(progress, SecurityProgressMessageCode.ASSISTANT_RESPONSE_COMPLETED)
            return self._complete(scoped)

        exposure = (
            scoped.assistant_context.exposure_state if scoped.assistant_context is not None else ExposureStateV4.UNKNOWN
        )
        if is_incident_exposure(exposure):
            await _emit(progress, SecurityProgressMessageCode.INCIDENT_RESPONSE_STARTED)
            memory_lookup = await self._resolve_memory_lookup()
            if memory_lookup is not None and owner_id is not None:
                await _emit(progress, SecurityProgressMessageCode.SECURITY_MEMORY_LOOKUP_STARTED)
                scoped = await memory_lookup.enrich(scoped, owner_id=owner_id)
                await _emit(progress, SecurityProgressMessageCode.SECURITY_MEMORY_LOOKUP_COMPLETED)
            await _emit(progress, SecurityProgressMessageCode.RISK_ASSESSMENT_STARTED)
            with observability.observation("assess-security-risk") as observation:
                scoped = assess_security_risk(
                    scoped,
                    memory_enabled=bool(memory_lookup and memory_lookup.enabled and owner_id),
                    official_verification_enforced=self._risk_v3_enforced,
                    familiarity_enforced=self._familiarity_enforced,
                )
                self._update_risk_observation(observation, scoped)
                self._trace_official_verification_risk_boundary(scoped)
            await _emit(progress, SecurityProgressMessageCode.RISK_ASSESSMENT_COMPLETED)
            await _emit(progress, SecurityProgressMessageCode.INCIDENT_RESPONSE_COMPLETED)
        else:
            await _emit(progress, SecurityProgressMessageCode.INVESTIGATION_STARTED)
            with observability.observation("investigate-security-case") as observation:
                investigation = await self._resolve_investigation()
                scoped = await investigation.investigate(request, scoped, runtime=runtime)
                scoped = await self._trust.enrich(request, scoped)
                self._record_tool_observations(observability, scoped)
                if observation is not None:
                    observation.update(
                        output={
                            "status": scoped.investigation_status.value,
                            "tool_calls_used": scoped.tool_calls_used,
                            "error_count": len(scoped.errors),
                        }
                    )
            await _emit(
                progress,
                SecurityProgressMessageCode.INVESTIGATION_COMPLETED
                if scoped.investigation_status is SecurityInvestigationStatusV4.COMPLETED
                else SecurityProgressMessageCode.INVESTIGATION_DEGRADED
                if scoped.investigation_status is SecurityInvestigationStatusV4.PARTIAL
                else SecurityProgressMessageCode.INVESTIGATION_SKIPPED,
            )
            official_verification_applicable = self._official_verification_may_run(scoped)
            if official_verification_applicable:
                await _emit(progress, SecurityProgressMessageCode.OFFICIAL_LINK_VERIFICATION_STARTED)
            with observability.observation("verify-official-identity") as observation:
                if self._official_verification_rollout is not None:
                    assert runtime.execution_context is not None
                    scoped = await self._official_verification_rollout.run(
                        request,
                        scoped,
                        execution_context=runtime.execution_context,
                    )
                elif self._official_verification is not None:
                    assert runtime.execution_context is not None
                    scoped = await self._official_verification.verify(
                        request,
                        scoped,
                        execution_context=runtime.execution_context,
                    )
                if observation is not None:
                    verification_failed = "official_verification_error" in scoped.limitations
                    observation.update(
                        output={
                            "status": (
                                "failed"
                                if verification_failed
                                else "completed"
                                if scoped.official_verification
                                else "not_applicable"
                            ),
                            "limitation_count": len(scoped.limitations),
                        },
                        level="ERROR" if verification_failed else "DEFAULT",
                    )
            if official_verification_applicable:
                await _emit(
                    progress,
                    SecurityProgressMessageCode.OFFICIAL_LINK_VERIFICATION_DEGRADED
                    if "official_verification_error" in scoped.limitations
                    else SecurityProgressMessageCode.OFFICIAL_LINK_VERIFICATION_COMPLETED
                    if scoped.official_verification is not None
                    else SecurityProgressMessageCode.OFFICIAL_LINK_VERIFICATION_SKIPPED,
                )
            memory_lookup = await self._resolve_memory_lookup()
            if memory_lookup is not None and owner_id is not None:
                await _emit(progress, SecurityProgressMessageCode.SECURITY_MEMORY_LOOKUP_STARTED)
                scoped = await memory_lookup.enrich(scoped, owner_id=owner_id)
                await _emit(progress, SecurityProgressMessageCode.SECURITY_MEMORY_LOOKUP_COMPLETED)
            await _emit(progress, SecurityProgressMessageCode.RISK_ASSESSMENT_STARTED)
            with observability.observation("assess-security-risk") as observation:
                scoped = assess_security_risk(
                    scoped,
                    memory_enabled=bool(memory_lookup and memory_lookup.enabled and owner_id),
                    official_verification_enforced=self._risk_v3_enforced,
                    familiarity_enforced=self._familiarity_enforced,
                )
                self._update_risk_observation(observation, scoped)
                self._trace_official_verification_risk_boundary(scoped)
            await _emit(progress, SecurityProgressMessageCode.RISK_ASSESSMENT_COMPLETED)
        await _emit(progress, SecurityProgressMessageCode.ASSISTANT_RESPONSE_STARTED)
        with observability.observation("generate-security-response") as observation:
            scoped = await self._responses.enrich(scoped)
            if observation is not None:
                response = scoped.assistant_response
                observation.update(
                    output={
                        "status": "completed",
                        "generation_mode": response.generation_mode.value if response else None,
                        "final_response_source": response.generation_mode.value if response else None,
                    }
                )
        await _emit(
            progress,
            SecurityProgressMessageCode.ASSISTANT_RESPONSE_DEGRADED
            if scoped.assistant_response is not None and scoped.assistant_response.degradation_reason is not None
            else SecurityProgressMessageCode.ASSISTANT_RESPONSE_COMPLETED,
        )
        return self._complete(scoped)

    @staticmethod
    def _update_risk_observation(observation, scoped: SecurityScopeResponseV4) -> None:
        if observation is not None:
            observation.update(
                output={
                    "status": "completed",
                    "risk": scoped.risk.value if scoped.risk else None,
                    "score": scoped.score,
                    "confidence": scoped.confidence,
                    "verdict_source": "evidence_policy",
                }
            )

    def _trace_official_verification_risk_boundary(self, scoped: SecurityScopeResponseV4) -> None:
        """Log the effective rollout-to-policy handoff without message content."""
        report = scoped.official_verification
        if report is None:
            return
        logger.info(
            "official_verification_risk_boundary",
            extra={
                "official_verification": {
                    "analysis_id": str(scoped.analysis_id),
                    "rollout_mode": (
                        self._official_verification_rollout.mode.value
                        if self._official_verification_rollout is not None
                        else "direct_coordinator"
                    ),
                    "risk_policy_enforced": self._risk_v3_enforced,
                    "ownership": report.domain_ownership_verification.status.value
                    if report.domain_ownership_verification.status is not None
                    else None,
                    "resource": report.resource_verification.status.value
                    if report.resource_verification.status is not None
                    else None,
                    "action": report.action_endorsement_verification.status.value
                    if report.action_endorsement_verification.status is not None
                    else None,
                    "sender": report.sender_verification.status.value
                    if report.sender_verification.status is not None
                    else None,
                    "verdict": scoped.risk.value if scoped.risk is not None else None,
                    "recommended_actions": [item.value for item in scoped.recommended_actions],
                    "policy_version": scoped.policy_version,
                }
            },
        )

    def _official_verification_may_run(self, scoped: SecurityScopeResponseV4) -> bool:
        """Match the existing coordinator's local applicability without calling it."""
        if self._official_verification_rollout is None and self._official_verification is None:
            return False
        context = scoped.security_context
        return bool(context and (context.claimed_entity or context.urls or context.requested_action))

    @staticmethod
    def _record_tool_observations(observability, scoped: SecurityScopeResponseV4) -> None:
        errors_by_step: dict[tuple[str, str], list[dict[str, object]]] = {}
        for error in scoped.errors:
            errors_by_step.setdefault((error.tool.value, error.target), []).append(
                {
                    "code": error.code,
                    "provider": error.provider,
                    "retryable": error.retryable,
                }
            )
        for step in scoped.investigation_plan:
            with observability.observation(
                f"run-{step.tool.value}",
                as_type="tool",
                input={
                    "reason_code": step.reason_code,
                    "dependency_count": len(step.depends_on),
                },
                metadata={"operation": step.tool.value},
            ) as observation:
                if observation is not None:
                    failed = step.status is SecurityInvestigationStepStatusV4.FAILED
                    observation.update(
                        output={
                            "status": step.status.value,
                            "status_reason": step.status_reason,
                            "step_id": step.step_id,
                            "errors": errors_by_step.get((step.tool.value, step.target), []),
                        },
                        level="ERROR" if failed else "DEFAULT",
                        status_message=step.status_reason if failed else None,
                    )

    @property
    def _risk_v3_enforced(self) -> bool:
        return bool(
            self._official_verification_rollout is not None and self._official_verification_rollout.risk_v3_enforced
        )

    async def _resolve_investigation(self) -> SecurityInvestigationService:
        if self._investigation is not None:
            return self._investigation
        if self._investigation_resolver is None:  # pragma: no cover - constructor invariant
            raise RuntimeError("investigation resolver is unavailable")
        return await self._investigation_resolver()

    async def _resolve_memory_lookup(self) -> SecurityMemoryLookupTool | None:
        if self._memory_lookup is not None:
            return self._memory_lookup
        if self._memory_lookup_resolver is None:
            return None
        return await self._memory_lookup_resolver()

    @staticmethod
    def _complete(scoped: SecurityScopeResponseV4) -> SecurityScopeResponseV4:
        if scoped.status is AnalysisStatus.COMPLETED and scoped.completed_at is not None:
            return scoped
        return scoped.model_copy(
            update={
                "status": AnalysisStatus.COMPLETED,
                "completed_at": datetime.now(UTC),
            }
        )


__all__ = ["SecurityTriagePipeline"]
