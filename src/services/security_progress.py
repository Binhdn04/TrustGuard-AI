"""Static policy for coarse Security v4 progress instrumentation.

This module intentionally has no delivery or persistence behavior.  It is the
Phase 0 baseline that later reporter and UI work must share.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from src.models.security_v4 import SecurityProgressStateV4


class SecurityProgressStage(StrEnum):
    RUNNING = "running"
    UNDERSTANDING = "understanding"
    SCOPE_GATE = "scope_gate"
    INCIDENT_RESPONSE = "incident_response"
    INVESTIGATION = "investigation"
    OFFICIAL_LINK_VERIFICATION = "official_link_verification"
    SECURITY_MEMORY_LOOKUP = "security_memory_lookup"
    RISK_ASSESSMENT = "risk_assessment"
    ASSISTANT_RESPONSE = "assistant_response"


# This is deliberately a closed, coarse list.  Tool/provider activity remains
# internal to the investigation stage and must never become a progress step.
PROGRESS_STAGE_ALLOWLIST = frozenset(stage.value for stage in SecurityProgressStage)

# Progress emission must stay bounded even if every applicable stage emits a
# start and a terminal update.  A one-second drain protects final commit
# latency; a timeout will drop remaining progress rather than delay the result.
PROGRESS_EVENT_QUEUE_MAXSIZE = 32
PROGRESS_QUIESCE_TIMEOUT_SECONDS = 1.0


class SecurityProgressMessageCode(StrEnum):
    RUNNING_STARTED = "progress.running.started"
    UNDERSTANDING_STARTED = "progress.understanding.started"
    UNDERSTANDING_COMPLETED = "progress.understanding.completed"
    UNDERSTANDING_DEGRADED = "progress.understanding.degraded"
    SCOPE_GATE_COMPLETED = "progress.scope_gate.completed"
    INCIDENT_RESPONSE_STARTED = "progress.incident_response.started"
    INCIDENT_RESPONSE_COMPLETED = "progress.incident_response.completed"
    INVESTIGATION_STARTED = "progress.investigation.started"
    INVESTIGATION_COMPLETED = "progress.investigation.completed"
    INVESTIGATION_SKIPPED = "progress.investigation.skipped"
    INVESTIGATION_DEGRADED = "progress.investigation.degraded"
    OFFICIAL_LINK_VERIFICATION_STARTED = "progress.official_link_verification.started"
    OFFICIAL_LINK_VERIFICATION_COMPLETED = "progress.official_link_verification.completed"
    OFFICIAL_LINK_VERIFICATION_SKIPPED = "progress.official_link_verification.skipped"
    OFFICIAL_LINK_VERIFICATION_DEGRADED = "progress.official_link_verification.degraded"
    SECURITY_MEMORY_LOOKUP_STARTED = "progress.security_memory_lookup.started"
    SECURITY_MEMORY_LOOKUP_COMPLETED = "progress.security_memory_lookup.completed"
    RISK_ASSESSMENT_STARTED = "progress.risk_assessment.started"
    RISK_ASSESSMENT_COMPLETED = "progress.risk_assessment.completed"
    ASSISTANT_RESPONSE_STARTED = "progress.assistant_response.started"
    ASSISTANT_RESPONSE_COMPLETED = "progress.assistant_response.completed"
    ASSISTANT_RESPONSE_DEGRADED = "progress.assistant_response.degraded"


_UPDATE_SPECIFICATIONS = MappingProxyType(
    {
        SecurityProgressMessageCode.RUNNING_STARTED: (
            SecurityProgressStage.RUNNING,
            SecurityProgressStateV4.STARTED,
        ),
        SecurityProgressMessageCode.UNDERSTANDING_STARTED: (
            SecurityProgressStage.UNDERSTANDING,
            SecurityProgressStateV4.STARTED,
        ),
        SecurityProgressMessageCode.UNDERSTANDING_COMPLETED: (
            SecurityProgressStage.UNDERSTANDING,
            SecurityProgressStateV4.COMPLETED,
        ),
        SecurityProgressMessageCode.UNDERSTANDING_DEGRADED: (
            SecurityProgressStage.UNDERSTANDING,
            SecurityProgressStateV4.DEGRADED,
        ),
        SecurityProgressMessageCode.SCOPE_GATE_COMPLETED: (
            SecurityProgressStage.SCOPE_GATE,
            SecurityProgressStateV4.COMPLETED,
        ),
        SecurityProgressMessageCode.INCIDENT_RESPONSE_STARTED: (
            SecurityProgressStage.INCIDENT_RESPONSE,
            SecurityProgressStateV4.STARTED,
        ),
        SecurityProgressMessageCode.INCIDENT_RESPONSE_COMPLETED: (
            SecurityProgressStage.INCIDENT_RESPONSE,
            SecurityProgressStateV4.COMPLETED,
        ),
        SecurityProgressMessageCode.INVESTIGATION_STARTED: (
            SecurityProgressStage.INVESTIGATION,
            SecurityProgressStateV4.STARTED,
        ),
        SecurityProgressMessageCode.INVESTIGATION_COMPLETED: (
            SecurityProgressStage.INVESTIGATION,
            SecurityProgressStateV4.COMPLETED,
        ),
        SecurityProgressMessageCode.INVESTIGATION_SKIPPED: (
            SecurityProgressStage.INVESTIGATION,
            SecurityProgressStateV4.SKIPPED,
        ),
        SecurityProgressMessageCode.INVESTIGATION_DEGRADED: (
            SecurityProgressStage.INVESTIGATION,
            SecurityProgressStateV4.DEGRADED,
        ),
        SecurityProgressMessageCode.OFFICIAL_LINK_VERIFICATION_STARTED: (
            SecurityProgressStage.OFFICIAL_LINK_VERIFICATION,
            SecurityProgressStateV4.STARTED,
        ),
        SecurityProgressMessageCode.OFFICIAL_LINK_VERIFICATION_COMPLETED: (
            SecurityProgressStage.OFFICIAL_LINK_VERIFICATION,
            SecurityProgressStateV4.COMPLETED,
        ),
        SecurityProgressMessageCode.OFFICIAL_LINK_VERIFICATION_SKIPPED: (
            SecurityProgressStage.OFFICIAL_LINK_VERIFICATION,
            SecurityProgressStateV4.SKIPPED,
        ),
        SecurityProgressMessageCode.OFFICIAL_LINK_VERIFICATION_DEGRADED: (
            SecurityProgressStage.OFFICIAL_LINK_VERIFICATION,
            SecurityProgressStateV4.DEGRADED,
        ),
        SecurityProgressMessageCode.SECURITY_MEMORY_LOOKUP_STARTED: (
            SecurityProgressStage.SECURITY_MEMORY_LOOKUP,
            SecurityProgressStateV4.STARTED,
        ),
        SecurityProgressMessageCode.SECURITY_MEMORY_LOOKUP_COMPLETED: (
            SecurityProgressStage.SECURITY_MEMORY_LOOKUP,
            SecurityProgressStateV4.COMPLETED,
        ),
        SecurityProgressMessageCode.RISK_ASSESSMENT_STARTED: (
            SecurityProgressStage.RISK_ASSESSMENT,
            SecurityProgressStateV4.STARTED,
        ),
        SecurityProgressMessageCode.RISK_ASSESSMENT_COMPLETED: (
            SecurityProgressStage.RISK_ASSESSMENT,
            SecurityProgressStateV4.COMPLETED,
        ),
        SecurityProgressMessageCode.ASSISTANT_RESPONSE_STARTED: (
            SecurityProgressStage.ASSISTANT_RESPONSE,
            SecurityProgressStateV4.STARTED,
        ),
        SecurityProgressMessageCode.ASSISTANT_RESPONSE_COMPLETED: (
            SecurityProgressStage.ASSISTANT_RESPONSE,
            SecurityProgressStateV4.COMPLETED,
        ),
        SecurityProgressMessageCode.ASSISTANT_RESPONSE_DEGRADED: (
            SecurityProgressStage.ASSISTANT_RESPONSE,
            SecurityProgressStateV4.DEGRADED,
        ),
    }
)


@dataclass(frozen=True, slots=True)
class SecurityProgressUpdate:
    """Internal-only progress payload with no user or provider content."""

    stage: SecurityProgressStage
    state: SecurityProgressStateV4
    message_code: SecurityProgressMessageCode

    def __post_init__(self) -> None:
        if not isinstance(self.stage, SecurityProgressStage):
            raise TypeError("progress stage must be allowlisted")
        if not isinstance(self.state, SecurityProgressStateV4):
            raise TypeError("progress state must be allowlisted")
        if not isinstance(self.message_code, SecurityProgressMessageCode):
            raise TypeError("progress message code must be allowlisted")
        if _UPDATE_SPECIFICATIONS[self.message_code] != (self.stage, self.state):
            raise ValueError("progress message code does not match stage and state")


__all__ = [
    "PROGRESS_EVENT_QUEUE_MAXSIZE",
    "PROGRESS_QUIESCE_TIMEOUT_SECONDS",
    "PROGRESS_STAGE_ALLOWLIST",
    "SecurityProgressMessageCode",
    "SecurityProgressStage",
    "SecurityProgressUpdate",
]
