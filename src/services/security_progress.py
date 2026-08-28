"""Static policy for coarse Security v4 progress instrumentation.

This module intentionally has no delivery or persistence behavior.  It is the
Phase 0 baseline that later reporter and UI work must share.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from src.models.security_v4 import (
    AnalysisStatus,
    SecurityAnalysisEventKindV4,
    SecurityAnalysisEventV4,
    SecurityProgressStateV4,
)

logger = logging.getLogger(__name__)

AppendSecurityProgressEvent = Callable[[SecurityAnalysisEventV4], Awaitable[SecurityAnalysisEventV4]]


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

    @classmethod
    def for_message_code(cls, message_code: SecurityProgressMessageCode) -> SecurityProgressUpdate:
        stage, state = _UPDATE_SPECIFICATIONS[message_code]
        return cls(stage=stage, state=state, message_code=message_code)

    def __post_init__(self) -> None:
        if not isinstance(self.stage, SecurityProgressStage):
            raise TypeError("progress stage must be allowlisted")
        if not isinstance(self.state, SecurityProgressStateV4):
            raise TypeError("progress state must be allowlisted")
        if not isinstance(self.message_code, SecurityProgressMessageCode):
            raise TypeError("progress message code must be allowlisted")
        if _UPDATE_SPECIFICATIONS[self.message_code] != (self.stage, self.state):
            raise ValueError("progress message code does not match stage and state")


_STOP = object()


class SecurityProgressReporter:
    """Fail-open, ordered delivery of coarse progress events for one job.

    ``emit`` is intentionally an async compatibility point but only performs
    a non-blocking queue write. Database persistence is isolated in a single
    background task, so a telemetry failure cannot affect the check result.
    """

    def __init__(
        self,
        analysis_id: UUID,
        append_event: AppendSecurityProgressEvent,
        *,
        queue_maxsize: int = PROGRESS_EVENT_QUEUE_MAXSIZE,
        quiesce_timeout_seconds: float = PROGRESS_QUIESCE_TIMEOUT_SECONDS,
    ) -> None:
        if queue_maxsize < 1:
            raise ValueError("progress queue must have positive capacity")
        if quiesce_timeout_seconds <= 0:
            raise ValueError("progress quiesce timeout must be positive")
        self._analysis_id = analysis_id
        self._append_event = append_event
        self._queue: asyncio.Queue[SecurityProgressUpdate | object] = asyncio.Queue(maxsize=queue_maxsize)
        self._quiesce_timeout_seconds = quiesce_timeout_seconds
        self._writer: asyncio.Task[None] | None = None
        self._accepting = False
        self._quiesced = False

    def start(self) -> None:
        if self._writer is not None:
            raise RuntimeError("progress reporter already started")
        self._accepting = True
        self._writer = asyncio.create_task(self._write(), name=f"security-progress-{self._analysis_id}")

    async def emit(self, update: SecurityProgressUpdate) -> None:
        if not self._accepting:
            return
        if not isinstance(update, SecurityProgressUpdate):
            logger.warning("security_progress_invalid_update", extra={"failure_code": "invalid_update"})
            return
        try:
            self._queue.put_nowait(update)
        except asyncio.QueueFull:
            logger.warning("security_progress_queue_full", extra={"failure_code": "queue_full"})

    async def quiesce(self) -> None:
        """Stop intake and boundedly drain; drop rather than delay final commit."""
        if self._quiesced:
            return
        self._accepting = False
        writer = self._writer
        if writer is None:
            self._quiesced = True
            return
        try:
            await asyncio.wait_for(self._queue.join(), timeout=self._quiesce_timeout_seconds)
        except TimeoutError:
            logger.warning("security_progress_quiesce_timeout", extra={"failure_code": "quiesce_timeout"})
            self._discard_pending()
            writer.cancel()
            await asyncio.gather(writer, return_exceptions=True)
        except asyncio.CancelledError:
            self._discard_pending()
            writer.cancel()
            await asyncio.gather(writer, return_exceptions=True)
            raise
        else:
            self._queue.put_nowait(_STOP)
            try:
                await writer
            except Exception as exc:
                logger.warning(
                    "security_progress_writer_failed",
                    extra={"failure_code": type(exc).__name__},
                )
        finally:
            self._quiesced = True

    def _discard_pending(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            else:
                self._queue.task_done()

    async def _write(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                if item is _STOP:
                    return
                assert isinstance(item, SecurityProgressUpdate)
                event = SecurityAnalysisEventV4(
                    analysis_id=self._analysis_id,
                    sequence=1,
                    status=AnalysisStatus.RUNNING,
                    step=item.stage.value,
                    kind=SecurityAnalysisEventKindV4.PROGRESS,
                    progress_state=item.state,
                    step_id=item.stage.value,
                    message=item.message_code.value,
                    occurred_at=datetime.now(UTC),
                )
                try:
                    await self._append_event(event)
                except Exception as exc:
                    logger.warning(
                        "security_progress_append_failed",
                        extra={"failure_code": type(exc).__name__},
                    )
            finally:
                self._queue.task_done()


__all__ = [
    "PROGRESS_EVENT_QUEUE_MAXSIZE",
    "PROGRESS_QUIESCE_TIMEOUT_SECONDS",
    "PROGRESS_STAGE_ALLOWLIST",
    "AppendSecurityProgressEvent",
    "SecurityProgressMessageCode",
    "SecurityProgressReporter",
    "SecurityProgressStage",
    "SecurityProgressUpdate",
]
