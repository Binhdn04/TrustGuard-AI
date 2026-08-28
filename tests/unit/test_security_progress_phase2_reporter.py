from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from src.models import SecurityProgressStateV4
from src.services.security_progress import (
    SecurityProgressMessageCode,
    SecurityProgressReporter,
    SecurityProgressUpdate,
)


class RecordingAppender:
    def __init__(self) -> None:
        self.events = []

    async def __call__(self, event):
        self.events.append(event)
        return event


@pytest.mark.asyncio
async def test_phase2_reporter_delivers_updates_in_enqueue_order() -> None:
    appender = RecordingAppender()
    reporter = SecurityProgressReporter(uuid4(), appender)
    reporter.start()

    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.RUNNING_STARTED))
    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.INVESTIGATION_STARTED))
    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.INVESTIGATION_COMPLETED))
    await reporter.quiesce()

    assert [(event.step, event.progress_state, event.message) for event in appender.events] == [
        ("running", SecurityProgressStateV4.STARTED, "progress.running.started"),
        ("investigation", SecurityProgressStateV4.STARTED, "progress.investigation.started"),
        ("investigation", SecurityProgressStateV4.COMPLETED, "progress.investigation.completed"),
    ]
    assert all(event.evidence_refs == [] and event.risk_hint is None for event in appender.events)


@pytest.mark.asyncio
async def test_phase2_queue_full_drops_progress_without_raising(caplog) -> None:
    appender = RecordingAppender()
    reporter = SecurityProgressReporter(uuid4(), appender, queue_maxsize=1)
    reporter.start()

    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.RUNNING_STARTED))
    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.INVESTIGATION_STARTED))
    await reporter.quiesce()

    assert len(appender.events) == 1
    assert "security_progress_queue_full" in caplog.text


@pytest.mark.asyncio
async def test_phase2_append_error_is_dropped_without_raising(caplog) -> None:
    async def failing_appender(event):
        del event
        raise ConnectionError("event store unavailable")

    reporter = SecurityProgressReporter(uuid4(), failing_appender)
    reporter.start()
    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.RUNNING_STARTED))
    await reporter.quiesce()

    assert "security_progress_append_failed" in caplog.text


@pytest.mark.asyncio
async def test_phase2_quiesce_timeout_drops_pending_progress_and_stops_writer(caplog) -> None:
    append_started = asyncio.Event()
    append_cancelled = asyncio.Event()

    async def blocked_appender(event):
        del event
        append_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            append_cancelled.set()
            raise

    reporter = SecurityProgressReporter(
        uuid4(),
        blocked_appender,
        queue_maxsize=2,
        quiesce_timeout_seconds=0.01,
    )
    reporter.start()
    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.RUNNING_STARTED))
    await append_started.wait()
    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.INVESTIGATION_STARTED))
    await reporter.quiesce()

    assert append_cancelled.is_set()
    assert "security_progress_quiesce_timeout" in caplog.text


@pytest.mark.asyncio
async def test_phase2_quiesce_propagates_cancellation_after_cleaning_up_writer() -> None:
    append_started = asyncio.Event()
    append_cancelled = asyncio.Event()

    async def blocked_appender(event):
        del event
        append_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            append_cancelled.set()
            raise

    reporter = SecurityProgressReporter(uuid4(), blocked_appender)
    reporter.start()
    await reporter.emit(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.RUNNING_STARTED))
    await append_started.wait()
    quiesce = asyncio.create_task(reporter.quiesce())
    await asyncio.sleep(0)
    quiesce.cancel()

    with pytest.raises(asyncio.CancelledError):
        await quiesce
    assert append_cancelled.is_set()
