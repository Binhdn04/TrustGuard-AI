from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.models import (
    AnalysisStatus,
    SecurityAnalysisEventKindV4,
    SecurityAnalysisEventV4,
    SecurityProgressStateV4,
)
from src.services.security_progress import (
    SecurityProgressMessageCode,
    SecurityProgressStage,
    SecurityProgressUpdate,
)


def event_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "analysis_id": uuid4(),
        "sequence": 1,
        "status": AnalysisStatus.RUNNING,
        "step": "investigation",
        "kind": SecurityAnalysisEventKindV4.PROGRESS,
        "occurred_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    payload.update(overrides)
    return payload


def test_phase1_event_contract_reads_existing_events_without_progress_state() -> None:
    event = SecurityAnalysisEventV4.model_validate(event_payload())

    assert event.progress_state is None


def test_phase1_event_contract_accepts_typed_progress_state_only_for_progress_events() -> None:
    event = SecurityAnalysisEventV4.model_validate(
        event_payload(progress_state=SecurityProgressStateV4.STARTED)
    )

    assert event.progress_state is SecurityProgressStateV4.STARTED

    with pytest.raises(ValidationError, match="only valid for progress events"):
        SecurityAnalysisEventV4.model_validate(
            event_payload(
                kind=SecurityAnalysisEventKindV4.FINAL,
                progress_state=SecurityProgressStateV4.COMPLETED,
            )
        )


def test_phase1_internal_update_accepts_only_matched_allowlisted_values() -> None:
    update = SecurityProgressUpdate(
        stage=SecurityProgressStage.INVESTIGATION,
        state=SecurityProgressStateV4.STARTED,
        message_code=SecurityProgressMessageCode.INVESTIGATION_STARTED,
    )

    assert update.message_code is SecurityProgressMessageCode.INVESTIGATION_STARTED
    assert [item.name for item in fields(SecurityProgressUpdate)] == ["stage", "state", "message_code"]

    with pytest.raises(ValueError, match="does not match"):
        SecurityProgressUpdate(
            stage=SecurityProgressStage.INVESTIGATION,
            state=SecurityProgressStateV4.COMPLETED,
            message_code=SecurityProgressMessageCode.INVESTIGATION_STARTED,
        )
    with pytest.raises(TypeError, match="unexpected keyword"):
        SecurityProgressUpdate(
            stage=SecurityProgressStage.INVESTIGATION,
            state=SecurityProgressStateV4.STARTED,
            message_code=SecurityProgressMessageCode.INVESTIGATION_STARTED,
            raw_provider_content="not allowed",  # type: ignore[call-arg]
        )
