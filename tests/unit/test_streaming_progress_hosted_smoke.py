from __future__ import annotations

import pytest

from scripts.smoke_streaming_progress import summarize_progress_events


def _event(sequence: int, *, kind: str, status: str, **values: object) -> dict[str, object]:
    return {
        "analysis_id": "analysis-1",
        "sequence": sequence,
        "kind": kind,
        "status": status,
        **values,
    }


def test_hosted_smoke_summary_is_redacted_and_records_coarse_progress() -> None:
    summary = summarize_progress_events(
        [
            _event(1, kind="status", status="queued", step="queued"),
            _event(
                2,
                kind="progress",
                status="running",
                step="understanding",
                progress_state="started",
                message="private",
                occurred_at="2026-08-28T12:00:01Z",
            ),
            _event(
                3,
                kind="progress",
                status="running",
                step="investigation",
                progress_state="completed",
                message="private",
                occurred_at="2026-08-28T12:00:03Z",
            ),
            _event(4, kind="final", status="completed", step="final", message="private"),
        ],
        analysis_id="analysis-1",
    )

    assert summary["event_count"] == 4
    assert summary["first_progress_sequence"] == 2
    assert summary["terminal_event_seen"] is True
    assert summary["stages"] == [
        {"sequence": 2, "step": "understanding", "progress_state": "started"},
        {"sequence": 3, "step": "investigation", "progress_state": "completed", "gap_from_previous_progress_ms": 2000},
    ]
    assert "message" not in str(summary)


@pytest.mark.parametrize(
    ("events", "error"),
    [
        (
            [
                _event(2, kind="status", status="queued", step="queued"),
                _event(1, kind="final", status="completed", step="final"),
            ],
            "increasing",
        ),
        (
            [_event(1, kind="progress", status="running", step="investigation", progress_state="invalid")],
            "progress contract",
        ),
        (
            [
                _event(1, kind="final", status="completed", step="final"),
                _event(2, kind="progress", status="running", step="investigation", progress_state="started"),
            ],
            "after final",
        ),
    ],
)
def test_hosted_smoke_rejects_unsafe_or_malformed_event_sequences(events: list[dict[str, object]], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        summarize_progress_events(events, analysis_id="analysis-1")
