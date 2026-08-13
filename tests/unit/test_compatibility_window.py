from datetime import UTC, datetime, timedelta

from scripts.check_compatibility_window import summarize_compatibility_window


def record(observed_at: datetime, usage: str) -> dict[str, str]:
    return {
        "timestamp": observed_at.isoformat(),
        "event": "http_request_completed",
        "compatibility_usage": usage,
    }


def test_compatibility_window_separates_reviewed_actions_from_legacy() -> None:
    start = datetime(2026, 8, 1, tzinfo=UTC)
    end = start + timedelta(days=7)
    report = summarize_compatibility_window(
        [
            record(start + timedelta(days=1), "security_write"),
            record(start + timedelta(days=2), "reviewed_action_write"),
        ],
        start=start,
        end=end,
        minimum_hours=168,
        require_zero_reads=True,
    )

    assert report["passed"] is True
    assert report["counts"]["reviewed_action_write"] == 1
    assert report["counts"]["legacy_write"] == 0


def test_compatibility_window_fails_on_legacy_usage_or_missing_security_traffic() -> None:
    start = datetime(2026, 8, 1, tzinfo=UTC)
    end = start + timedelta(days=7)
    legacy = summarize_compatibility_window(
        [record(start + timedelta(days=1), "legacy_read")],
        start=start,
        end=end,
        minimum_hours=168,
        require_zero_reads=True,
    )

    assert legacy["passed"] is False
    assert legacy["gates"]["zero_legacy_reads"] is False
    assert legacy["gates"]["security_traffic_observed"] is False
