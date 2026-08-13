"""Verify a bounded zero-legacy-usage window from structured HTTP JSON logs."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

USAGE_DIMENSIONS = (
    "legacy_read",
    "legacy_write",
    "security_read",
    "security_write",
    "reviewed_action_read",
    "reviewed_action_write",
)


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("compatibility window timestamps must include a UTC offset")
    return parsed.astimezone(UTC)


def load_records(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for value in paths:
        path = Path(value)
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} is not valid JSON") from exc
            if item.get("event") == "http_request_completed" and item.get("compatibility_usage"):
                records.append(item)
    return records


def summarize_compatibility_window(
    records: Iterable[dict[str, Any]],
    *,
    start: datetime,
    end: datetime,
    minimum_hours: float,
    require_zero_reads: bool,
) -> dict[str, Any]:
    start = start.astimezone(UTC)
    end = end.astimezone(UTC)
    duration_hours = (end - start).total_seconds() / 3600
    if duration_hours <= 0:
        raise ValueError("compatibility window end must be after start")
    counts: Counter[str] = Counter()
    for item in records:
        usage = item.get("compatibility_usage")
        if usage not in USAGE_DIMENSIONS:
            raise ValueError(f"unknown compatibility_usage: {usage}")
        observed_at = _timestamp(str(item.get("timestamp", "")))
        if start <= observed_at <= end:
            counts[usage] += 1
    normalized = {name: counts[name] for name in USAGE_DIMENSIONS}
    gates = {
        "minimum_window": duration_hours >= minimum_hours,
        "zero_legacy_writes": normalized["legacy_write"] == 0,
        "security_traffic_observed": (
            normalized["security_read"] + normalized["security_write"]
        )
        > 0,
    }
    if require_zero_reads:
        gates["zero_legacy_reads"] = normalized["legacy_read"] == 0
    return {
        "profile": "structured_http_compatibility_window_v1",
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "duration_hours": round(duration_hours, 3),
        "counts": normalized,
        "gates": gates,
        "passed": all(gates.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", help="Structured JSONL application log exports")
    parser.add_argument("--window-start", required=True, help="Inclusive ISO-8601 timestamp")
    parser.add_argument("--window-end", required=True, help="Inclusive ISO-8601 timestamp")
    parser.add_argument("--minimum-hours", type=float, default=168)
    parser.add_argument("--require-zero-legacy-reads", action="store_true")
    parser.add_argument("--output", help="Optional JSON evidence destination")
    args = parser.parse_args()
    report = summarize_compatibility_window(
        load_records(args.logs),
        start=_timestamp(args.window_start),
        end=_timestamp(args.window_end),
        minimum_hours=args.minimum_hours,
        require_zero_reads=args.require_zero_legacy_reads,
    )
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
