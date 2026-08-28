"""Collect redacted hosted evidence for async Security v4 progress streaming.

This script is deliberately an operator-run release gate.  It does not enable
async execution, alter deployment configuration, or print access tokens,
messages, URLs, event messages, or final-analysis payloads.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

_TERMINAL_STATUSES = frozenset({"completed", "failed"})
_PROGRESS_STATES = frozenset({"started", "completed", "skipped", "degraded"})


class SmokeRequestError(RuntimeError):
    """An HTTP request failed without exposing its response body in evidence."""


def _request(
    base_url: str,
    token: str | None,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], int]:
    headers = {"Accept": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method, headers=headers)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - operator-controlled host
            body = json.load(response)
            return response.status, _object(body, method, path), _elapsed_ms(started)
    except urllib.error.HTTPError as exc:
        # Do not include a potentially sensitive error body in terminal output or evidence.
        return exc.code, {}, _elapsed_ms(started)
    except urllib.error.URLError as exc:
        raise SmokeRequestError(f"{method} {path} could not reach the hosted service") from exc


def _object(value: Any, method: str, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SmokeRequestError(f"{method} {path} returned a non-object JSON response")
    return value


def _elapsed_ms(started: float) -> int:
    return round((time.perf_counter() - started) * 1000)


def _cursor_path(analysis_id: str, cursor: str | None) -> str:
    query = urllib.parse.urlencode({"cursor": cursor}) if cursor else ""
    suffix = f"?{query}" if query else ""
    return f"/api/v4/analyses/{analysis_id}/events{suffix}"


def summarize_progress_events(
    events: Iterable[dict[str, Any]], *, analysis_id: str
) -> dict[str, Any]:
    """Validate and redact a cursor-replayed event sequence for release evidence."""
    sequence: list[int] = []
    stages: list[dict[str, Any]] = []
    payload_bytes = 0
    terminal_seen = False
    first_progress_sequence: int | None = None
    previous_progress_at: datetime | None = None

    for event in events:
        if event.get("analysis_id") != analysis_id:
            raise ValueError("event replay included a different analysis")
        item_sequence = event.get("sequence")
        if not isinstance(item_sequence, int) or item_sequence < 1:
            raise ValueError("event replay has an invalid sequence")
        if sequence and item_sequence <= sequence[-1]:
            raise ValueError("event replay is not strictly increasing")
        if terminal_seen:
            raise ValueError("progress or status event arrived after final event")
        sequence.append(item_sequence)
        payload_bytes += len(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode())

        kind = event.get("kind")
        status = event.get("status")
        if kind == "progress":
            state = event.get("progress_state")
            step = event.get("step")
            if not isinstance(step, str) or state not in _PROGRESS_STATES:
                raise ValueError("progress event does not use the optional progress contract correctly")
            first_progress_sequence = first_progress_sequence or item_sequence
            occurred_at = _event_time(event)
            stage = {"sequence": item_sequence, "step": step, "progress_state": state}
            if occurred_at is not None and previous_progress_at is not None:
                stage["gap_from_previous_progress_ms"] = round((occurred_at - previous_progress_at).total_seconds() * 1000)
            stages.append(stage)
            previous_progress_at = occurred_at or previous_progress_at
        if kind == "final":
            if status not in _TERMINAL_STATUSES:
                raise ValueError("final event is not terminal")
            terminal_seen = True

    summary = {
        "event_count": len(sequence),
        "event_payload_bytes": payload_bytes,
        "first_progress_sequence": first_progress_sequence,
        "terminal_event_seen": terminal_seen,
        "stages": stages,
    }
    return summary


def _event_time(event: dict[str, Any]) -> datetime | None:
    value = event.get("occurred_at")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("event replay has an invalid occurred_at timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("event replay has an invalid occurred_at timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("event replay has an invalid occurred_at timestamp")
    return parsed


async def _consume_ticket_once(websocket_url: str) -> list[dict[str, Any]]:
    try:
        from websockets.asyncio.client import connect
    except ImportError as exc:  # pragma: no cover - exercised only in stripped operator environments
        raise SmokeRequestError("websockets client is required; run this via uv run") from exc

    received: list[dict[str, Any]] = []
    try:
        async with connect(websocket_url, open_timeout=15, close_timeout=10) as websocket:
            async for raw_event in websocket:
                value = json.loads(raw_event)
                if not isinstance(value, dict):
                    raise SmokeRequestError("WebSocket sent a non-object event")
                received.append(value)
    except Exception as exc:
        # A clean terminal close is handled by the websocket client.  Other failures are evidence failures.
        if exc.__class__.__name__ == "ConnectionClosedOK":
            return received
        raise SmokeRequestError("WebSocket stream failed before terminal completion") from exc
    return received


def _websocket_url(base_url: str, stream_path: str, ticket: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    query = urllib.parse.urlencode({"ticket": ticket})
    return urllib.parse.urlunsplit((scheme, parsed.netloc, stream_path, query, ""))


def _ticket(base_url: str, token: str, analysis_id: str) -> tuple[str, str]:
    status, body, _ = _request(base_url, token, "POST", "/api/v4/ws-tickets", {"analysis_id": analysis_id})
    if status != 201 or body.get("analysis_id") != analysis_id:
        raise SmokeRequestError("could not issue an analysis-bound WebSocket ticket")
    ticket = body.get("ticket")
    stream_path = body.get("stream_path")
    if not isinstance(ticket, str) or not isinstance(stream_path, str):
        raise SmokeRequestError("WebSocket ticket response is malformed")
    return ticket, stream_path


async def run_smoke(*, base_url: str, token: str, other_owner_token: str, message: str, timeout_seconds: int) -> dict[str, Any]:
    ready_status, readiness, _ = _request(base_url, None, "GET", "/health/ready")
    if ready_status != 200 or readiness.get("status") != "ready":
        raise SmokeRequestError("hosted readiness is not ready")
    capability_status, capabilities, _ = _request(base_url, token, "GET", "/api/v4/capabilities")
    if capability_status != 200 or capabilities.get("security_async_execution") is not True:
        raise SmokeRequestError("hosted deployment does not advertise async Security v4 capability")

    started = time.perf_counter()
    accepted_status, accepted, _ = _request(
        base_url,
        token,
        "POST",
        "/api/v4/analyses",
        {"message": message, "execution_mode": "async", "consent": {"external_url_lookup": False}},
        {"Idempotency-Key": f"streaming-smoke-{uuid4()}"},
    )
    if accepted_status != 202 or not isinstance(accepted.get("analysis_id"), str):
        raise SmokeRequestError("async analysis was not accepted with HTTP 202")
    analysis_id = accepted["analysis_id"]

    forbidden_status, _, _ = _request(base_url, other_owner_token, "GET", f"/api/v4/analyses/{analysis_id}")
    if forbidden_status != 403:
        raise SmokeRequestError("owner isolation check did not return HTTP 403")

    first_ticket, stream_path = _ticket(base_url, token, analysis_id)
    websocket_task = asyncio.create_task(_consume_ticket_once(_websocket_url(base_url, stream_path, first_ticket)))

    cursor: str | None = None
    replayed: list[dict[str, Any]] = []
    first_progress_observed_ms: int | None = None
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        status, page, _ = _request(base_url, token, "GET", _cursor_path(analysis_id, cursor))
        if status != 200 or not isinstance(page.get("events"), list):
            raise SmokeRequestError("owner-scoped cursor polling did not return an event page")
        events = page["events"]
        if any(not isinstance(event, dict) for event in events):
            raise SmokeRequestError("cursor polling returned a malformed event")
        replayed.extend(events)
        if first_progress_observed_ms is None and any(event.get("kind") == "progress" for event in events):
            first_progress_observed_ms = _elapsed_ms(started)
        next_cursor = page.get("next_cursor")
        if next_cursor is not None and not isinstance(next_cursor, str):
            raise SmokeRequestError("cursor polling returned a malformed cursor")
        cursor = next_cursor
        if any(event.get("kind") == "final" for event in replayed):
            break
        await asyncio.sleep(0.25)
    else:
        websocket_task.cancel()
        with suppress(asyncio.CancelledError):
            await websocket_task
        raise SmokeRequestError("async analysis did not reach a final event before timeout")

    websocket_events = await asyncio.wait_for(websocket_task, timeout=timeout_seconds)
    # The ticket was consumed by the first connection and must reject a second connection.
    try:
        await asyncio.wait_for(
            _consume_ticket_once(_websocket_url(base_url, stream_path, first_ticket)), timeout=15
        )
    except SmokeRequestError:
        ticket_single_use = True
    else:
        raise SmokeRequestError("WebSocket ticket was accepted more than once")

    # A fresh ticket provides the reconnect path.  Cursor replay remains authoritative if Redis/WS is unavailable.
    reconnect_ticket, reconnect_path = _ticket(base_url, token, analysis_id)
    reconnect_events = await asyncio.wait_for(
        _consume_ticket_once(_websocket_url(base_url, reconnect_path, reconnect_ticket)), timeout=timeout_seconds
    )

    final_status, final_analysis, _ = _request(base_url, token, "GET", f"/api/v4/analyses/{analysis_id}")
    if final_status != 200 or final_analysis.get("analysis_id") != analysis_id or not final_analysis.get("terminal"):
        raise SmokeRequestError("authoritative final analysis fetch did not complete")

    summary = summarize_progress_events(replayed, analysis_id=analysis_id)
    summary.update(
        {
            "analysis_id": analysis_id,
            "readiness": "ready",
            "async_capability": True,
            "owner_isolation_status": forbidden_status,
            "ticket_single_use": ticket_single_use,
            "websocket_event_count": len(websocket_events),
            "reconnect_event_count": len(reconnect_events),
            "cursor_polling_event_count": len(replayed),
            "time_to_first_progress_observed_ms": first_progress_observed_ms,
            "time_to_final_ms": _elapsed_ms(started),
        }
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("message", help="Reviewed non-sensitive in-scope security message; never printed")
    parser.add_argument("--base-url", default=os.getenv("TRUSTGUARD_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--output", required=True, help="Write sanitized JSON evidence here")
    args = parser.parse_args()
    if args.timeout_seconds < 10:
        raise SystemExit("--timeout-seconds must be at least 10")
    if not (token := os.getenv("LIVE_SMOKE_TOKEN")) or not (other := os.getenv("LIVE_SMOKE_OTHER_OWNER_TOKEN")):
        raise SystemExit("Set LIVE_SMOKE_TOKEN and LIVE_SMOKE_OTHER_OWNER_TOKEN to separate hosted OIDC user tokens.")
    summary = asyncio.run(
        run_smoke(
            base_url=args.base_url,
            token=token,
            other_owner_token=other,
            message=args.message,
            timeout_seconds=args.timeout_seconds,
        )
    )
    serialized = json.dumps(summary, ensure_ascii=False, indent=2) + "\n"
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
