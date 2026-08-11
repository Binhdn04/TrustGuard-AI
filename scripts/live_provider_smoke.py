"""Run one consented analysis against the configured live API profile."""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request


def _request(base_url: str, token: str, method: str, path: str, payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - operator-supplied API URL
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode(errors="replace")
        raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("message", help="A current claim or public URL selected for the live smoke test")
    parser.add_argument(
        "--base-url",
        default=os.getenv("TRUSTGUARD_BASE_URL", "http://localhost:8000"),
    )
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--screenshot", action="store_true")
    args = parser.parse_args()
    token = os.getenv("LIVE_SMOKE_TOKEN") or os.getenv("DEMO_USER_TOKEN")
    if not token:
        raise SystemExit("Set LIVE_SMOKE_TOKEN (OIDC access token) or DEMO_USER_TOKEN before running the smoke test.")

    capabilities = _request(args.base_url, token, "GET", "/api/v3/capabilities")
    if capabilities.get("profile") != "live":
        missing = [name for name, value in capabilities.get("capabilities", {}).items() if value != "ready"]
        raise SystemExit("API is not using the live profile; unavailable capabilities: " + ", ".join(missing))

    accepted = _request(
        args.base_url,
        token,
        "POST",
        "/api/v3/analyses",
        {
            "message": args.message,
            "consent_to_scan_urls": True,
            "consent_to_capture_screenshot": args.screenshot,
        },
    )
    analysis_id = accepted["analysis_id"]
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        result = _request(args.base_url, token, "GET", f"/api/v3/analyses/{analysis_id}")
        status = result.get("status")
        if status == "completed":
            print(
                json.dumps(
                    {
                        "analysis_id": analysis_id,
                        "status": status,
                        "risk_level": result.get("risk_level"),
                        "verdict": result.get("verdict"),
                        "evidence_count": len(result.get("evidence", [])),
                        "limitation_count": len(result.get("limitations", [])),
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        if status == "failed":
            raise SystemExit(f"Analysis {analysis_id} failed; inspect persisted events and worker logs.")
        time.sleep(1)
    raise SystemExit(f"Analysis {analysis_id} did not finish within {args.timeout:g} seconds.")


if __name__ == "__main__":
    raise SystemExit(main())
