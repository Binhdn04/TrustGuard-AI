"""Run one consented Security v4 analysis against a hosted production profile."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any


def _request(
    base_url: str,
    token: str | None,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=body,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode(errors="replace")
        raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc


def validate_security_v4_result(
    result: dict[str, Any],
    *,
    expected_risk: str | None,
) -> dict[str, Any]:
    if result.get("contract_version") != "v4":
        raise ValueError("hosted smoke returned a non-v4 contract")
    if result.get("scope_decision") != "IN_SCOPE":
        raise ValueError(f"hosted smoke was not in scope: {result.get('scope_decision')}")
    if result.get("status") != "completed" or not result.get("terminal"):
        raise ValueError(f"hosted smoke did not complete: {result.get('status')}")
    if expected_risk and result.get("risk") != expected_risk:
        raise ValueError(f"expected risk {expected_risk}, got {result.get('risk')}")

    evidence = result.get("evidence") or []
    evidence_types = {item.get("type") for item in evidence}
    if result.get("tool_calls_used", 0) < 1 or "url_reputation" not in evidence_types:
        raise ValueError("hosted smoke did not produce live URL-reputation evidence")
    evidence_refs = {item.get("evidence_ref") for item in evidence}
    explanation_refs = set(result.get("explanation_evidence_refs") or [])
    if not explanation_refs or not explanation_refs <= evidence_refs:
        raise ValueError("risk explanation is not grounded in returned evidence")
    return {
        "analysis_id": result.get("analysis_id"),
        "status": result.get("status"),
        "scope_decision": result.get("scope_decision"),
        "risk": result.get("risk"),
        "evidence_count": len(evidence),
        "evidence_types": sorted(item for item in evidence_types if item),
        "tool_calls_used": result.get("tool_calls_used"),
        "limitation_count": len(result.get("limitations") or []),
        "error_codes": sorted({item.get("code") for item in result.get("errors") or [] if item.get("code")}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("message", help="A security-risk message containing a public URL")
    parser.add_argument(
        "--base-url",
        default=os.getenv("TRUSTGUARD_BASE_URL", "http://localhost:8000"),
    )
    parser.add_argument("--expect-risk", choices=["SAFE", "LOW_RISK", "SUSPICIOUS", "HIGH_RISK", "MALICIOUS"])
    args = parser.parse_args()
    token = os.getenv("LIVE_SMOKE_TOKEN")
    if not token:
        raise SystemExit("Set LIVE_SMOKE_TOKEN to a production OIDC access token.")

    readiness = _request(args.base_url, None, "GET", "/health/ready")
    if readiness.get("status") != "ready":
        raise SystemExit("API readiness is not ready; inspect the returned dependency checks.")
    capabilities = _request(args.base_url, token, "GET", "/api/v4/capabilities")
    if capabilities.get("product_profile") != "security_triage_vnext":
        raise SystemExit("API does not advertise the Security v4 product profile.")

    result = _request(
        args.base_url,
        token,
        "POST",
        "/api/v4/analyses",
        {
            "message": args.message,
            "consent": {
                "external_url_lookup": True,
            },
        },
    )
    summary = validate_security_v4_result(
        result,
        expected_risk=args.expect_risk,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
