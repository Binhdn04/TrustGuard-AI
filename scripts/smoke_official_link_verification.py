"""Run the CP10 hard-case smoke against a real hosted v4 deployment."""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SOCIAL_HOSTS = frozenset({"facebook.com", "instagram.com", "linkedin.com", "x.com", "youtube.com"})
SHORT_HOSTS = frozenset({"bit.ly", "bitly.com", "forms.gle", "aka.ms"})


def _request(base_url: str, token: str | None, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=35) as response:  # noqa: S310
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode(errors="replace")
        raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc
    if not isinstance(result, dict):
        raise ValueError(f"{method} {path} did not return an object")
    return result


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").casefold().removeprefix("www.")


def validate_hard_case(result: dict[str, Any], *, latency_ms: float) -> dict[str, Any]:
    if result.get("contract_version") != "v4" or result.get("scope_decision") != "IN_SCOPE":
        raise ValueError("hard-case smoke did not return an in-scope v4 result")
    report = result.get("official_verification")
    if not isinstance(report, dict) or report.get("overall_status") != "VERIFIED":
        raise ValueError("hard-case smoke did not return a VERIFIED official report")

    sources = report.get("source_refs") or []
    links = report.get("link_refs") or []
    source_refs = {item.get("source_ref") for item in sources}
    link_refs = {item.get("link_ref") for item in links}
    available = source_refs | link_refs
    cited: set[str] = set()
    for name in ("publisher_verification", "claim_verification", "resource_verification"):
        component = report.get(name) or {}
        cited.update(component.get("evidence_refs") or [])
    if not cited <= available or any(item.get("source_ref") not in source_refs for item in links):
        raise ValueError("hard-case official evidence references are not closed")

    social_source = any(
        (item.get("identity") or {}).get("identity_type") == "social_profile"
        or _host(str(item.get("canonical_url") or "")) in SOCIAL_HOSTS
        for item in sources
    )
    short_link = any(_host(str(item.get("display_url") or "")) in SHORT_HOSTS for item in links)
    resource = ((report.get("resource_verification") or {}).get("match") or {}).get("official_resource") or {}
    third_party_form = resource.get("resource_type") in {"google_form", "microsoft_form"}
    match_status = ((report.get("resource_verification") or {}).get("match") or {}).get("status")
    if not social_source or not short_link or not third_party_form or match_status not in {"EXACT_RESOURCE", "EXACT_CANONICAL_URL"}:
        raise ValueError("hard-case social -> short URL -> third-party form chain was not proven")
    if latency_ms > 30_000:
        raise ValueError("hard-case latency exceeded 30 seconds")

    return {
        "analysis_id": result.get("analysis_id"),
        "overall_status": report.get("overall_status"),
        "resource_match_status": match_status,
        "source_ref_count": len(source_refs),
        "link_ref_count": len(link_refs),
        "evidence_reference_closure": True,
        "official_social_source": True,
        "short_url_observed": True,
        "third_party_form_observed": True,
        "derived_organization_count": len((report.get("intent") or {}).get("derived_organization_names") or []),
        "latency_ms": round(latency_ms, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("message", help="Reviewed Vietnamese hard-case message")
    parser.add_argument("--base-url", default=os.getenv("TRUSTGUARD_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--output", help="Optional JSON summary destination")
    args = parser.parse_args()
    token = os.getenv("LIVE_SMOKE_TOKEN")
    if not token:
        raise SystemExit("Set LIVE_SMOKE_TOKEN to a hosted OIDC user access token.")

    readiness = _request(args.base_url, None, "GET", "/health/ready")
    if readiness.get("status") != "ready":
        raise SystemExit("Hosted readiness is not ready.")
    capabilities = _request(args.base_url, token, "GET", "/api/v4/capabilities")
    if capabilities.get("official_link_verification") is not True:
        raise SystemExit("Hosted deployment does not advertise official_link_verification.")

    started = time.perf_counter()
    result = _request(
        args.base_url,
        token,
        "POST",
        "/api/v4/analyses",
        {
            "message": args.message,
            "execution_mode": "inline",
            "consent": {"external_url_lookup": True, "official_source_lookup": True},
        },
    )
    summary = validate_hard_case(result, latency_ms=(time.perf_counter() - started) * 1000)
    summary["official_web_search_ready"] = capabilities.get("official_web_search_ready") is True
    serialized = json.dumps(summary, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
