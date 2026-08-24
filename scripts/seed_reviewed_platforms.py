#!/usr/bin/env python3
"""Plan or apply reviewed platform brand versions through audited Security v4 admin APIs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "resources/security/reviewed_platforms.v1.json"


def _request(base_url: str, token: str, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(
        f"{base_url.rstrip('/')}/api/v4{path}",
        data=body,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=15) as response:  # noqa: S310 - operator-supplied admin endpoint
            return json.load(response)
    except HTTPError as exc:
        raise RuntimeError(f"admin API returned HTTP {exc.code}: {exc.read().decode(errors='replace')}") from exc


def _payload(manifest: dict[str, Any], brand: dict[str, Any]) -> dict[str, Any]:
    effective_from = manifest["effective_from"]
    policy_version = manifest["policy_version"]
    identities = [
        {
            "identity_type": "domain",
            "canonical_value": service["domain"],
            "display_value": service["domain"],
            "entity_name": service["name"],
            "match_scope": "host_and_subdomains",
            "relationship": "platform_service",
            "provenance": service["provenance"],
            "policy_version": policy_version,
            "effective_from": effective_from,
            "reviewed": True,
        }
        for service in brand["platform_services"]
    ]
    return {
        "name": brand["name"],
        "aliases": brand["aliases"],
        "official_domains": [brand["primary_domain"]],
        "official_identities": identities,
        "official_contacts": [],
        "provenance": brand["provenance"],
        "policy_version": policy_version,
        "effective_from": effective_from,
    }


def _comparable(record: dict[str, Any]) -> dict[str, Any]:
    identities = sorted(
        (
            item["identity_type"],
            item["canonical_value"],
            item["entity_name"],
            item["relationship"],
            item["policy_version"],
            item["provenance"],
            item.get("match_scope", "host_and_subdomains"),
        )
        for item in record.get("official_identities", [])
    )
    return {
        "name": record["name"],
        "aliases": sorted(record.get("aliases", [])),
        "official_domains": sorted(record.get("official_domains", [])),
        "official_identities": identities,
        "provenance": record["provenance"],
        "policy_version": record["policy_version"],
        "effective_from": record["effective_from"].replace("+00:00", "Z"),
    }


def _merge_existing(payload: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    merged = dict(payload)
    merged["aliases"] = list(dict.fromkeys([*current.get("aliases", []), *payload["aliases"]]))
    merged["official_domains"] = list(
        dict.fromkeys([*current.get("official_domains", []), *payload["official_domains"]])
    )
    identities = {
        (item["identity_type"], item["canonical_value"].casefold(), item["relationship"]): item
        for item in current.get("official_identities", [])
    }
    identities.update(
        {
            (item["identity_type"], item["canonical_value"].casefold(), item["relationship"]): item
            for item in payload["official_identities"]
        }
    )
    merged["official_identities"] = list(identities.values())
    merged["official_contacts"] = current.get("official_contacts", [])
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", default=os.getenv("TRUSTGUARD_ADMIN_TOKEN", ""))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--apply", action="store_true", help="Perform audited create/version API calls")
    args = parser.parse_args()
    if not args.token:
        parser.error("--token or TRUSTGUARD_ADMIN_TOKEN is required")

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    existing = _request(args.base_url, args.token, "GET", "/admin/brands")
    superseded_ids = {item["supersedes"] for item in existing if item.get("supersedes")}
    current_versions = [
        item
        for item in existing
        if item.get("lifecycle") == "active" and item.get("brand_id") not in superseded_ids
    ]
    active_by_name = {
        item["name"].casefold(): item
        for item in sorted(current_versions, key=lambda record: record["effective_from"])
    }
    changes = 0
    for brand in manifest["brands"]:
        payload = _payload(manifest, brand)
        current = active_by_name.get(brand["name"].casefold())
        if current is not None:
            payload = _merge_existing(payload, current)
        if current is not None and _comparable(current) == _comparable(payload):
            print(f"UNCHANGED {brand['name']}")
            continue
        action = "CREATE" if current is None else "SUPERSEDE"
        print(f"{action} {brand['name']}")
        changes += 1
        if args.apply:
            path = "/admin/brands" if current is None else f"/admin/brands/{current['brand_id']}/versions"
            created = _request(args.base_url, args.token, "POST", path, payload)
            print(f"APPLIED {created['name']} version={created['brand_id']}")
    print(f"mode={'apply' if args.apply else 'dry-run'} changes={changes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
