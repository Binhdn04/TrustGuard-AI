from __future__ import annotations

import pytest

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


def _brand_payload(domain: str, policy_version: str) -> dict[str, object]:
    return {
        "name": "CP4 Versioned University",
        "aliases": ["CP4 University"],
        "official_domains": [],
        "official_identities": [
            {
                "identity_type": "primary_website",
                "canonical_value": domain,
                "display_value": domain,
                "entity_name": "CP4 Versioned University",
                "provenance": "reviewed CP4 fixture",
                "policy_version": policy_version,
            },
            {
                "identity_type": "social_profile",
                "canonical_value": "https://linkedin.com/company/cp4-university",
                "display_value": "CP4 University LinkedIn",
                "entity_name": "CP4 Versioned University",
                "provenance": "reviewed CP4 fixture",
                "policy_version": policy_version,
            },
        ],
        "official_contacts": [],
        "provenance": "reviewed CP4 fixture",
        "policy_version": policy_version,
        "effective_from": "2026-01-01T00:00:00Z",
    }


@pytest.mark.asyncio
async def test_brand_version_and_disable_require_admin_and_append_audit(client) -> None:
    created = await client.post(
        "/api/v4/admin/brands",
        headers=ADMIN_HEADERS,
        json=_brand_payload("cp4-version-one.example", "brand-registry-v1"),
    )
    assert created.status_code == 201
    initial = created.json()

    version_path = f"/api/v4/admin/brands/{initial['brand_id']}/versions"
    denied_version = await client.post(
        version_path,
        headers=USER_HEADERS,
        json=_brand_payload("cp4-version-two.example", "brand-registry-v2"),
    )
    versioned = await client.post(
        version_path,
        headers=ADMIN_HEADERS,
        json=_brand_payload("cp4-version-two.example", "brand-registry-v2"),
    )

    assert denied_version.status_code == 403
    assert versioned.status_code == 201
    version = versioned.json()
    assert version["brand_id"] != initial["brand_id"]
    assert version["supersedes"] == initial["brand_id"]
    assert all(item["reviewed"] is True for item in version["official_identities"])

    disable_path = f"/api/v4/admin/brands/{version['brand_id']}/disable"
    denied_disable = await client.post(disable_path, headers=USER_HEADERS)
    disabled_response = await client.post(disable_path, headers=ADMIN_HEADERS)

    assert denied_disable.status_code == 403
    assert disabled_response.status_code == 200
    disabled = disabled_response.json()
    assert disabled["brand_id"] != version["brand_id"]
    assert disabled["supersedes"] == version["brand_id"]
    assert disabled["lifecycle"] == "disabled"

    listed = await client.get("/api/v4/admin/brands", headers=ADMIN_HEADERS)
    lineage = [item for item in listed.json() if item["name"] == "CP4 Versioned University"]
    assert len(lineage) == 3
    assert [item["lifecycle"] for item in lineage] == ["active", "active", "disabled"]

    audit = await client.get("/api/v4/admin/audit", headers=ADMIN_HEADERS)
    actions = [
        item["action"]
        for item in audit.json()["items"]
        if item["resource_type"] == "brand"
        and item["resource_id"] in {initial["brand_id"], version["brand_id"], disabled["brand_id"]}
    ]
    assert actions == ["disabled", "superseded", "created"]
