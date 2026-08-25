import pytest

from src.api.dependencies import get_security_blacklist_admin_service
from src.main import app
from src.services.platform_wave2 import MemoryWave2Repository, Wave2PlatformService
from src.services.security_blacklist import SecurityBlacklistAdminService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


@pytest.mark.asyncio
async def test_security_blacklist_v4_admin_flow_is_proposal_then_review(client) -> None:
    service = SecurityBlacklistAdminService(Wave2PlatformService(MemoryWave2Repository()))
    app.dependency_overrides[get_security_blacklist_admin_service] = lambda: service
    payload = {
        "canonical_domain": "malicious.example",
        "reason": "Reviewed phishing evidence.",
        "evidence_refs": ["evidence:api-reviewed"],
        "provenance": "api-test",
    }
    try:
        denied = await client.post(
            "/api/v4/admin/blacklist/proposals", headers=USER_HEADERS, json=payload
        )
        proposal = await client.post(
            "/api/v4/admin/blacklist/proposals", headers=ADMIN_HEADERS, json=payload
        )
        before = await client.get("/api/v4/admin/blacklist/page", headers=ADMIN_HEADERS)
        decision = await client.post(
            f"/api/v4/admin/blacklist/actions/{proposal.json()['action_id']}/decision",
            headers=ADMIN_HEADERS,
            json={"decision": "approved", "note": "Human reviewer approved execution."},
        )
        blacklist_id = decision.json()["record"]["blacklist_id"]
        detail = await client.get(
            f"/api/v4/admin/blacklist/{blacklist_id}", headers=ADMIN_HEADERS
        )
        audit = await client.get(
            f"/api/v4/admin/blacklist/{blacklist_id}/audit", headers=ADMIN_HEADERS
        )
    finally:
        app.dependency_overrides.pop(get_security_blacklist_admin_service, None)

    assert denied.status_code == 403
    assert proposal.status_code == 201
    assert proposal.json()["status"] == "pending_review"
    assert before.json()["total"] == 0
    assert decision.status_code == 200
    assert decision.json()["status"] == "executed"
    assert detail.json()["lifecycle"] == "active"
    assert audit.json()[0]["evidence_refs"] == ["evidence:api-reviewed"]
