from datetime import UTC, datetime

import pytest

from src.api.dependencies import get_wave2_service
from src.main import app
from src.models import Evidence, EvidenceType, ReviewedAction
from src.services.platform_wave2 import MemoryWave2Repository, Wave2PlatformService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}
NOW = datetime.now(UTC).replace(microsecond=0)


@pytest.fixture
def reviewed_action_platform():
    repository = MemoryWave2Repository()
    service = Wave2PlatformService(repository)
    app.dependency_overrides[get_wave2_service] = lambda: service
    try:
        yield repository
    finally:
        app.dependency_overrides.pop(get_wave2_service, None)


@pytest.mark.asyncio
async def test_reviewed_action_v4_requires_one_approved_transaction(
    client,
    reviewed_action_platform,
) -> None:
    repository = reviewed_action_platform
    evidence = Evidence(
        type=EvidenceType.BLACKLIST,
        source="reviewed-evidence",
        title="Known malicious domain",
        url="https://malicious.example/path?secret=redacted",
        finding="The domain matches reviewed threat intelligence.",
        observed_at=NOW,
    )
    action = await repository.propose_admin_action(
        analysis_id=None,
        campaign_id=None,
        action=ReviewedAction.ADD_TO_BLACKLIST,
        target="https://Malicious.Example/path?token=secret",
        evidence=[evidence],
    )
    assert action.target == "malicious.example"

    response = await client.post(
        f"/api/v4/admin/actions/{action.action_id}/decision",
        headers=ADMIN_HEADERS,
        json={"decision": "approved", "note": "Evidence snapshot reviewed."},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "executed"
    assert response.json()["executed_at"] is not None
    assert len(repository.audit) == 1

    audit = await client.get(
        f"/api/v4/admin/actions/{action.action_id}/audit",
        headers=ADMIN_HEADERS,
    )
    assert audit.status_code == 200
    assert audit.json()[0]["execution_status"] == "executed"

    unauthorized = await client.get("/api/v4/admin/actions", headers=USER_HEADERS)
    assert unauthorized.status_code == 403

    duplicate = await client.post(
        f"/api/v4/admin/actions/{action.action_id}/decision",
        headers=ADMIN_HEADERS,
        json={"decision": "rejected", "note": "Cannot mutate an immutable decision."},
    )
    assert duplicate.status_code == 409
    assert len(repository.audit) == 1
