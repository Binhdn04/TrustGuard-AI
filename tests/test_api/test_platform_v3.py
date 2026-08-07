import base64

import pytest

from src.api.dependencies import get_analysis_service
from src.main import app
from src.services.analysis import AnalysisService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


@pytest.fixture
def platform_service_v3():
    service = AnalysisService()
    app.dependency_overrides[get_analysis_service] = lambda: service
    yield service
    app.dependency_overrides.pop(get_analysis_service, None)


@pytest.mark.asyncio
async def test_v3_core_adapter_and_v2_contract_coexist(client, platform_service_v3):
    created = await client.post(
        "/api/v3/analyses",
        headers=USER_HEADERS,
        json={"message": "Kiểm tra https://example.com", "consent_to_scan_urls": True},
    )
    assert created.status_code == 202
    assert created.json()["contract_version"] == "v3"
    analysis_id = created.json()["analysis_id"]

    v3_detail = await client.get(f"/api/v3/analyses/{analysis_id}", headers=USER_HEADERS)
    assert v3_detail.status_code == 200
    assert v3_detail.json()["contract_version"] == "v3"

    v2_detail = await client.get(f"/api/v2/analyses/{analysis_id}", headers=USER_HEADERS)
    assert v2_detail.status_code == 200
    assert v2_detail.json()["contract_version"] == "v2"


@pytest.mark.asyncio
async def test_v3_event_polling_returns_typed_stable_replay(client, platform_service_v3):
    created = await client.post(
        "/api/v3/analyses",
        headers=USER_HEADERS,
        json={"message": "Kiểm tra nội dung", "consent_to_scan_urls": False},
    )
    analysis_id = created.json()["analysis_id"]

    first = await client.get(f"/api/v3/analyses/{analysis_id}/events", headers=USER_HEADERS)
    assert first.status_code == 200
    body = first.json()
    assert body["contract_version"] == "v3"
    assert body["events"][0]["event_type"] == "analysis_status"
    assert body["events"][0]["sequence"] == 1
    assert body["next_cursor"] == base64.urlsafe_b64encode(b"1").decode().rstrip("=")

    replay = await client.get(f"/api/v3/analyses/{analysis_id}/events", headers=USER_HEADERS)
    assert replay.json()["events"][0]["event_id"] == body["events"][0]["event_id"]

    after = await client.get(
        f"/api/v3/analyses/{analysis_id}/events",
        headers=USER_HEADERS,
        params={"cursor": body["next_cursor"]},
    )
    assert after.status_code == 200
    assert after.json()["events"] == []


@pytest.mark.asyncio
async def test_invalid_v3_cursor_uses_error_envelope(client, platform_service_v3):
    created = await client.post(
        "/api/v3/analyses",
        headers=USER_HEADERS,
        json={"message": "Kiểm tra nội dung", "consent_to_scan_urls": False},
    )
    analysis_id = created.json()["analysis_id"]
    response = await client.get(
        f"/api/v3/analyses/{analysis_id}/events",
        headers=USER_HEADERS,
        params={"cursor": "not-a-cursor"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_wave2_contract_routes_enforce_admin_and_fail_explicitly(client, platform_service_v3):
    forbidden = await client.get(
        "/api/v3/admin/metrics",
        headers=USER_HEADERS,
        params={"from": "2026-08-01T00:00:00Z", "to": "2026-08-07T00:00:00Z"},
    )
    assert forbidden.status_code == 403

    planned = await client.get(
        "/api/v3/admin/metrics",
        headers=ADMIN_HEADERS,
        params={"from": "2026-08-01T00:00:00Z", "to": "2026-08-07T00:00:00Z"},
    )
    assert planned.status_code == 501
    assert planned.json()["error"]["message"].endswith("not implemented in Wave 0.")
