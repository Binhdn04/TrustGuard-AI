from datetime import UTC, datetime

import pytest

from src.api.dependencies import get_analysis_service
from src.main import app
from src.models import AnalysisResponse, Evidence
from src.services.analysis import AnalysisService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


@pytest.fixture
def platform_service():
    service = AnalysisService()
    app.dependency_overrides[get_analysis_service] = lambda: service
    yield service
    app.dependency_overrides.pop(get_analysis_service, None)


@pytest.mark.asyncio
async def test_analysis_api_requires_auth_and_uses_error_envelope(client, platform_service):
    response = await client.get("/api/v1/analyses")

    assert response.status_code == 403
    assert response.json() == {
        "error": {
            "code": "FORBIDDEN",
            "message": "A valid bearer token is required.",
            "retryable": False,
            "details": {},
        }
    }


@pytest.mark.asyncio
async def test_create_get_list_report_and_poll_events(client, platform_service):
    created = await client.post(
        "/api/v1/analyses",
        headers=USER_HEADERS,
        json={"message": "Kiểm tra https://example.com", "consent_to_scan_urls": True},
    )

    assert created.status_code == 202
    accepted = created.json()
    assert accepted["contract_version"] == "v1"
    assert accepted["status"] == "queued"

    analysis_id = accepted["analysis_id"]
    detail = await client.get(f"/api/v1/analyses/{analysis_id}", headers=USER_HEADERS)
    assert detail.status_code == 200
    assert detail.json()["status"] == "queued"

    listing = await client.get("/api/v1/analyses", headers=USER_HEADERS)
    assert [item["analysis_id"] for item in listing.json()] == [analysis_id]

    events = await client.get(f"/api/v1/analyses/{analysis_id}/events", headers=USER_HEADERS)
    assert events.status_code == 200
    assert events.json()[0]["step"] == "queued"

    report = await client.post(
        f"/api/v1/analyses/{analysis_id}/reports",
        headers=USER_HEADERS,
        json={"reason": "Kết quả cần được kiểm tra lại."},
    )
    assert report.status_code == 201
    assert report.json()["analysis_id"] == analysis_id


@pytest.mark.asyncio
async def test_contract_validation_returns_v1_error_envelope(client, platform_service):
    response = await client.post(
        "/api/v1/analyses",
        headers=USER_HEADERS,
        json={"message": "   ", "consent_to_scan_urls": True},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert response.json()["error"]["retryable"] is False


@pytest.mark.asyncio
async def test_regular_user_cannot_access_admin_queue(client, platform_service):
    response = await client.get("/api/v1/admin/cases", headers=USER_HEADERS)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_admin_can_review_escalated_case(client, platform_service):
    created = await client.post(
        "/api/v1/analyses",
        headers=USER_HEADERS,
        json={"message": "https://phishing.example/login", "consent_to_scan_urls": True},
    )
    accepted = created.json()
    now = datetime.now(UTC)
    result = AnalysisResponse(
        analysis_id=accepted["analysis_id"],
        status="completed",
        input_type="url",
        normalized_urls=["https://phishing.example/login"],
        claims=[],
        risk_score=92,
        risk_level="critical",
        verdict="malicious",
        recommended_action="escalate_for_review",
        confidence=0.95,
        summary="Tên miền có tín hiệu phishing.",
        reasons=["URL yêu cầu thông tin đăng nhập."],
        evidence=[
            Evidence(
                type="domain_reputation",
                source="fixture-provider",
                title="Domain reputation",
                url="https://provider.example/result",
                finding="Tên miền bị đánh dấu độc hại.",
                observed_at=now,
            )
        ],
        limitations=[],
        case_status="pending_review",
        scoring_version="risk-v1",
        created_at=datetime.fromisoformat(accepted["created_at"].replace("Z", "+00:00")),
        completed_at=now,
    )
    await platform_service.persist_result(result.analysis_id, result)

    queue = await client.get("/api/v1/admin/cases", headers=ADMIN_HEADERS)
    assert queue.status_code == 200
    assert queue.json()[0]["analysis_id"] == accepted["analysis_id"]

    decision = await client.post(
        f"/api/v1/admin/cases/{accepted['analysis_id']}/decision",
        headers=ADMIN_HEADERS,
        json={"decision": "approved", "action": "none", "note": "Evidence is sufficient."},
    )
    assert decision.status_code == 200
    assert decision.json()["case_status"] == "approved"

    queue_after = await client.get("/api/v1/admin/cases", headers=ADMIN_HEADERS)
    assert queue_after.json() == []
