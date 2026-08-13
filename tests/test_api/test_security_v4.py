import logging

import pytest

from src.api.dependencies import get_analysis_service, get_security_investigation_service
from src.main import app

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}


@pytest.mark.asyncio
async def test_v4_requires_authentication(client) -> None:
    response = await client.post("/api/v4/analyses", json={"message": "Tôi nhận được tin nhắn lạ"})

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_v4_out_of_scope_is_terminal_and_does_not_resolve_legacy_analysis_service(client) -> None:
    def legacy_service_must_not_be_resolved():
        raise AssertionError("v4 scope route reached the legacy analysis service")

    def investigation_must_not_be_resolved():
        raise AssertionError("terminal scope route resolved the investigation service")

    app.dependency_overrides[get_analysis_service] = legacy_service_must_not_be_resolved
    app.dependency_overrides[get_security_investigation_service] = investigation_must_not_be_resolved
    try:
        response = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Tây Ban Nha vô địch World Cup đúng không?"},
        )
    finally:
        app.dependency_overrides.pop(get_analysis_service, None)
        app.dependency_overrides.pop(get_security_investigation_service, None)

    assert response.status_code == 200
    body = response.json()
    assert body["contract_version"] == "v4"
    assert body["scope_decision"] == "OUT_OF_SCOPE_GENERAL_FACT_CHECK"
    assert body["terminal"] is True
    assert body["next_step"] == "END"
    assert body["security_context"] is None


@pytest.mark.asyncio
async def test_v4_in_scope_returns_context_and_completes_local_investigation(client, caplog) -> None:
    with caplog.at_level(logging.INFO, logger="trustguard.http"):
        response = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={
                "message": "HR yêu cầu tôi đóng 500k phí hồ sơ",
                "consent": {"external_url_lookup": True, "official_source_lookup": False},
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["scope_decision"] == "IN_SCOPE"
    assert body["terminal"] is False
    assert body["next_step"] == "RISK_ASSESSMENT"
    assert body["investigation_status"] == "completed"
    assert [step["tool"] for step in body["investigation_plan"]] == ["security_context_analysis"]
    assert body["evidence"][0]["type"] == "security_context"
    assert body["tool_calls_used"] == 0
    assert body["security_context"]["scenario"] == "recruitment"
    assert body["security_context"]["potential_threat"] == "RECRUITMENT_SCAM"
    assert body["limitations"] == []
    record = next(item for item in caplog.records if item.getMessage() == "http_request_completed")
    assert record.api_contract == "v4"
    assert record.compatibility_usage == "security_write"


@pytest.mark.asyncio
async def test_v4_need_more_info_is_terminal(client) -> None:
    response = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={"message": "Tôi nhận được tin nhắn lạ"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scope_decision"] == "NEED_MORE_INFO"
    assert body["terminal"] is True
    assert body["follow_up_question"].endswith("?")


@pytest.mark.asyncio
async def test_v4_rejects_legacy_or_unknown_request_fields(client) -> None:
    response = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={
            "message": "Kiểm tra example.com",
            "consent_to_scan_urls": True,
            "consent_to_capture_screenshot": True,
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
