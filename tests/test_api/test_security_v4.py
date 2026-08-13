import logging

import pytest

from src.api.dependencies import get_analysis_service, get_security_investigation_service
from src.main import app

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


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
    assert body["terminal"] is True
    assert body["next_step"] == "END"
    assert body["investigation_status"] == "completed"
    assert [step["tool"] for step in body["investigation_plan"]] == [
        "security_context_analysis",
        "brand_match",
        "official_claim_verifier",
    ]
    assert body["evidence"][0]["type"] == "security_context"
    assert body["tool_calls_used"] == 0
    assert body["security_context"]["scenario"] == "recruitment"
    assert body["security_context"]["potential_threat"] == "RECRUITMENT_SCAM"
    assert body["limitations"] == []
    assert body["risk"] == "HIGH_RISK"
    assert body["score"] == 83
    assert body["policy_version"] == "security-risk-v1"
    assert body["threat_type"] == "RECRUITMENT_SCAM"
    assert body["explanation_evidence_refs"] == [body["evidence"][0]["evidence_ref"]]
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


@pytest.mark.asyncio
async def test_v4_persistence_and_event_polling_round_trip(client) -> None:
    created = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={"message": "Ngân hàng giả mạo yêu cầu gửi OTP ngay"},
    )
    analysis_id = created.json()["analysis_id"]

    fetched = await client.get(f"/api/v4/analyses/{analysis_id}", headers=USER_HEADERS)
    events = await client.get(f"/api/v4/analyses/{analysis_id}/events", headers=USER_HEADERS)
    replay = await client.get(
        f"/api/v4/analyses/{analysis_id}/events",
        headers=USER_HEADERS,
        params={"cursor": events.json()["next_cursor"]},
    )
    other_owner = await client.get(f"/api/v4/analyses/{analysis_id}", headers=ADMIN_HEADERS)
    ticket = await client.post(
        "/api/v4/ws-tickets", headers=USER_HEADERS, json={"analysis_id": analysis_id}
    )

    assert fetched.status_code == 200
    assert fetched.json() == created.json()
    assert [item["status"] for item in events.json()["events"]] == ["queued", "running", "completed"]
    assert replay.json()["events"] == []
    assert other_owner.status_code == 403
    assert ticket.status_code == 201
    assert ticket.json()["stream_path"].endswith(f"/{analysis_id}/stream")


@pytest.mark.asyncio
async def test_v4_failed_lifecycle_is_persisted(client) -> None:
    class FailingInvestigation:
        async def investigate(self, request, scoped):
            del request, scoped
            raise RuntimeError("fixture failure")

    app.dependency_overrides[get_security_investigation_service] = FailingInvestigation
    try:
        failed = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "HR yêu cầu đóng phí hồ sơ"},
        )
    finally:
        app.dependency_overrides.pop(get_security_investigation_service, None)

    assert failed.status_code == 500
    analysis_id = failed.json()["error"]["details"]["analysis_id"]
    fetched = await client.get(f"/api/v4/analyses/{analysis_id}", headers=USER_HEADERS)
    events = await client.get(f"/api/v4/analyses/{analysis_id}/events", headers=USER_HEADERS)
    assert fetched.json()["status"] == "failed"
    assert [item["status"] for item in events.json()["events"]] == ["queued", "running", "failed"]


@pytest.mark.asyncio
async def test_v4_trust_registry_mutations_require_admin(client) -> None:
    brand = {
        "name": "WP4 Test Brand",
        "aliases": ["WP4 Brand"],
        "official_domains": ["wp4-test.example"],
        "official_contacts": ["security@wp4-test.example"],
        "provenance": "reviewed fixture",
        "effective_from": "2026-01-01T00:00:00Z",
    }
    denied_brand = await client.post("/api/v4/admin/brands", headers=USER_HEADERS, json=brand)
    denied_whitelist = await client.post(
        "/api/v4/admin/whitelist",
        headers=USER_HEADERS,
        json={
            "indicator": "wp4-test.example",
            "scope": "domain",
            "provenance": "reviewed fixture",
            "effective_from": "2026-01-01T00:00:00Z",
        },
    )
    created = await client.post("/api/v4/admin/brands", headers=ADMIN_HEADERS, json=brand)
    disabled = await client.post(
        f"/api/v4/admin/brands/{created.json()['brand_id']}/disable", headers=ADMIN_HEADERS
    )

    assert denied_brand.status_code == 403
    assert denied_whitelist.status_code == 403
    assert created.status_code == 201
    assert disabled.json()["lifecycle"] == "disabled"


@pytest.mark.asyncio
async def test_v4_owner_history_report_and_appeal_round_trip(client) -> None:
    created = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={"message": "Ngân hàng yêu cầu gửi OTP"},
    )
    analysis_id = created.json()["analysis_id"]

    history = await client.get("/api/v4/analyses", headers=USER_HEADERS)
    report = await client.post(
        f"/api/v4/analyses/{analysis_id}/reports",
        headers=USER_HEADERS,
        json={"reason": "Cần xem lại bằng chứng"},
    )
    appeal = await client.post(
        f"/api/v4/analyses/{analysis_id}/appeals",
        headers=USER_HEADERS,
        json={"reason": "Kết luận có thể chưa phù hợp"},
    )
    reports = await client.get(f"/api/v4/analyses/{analysis_id}/reports", headers=USER_HEADERS)
    appeals = await client.get(f"/api/v4/analyses/{analysis_id}/appeals", headers=USER_HEADERS)
    denied = await client.get(f"/api/v4/analyses/{analysis_id}/reports", headers=ADMIN_HEADERS)

    assert any(item["analysis_id"] == analysis_id for item in history.json())
    assert report.status_code == 201
    assert report.json()["contract_version"] == "v4"
    assert reports.json()[0]["report_id"] == report.json()["report_id"]
    assert appeal.status_code == 201
    assert appeals.json()[0]["appeal_id"] == appeal.json()["appeal_id"]
    assert denied.status_code == 403
