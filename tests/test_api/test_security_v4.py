import logging

import pytest

from src.api.dependencies import (
    get_security_investigation_service,
    get_security_memory_service,
    get_wave2_service,
)
from src.main import app
from src.services.platform_wave2 import MemoryWave2Repository, Wave2PlatformService
from src.services.security_memory import SecurityMemoryService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


@pytest.mark.asyncio
async def test_v4_requires_authentication(client) -> None:
    response = await client.post("/api/v4/analyses", json={"message": "Tôi nhận được tin nhắn lạ"})

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_v4_out_of_scope_is_terminal_without_resolving_investigation(client) -> None:
    def investigation_must_not_be_resolved():
        raise AssertionError("terminal scope route resolved the investigation service")

    app.dependency_overrides[get_security_investigation_service] = investigation_must_not_be_resolved
    try:
        response = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Tây Ban Nha vô địch World Cup đúng không?"},
        )
    finally:
        app.dependency_overrides.pop(get_security_investigation_service, None)

    assert response.status_code == 200
    body = response.json()
    assert body["contract_version"] == "v4"
    assert body["scope_decision"] == "OUT_OF_SCOPE_GENERAL_FACT_CHECK"
    assert body["terminal"] is True
    assert body["next_step"] == "END"
    assert body["security_context"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("message", ["Xin chào", "Bạn là ai?"])
async def test_v4_chat_answers_basic_local_intents_without_ai_provider(client, message: str) -> None:
    response = await client.post(
        "/api/v4/chat",
        headers=USER_HEADERS,
        json={"message": message},
    )

    assert response.status_code == 200
    assert response.json()["route"] == "conversation"
    assert "TrustGuard" in response.json()["response"]


@pytest.mark.asyncio
async def test_v4_in_scope_returns_context_and_completes_local_investigation(client, caplog) -> None:
    with caplog.at_level(logging.INFO, logger="trustguard.http"):
        response = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={
                "message": "HR yêu cầu tôi đóng 500k phí hồ sơ",
                "consent": {"external_url_lookup": True},
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
    ]
    assert body["evidence"][0]["type"] == "security_context"
    assert body["tool_calls_used"] == 0
    assert body["security_context"]["scenario"] == "recruitment"
    assert body["security_context"]["potential_threat"] == "RECRUITMENT_SCAM"
    assert body["limitations"] == ["AI semantic understanding không khả dụng; kết quả chỉ dùng rule cục bộ."]
    assert body["risk"] == "INSUFFICIENT_EVIDENCE"
    assert body["score"] == 0
    assert body["policy_version"] == "security-risk-v7"
    assert body["threat_type"] == "RECRUITMENT_SCAM"
    assert body["explanation_evidence_refs"] == [body["evidence"][0]["evidence_ref"]]
    record = next(item for item in caplog.records if item.getMessage() == "http_request_completed")
    assert record.api_contract == "v4"
    assert not hasattr(record, "compatibility_usage")


@pytest.mark.asyncio
async def test_v4_unavailable_semantic_grounding_does_not_produce_admin_review_action(client) -> None:
    repository = MemoryWave2Repository()
    wave2 = Wave2PlatformService(repository)
    app.dependency_overrides[get_wave2_service] = lambda: wave2
    try:
        response = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Đăng nhập https://hitl.example/login và gửi mật khẩu ngay"},
        )
        queue = await client.get("/api/v4/admin/actions", headers=ADMIN_HEADERS)
    finally:
        app.dependency_overrides.pop(get_wave2_service, None)

    assert response.status_code == 200
    assert response.json()["risk"] == "INSUFFICIENT_EVIDENCE"
    assert queue.status_code == 200
    assert queue.json()["total"] == 0


@pytest.mark.asyncio
async def test_v4_security_memory_admin_correction_remains_owner_scoped(client) -> None:
    memory = SecurityMemoryService()
    app.dependency_overrides[get_security_memory_service] = lambda: memory
    try:
        created = []
        for suffix in ("login", "verify", "account"):
            response = await client.post(
                "/api/v4/analyses",
                headers=USER_HEADERS,
                json={
                    "message": (f"ACME gửi https://campaign.example/{suffix} yêu cầu đăng nhập và gửi mật khẩu ngay")
                },
            )
            assert response.status_code == 200
            created.append(response.json())

        forbidden = await client.get("/api/v4/admin/security-memory", headers=USER_HEADERS)
        records = await client.get("/api/v4/admin/security-memory", headers=ADMIN_HEADERS)
        campaigns = await client.get("/api/v4/admin/security-campaigns", headers=ADMIN_HEADERS)
        memory_id = records.json()[0]["memory_id"]
        correction = await client.post(
            f"/api/v4/admin/security-memory/{memory_id}/corrections",
            headers=ADMIN_HEADERS,
            json={"verdict": "false_positive", "note": "Verified test infrastructure."},
        )
        memory_audit = await client.get(f"/api/v4/admin/security-memory/{memory_id}/audit", headers=ADMIN_HEADERS)
    finally:
        app.dependency_overrides.pop(get_security_memory_service, None)

    assert forbidden.status_code == 403
    assert records.status_code == 200
    assert {item["analysis_id"] for item in records.json()} == {item["analysis_id"] for item in created}
    assert all("message" not in item for item in records.json())
    assert campaigns.status_code == 200
    assert campaigns.json() == []
    assert correction.json()["admin_verdict"] == "false_positive"
    assert [item["verdict"] for item in memory_audit.json()] == ["false_positive"]


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
            "unsupported_legacy_option": True,
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
    ticket = await client.post("/api/v4/ws-tickets", headers=USER_HEADERS, json={"analysis_id": analysis_id})

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
    assert failed.json()["error"] == {
        "code": "INTERNAL_ERROR",
        "message": "Security analysis failed.",
        "retryable": True,
        "details": {},
    }


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
    disabled = await client.post(f"/api/v4/admin/brands/{created.json()['brand_id']}/disable", headers=ADMIN_HEADERS)

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
