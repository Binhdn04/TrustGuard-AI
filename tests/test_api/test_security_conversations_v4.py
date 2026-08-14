import asyncio

import pytest

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


@pytest.mark.asyncio
async def test_create_and_continue_conversation_from_need_more_info(client) -> None:
    first = await client.post("/api/v4/analyses", headers=USER_HEADERS, json={"message": "Tôi nhận được tin nhắn lạ"})
    first_body = first.json()

    second = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={
            "message": "Ngân hàng yêu cầu tôi gửi OTP ngay",
            "conversation_id": first_body["conversation_id"],
            "conversation_version": first_body["conversation_version"],
        },
    )
    conversation = await client.get(f"/api/v4/conversations/{first_body['conversation_id']}", headers=USER_HEADERS)

    assert first.status_code == 200
    assert first_body["scope_decision"] == "NEED_MORE_INFO"
    assert second.status_code == 200
    assert second.json()["conversation_version"] == 2
    assert second.json()["security_context"]["otp_request"] is True
    assert conversation.status_code == 200
    assert conversation.json()["context_version"] == 2
    assert conversation.json()["active_analysis_id"] == second.json()["analysis_id"]
    assert conversation.json()["summary"]["evidence_refs"]


@pytest.mark.asyncio
async def test_conversation_owner_is_enforced_before_context_read(client) -> None:
    created = await client.post("/api/v4/analyses", headers=USER_HEADERS, json={"message": "Tin nhắn yêu cầu OTP"})
    body = created.json()
    denied_get = await client.get(f"/api/v4/conversations/{body['conversation_id']}", headers=ADMIN_HEADERS)
    denied_continue = await client.post(
        "/api/v4/analyses",
        headers=ADMIN_HEADERS,
        json={
            "message": "Họ yêu cầu đăng nhập",
            "conversation_id": body["conversation_id"],
            "conversation_version": body["conversation_version"],
        },
    )

    assert denied_get.status_code == 403
    assert denied_continue.status_code == 403


@pytest.mark.asyncio
async def test_stale_and_concurrent_conversation_updates_conflict(client) -> None:
    created = await client.post("/api/v4/analyses", headers=USER_HEADERS, json={"message": "Tin nhắn yêu cầu OTP"})
    body = created.json()
    payload = {
        "message": "Họ còn yêu cầu đăng nhập",
        "conversation_id": body["conversation_id"],
        "conversation_version": body["conversation_version"],
    }
    results = await asyncio.gather(
        client.post("/api/v4/analyses", headers=USER_HEADERS, json=payload),
        client.post("/api/v4/analyses", headers=USER_HEADERS, json=payload),
    )

    assert sorted(item.status_code for item in results) == [200, 409]
    conflict = next(item for item in results if item.status_code == 409)
    assert conflict.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_unrelated_case_is_not_merged(client) -> None:
    created = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={"message": "Ngân hàng yêu cầu xác minh tài khoản và gửi OTP"},
    )
    body = created.json()
    unrelated = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={
            "message": "HR yêu cầu đóng phí hồ sơ tuyển dụng",
            "conversation_id": body["conversation_id"],
            "conversation_version": body["conversation_version"],
        },
    )

    assert unrelated.status_code == 409
    assert unrelated.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_conversation_summary_redacts_url_secrets_and_does_not_inherit_consent(client) -> None:
    first = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={
            "message": "Ngân hàng yêu cầu tôi gửi OTP",
            "consent": {"official_source_lookup": True},
        },
    )
    body = first.json()
    second = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={
            "message": "Mở https://alice:password@example.com/login?token=secret#otp để đăng nhập",
            "conversation_id": body["conversation_id"],
            "conversation_version": body["conversation_version"],
        },
    )
    conversation = await client.get(f"/api/v4/conversations/{body['conversation_id']}", headers=USER_HEADERS)
    retained_url = conversation.json()["summary"]["security_context"]["urls"][0]

    assert retained_url == "https://example.com/login"
    assert any("consent" in item for item in second.json()["limitations"])
