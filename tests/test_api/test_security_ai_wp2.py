from __future__ import annotations

import asyncio

import pytest

from src.api.dependencies import (
    get_security_investigation_service,
    get_security_understanding_service,
)
from src.main import app
from src.models import SecurityRecommendedActionV4
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_understanding import SecuritySemanticUnderstandingService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}


class TimeoutUnderstandingModel:
    async def understand(self, message: str, conversation_summary: str | None):
        await asyncio.sleep(1)
        raise AssertionError("provider timeout did not cancel the call")


class MustNotInvestigate:
    async def investigate(self, request, scope):
        raise AssertionError("incident response must bypass investigation")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("message", "required_action", "exposure"),
    [
        (
            "Ngân hàng yêu cầu OTP và tôi đã gửi OTP 123456 qua "
            "https://alice:password@example.com/login?token=secret#otp",
            SecurityRecommendedActionV4.REVOKE_ACTIVE_SESSIONS,
            "OTP_SHARED",
        ),
        (
            "Ngân hàng yêu cầu chuyển tiền và tôi đã chuyển tiền 2 triệu",
            SecurityRecommendedActionV4.CONTACT_BANK_OR_PAYMENT_PROVIDER,
            "PAYMENT_SENT",
        ),
    ],
)
async def test_incident_recovery_is_immediate_when_understanding_provider_times_out(
    client,
    message: str,
    required_action: SecurityRecommendedActionV4,
    exposure: str,
) -> None:
    service = SecuritySemanticUnderstandingService(
        enabled=True,
        model=TimeoutUnderstandingModel(),
        runtime=SecurityAssistantRuntime(timeout_seconds=0.001, max_retries=0),
    )
    investigation_requested = False

    async def override_understanding():
        return service

    def override_investigation():
        nonlocal investigation_requested
        investigation_requested = True
        return MustNotInvestigate()

    app.dependency_overrides[get_security_understanding_service] = override_understanding
    app.dependency_overrides[get_security_investigation_service] = override_investigation
    try:
        response = await client.post("/api/v4/analyses", headers=USER_HEADERS, json={"message": message})
        body = response.json()
        conversation = await client.get(
            f"/api/v4/conversations/{body['conversation_id']}",
            headers=USER_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_security_understanding_service, None)
        app.dependency_overrides.pop(get_security_investigation_service, None)

    assert response.status_code == 200
    assert body["assistant_context"]["processing_mode"] == "fallback"
    assert body["assistant_context"]["exposure_state"] == exposure
    assert required_action.value in body["recommended_actions"]
    assert "PRESERVE_MESSAGE_FOR_REPORTING" in body["recommended_actions"]
    assert investigation_requested is False
    assert "123456" not in conversation.text
    assert "password" not in conversation.text
    assert "token=secret" not in conversation.text


@pytest.mark.asyncio
async def test_multi_turn_follow_up_changes_with_missing_information(client) -> None:
    service = SecuritySemanticUnderstandingService(
        enabled=True,
        model=None,
        runtime=SecurityAssistantRuntime(max_retries=0),
    )

    async def override_understanding():
        return service

    app.dependency_overrides[get_security_understanding_service] = override_understanding
    try:
        first = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Tôi nhận được tin nhắn lạ"},
        )
        first_body = first.json()
        second = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={
                "message": "Tôi chưa làm gì",
                "conversation_id": first_body["conversation_id"],
                "conversation_version": first_body["conversation_version"],
            },
        )
        conversation = await client.get(
            f"/api/v4/conversations/{first_body['conversation_id']}",
            headers=USER_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_security_understanding_service, None)

    assert first.status_code == 200
    assert first_body["follow_up_slot"] == "action_taken"
    assert second.status_code == 200
    assert second.json()["follow_up_slot"] == "requested_sensitive_action"
    assert second.json()["follow_up_question"] != first_body["follow_up_question"]
    assert conversation.json()["summary"]["assistant_context"]["exposure_state"] == "PRE_ACTION"
    assert conversation.json()["summary"]["unresolved_slots"][0] == "requested_sensitive_action"


@pytest.mark.asyncio
async def test_conversation_never_downgrades_the_highest_exposure(client) -> None:
    service = SecuritySemanticUnderstandingService(
        enabled=True,
        model=None,
        runtime=SecurityAssistantRuntime(max_retries=0),
    )

    async def override_understanding():
        return service

    app.dependency_overrides[get_security_understanding_service] = override_understanding
    try:
        first = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Ngân hàng yêu cầu OTP và tôi đã gửi OTP cho họ"},
        )
        first_body = first.json()
        second = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={
                "message": "Tôi chưa làm gì thêm",
                "conversation_id": first_body["conversation_id"],
                "conversation_version": first_body["conversation_version"],
            },
        )
    finally:
        app.dependency_overrides.pop(get_security_understanding_service, None)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["assistant_context"]["exposure_state"] == "OTP_SHARED"
    assert "REVOKE_ACTIVE_SESSIONS" in second.json()["recommended_actions"]
