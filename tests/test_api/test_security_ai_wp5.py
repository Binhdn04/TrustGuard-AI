from __future__ import annotations

import pytest

from src.api.dependencies import get_security_analysis_service
from src.config import Settings
from src.core.errors import PlatformError
from src.main import app
from src.models import ErrorCode
from src.services.security_analysis import SecurityAnalysisService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}


class FakeDurableSecurityRepository:
    def __init__(self) -> None:
        self.records = {}
        self.conversations = {}
        self.idempotency = {}

    async def load_security_idempotent(self, owner_id, key, payload_hash):
        item = self.idempotency.get((owner_id, key))
        if item is None:
            return None
        stored_hash, response = item
        if stored_hash != payload_hash:
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONFLICT,
                message="different payload",
                retryable=False,
            )
        return response

    async def enqueue_security_analysis(self, **values):
        response = values["response"]
        owner_id = values["owner_id"]
        key = (owner_id, values["idempotency_key"])
        existing = self.idempotency.get(key)
        if existing is not None:
            if existing[0] != values["payload_hash"]:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="different payload",
                    retryable=False,
                )
            return existing[1]
        events = values["events"]
        conversation = values["conversation"]
        self.idempotency[key] = (values["payload_hash"], response)
        self.records[response.analysis_id] = (owner_id, response, events)
        self.conversations[conversation.conversation_id] = (owner_id, conversation)
        return response

    async def load_security_analysis(self, analysis_id):
        from uuid import UUID

        return self.records.get(UUID(analysis_id))

    async def load_security_conversation(self, conversation_id):
        from uuid import UUID

        return self.conversations.get(UUID(conversation_id))


@pytest.mark.asyncio
async def test_async_turn_is_accepted_idempotently_with_provisional_event(client, monkeypatch) -> None:
    repository = FakeDurableSecurityRepository()
    analyses = SecurityAnalysisService(repository)
    settings = Settings(
        database_url="postgresql://test:test@localhost/test",
        security_async_execution_enabled=True,
        run_durable_worker=True,
        _env_file=None,
    )

    def override_analyses():
        return analyses

    monkeypatch.setattr("src.api.security_v4.get_settings", lambda: settings)
    app.dependency_overrides[get_security_analysis_service] = override_analyses
    payload = {"message": "Ngân hàng yêu cầu gửi OTP ngay", "execution_mode": "async"}
    try:
        first = await client.post(
            "/api/v4/analyses",
            headers={**USER_HEADERS, "Idempotency-Key": "turn-1"},
            json=payload,
        )
        replay = await client.post(
            "/api/v4/analyses",
            headers={**USER_HEADERS, "Idempotency-Key": "turn-1"},
            json=payload,
        )
        conflict = await client.post(
            "/api/v4/analyses",
            headers={**USER_HEADERS, "Idempotency-Key": "turn-1"},
            json={"message": "Nội dung khác yêu cầu chuyển tiền", "execution_mode": "async"},
        )
        events = await client.get(
            f"/api/v4/analyses/{first.json()['analysis_id']}/events",
            headers=USER_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_security_analysis_service, None)

    assert first.status_code == 202
    assert replay.status_code == 202
    assert replay.json()["analysis_id"] == first.json()["analysis_id"]
    assert conflict.status_code == 409
    assert [item["kind"] for item in events.json()["events"]] == ["status", "provisional"]
    assert events.json()["events"][1]["risk_hint"] == "HIGH_RISK"


@pytest.mark.asyncio
async def test_async_turn_requires_capability_and_idempotency_key(client, monkeypatch) -> None:
    disabled = Settings(_env_file=None)
    monkeypatch.setattr("src.api.security_v4.get_settings", lambda: disabled)
    unavailable = await client.post(
        "/api/v4/analyses",
        headers={**USER_HEADERS, "Idempotency-Key": "turn-disabled"},
        json={"message": "Tin nhắn yêu cầu OTP", "execution_mode": "async"},
    )
    assert unavailable.status_code == 409

    enabled = Settings(
        database_url="postgresql://test:test@localhost/test",
        security_async_execution_enabled=True,
        _env_file=None,
    )
    monkeypatch.setattr("src.api.security_v4.get_settings", lambda: enabled)
    missing_key = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={"message": "Tin nhắn yêu cầu OTP", "execution_mode": "async"},
    )
    assert missing_key.status_code == 422
