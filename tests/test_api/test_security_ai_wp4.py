from __future__ import annotations

import pytest

from src.api.dependencies import get_grounded_security_response_service
from src.main import app
from src.security_ai.contracts import AssistantSynthesis, ModelResponse, SynthesisReason
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_response import GroundedSecurityResponseService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}


@pytest.mark.asyncio
async def test_v4_completed_result_returns_and_persists_policy_grounded_assistant_response(client) -> None:
    created = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={"message": "HR yêu cầu tôi đóng 500k phí hồ sơ"},
    )

    assert created.status_code == 200
    body = created.json()
    assistant = body["assistant_response"]
    assert assistant["generation_mode"] == "policy_grounded"
    assert [item["action"] for item in assistant["immediate_steps"]] == body["recommended_actions"]
    assert {item["policy_ref"] for item in assistant["immediate_steps"]} == {body["policy_version"]}
    assert {ref for reason in assistant["top_reasons"] for ref in reason["evidence_refs"]} <= {
        item["evidence_ref"] for item in body["evidence"]
    }

    detail = await client.get(f"/api/v4/analyses/{body['analysis_id']}", headers=USER_HEADERS)
    assert detail.status_code == 200
    assert detail.json()["assistant_response"] == assistant


class _UngroundedModel:
    async def synthesize(self, result):
        del result
        return ModelResponse(
            output=AssistantSynthesis(
                summary="Invented result",
                top_reasons=[SynthesisReason(text="Invented evidence", evidence_refs=["evidence:ffffffffffffffff"])],
            ),
            provider="fake",
            model="bad-synthesis-v1",
        )


@pytest.mark.asyncio
async def test_v4_ungrounded_synthesis_keeps_grounded_answer_without_failing_analysis(client) -> None:
    async def override_response_service():
        return GroundedSecurityResponseService(
            ai_enabled=True,
            model=_UngroundedModel(),
            runtime=SecurityAssistantRuntime(max_retries=0),
        )

    app.dependency_overrides[get_grounded_security_response_service] = override_response_service
    try:
        response = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Ngân hàng yêu cầu tôi gửi OTP ngay"},
        )
    finally:
        app.dependency_overrides.pop(get_grounded_security_response_service, None)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["assistant_response"]["generation_mode"] == "policy_grounded"
    assert any("bằng chứng và hành động đã kiểm chứng" in item for item in body["limitations"])
