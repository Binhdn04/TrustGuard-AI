from __future__ import annotations

import pytest

from src.services.security_pipeline import SecurityTriagePipeline

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}


@pytest.mark.asyncio
async def test_inline_analysis_executes_through_shared_security_pipeline(client, monkeypatch) -> None:
    original = SecurityTriagePipeline.process
    observed = []

    async def record_pipeline_call(self, request, scoped, **kwargs):
        runtime = kwargs["runtime"]
        observed.append(
            {
                "analysis_id": scoped.analysis_id,
                "runtime": runtime,
                "execution_context": runtime.execution_context,
            }
        )
        return await original(self, request, scoped, **kwargs)

    monkeypatch.setattr(SecurityTriagePipeline, "process", record_pipeline_call)

    response = await client.post(
        "/api/v4/analyses",
        headers=USER_HEADERS,
        json={"message": "Ngan hang yeu cau gui OTP ngay"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert len(observed) == 1
    assert observed[0]["execution_context"] is not None
    assert observed[0]["runtime"].budget is observed[0]["execution_context"].ai_budget
