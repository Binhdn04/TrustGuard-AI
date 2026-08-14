from datetime import UTC, datetime
from uuid import uuid4

import pytest

from src.api.dependencies import get_security_admin_copilot_service
from src.main import app
from src.models import (
    AssistantGenerationModeV4,
    SecurityAdminCopilotDispositionV4,
    SecurityAdminCopilotResponseV4,
    SecurityAdminCopilotUsageV4,
)

ADMIN = {"Authorization": "Bearer dev-admin-token"}
USER = {"Authorization": "Bearer dev-user-token"}


class _Copilot:
    def __init__(self): self.calls = []
    async def suggest(self, analysis_id, principal, *, refresh=False):
        self.calls.append((analysis_id, principal.user_id, refresh))
        return SecurityAdminCopilotResponseV4(
            analysis_id=analysis_id,
            evidence_summary="Grounded summary.",
            proposed_disposition=SecurityAdminCopilotDispositionV4.NO_CHANGE,
            evidence_refs=[],
            generation_mode=AssistantGenerationModeV4.TEMPLATE_FALLBACK,
            usage=SecurityAdminCopilotUsageV4(status="fallback"),
            generated_at=datetime.now(UTC),
        )


@pytest.mark.asyncio
async def test_admin_copilot_endpoint_is_admin_only_and_additive(client) -> None:
    service, analysis_id = _Copilot(), uuid4()
    app.dependency_overrides[get_security_admin_copilot_service] = lambda: service
    try:
        denied = await client.post(f"/api/v4/admin/analyses/{analysis_id}/copilot", headers=USER, json={"refresh": False})
        allowed = await client.post(f"/api/v4/admin/analyses/{analysis_id}/copilot", headers=ADMIN, json={"refresh": True})
    finally:
        app.dependency_overrides.pop(get_security_admin_copilot_service, None)
    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json()["executed"] is False
    assert service.calls == [(analysis_id, "demo-security-admin", True)]


def test_openapi_exposes_typed_admin_copilot() -> None:
    document = app.openapi()
    operation = document["paths"]["/api/v4/admin/analyses/{analysis_id}/copilot"]["post"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("SecurityAdminCopilotResponseV4")


@pytest.mark.asyncio
async def test_admin_copilot_has_a_dedicated_refresh_rate_limit(client, monkeypatch) -> None:
    class _DeniedLimiter:
        async def allow(self, key, limit, window_seconds=60):
            assert key.startswith("security-admin-copilot:demo-security-admin:")
            assert limit >= 1 and window_seconds == 60
            return False

    service, analysis_id = _Copilot(), uuid4()
    monkeypatch.setattr("src.api.security_v4.get_rate_limiter", lambda: _DeniedLimiter())
    app.dependency_overrides[get_security_admin_copilot_service] = lambda: service
    try:
        response = await client.post(
            f"/api/v4/admin/analyses/{analysis_id}/copilot",
            headers=ADMIN,
            json={"refresh": True},
        )
    finally:
        app.dependency_overrides.pop(get_security_admin_copilot_service, None)
    assert response.status_code == 429
    assert service.calls == []
