from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from src.api.dependencies import get_security_memory_service
from src.config import Settings
from src.main import app
from src.models import (
    PotentialThreatV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryRecordV4,
    SecurityRiskV4,
    SecurityScenarioV4,
)
from src.services.security_memory import ReviewedMemoryCandidate

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
NOW = datetime(2026, 8, 15, 8, tzinfo=UTC)


class ReviewedMemoryFixture:
    def __init__(self) -> None:
        self.recorded = []
        self.owner_ids = []
        self.memory = SecurityMemoryRecordV4(
            analysis_id=uuid4(),
            canonical_domains=["reviewed.example"],
            scenario=SecurityScenarioV4.UNKNOWN,
            threat_type=PotentialThreatV4.UNDETERMINED_SECURITY_THREAT,
            risk=SecurityRiskV4.SUSPICIOUS,
            risk_policy_version="security-risk-v1",
            first_seen_at=NOW,
            last_seen_at=NOW,
            admin_verdict=SecurityMemoryAdminVerdictV4.MALICIOUS,
            evidence_refs=["evidence:7777777777777777"],
        )

    async def reviewed_candidates(self, owner_id, current_analysis_id):
        assert current_analysis_id != self.memory.analysis_id
        self.owner_ids.append(owner_id)
        return [ReviewedMemoryCandidate(self.memory, NOW)], []

    async def record(self, response, owner_id=None):
        self.recorded.append(response.analysis_id)
        self.owner_ids.append(owner_id)
        return None


@pytest.mark.asyncio
async def _enabled_wp6_adds_privacy_minimized_reviewed_evidence_and_risk_v2(client, monkeypatch) -> None:
    fixture = ReviewedMemoryFixture()
    settings = Settings(security_memory_retrieval_enabled=True, _env_file=None)

    async def override_memory():
        return fixture

    monkeypatch.setattr("src.api.security_v4.get_settings", lambda: settings)
    app.dependency_overrides[get_security_memory_service] = override_memory
    try:
        capabilities = await client.get("/api/v4/capabilities", headers=USER_HEADERS)
        created = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Kiểm tra link https://reviewed.example/login"},
        )
    finally:
        app.dependency_overrides.pop(get_security_memory_service, None)

    assert capabilities.status_code == 200
    assert capabilities.json()["security_memory_retrieval"] is True
    assert created.status_code == 200
    body = created.json()
    reviewed = [item for item in body["evidence"] if item["type"] == "reviewed_security_memory"]
    assert body["policy_version"] == "security-risk-v2"
    assert len(reviewed) == 1
    assert reviewed[0]["source"] == "security_memory_lookup"
    assert reviewed[0]["provenance_ref"].startswith("security-memory:")
    assert "reviewed_at=" in reviewed[0]["description"]
    assert str(fixture.memory.analysis_id) not in created.text
    assert all(owner_id == "demo-user" for owner_id in fixture.owner_ids)
    assert fixture.recorded == [UUID(body["analysis_id"])]
