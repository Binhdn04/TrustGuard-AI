from types import SimpleNamespace

import pytest

from src.api.dependencies import get_security_analysis_service, get_security_memory_service
from src.config import Settings
from src.main import app
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_memory import SecurityMemoryService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


def test_openapi_freezes_wp9a_api_surface() -> None:
    paths = app.openapi()["paths"]

    assert {
        "/api/v4/capabilities",
        "/api/v4/analyses/page",
        "/api/v4/conversations",
        "/api/v4/admin/reports",
        "/api/v4/admin/analyses/{analysis_id}",
        "/api/v4/admin/reports/{report_id}/decision",
        "/api/v4/admin/appeals",
        "/api/v4/admin/appeals/{appeal_id}/decision",
        "/api/v4/admin/intelligence/domains",
        "/api/v4/admin/intelligence/threats",
        "/api/v4/admin/audit",
        "/api/v4/admin/brands/page",
        "/api/v4/admin/whitelist/page",
        "/api/v4/admin/security-memory/page",
        "/api/v4/admin/security-campaigns/page",
    } <= set(paths)


@pytest.mark.asyncio
async def test_capabilities_publish_truthful_pre_cutover_boundary(client) -> None:
    response = await client.get("/api/v4/capabilities")

    assert response.status_code == 200
    assert response.json() == {
        "contract_version": "v4",
        "product_profile": "security_triage_vnext",
        "release_profile": "pre_cutover",
        "conversation_resume": True,
        "admin_feedback_review": True,
        "intelligence_explorer": True,
        "unified_v4_audit": True,
        "admin_action_contract": "v3",
        "executable_admin_actions": ["add_to_blacklist"],
        "deferred_admin_actions": [
            "block_domain",
            "publish_broad_warning",
            "ai_security_copilot",
        ],
        "compatibility_contracts": ["v2", "v3", "v4"],
    }


@pytest.mark.asyncio
async def test_disabled_ai_flags_are_byte_compatible_with_legacy_capabilities(client, monkeypatch) -> None:
    disabled_settings = Settings(_env_file=None)
    monkeypatch.setattr(
        "src.api.security_v4.get_settings",
        lambda: disabled_settings,
    )
    disabled = await client.get("/api/v4/capabilities")

    monkeypatch.setattr(
        "src.api.security_v4.get_settings",
        lambda: SimpleNamespace(security_release_profile="pre_cutover"),
    )
    legacy = await client.get("/api/v4/capabilities")

    assert disabled.status_code == legacy.status_code == 200
    assert disabled.content == legacy.content


@pytest.mark.asyncio
async def test_capabilities_publish_only_actually_enabled_ai_features(client, monkeypatch) -> None:
    enabled_settings = Settings(
        openai_api_key="configured-test-provider-key",
        security_ai_understanding_enabled=True,
        security_ai_planning_enabled=True,
        security_ai_explanation_enabled=True,
        security_async_execution_enabled=True,
        security_memory_retrieval_enabled=True,
        security_admin_copilot_enabled=True,
        _env_file=None,
    )
    monkeypatch.setattr(
        "src.api.security_v4.get_settings",
        lambda: enabled_settings,
    )

    response = await client.get("/api/v4/capabilities")

    assert response.status_code == 200
    assert {
        name: response.json()[name]
        for name in (
            "security_ai_understanding",
            "security_ai_planning",
            "security_ai_explanation",
            "security_async_execution",
            "security_memory_retrieval",
            "security_admin_copilot",
        )
    } == {
        "security_ai_understanding": True,
        "security_ai_planning": True,
        "security_ai_explanation": True,
        "security_async_execution": True,
        "security_memory_retrieval": True,
        "security_admin_copilot": True,
    }


@pytest.mark.asyncio
async def test_capabilities_publish_configured_cutover_profile(client, monkeypatch) -> None:
    monkeypatch.setattr(
        "src.api.security_v4.get_settings",
        lambda: SimpleNamespace(security_release_profile="cutover"),
    )

    response = await client.get("/api/v4/capabilities")

    assert response.status_code == 200
    assert response.json()["release_profile"] == "cutover"


@pytest.mark.asyncio
async def test_paginated_history_and_conversations_are_owner_scoped(client) -> None:
    service = SecurityAnalysisService()
    app.dependency_overrides[get_security_analysis_service] = lambda: service
    app.dependency_overrides[get_security_memory_service] = SecurityMemoryService
    try:
        created = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Bank asks me to share an OTP immediately"},
        )
        history = await client.get("/api/v4/analyses/page", headers=USER_HEADERS, params={"limit": 1})
        in_scope = await client.get(
            "/api/v4/analyses/page",
            headers=USER_HEADERS,
            params={"scope_decision": "IN_SCOPE"},
        )
        need_more_info = await client.get(
            "/api/v4/analyses/page",
            headers=USER_HEADERS,
            params={"scope_decision": "NEED_MORE_INFO"},
        )
        conversations = await client.get("/api/v4/conversations", headers=USER_HEADERS, params={"limit": 1})
        other_owner = await client.get("/api/v4/conversations", headers=ADMIN_HEADERS)
    finally:
        app.dependency_overrides.pop(get_security_analysis_service, None)
        app.dependency_overrides.pop(get_security_memory_service, None)

    assert created.status_code == 200
    assert history.json()["total"] == 1
    assert history.json()["items"][0]["analysis_id"] == created.json()["analysis_id"]
    assert in_scope.json()["total"] == 1
    assert need_more_info.json()["total"] == 0
    assert conversations.json()["total"] == 1
    assert conversations.json()["items"][0]["conversation_id"] == created.json()["conversation_id"]
    assert other_owner.json()["total"] == 0


@pytest.mark.asyncio
async def test_admin_can_review_v4_report_and_appeal_with_immutable_audit(client) -> None:
    service = SecurityAnalysisService()
    app.dependency_overrides[get_security_analysis_service] = lambda: service
    app.dependency_overrides[get_security_memory_service] = SecurityMemoryService
    try:
        created = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Bank asks me to share an OTP at https://secure.example/login?token=secret"},
        )
        analysis_id = created.json()["analysis_id"]
        report = await client.post(
            f"/api/v4/analyses/{analysis_id}/reports",
            headers=USER_HEADERS,
            json={"reason": "Evidence needs review"},
        )
        appeal = await client.post(
            f"/api/v4/analyses/{analysis_id}/appeals",
            headers=USER_HEADERS,
            json={"reason": "Risk decision may be incorrect"},
        )
        denied = await client.get("/api/v4/admin/reports", headers=USER_HEADERS)
        reports = await client.get("/api/v4/admin/reports", headers=ADMIN_HEADERS)
        appeals = await client.get("/api/v4/admin/appeals", headers=ADMIN_HEADERS)
        detail_denied = await client.get(f"/api/v4/admin/analyses/{analysis_id}", headers=USER_HEADERS)
        detail = await client.get(f"/api/v4/admin/analyses/{analysis_id}", headers=ADMIN_HEADERS)
        report_decision = await client.post(
            f"/api/v4/admin/reports/{report.json()['report_id']}/decision",
            headers=ADMIN_HEADERS,
            json={"decision": "approved", "note": "Confirmed by reviewer"},
        )
        appeal_decision = await client.post(
            f"/api/v4/admin/appeals/{appeal.json()['appeal_id']}/decision",
            headers=ADMIN_HEADERS,
            json={"outcome": "overturn", "note": "Official evidence changed the result"},
        )
        duplicate = await client.post(
            f"/api/v4/admin/appeals/{appeal.json()['appeal_id']}/decision",
            headers=ADMIN_HEADERS,
            json={"outcome": "uphold", "note": "Second decision is forbidden"},
        )
        audit = await client.get("/api/v4/admin/audit", headers=ADMIN_HEADERS)
    finally:
        app.dependency_overrides.pop(get_security_analysis_service, None)
        app.dependency_overrides.pop(get_security_memory_service, None)

    assert denied.status_code == 403
    assert detail_denied.status_code == 403
    assert detail.status_code == 200
    assert detail.json()["analysis_id"] == analysis_id
    assert detail.json()["security_context"]["urls"] == ["https://secure.example/login"]
    assert "token=secret" not in detail.text
    assert "message" not in detail.json()
    assert "owner_id" not in detail.json()
    assert reports.json()["total"] == 1
    assert appeals.json()["total"] == 1
    assert report_decision.json()["status"] == "processed"
    assert report_decision.json()["decision"] == "approved"
    assert appeal_decision.json()["status"] == "resolved"
    assert appeal_decision.json()["outcome"] == "overturn"
    assert duplicate.status_code == 409
    assert {item["resource_type"] for item in audit.json()["items"]} == {"report", "appeal"}


@pytest.mark.asyncio
async def test_intelligence_explorer_is_admin_only_and_paginated(client) -> None:
    denied = await client.get("/api/v4/admin/intelligence/domains", headers=USER_HEADERS)
    domains = await client.get("/api/v4/admin/intelligence/domains", headers=ADMIN_HEADERS, params={"limit": 1})
    threats = await client.get("/api/v4/admin/intelligence/threats", headers=ADMIN_HEADERS, params={"limit": 1})

    assert denied.status_code == 403
    assert domains.status_code == 200
    assert set(domains.json()) == {"contract_version", "items", "total", "limit", "offset"}
    assert threats.status_code == 200
