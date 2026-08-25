from datetime import UTC, datetime

import pytest

from src.agents.security_investigation import SecurityInvestigationService
from src.agents.security_trust import SecurityTrustService
from src.api.dependencies import (
    get_security_analysis_service,
    get_security_blacklist_admin_service,
    get_security_investigation_service,
    get_security_memory_service,
    get_security_trust_admin_service,
    get_security_trust_service,
    get_wave2_service,
)
from src.main import app
from src.repositories.blacklist import SQLiteBlacklistRepository
from src.services.platform_wave2 import MemoryWave2Repository, Wave2PlatformService
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_blacklist import SecurityBlacklistAdminService
from src.services.security_memory import SecurityMemoryService
from src.services.security_trust import SecurityTrustAdminService

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}


@pytest.mark.asyncio
async def test_mvp_report_blacklist_whitelist_and_reanalysis_flow(client, tmp_path) -> None:
    repository = SQLiteBlacklistRepository(tmp_path / "mvp-flow.db")
    analyses = SecurityAnalysisService(repository)
    memory = SecurityMemoryService(repository)
    trust = SecurityTrustService(repository)
    trust_admin = SecurityTrustAdminService(repository)
    wave = Wave2PlatformService(MemoryWave2Repository(action_sink=repository))
    blacklist = SecurityBlacklistAdminService(wave)
    investigation = SecurityInvestigationService(blacklist=repository)
    overrides = {
        get_security_analysis_service: lambda: analyses,
        get_security_memory_service: lambda: memory,
        get_security_trust_service: lambda: trust,
        get_security_trust_admin_service: lambda: trust_admin,
        get_security_blacklist_admin_service: lambda: blacklist,
        get_security_investigation_service: lambda: investigation,
        get_wave2_service: lambda: wave,
    }
    app.dependency_overrides.update(overrides)
    try:
        malicious = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Kiểm tra https://m12-malicious.example/login đang yêu cầu nhập mật khẩu ngay"},
        )
        assert malicious.status_code == 200
        malicious_id = malicious.json()["analysis_id"]
        report = await client.post(
            f"/api/v4/analyses/{malicious_id}/reports",
            headers=USER_HEADERS,
            json={"reason": "Cần admin xác minh hành vi lấy thông tin đăng nhập"},
        )
        assert report.status_code == 201

        queue = await client.get("/api/v4/admin/reports", headers=ADMIN_HEADERS)
        assert queue.status_code == 200
        assert any(item["report_id"] == report.json()["report_id"] for item in queue.json()["items"])
        decision = await client.post(
            f"/api/v4/admin/reports/{report.json()['report_id']}/decision",
            headers=ADMIN_HEADERS,
            json={
                "decision": "approved",
                "resolution": "confirm_malicious",
                "remediation_action": "propose_blacklist",
                "blacklist_proposal": {
                    "canonical_domain": "m12-malicious.example",
                    "reason": "Biểu mẫu yêu cầu thông tin đăng nhập đã được xác minh",
                    "evidence_refs": malicious.json()["explanation_evidence_refs"],
                    "provenance": "mvp-smoke:reviewed-report",
                },
                "evidence_refs": malicious.json()["explanation_evidence_refs"],
                "note": "Admin xác nhận bằng chứng độc hại và tạo đề xuất chặn",
            },
        )
        assert decision.status_code == 200
        assert decision.json()["remediation_status"] == "pending"
        action_id = decision.json()["remediation_reference"]["admin_action_id"]

        execute = await client.post(
            f"/api/v4/admin/blacklist/actions/{action_id}/decision",
            headers=ADMIN_HEADERS,
            json={"decision": "approved", "note": "Admin xác nhận thực thi sau bước rà soát riêng"},
        )
        assert execute.status_code == 200
        assert execute.json()["status"] == "executed"
        blacklist_page = await client.get(
            "/api/v4/admin/blacklist/page",
            headers=ADMIN_HEADERS,
            params={"q": "m12-malicious.example", "lifecycle": "active"},
        )
        assert blacklist_page.status_code == 200
        assert blacklist_page.json()["total"] == 1

        malicious_again = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Kiểm tra lại https://m12-malicious.example/login"},
        )
        assert malicious_again.status_code == 200
        assert malicious_again.json()["risk"] == "MALICIOUS"
        assert any(item["signal"] == "approved_blacklist_hit" for item in malicious_again.json()["evidence"])

        trusted = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Kiểm tra https://m12-trusted.example/status"},
        )
        assert trusted.status_code == 200
        trusted_report = await client.post(
            f"/api/v4/analyses/{trusted.json()['analysis_id']}/reports",
            headers=USER_HEADERS,
            json={"reason": "Đây là cảnh báo sai đã được đối chiếu"},
        )
        whitelist_decision = await client.post(
            f"/api/v4/admin/reports/{trusted_report.json()['report_id']}/decision",
            headers=ADMIN_HEADERS,
            json={
                "decision": "approved",
                "resolution": "mark_false_positive",
                "remediation_action": "add_to_whitelist",
                "whitelist_entry": {
                    "indicator": "m12-trusted.example",
                    "scope": "domain",
                    "provenance": "mvp-smoke:official-security-contact",
                    "effective_from": datetime.now(UTC).isoformat(),
                },
                "note": "Admin xác minh cảnh báo sai và phạm vi domain",
            },
        )
        assert whitelist_decision.status_code == 200
        assert whitelist_decision.json()["remediation_status"] == "executed"

        trusted_again = await client.post(
            "/api/v4/analyses",
            headers=USER_HEADERS,
            json={"message": "Kiểm tra lại https://m12-trusted.example/status"},
        )
        assert trusted_again.status_code == 200
        assert any(item["signal"] == "approved_whitelist" for item in trusted_again.json()["evidence"])
        assert any(item["tool"] == "whitelist_lookup" for item in trusted_again.json()["investigation_plan"])

        unreviewed_message = "Kiểm tra https://m12-unreviewed.example/status"
        unreviewed = await client.post(
            "/api/v4/analyses", headers=USER_HEADERS, json={"message": unreviewed_message}
        )
        unreviewed_report = await client.post(
            f"/api/v4/analyses/{unreviewed.json()['analysis_id']}/reports",
            headers=USER_HEADERS,
            json={"reason": "Báo cáo này chưa tạo ra bằng chứng đã duyệt"},
        )
        before_rejection = await client.post(
            "/api/v4/analyses", headers=USER_HEADERS, json={"message": unreviewed_message}
        )
        rejected = await client.post(
            f"/api/v4/admin/reports/{unreviewed_report.json()['report_id']}/decision",
            headers=ADMIN_HEADERS,
            json={
                "decision": "rejected",
                "remediation_action": "none",
                "note": "Báo cáo không có đủ căn cứ để thay đổi kết quả",
            },
        )
        after_rejection = await client.post(
            "/api/v4/analyses", headers=USER_HEADERS, json={"message": unreviewed_message}
        )
        assert rejected.status_code == 200
        assert (before_rejection.json()["risk"], before_rejection.json()["score"]) == (
            after_rejection.json()["risk"], after_rejection.json()["score"]
        )
        assert not any(
            item["type"] in {"reviewed_security_memory", "whitelist", "blacklist"}
            for item in after_rejection.json()["evidence"]
        )

        audit = await client.get("/api/v4/admin/audit", headers=ADMIN_HEADERS, params={"limit": 100})
        assert audit.status_code == 200
        report_events = [
            item for item in audit.json()["items"]
            if item["resource_id"] == report.json()["report_id"]
        ]
        assert any(item["actor_id"] == "demo-security-admin" and item["occurred_at"] for item in report_events)
        assert any(
            item["report_details"]
            and item["report_details"]["remediation_reference"]
            and item["report_details"]["remediation_reference"]["admin_action_id"] == action_id
            for item in report_events
        )
    finally:
        for dependency in overrides:
            app.dependency_overrides.pop(dependency, None)
        await analyses.aclose()
