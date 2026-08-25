from datetime import UTC, datetime

import pytest

from src.api.security_v4 import (
    decide_security_blacklist_action_admin_v4,
    decide_security_report_admin_v4,
)
from src.core.auth import Principal, UserRole
from src.models import (
    AnalysisStatus,
    PotentialThreatV4,
    SecurityBlacklistDecisionRequestV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryRecordV4,
    SecurityReportCreateRequestV4,
    SecurityReportDecisionRequestV4,
    SecurityReportRemediationStatusV4,
    SecurityRiskV4,
    SecurityScenarioV4,
    SecurityTriageCreateRequestV4,
)
from src.repositories.blacklist import SQLiteBlacklistRepository
from src.services.platform_wave2 import MemoryWave2Repository, Wave2PlatformService
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_blacklist import SecurityBlacklistAdminService
from src.services.security_memory import SecurityMemoryService
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_trust import SecurityTrustAdminService

USER = Principal("m4-owner", UserRole.USER)
ADMIN = Principal("m4-admin", UserRole.SECURITY_ADMIN)
NOW = datetime(2026, 8, 24, 12, tzinfo=UTC)


async def _seed(analyses: SecurityAnalysisService):
    triage = SecurityTriageCreateRequestV4(message="Kiểm tra yêu cầu cung cấp OTP từ malicious.example")
    response = SecurityTriageScopeService().assess(triage)
    response = await analyses.begin_turn(triage, response, USER)
    response = response.model_copy(update={"status": AnalysisStatus.COMPLETED, "completed_at": NOW})
    await analyses.persist_completed(response, USER)
    return response


async def _report(analyses, analysis_id):
    return await analyses.create_report(
        analysis_id,
        SecurityReportCreateRequestV4(reason="Reviewer must resolve this result."),
        USER,
    )


@pytest.mark.asyncio
async def test_m4_executes_explicit_memory_whitelist_and_blacklist_remediation(tmp_path) -> None:
    analyses = SecurityAnalysisService()
    response = await _seed(analyses)
    memory = SecurityMemoryService()
    memory_record = SecurityMemoryRecordV4(
        analysis_id=response.analysis_id,
        canonical_domains=["malicious.example"],
        scenario=SecurityScenarioV4.UNKNOWN,
        threat_type=PotentialThreatV4.UNDETERMINED_SECURITY_THREAT,
        risk=SecurityRiskV4.SUSPICIOUS,
        risk_policy_version="security-risk-v6",
        first_seen_at=NOW,
        last_seen_at=NOW,
        evidence_refs=["evidence:reviewed"],
    )
    memory._memory.records[memory_record.memory_id] = memory_record
    trust = SecurityTrustAdminService(SQLiteBlacklistRepository(tmp_path / "m4-trust.db"))
    blacklist = SecurityBlacklistAdminService(Wave2PlatformService(MemoryWave2Repository()))

    expected = {
        "confirm_safe": SecurityMemoryAdminVerdictV4.SAFE,
        "mark_false_positive": SecurityMemoryAdminVerdictV4.FALSE_POSITIVE,
        "confirm_malicious": SecurityMemoryAdminVerdictV4.MALICIOUS,
    }
    for resolution, verdict in expected.items():
        report = await _report(analyses, response.analysis_id)
        decided = await decide_security_report_admin_v4(
            report.report_id,
            SecurityReportDecisionRequestV4(
                decision="approved",
                resolution=resolution,
                remediation_action="update_memory",
                evidence_refs=["evidence:reviewed"],
                note=f"Apply {resolution} to reviewed memory.",
            ),
            analyses,
            memory,
            trust,
            blacklist,
            ADMIN,
        )
        assert decided.remediation_status is SecurityReportRemediationStatusV4.EXECUTED
        assert (await memory.memory_for_analysis(response.analysis_id, ADMIN)).admin_verdict is verdict

    whitelist_report = await _report(analyses, response.analysis_id)
    whitelisted = await decide_security_report_admin_v4(
        whitelist_report.report_id,
        SecurityReportDecisionRequestV4(
            decision="approved",
            resolution="confirm_safe",
            remediation_action="add_to_whitelist",
            whitelist_entry={
                "indicator": "trusted.example",
                "scope": "domain",
                "provenance": "reviewed-report",
                "effective_from": NOW,
            },
            note="Reviewer explicitly approved this whitelist entry.",
        ),
        analyses,
        memory,
        trust,
        blacklist,
        ADMIN,
    )
    assert whitelisted.remediation_status is SecurityReportRemediationStatusV4.EXECUTED
    whitelist_records = await trust.list_whitelist(ADMIN)
    assert f"report:{whitelist_report.report_id}" in whitelist_records[0].provenance
    assert f"analysis:{response.analysis_id}" in whitelist_records[0].provenance

    blacklist_report = await _report(analyses, response.analysis_id)
    proposed = await decide_security_report_admin_v4(
        blacklist_report.report_id,
        SecurityReportDecisionRequestV4(
            decision="approved",
            resolution="confirm_malicious",
            remediation_action="propose_blacklist",
            blacklist_proposal={
                "canonical_domain": "malicious.example",
                "reason": "Reviewed credential theft evidence.",
                "evidence_refs": ["evidence:blacklist"],
                "provenance": "reviewed-report",
            },
            note="Create proposal only; a second review executes it.",
        ),
        analyses,
        memory,
        trust,
        blacklist,
        ADMIN,
    )
    assert proposed.remediation_status is SecurityReportRemediationStatusV4.PENDING
    assert await blacklist.list_records(ADMIN) == await blacklist.list_records(ADMIN, lifecycle=None)
    action_id = proposed.remediation_reference.admin_action_id
    action_result = await decide_security_blacklist_action_admin_v4(
        action_id,
        SecurityBlacklistDecisionRequestV4(
            decision="approved", note="Second human review approved execution."
        ),
        blacklist,
        analyses,
        ADMIN,
    )
    assert action_result.status.value == "executed"
    linked = await analyses.report_for_admin_action(action_id, ADMIN)
    assert linked.remediation_status is SecurityReportRemediationStatusV4.EXECUTED


@pytest.mark.asyncio
@pytest.mark.parametrize("resolution", ["needs_more_information", "no_change"])
async def test_m4_non_conclusive_resolution_has_no_side_effect(resolution, tmp_path) -> None:
    analyses = SecurityAnalysisService()
    response = await _seed(analyses)
    report = await _report(analyses, response.analysis_id)
    memory = SecurityMemoryService()
    trust = SecurityTrustAdminService(SQLiteBlacklistRepository(tmp_path / f"{resolution}.db"))
    blacklist = SecurityBlacklistAdminService(Wave2PlatformService(MemoryWave2Repository()))

    decided = await decide_security_report_admin_v4(
        report.report_id,
        SecurityReportDecisionRequestV4(
            decision="approved",
            resolution=resolution,
            remediation_action="none",
            note="No remediation is justified by this resolution.",
        ),
        analyses,
        memory,
        trust,
        blacklist,
        ADMIN,
    )
    assert decided.remediation_status is SecurityReportRemediationStatusV4.NOT_REQUESTED
    assert (await blacklist.list_records(ADMIN)).total == 0
    assert await trust.list_whitelist(ADMIN) == []


@pytest.mark.asyncio
async def test_m4_rejected_blacklist_action_keeps_report_and_audit_linkage(tmp_path) -> None:
    analyses = SecurityAnalysisService()
    response = await _seed(analyses)
    report = await _report(analyses, response.analysis_id)
    memory = SecurityMemoryService()
    trust_repository = SQLiteBlacklistRepository(tmp_path / "m4-rejected-link.db")
    trust = SecurityTrustAdminService(trust_repository)
    blacklist = SecurityBlacklistAdminService(Wave2PlatformService(MemoryWave2Repository()))

    pending = await decide_security_report_admin_v4(
        report.report_id,
        SecurityReportDecisionRequestV4(
            decision="approved",
            resolution="confirm_malicious",
            remediation_action="propose_blacklist",
            blacklist_proposal={
                "canonical_domain": "rejected.example",
                "reason": "Evidence needs a separate block review.",
                "evidence_refs": ["evidence:rejected-block"],
                "provenance": "reviewed-report",
            },
            note="Create a reviewer-gated block proposal.",
        ),
        analyses,
        memory,
        trust,
        blacklist,
        ADMIN,
    )
    action_id = pending.remediation_reference.admin_action_id

    result = await decide_security_blacklist_action_admin_v4(
        action_id,
        SecurityBlacklistDecisionRequestV4(
            decision="rejected",
            note="The evidence does not justify blocking the domain.",
        ),
        blacklist,
        analyses,
        ADMIN,
    )
    linked = await analyses.report_for_admin_action(action_id, ADMIN)
    audit = [item for item in await analyses.list_admin_audit(ADMIN) if item.resource_id == report.report_id]
    await trust_repository.close()

    assert result.status.value == "rejected"
    assert linked is not None
    assert linked.remediation_status is SecurityReportRemediationStatusV4.FAILED
    assert linked.remediation_reference is not None
    assert linked.remediation_reference.admin_action_id == action_id
    terminal_audit = next(item for item in audit if item.action == "report_remediation_failed")
    assert terminal_audit.report_details is not None
    assert terminal_audit.report_details.remediation_reference is not None
    assert terminal_audit.report_details.remediation_reference.admin_action_id == action_id
