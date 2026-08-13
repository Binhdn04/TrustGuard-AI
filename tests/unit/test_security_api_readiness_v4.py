import sqlite3
from datetime import UTC, datetime

import pytest

from src.core.auth import Principal, UserRole
from src.models import (
    AnalysisStatus,
    AppealOutcome,
    ReportReviewDecision,
    SecurityAppealCreateRequestV4,
    SecurityReportCreateRequestV4,
    SecurityTriageCreateRequestV4,
)
from src.repositories.blacklist import SQLiteBlacklistRepository
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_triage import SecurityTriageScopeService

USER = Principal("api-readiness-user", UserRole.USER)
ADMIN = Principal("api-readiness-admin", UserRole.SECURITY_ADMIN)


def test_sqlite_adds_report_status_to_existing_wp8_database(tmp_path) -> None:
    database = tmp_path / "wp8.db"
    connection = sqlite3.connect(database)
    connection.execute(
        """CREATE TABLE security_analysis_reports_v4(
               report_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, owner_id TEXT NOT NULL,
               record_json TEXT NOT NULL, created_at TEXT NOT NULL
           )"""
    )
    connection.commit()
    connection.close()

    repository = SQLiteBlacklistRepository(database)
    columns = {
        row[1]
        for row in repository._connection.execute(  # noqa: SLF001 - migration contract assertion
            "PRAGMA table_info(security_analysis_reports_v4)"
        )
    }
    indexes = {
        row[1]
        for row in repository._connection.execute(  # noqa: SLF001 - migration contract assertion
            "PRAGMA index_list(security_analysis_reports_v4)"
        )
    }
    repository._connection.close()  # noqa: SLF001 - synchronous fixture cleanup

    assert "status" in columns
    assert "ix_security_reports_v4_status_created" in indexes


@pytest.mark.asyncio
async def test_sqlite_persists_feedback_decisions_conversations_and_unified_audit(tmp_path) -> None:
    repository = SQLiteBlacklistRepository(tmp_path / "api-readiness.db")
    service = SecurityAnalysisService(repository)
    request = SecurityTriageCreateRequestV4(message="Is Spain the World Cup champion?")
    scoped = SecurityTriageScopeService().assess(request)
    scoped = await service.begin_turn(request, scoped, USER)
    completed = scoped.model_copy(
        update={"status": AnalysisStatus.COMPLETED, "completed_at": datetime.now(UTC)}
    )
    await service.persist_completed(completed, USER)

    report = await service.create_report(
        completed.analysis_id,
        SecurityReportCreateRequestV4(reason="Evidence requires review"),
        USER,
    )
    appeal = await service.create_appeal(
        completed.analysis_id,
        SecurityAppealCreateRequestV4(reason="Decision requires review"),
        USER,
    )
    reviewed_report = await service.decide_report(
        report.report_id,
        ReportReviewDecision.APPROVED,
        "Reviewed evidence",
        ADMIN,
    )
    reviewed_appeal = await service.decide_appeal(
        appeal.appeal_id,
        AppealOutcome.OVERTURN,
        "Official evidence changed the decision",
        ADMIN,
    )

    conversations = await service.list_conversations_for(USER)
    reports = await service.list_reports_admin(ADMIN)
    appeals = await service.list_appeals_admin(ADMIN)
    audit = await service.list_admin_audit(ADMIN)
    await service.aclose()

    assert conversations[0].conversation_id == completed.conversation_id
    assert reports[0] == reviewed_report
    assert appeals[0] == reviewed_appeal
    assert {item.resource_type.value for item in audit} == {"appeal", "report"}
