import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from src.core.auth import Principal, UserRole
from src.core.errors import PlatformError
from src.models import (
    AnalysisStatus,
    SecurityReportCreateRequestV4,
    SecurityReportDecisionRequestV4,
    SecurityReportRecordV4,
    SecurityReportRemediationReferenceV4,
    SecurityReportRemediationStatusV4,
    SecurityReportRemediationUpdateV4,
    SecurityTriageCreateRequestV4,
)
from src.repositories.blacklist import SQLiteBlacklistRepository
from src.repositories.postgres import PostgresPlatformRepository
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_triage import SecurityTriageScopeService

USER = Principal("m2-owner", UserRole.USER)
ADMIN = Principal("m2-admin", UserRole.SECURITY_ADMIN)
OTHER_ADMIN = Principal("m2-other-admin", UserRole.SECURITY_ADMIN)
NOW = datetime(2026, 8, 24, 10, tzinfo=UTC)


async def _seed_sqlite_service(database: Path) -> tuple[SQLiteBlacklistRepository, SecurityAnalysisService, UUID]:
    repository = SQLiteBlacklistRepository(database)
    service = SecurityAnalysisService(repository)
    request = SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu cung cấp OTP qua một liên kết lạ")
    scoped = SecurityTriageScopeService().assess(request)
    scoped = await service.begin_turn(request, scoped, USER)
    completed = scoped.model_copy(update={"status": AnalysisStatus.COMPLETED, "completed_at": NOW})
    await service.persist_completed(completed, USER)
    return repository, service, completed.analysis_id


def _decision(action: str) -> SecurityReportDecisionRequestV4:
    common: dict[str, Any] = {
        "decision": "approved",
        "note": f"Reviewed remediation {action}",
    }
    if action == "update_memory":
        return SecurityReportDecisionRequestV4(
            **common,
            resolution="confirm_safe",
            remediation_action=action,
        )
    if action == "add_to_whitelist":
        return SecurityReportDecisionRequestV4(
            **common,
            resolution="mark_false_positive",
            remediation_action=action,
            whitelist_entry={
                "indicator": "trusted.example",
                "scope": "domain",
                "provenance": "report:m2-reviewed",
                "effective_from": NOW,
                "effective_until": NOW + timedelta(days=30),
            },
        )
    return SecurityReportDecisionRequestV4(
        **common,
        resolution="confirm_malicious",
        remediation_action="propose_blacklist",
        blacklist_proposal={
            "canonical_domain": "malicious.example",
            "reason": "Credential theft evidence was reviewed",
            "evidence_refs": ["evidence:0123456789abcdef"],
            "provenance": "report:m2-reviewed",
        },
    )


@pytest.mark.asyncio
async def test_sqlite_round_trips_all_report_remediation_references_and_audit(tmp_path) -> None:
    repository, service, analysis_id = await _seed_sqlite_service(tmp_path / "m2-parity.db")
    cases = [
        ("update_memory", SecurityReportRemediationReferenceV4(memory_id=uuid4())),
        ("add_to_whitelist", SecurityReportRemediationReferenceV4(whitelist_id=uuid4())),
        ("propose_blacklist", SecurityReportRemediationReferenceV4(admin_action_id=uuid4())),
    ]

    for action, reference in cases:
        report = await service.create_report(
            analysis_id,
            SecurityReportCreateRequestV4(reason=f"Review {action}"),
            USER,
        )
        pending = await service.decide_report(report.report_id, _decision(action), ADMIN)
        assert pending.remediation_status is SecurityReportRemediationStatusV4.PENDING
        completed = await service.record_report_remediation(
            report.report_id,
            SecurityReportRemediationUpdateV4(
                status="executed",
                reference=reference,
                note=f"Completed {action}",
                evidence_refs=[f"evidence:{action}"],
            ),
            ADMIN,
        )
        assert completed.remediation_reference == reference

    persisted = await service.list_reports_for(analysis_id, USER)
    audit = await service.list_admin_audit(ADMIN)
    await service.aclose()

    assert {item.remediation_reference.memory_id for item in persisted if item.remediation_reference} >= {
        cases[0][1].memory_id
    }
    assert {item.remediation_reference.whitelist_id for item in persisted if item.remediation_reference} >= {
        cases[1][1].whitelist_id
    }
    assert {item.remediation_reference.admin_action_id for item in persisted if item.remediation_reference} >= {
        cases[2][1].admin_action_id
    }
    report_audit = [item for item in audit if item.resource_type.value == "report"]
    assert len(report_audit) == 6
    assert all(item.report_details is not None for item in report_audit)
    assert any(item.evidence_refs == ["evidence:0123456789abcdef"] for item in report_audit)
    assert any(
        item.report_details
        and item.report_details.remediation_reference == cases[2][1]
        and item.report_details.remediation_status is SecurityReportRemediationStatusV4.EXECUTED
        for item in report_audit
    )


@pytest.mark.asyncio
async def test_sqlite_concurrent_report_decision_writes_one_record_and_one_audit(tmp_path) -> None:
    _repository, service, analysis_id = await _seed_sqlite_service(tmp_path / "m2-concurrency.db")
    report = await service.create_report(
        analysis_id,
        SecurityReportCreateRequestV4(reason="Concurrent review"),
        USER,
    )
    request = SecurityReportDecisionRequestV4(
        decision="approved",
        resolution="no_change",
        remediation_action="none",
        note="First terminal review wins",
    )

    results = await asyncio.gather(
        service.decide_report(report.report_id, request, ADMIN),
        service.decide_report(report.report_id, request, OTHER_ADMIN),
        return_exceptions=True,
    )
    audit = await service.list_admin_audit(ADMIN)
    with pytest.raises(PlatformError) as retry:
        await service.decide_report(report.report_id, request, ADMIN)
    await service.aclose()

    assert sum(not isinstance(item, Exception) for item in results) == 1
    conflicts = [item for item in results if isinstance(item, PlatformError)]
    assert len(conflicts) == 1
    assert conflicts[0].status_code == 409
    assert retry.value.status_code == 409
    assert len([item for item in audit if item.resource_id == report.report_id]) == 1


def test_sqlite_additive_migration_preserves_legacy_feedback_audit(tmp_path) -> None:
    database = tmp_path / "legacy-audit.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO schema_migrations(version,applied_at) VALUES
          (2,'2026-08-24T00:00:00+00:00'),
          (3,'2026-08-24T00:00:00+00:00'),
          (4,'2026-08-24T00:00:00+00:00');
        CREATE TABLE security_feedback_audit_v4 (
          audit_id TEXT PRIMARY KEY, resource_type TEXT NOT NULL,
          resource_id TEXT NOT NULL, action TEXT NOT NULL, actor_id TEXT NOT NULL,
          note TEXT, evidence_refs_json TEXT NOT NULL, occurred_at TEXT NOT NULL
        );
        """
    )
    audit_id = uuid4()
    resource_id = uuid4()
    connection.execute(
        """INSERT INTO security_feedback_audit_v4(
               audit_id,resource_type,resource_id,action,actor_id,note,evidence_refs_json,occurred_at
           ) VALUES(?,?,?,?,?,?,?,?)""",
        (
            str(audit_id),
            "report",
            str(resource_id),
            "report_approved",
            "legacy-admin",
            "Legacy audit",
            "[]",
            NOW.isoformat(),
        ),
    )
    connection.commit()
    connection.close()

    repository = SQLiteBlacklistRepository(database)
    columns = {
        row[1]
        for row in repository._connection.execute(  # noqa: SLF001 - migration contract assertion
            "PRAGMA table_info(security_feedback_audit_v4)"
        ).fetchall()
    }
    migrated = repository._connection.execute(  # noqa: SLF001 - migration contract assertion
        "SELECT details_json FROM security_feedback_audit_v4 WHERE audit_id=?",
        (str(audit_id),),
    ).fetchone()
    version = repository._connection.execute(  # noqa: SLF001 - migration contract assertion
        "SELECT version FROM schema_migrations WHERE version=5"
    ).fetchone()
    repository._connection.close()  # noqa: SLF001 - synchronous fixture cleanup

    assert "details_json" in columns
    assert migrated == ("{}",)
    assert version == (5,)


class _AsyncContext:
    def __init__(self, value: Any) -> None:
        self._value = value

    async def __aenter__(self) -> Any:
        return self._value

    async def __aexit__(self, *_args: object) -> None:
        return None


class _FakePostgresConnection:
    def __init__(self, record: SecurityReportRecordV4) -> None:
        self.owner_id = USER.user_id
        self.status = record.status.value
        self.record = record.model_dump(mode="json")
        self.audit_rows: list[dict[str, Any]] = []
        self.selects: list[str] = []

    def transaction(self) -> _AsyncContext:
        return _AsyncContext(self)

    async def fetchrow(self, query: str, *_args: object) -> dict[str, Any]:
        self.selects.append(query)
        return {"owner_id": self.owner_id, "status": self.status, "record": self.record}

    async def execute(self, query: str, *args: object) -> str:
        normalized = " ".join(query.split())
        if normalized.startswith("UPDATE security_analysis_reports_v4 SET status="):
            self.status = str(args[1])
            self.record = json.loads(str(args[2]))
        elif normalized.startswith("UPDATE security_analysis_reports_v4 SET record="):
            self.record = json.loads(str(args[1]))
        elif normalized.startswith("INSERT INTO security_feedback_audit_v4"):
            self.audit_rows.append(
                {
                    "action": args[3],
                    "evidence_refs": json.loads(str(args[6])),
                    "details": json.loads(str(args[7])),
                }
            )
        return "OK"


class _FakePostgresPool:
    def __init__(self, connection: _FakePostgresConnection) -> None:
        self.connection = connection

    def acquire(self) -> _AsyncContext:
        return _AsyncContext(self.connection)


@pytest.mark.asyncio
async def test_postgres_contract_locks_row_and_persists_same_report_audit_shape() -> None:
    report = SecurityReportRecordV4(analysis_id=uuid4(), reason="PostgreSQL parity")
    connection = _FakePostgresConnection(report)
    repository = PostgresPlatformRepository(
        "postgresql://test.invalid/platform",
        "test-key",
        pool=_FakePostgresPool(connection),
    )
    request = _decision("propose_blacklist")

    pending = await repository.decide_security_report(report.report_id, request, ADMIN.user_id, NOW)
    assert pending is not None
    assert pending.remediation_status is SecurityReportRemediationStatusV4.PENDING
    with pytest.raises(PlatformError) as retry:
        await repository.decide_security_report(report.report_id, request, OTHER_ADMIN.user_id, NOW)

    reference = SecurityReportRemediationReferenceV4(admin_action_id=uuid4())
    completed = await repository.complete_security_report_remediation(
        report.report_id,
        SecurityReportRemediationUpdateV4(
            status="executed",
            reference=reference,
            note="Action executed",
            evidence_refs=["evidence:execution"],
        ),
        ADMIN.user_id,
        NOW + timedelta(minutes=1),
    )
    with pytest.raises(PlatformError) as duplicate_completion:
        await repository.complete_security_report_remediation(
            report.report_id,
            SecurityReportRemediationUpdateV4(
                status="executed",
                reference=reference,
                note="Duplicate completion",
            ),
            ADMIN.user_id,
            NOW + timedelta(minutes=2),
        )

    assert retry.value.status_code == 409
    assert duplicate_completion.value.status_code == 409
    assert completed is not None
    assert completed.remediation_reference == reference
    assert all("FOR UPDATE" in query for query in connection.selects)
    assert len(connection.audit_rows) == 2
    assert connection.audit_rows[0]["evidence_refs"] == ["evidence:0123456789abcdef"]
    assert connection.audit_rows[0]["details"]["resolution"] == "confirm_malicious"
    assert connection.audit_rows[1]["details"]["remediation_reference"]["admin_action_id"] == str(
        reference.admin_action_id
    )
