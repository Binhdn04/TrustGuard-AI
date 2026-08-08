from __future__ import annotations

import asyncio
import ipaddress
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST
from src.models import (
    AdminDecisionAudit,
    AnalysisCreateRequest,
    AnalysisEvent,
    AnalysisReportRecord,
    AnalysisResponse,
    BlacklistEntry,
    BlacklistLookupEntry,
    Evidence,
    InvestigationStep,
    ReviewAction,
    ReviewDecision,
    ToolError,
    ReviewQueueItem,
    ReportStatus,
    ReportReviewDecision,
)


def normalize_domain(domain: str) -> str:
    candidate = domain.strip().casefold().rstrip(".")
    if "://" in candidate or "/" in candidate or "@" in candidate:
        raise ValueError("domain must be a hostname, not a URL")
    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain is not valid IDNA") from exc
    if not normalized or len(normalized) > 253:
        raise ValueError("domain is required and must not exceed 253 characters")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        labels = normalized.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
            raise ValueError("domain is invalid")
        if any(not all(char.isalnum() or char == "-" for char in label) for label in labels):
            raise ValueError("domain is invalid")
    registrable = DEFAULT_PUBLIC_SUFFIX_LIST.registrable_domain(normalized)
    if registrable is None:
        raise ValueError("domain must be registrable and cannot be an IP or public suffix")
    return normalized


class SQLiteBlacklistRepository:
    """Persistent blacklist whose writes require an audited approved decision."""

    def __init__(self, database: str | Path) -> None:
        self._database = str(database)
        if self._database != ":memory:":
            Path(self._database).parent.mkdir(parents=True, exist_ok=True)
        # This repository is scoped to one event-loop thread.  Retaining
        # SQLite's thread check prevents accidental cross-thread connection
        # sharing, which an asyncio.Lock cannot make safe.
        self._connection = sqlite3.connect(self._database)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._lock = asyncio.Lock()
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS admin_decisions (
                decision_id TEXT PRIMARY KEY,
                analysis_id TEXT,
                reviewer_id TEXT NOT NULL,
                decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
                action TEXT NOT NULL CHECK (action IN ('add_to_blacklist', 'none')),
                note TEXT NOT NULL,
                decided_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blacklist (
                domain TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL,
                added_at TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'approved-blacklist',
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                FOREIGN KEY (decision_id) REFERENCES admin_decisions(decision_id)
            );
            CREATE TABLE IF NOT EXISTS analysis_reports (
                report_id TEXT PRIMARY KEY,
                analysis_id TEXT NOT NULL,
                reporter_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                comment TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                request_json TEXT NOT NULL,
                response_json TEXT NOT NULL,
                case_status TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analysis_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                event_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id)
            );
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS review_queue_items (
                item_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL UNIQUE,
                analysis_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('submitted', 'reviewing', 'processed')),
                evidence_snapshot_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (report_id) REFERENCES analysis_reports(report_id),
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id)
            );
            """
        )
        columns = {row[1] for row in self._connection.execute("PRAGMA table_info(admin_decisions)").fetchall()}
        if "analysis_id" not in columns:
            self._connection.execute("ALTER TABLE admin_decisions ADD COLUMN analysis_id TEXT")
        self._connection.commit()
        self._apply_migrations()

    def _apply_migrations(self) -> None:
        """Apply additive SQLite migrations to existing vertical-slice databases."""
        applied = {row[0] for row in self._connection.execute("SELECT version FROM schema_migrations")}
        if 2 in applied:
            return
        statements = (
            """CREATE TABLE IF NOT EXISTS analysis_steps (
                analysis_id TEXT NOT NULL, step_id TEXT NOT NULL, step_json TEXT NOT NULL,
                PRIMARY KEY (analysis_id, step_id),
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id))""",
            """CREATE TABLE IF NOT EXISTS analysis_evidence (
                analysis_id TEXT NOT NULL, evidence_index INTEGER NOT NULL, evidence_json TEXT NOT NULL,
                PRIMARY KEY (analysis_id, evidence_index),
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id))""",
            """CREATE TABLE IF NOT EXISTS analysis_errors (
                analysis_id TEXT NOT NULL, error_index INTEGER NOT NULL, error_json TEXT NOT NULL,
                PRIMARY KEY (analysis_id, error_index),
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id))""",
            """CREATE TABLE IF NOT EXISTS tool_executions (
                analysis_id TEXT NOT NULL, step_id TEXT NOT NULL, target TEXT NOT NULL,
                provider TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'skipped')),
                attempt_count INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL,
                PRIMARY KEY (analysis_id, step_id, target, provider),
                FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id))""",
            """CREATE TABLE IF NOT EXISTS outbox_events (
                outbox_id TEXT PRIMARY KEY, event_key TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL, payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL, published_at TEXT)""",
            """CREATE TABLE IF NOT EXISTS analysis_migration_errors (
                analysis_id TEXT PRIMARY KEY, error_code TEXT NOT NULL,
                hidden INTEGER NOT NULL CHECK (hidden IN (0, 1)), recorded_at TEXT NOT NULL)""",
        )
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            for statement in statements:
                self._connection.execute(statement)
            rows = self._connection.execute("SELECT analysis_id, response_json, created_at FROM analyses").fetchall()
            for analysis_id, response_json, created_at in rows:
                try:
                    payload = json.loads(response_json)
                    if not isinstance(payload, dict):
                        raise ValueError("analysis response must be a JSON object")
                    payload["contract_version"] = "v2"
                    payload.setdefault("investigation_plan", [])
                    upgraded = AnalysisResponse.model_validate(payload)
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    self._quarantine_analysis_migration(analysis_id, created_at, exc)
                    continue
                self._connection.execute(
                    "UPDATE analyses SET response_json = ? WHERE analysis_id = ?",
                    (upgraded.model_dump_json(), analysis_id),
                )
                self._replace_analysis_artifacts(upgraded, [])
            self._connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (2, ?)",
                (datetime.now(UTC).isoformat(),),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def _quarantine_analysis_migration(self, analysis_id: str, created_at: str, exc: Exception) -> None:
        try:
            identifier = UUID(analysis_id)
            timestamp = datetime.fromisoformat(created_at).astimezone(UTC)
        except (TypeError, ValueError):
            self._record_migration_error(analysis_id, exc, hidden=True)
            return
        self._record_migration_error(analysis_id, exc, hidden=False)
        failed = AnalysisResponse(analysis_id=identifier, status="failed", created_at=timestamp)
        self._connection.execute(
            "UPDATE analyses SET response_json = ?, case_status = NULL WHERE analysis_id = ?",
            (failed.model_dump_json(), analysis_id),
        )

    def _record_migration_error(self, analysis_id: str, exc: Exception, *, hidden: bool) -> None:
        self._connection.execute(
            """INSERT OR REPLACE INTO analysis_migration_errors(
                   analysis_id, error_code, hidden, recorded_at
               ) VALUES (?, ?, ?, ?)""",
            (analysis_id, type(exc).__name__, int(hidden), datetime.now(UTC).isoformat()),
        )

    async def get(self, domain: str) -> BlacklistLookupEntry | None:
        normalized = normalize_domain(domain)
        async with self._lock:
            row = self._connection.execute(
                """
                SELECT b.domain, b.decision_id, b.source, b.added_at, b.active
                FROM blacklist AS b
                JOIN admin_decisions AS d ON d.decision_id = b.decision_id
                WHERE b.domain = ? AND b.active = 1
                  AND d.decision = 'approved' AND d.action = 'add_to_blacklist'
                """,
                (normalized,),
            ).fetchone()
        if row is None:
            return None
        return BlacklistLookupEntry(
            domain=row[0],
            decision_id=row[1],
            source=row[2],
            added_at=datetime.fromisoformat(row[3]).astimezone(UTC),
            active=bool(row[4]),
        )

    async def record_decision(
        self,
        *,
        decision_id: str,
        reviewer_id: str,
        decision: str,
        action: str,
        note: str,
    ) -> None:
        await self.apply_decision(
            decision_id=decision_id,
            analysis_id=None,
            reviewer_id=reviewer_id,
            decision=decision,
            action=action,
            note=note,
            domains=(),
        )

    async def apply_decision(
        self,
        *,
        decision_id: str,
        analysis_id: str | None,
        reviewer_id: str,
        decision: str,
        action: str,
        note: str,
        domains: tuple[str, ...] | list[str],
    ) -> None:
        normalized_domains = sorted({normalize_domain(domain) for domain in domains})
        values = (decision_id.strip(), reviewer_id.strip(), decision, action, note.strip())
        if not all(values):
            raise ValueError("all decision audit fields are required")
        if decision not in {"approved", "rejected"} or action not in {"add_to_blacklist", "none"}:
            raise ValueError("invalid decision or action")
        if action == "add_to_blacklist" and decision != "approved":
            raise ValueError("blacklist action requires an approved decision")
        if action != "add_to_blacklist" and normalized_domains:
            raise ValueError("blacklist domains require add_to_blacklist action")
        now = datetime.now(UTC).isoformat()
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                self._connection.execute(
                    """
                    INSERT INTO admin_decisions(
                        decision_id, analysis_id, reviewer_id, decision, action, note, decided_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (values[0], analysis_id, *values[1:], now),
                )
                for domain in normalized_domains:
                    self._connection.execute(
                        """
                        INSERT INTO blacklist(domain, decision_id, added_at) VALUES (?, ?, ?)
                        ON CONFLICT(domain) DO NOTHING
                        """,
                        (domain, values[0], now),
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    async def apply_review_decision(
        self,
        *,
        decision_id: str,
        analysis_id: str,
        reviewer_id: str,
        decision: str,
        action: str,
        note: str,
        domains: tuple[str, ...] | list[str],
        response: AnalysisResponse,
        event: AnalysisEvent,
    ) -> None:
        """Atomically persist audit, blacklist writes, case state, event and outbox."""
        normalized_domains = sorted({normalize_domain(domain) for domain in domains})
        values = (decision_id.strip(), analysis_id.strip(), reviewer_id.strip(), decision, action, note.strip())
        if not all(values):
            raise ValueError("all review decision fields are required")
        if action == "add_to_blacklist" and decision != "approved":
            raise ValueError("blacklist action requires an approved decision")
        if action != "add_to_blacklist" and normalized_domains:
            raise ValueError("blacklist domains require add_to_blacklist action")
        now = event.occurred_at.isoformat()
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                self._connection.execute(
                    """INSERT INTO admin_decisions(
                           decision_id, analysis_id, reviewer_id, decision, action, note, decided_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (*values, now),
                )
                for domain in normalized_domains:
                    self._connection.execute(
                        """INSERT INTO blacklist(domain, decision_id, added_at)
                           VALUES (?, ?, ?) ON CONFLICT(domain) DO NOTHING""",
                        (domain, values[0], now),
                    )
                cursor = self._connection.execute(
                    "UPDATE analyses SET response_json = ?, case_status = ? WHERE analysis_id = ?",
                    (response.model_dump_json(), response.case_status.value, analysis_id),
                )
                if cursor.rowcount != 1:
                    raise LookupError("analysis is not persisted")
                self._insert_event(event)
                self._insert_outbox(
                    event_key=f"admin-decision:{decision_id}",
                    event_type="admin.decision.applied",
                    payload={"analysis_id": analysis_id, "decision_id": decision_id, "action": action},
                    created_at=event.occurred_at,
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    async def record_report(
        self,
        *,
        report_id: str,
        analysis_id: str,
        reporter_id: str,
        reason: str,
        comment: str | None,
        created_at: datetime,
        evidence_snapshot: list[Evidence],
    ) -> None:
        async with self._lock:
            self._connection.execute(
                """
                INSERT INTO analysis_reports(
                    report_id, analysis_id, reporter_id, reason, comment, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (report_id, analysis_id, reporter_id, reason.strip(), comment, created_at.isoformat()),
            )
            self._connection.execute(
                """
                INSERT INTO review_queue_items(
                    item_id, report_id, analysis_id, status, evidence_snapshot_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    report_id,
                    analysis_id,
                    ReportStatus.SUBMITTED.value,
                    json.dumps([e.model_dump() for e in evidence_snapshot]),
                    created_at.isoformat(),
                    created_at.isoformat(),
                ),
            )
            self._connection.commit()

    async def list_review_queue_items(self) -> list[ReviewQueueItem]:
        async with self._lock:
            rows = self._connection.execute(
                """
                SELECT r.item_id, r.report_id, r.analysis_id, r.status, r.evidence_snapshot_json, r.created_at, r.updated_at, a.reason, a.comment, an.request_json
                FROM review_queue_items r
                JOIN analysis_reports a ON r.report_id = a.report_id
                JOIN analyses an ON r.analysis_id = an.analysis_id
                ORDER BY r.created_at ASC
                """
            ).fetchall()
            return [
                ReviewQueueItem(
                    item_id=UUID(row[0]),
                    report_id=UUID(row[1]),
                    analysis_id=UUID(row[2]),
                    status=ReportStatus(row[3]),
                    evidence_snapshot=[Evidence.model_validate(e) for e in json.loads(row[4])],
                    created_at=datetime.fromisoformat(row[5]),
                    updated_at=datetime.fromisoformat(row[6]),
                    reason=row[7],
                    comment=row[8],
                    analysis_content=json.loads(row[9]).get("message"),
                )
                for row in rows
            ]

    async def get_review_queue_item(self, item_id: str) -> ReviewQueueItem | None:
        async with self._lock:
            row = self._connection.execute(
                """
                SELECT r.item_id, r.report_id, r.analysis_id, r.status, r.evidence_snapshot_json, r.created_at, r.updated_at, a.reason, a.comment, an.request_json
                FROM review_queue_items r
                JOIN analysis_reports a ON r.report_id = a.report_id
                JOIN analyses an ON r.analysis_id = an.analysis_id
                WHERE r.item_id = ?
                """,
                (item_id,),
            ).fetchone()
            if not row:
                return None
            return ReviewQueueItem(
                item_id=UUID(row[0]),
                report_id=UUID(row[1]),
                analysis_id=UUID(row[2]),
                status=ReportStatus(row[3]),
                evidence_snapshot=[Evidence.model_validate(e) for e in json.loads(row[4])],
                created_at=datetime.fromisoformat(row[5]),
                updated_at=datetime.fromisoformat(row[6]),
                reason=row[7],
                comment=row[8],
                analysis_content=json.loads(row[9]).get("message"),
            )

    async def update_review_queue_item_status(self, item_id: str, status: ReportStatus) -> None:
        async with self._lock:
            self._connection.execute(
                """
                UPDATE review_queue_items
                SET status = ?, updated_at = ?
                WHERE item_id = ?
                """,
                (status.value, datetime.now(UTC).isoformat(), item_id),
            )
            self._connection.commit()


    async def create_analysis(
        self,
        *,
        owner_id: str,
        request: AnalysisCreateRequest,
        response: AnalysisResponse,
        event: AnalysisEvent,
    ) -> None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                self._connection.execute(
                    """
                    INSERT INTO analyses(
                        analysis_id, owner_id, request_json, response_json, case_status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(response.analysis_id),
                        owner_id,
                        request.model_dump_json(),
                        response.model_dump_json(),
                        response.case_status.value if response.case_status else None,
                        response.created_at.isoformat(),
                    ),
                )
                self._insert_event(event)
                self._insert_outbox(
                    event_key=f"analysis-queued:{response.analysis_id}",
                    event_type="analysis.queued",
                    payload={"analysis_id": str(response.analysis_id), "status": response.status.value},
                    created_at=event.occurred_at,
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    async def update_analysis(self, response: AnalysisResponse, event: AnalysisEvent) -> None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                cursor = self._connection.execute(
                    """
                    UPDATE analyses SET response_json = ?, case_status = ? WHERE analysis_id = ?
                    """,
                    (
                        response.model_dump_json(),
                        response.case_status.value if response.case_status else None,
                        str(response.analysis_id),
                    ),
                )
                if cursor.rowcount != 1:
                    raise LookupError("analysis is not persisted")
                self._replace_analysis_artifacts(response, [])
                self._insert_event(event)
                self._insert_event_outbox(event)
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    async def append_analysis_event(self, event: AnalysisEvent) -> None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                self._insert_event(event)
                self._insert_event_outbox(event)
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    async def complete_analysis(
        self,
        response: AnalysisResponse,
        event: AnalysisEvent,
        errors: list[ToolError],
    ) -> None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                cursor = self._connection.execute(
                    "UPDATE analyses SET response_json = ?, case_status = ? WHERE analysis_id = ?",
                    (
                        response.model_dump_json(),
                        response.case_status.value if response.case_status else None,
                        str(response.analysis_id),
                    ),
                )
                if cursor.rowcount != 1:
                    raise LookupError("analysis is not persisted")
                self._replace_analysis_artifacts(response, errors)
                self._insert_event(event)
                self._insert_event_outbox(event)
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def _replace_analysis_artifacts(self, response: AnalysisResponse, errors: list[ToolError]) -> None:
        analysis_id = str(response.analysis_id)
        self._connection.execute("DELETE FROM analysis_steps WHERE analysis_id = ?", (analysis_id,))
        self._connection.execute("DELETE FROM analysis_evidence WHERE analysis_id = ?", (analysis_id,))
        self._connection.execute("DELETE FROM analysis_errors WHERE analysis_id = ?", (analysis_id,))
        self._connection.executemany(
            "INSERT INTO analysis_steps(analysis_id, step_id, step_json) VALUES (?, ?, ?)",
            [(analysis_id, step.step_id, step.model_dump_json()) for step in response.investigation_plan],
        )
        self._connection.executemany(
            "INSERT INTO analysis_evidence(analysis_id, evidence_index, evidence_json) VALUES (?, ?, ?)",
            [
                (analysis_id, index, evidence.model_dump_json())
                for index, evidence in enumerate(response.evidence or [])
            ],
        )
        self._connection.executemany(
            "INSERT INTO analysis_errors(analysis_id, error_index, error_json) VALUES (?, ?, ?)",
            [(analysis_id, index, error.model_dump_json()) for index, error in enumerate(errors)],
        )

    async def claim_tool_execution(
        self,
        analysis_id: str,
        step_id: str,
        target: str,
        provider: str,
    ) -> bool:
        """Claim one provider call before work is created; completed/running claims dedupe."""
        now = datetime.now(UTC)
        key = (analysis_id, step_id, target, provider)
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                row = self._connection.execute(
                    """SELECT status, attempt_count FROM tool_executions
                       WHERE analysis_id = ? AND step_id = ? AND target = ? AND provider = ?""",
                    key,
                ).fetchone()
                if row is None:
                    attempt = 1
                    self._connection.execute(
                        """INSERT INTO tool_executions(
                               analysis_id, step_id, target, provider, status, attempt_count, updated_at
                           ) VALUES (?, ?, ?, ?, 'running', ?, ?)""",
                        (*key, attempt, now.isoformat()),
                    )
                elif row[0] == "failed":
                    attempt = int(row[1]) + 1
                    self._connection.execute(
                        """UPDATE tool_executions SET status = 'running', attempt_count = ?, updated_at = ?
                           WHERE analysis_id = ? AND step_id = ? AND target = ? AND provider = ?""",
                        (attempt, now.isoformat(), *key),
                    )
                else:
                    self._connection.rollback()
                    return False
                self._insert_outbox(
                    event_key=f"tool-claimed:{analysis_id}:{step_id}:{target}:{provider}:{attempt}",
                    event_type="tool.execution.claimed",
                    payload={
                        "analysis_id": analysis_id,
                        "step_id": step_id,
                        "target": target,
                        "provider": provider,
                        "attempt": attempt,
                    },
                    created_at=now,
                )
                self._connection.commit()
                return True
            except Exception:
                self._connection.rollback()
                raise

    async def finish_tool_execution(
        self,
        analysis_id: str,
        step_id: str,
        target: str,
        provider: str,
        status: str,
    ) -> None:
        if status not in {"completed", "failed", "skipped"}:
            raise ValueError("tool execution status must be terminal")
        now = datetime.now(UTC)
        key = (analysis_id, step_id, target, provider)
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                cursor = self._connection.execute(
                    """UPDATE tool_executions SET status = ?, updated_at = ?
                       WHERE analysis_id = ? AND step_id = ? AND target = ? AND provider = ?""",
                    (status, now.isoformat(), *key),
                )
                if cursor.rowcount != 1:
                    raise LookupError("tool execution was not claimed")
                self._insert_outbox(
                    event_key=f"tool-finished:{analysis_id}:{step_id}:{target}:{provider}:{status}:{now.isoformat()}",
                    event_type="tool.execution.finished",
                    payload={
                        "analysis_id": analysis_id,
                        "step_id": step_id,
                        "target": target,
                        "provider": provider,
                        "status": status,
                    },
                    created_at=now,
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    async def load_analysis(
        self,
        analysis_id: str,
    ) -> tuple[str, AnalysisCreateRequest, AnalysisResponse, list[AnalysisEvent]] | None:
        async with self._lock:
            row = self._connection.execute(
                """SELECT owner_id, request_json, response_json FROM analyses
                   WHERE analysis_id = ?
                     AND NOT EXISTS (
                         SELECT 1 FROM analysis_migration_errors AS migration_error
                         WHERE migration_error.analysis_id = analyses.analysis_id
                           AND migration_error.hidden = 1
                     )""",
                (analysis_id,),
            ).fetchone()
            if row is None:
                return None
            event_rows = self._connection.execute(
                # event_id is the monotonic insertion key. This ordering is a
                # contract: the v3 compatibility adapter derives stable
                # per-analysis sequences from the returned append order.
                "SELECT event_json FROM analysis_events WHERE analysis_id = ? ORDER BY event_id ASC",
                (analysis_id,),
            ).fetchall()
        return (
            row[0],
            AnalysisCreateRequest.model_validate_json(row[1]),
            AnalysisResponse.model_validate_json(row[2]),
            [AnalysisEvent.model_validate_json(event_row[0]) for event_row in event_rows],
        )

    async def list_analysis_responses(
        self,
        *,
        owner_id: str | None = None,
        case_status: str | None = None,
    ) -> list[AnalysisResponse]:
        if owner_id is not None and case_status is not None:
            sql = """SELECT response_json FROM analyses
                WHERE owner_id = ? AND case_status = ? AND NOT EXISTS (
                    SELECT 1 FROM analysis_migration_errors AS migration_error
                    WHERE migration_error.analysis_id = analyses.analysis_id
                      AND migration_error.hidden = 1
                )
                ORDER BY created_at DESC"""
            parameters = (owner_id, case_status)
        elif owner_id is not None:
            sql = """SELECT response_json FROM analyses
                WHERE owner_id = ? AND NOT EXISTS (
                    SELECT 1 FROM analysis_migration_errors AS migration_error
                    WHERE migration_error.analysis_id = analyses.analysis_id
                      AND migration_error.hidden = 1
                ) ORDER BY created_at DESC"""
            parameters = (owner_id,)
        elif case_status is not None:
            sql = """SELECT response_json FROM analyses
                WHERE case_status = ? AND NOT EXISTS (
                    SELECT 1 FROM analysis_migration_errors AS migration_error
                    WHERE migration_error.analysis_id = analyses.analysis_id
                      AND migration_error.hidden = 1
                ) ORDER BY created_at DESC"""
            parameters = (case_status,)
        else:
            sql = """SELECT response_json FROM analyses WHERE NOT EXISTS (
                SELECT 1 FROM analysis_migration_errors AS migration_error
                WHERE migration_error.analysis_id = analyses.analysis_id
                  AND migration_error.hidden = 1
            ) ORDER BY created_at DESC"""
            parameters = ()
        async with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return [AnalysisResponse.model_validate_json(row[0]) for row in rows]

    async def load_analysis_artifacts(self, analysis_id: str) -> dict[str, list]:
        """Read normalized v2 artifacts for recovery, audit and tests."""
        async with self._lock:
            step_rows = self._connection.execute(
                "SELECT step_json FROM analysis_steps WHERE analysis_id = ? ORDER BY rowid", (analysis_id,)
            ).fetchall()
            evidence_rows = self._connection.execute(
                """SELECT evidence_json FROM analysis_evidence
                   WHERE analysis_id = ? ORDER BY evidence_index""",
                (analysis_id,),
            ).fetchall()
            error_rows = self._connection.execute(
                "SELECT error_json FROM analysis_errors WHERE analysis_id = ? ORDER BY error_index",
                (analysis_id,),
            ).fetchall()
        return {
            "investigation_plan": [InvestigationStep.model_validate_json(row[0]) for row in step_rows],
            "evidence": [Evidence.model_validate_json(row[0]) for row in evidence_rows],
            "errors": [ToolError.model_validate_json(row[0]) for row in error_rows],
        }

    async def list_tool_executions(self, analysis_id: str) -> list[tuple[str, str, str, str, int]]:
        async with self._lock:
            return self._connection.execute(
                """SELECT step_id, target, provider, status, attempt_count FROM tool_executions
                   WHERE analysis_id = ? ORDER BY step_id, target, provider""",
                (analysis_id,),
            ).fetchall()

    async def list_outbox_events(self) -> list[tuple[str, str, str | None]]:
        async with self._lock:
            return self._connection.execute(
                "SELECT event_key, event_type, published_at FROM outbox_events ORDER BY created_at, rowid"
            ).fetchall()

    async def list_migration_errors(self) -> list[tuple[str, str, bool]]:
        async with self._lock:
            rows = self._connection.execute(
                """SELECT analysis_id, error_code, hidden
                   FROM analysis_migration_errors ORDER BY analysis_id"""
            ).fetchall()
        return [(analysis_id, error_code, bool(hidden)) for analysis_id, error_code, hidden in rows]

    def _insert_event(self, event: AnalysisEvent) -> None:
        self._connection.execute(
            """
            INSERT INTO analysis_events(analysis_id, event_json, occurred_at) VALUES (?, ?, ?)
            """,
            (str(event.analysis_id), event.model_dump_json(), event.occurred_at.isoformat()),
        )

    def _insert_event_outbox(self, event: AnalysisEvent) -> None:
        self._insert_outbox(
            event_key=(
                f"analysis-event:{event.analysis_id}:{event.step}:"
                f"{event.step_id or '-'}:{event.step_status.value if event.step_status else '-'}:"
                f"{event.occurred_at.isoformat()}"
            ),
            event_type="analysis.progressed",
            payload=event.model_dump(mode="json"),
            created_at=event.occurred_at,
        )

    def _insert_outbox(
        self,
        *,
        event_key: str,
        event_type: str,
        payload: dict,
        created_at: datetime,
    ) -> None:
        self._connection.execute(
            """INSERT INTO outbox_events(
                   outbox_id, event_key, event_type, payload_json, created_at
               ) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(event_key) DO NOTHING""",
            (str(uuid4()), event_key, event_type, json.dumps(payload, ensure_ascii=False), created_at.isoformat()),
        )

    async def list_reports(self, *, limit: int, offset: int) -> list[AnalysisReportRecord]:
        async with self._lock:
            rows = self._connection.execute(
                """
                SELECT report_id, analysis_id, reporter_id, reason, comment, created_at
                FROM analysis_reports ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [
            AnalysisReportRecord(
                report_id=UUID(row[0]),
                analysis_id=UUID(row[1]),
                reporter_id=row[2],
                reason=row[3],
                comment=row[4],
                created_at=datetime.fromisoformat(row[5]),
            )
            for row in rows
        ]

    async def list_reports_by_analysis(self, analysis_id: str) -> list[AnalysisReportResponse]:
        async with self._lock:
            rows = self._connection.execute(
                """
                SELECT r.report_id, r.analysis_id, r.created_at, q.status
                FROM analysis_reports r
                LEFT JOIN review_queue_items q ON r.report_id = q.report_id
                WHERE r.analysis_id = ?
                ORDER BY r.created_at DESC
                """,
                (analysis_id,),
            ).fetchall()
        return [
            AnalysisReportResponse(
                report_id=UUID(row[0]),
                analysis_id=UUID(row[1]),
                created_at=datetime.fromisoformat(row[2]),
                status=ReportStatus(row[3] or ReportStatus.SUBMITTED.value),
            )
            for row in rows
        ]

    async def list_decisions(self, *, limit: int, offset: int) -> list[AdminDecisionAudit]:
        async with self._lock:
            rows = self._connection.execute(
                """
                SELECT decision_id, analysis_id, reviewer_id, decision, action, note, decided_at
                FROM admin_decisions ORDER BY decided_at DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [
            AdminDecisionAudit(
                decision_id=UUID(row[0]),
                analysis_id=UUID(row[1]) if row[1] else None,
                reviewer_id=row[2],
                decision=ReviewDecision(row[3]),
                action=ReviewAction(row[4]),
                note=row[5],
                decided_at=datetime.fromisoformat(row[6]),
            )
            for row in rows
        ]

    async def list_blacklist(
        self,
        *,
        query: str | None,
        limit: int,
        offset: int,
    ) -> list[BlacklistEntry]:
        sql = "SELECT domain, decision_id, added_at FROM blacklist"
        parameters: list[str | int] = []
        if query:
            sql += " WHERE domain LIKE ?"
            parameters.append(f"%{query.strip().casefold()}%")
        sql += " ORDER BY added_at DESC LIMIT ? OFFSET ?"
        parameters.extend((limit, offset))
        async with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return [
            BlacklistEntry(
                domain=row[0],
                decision_id=UUID(row[1]),
                added_at=datetime.fromisoformat(row[2]),
            )
            for row in rows
        ]

    async def contains(self, domain: str) -> bool:
        return await self.get(domain) is not None

    async def add_approved(self, domain: str, decision_id: str) -> None:
        normalized = normalize_domain(domain)
        decision_id = decision_id.strip()
        if not decision_id:
            raise ValueError("decision_id is required")
        async with self._lock:
            row = self._connection.execute(
                "SELECT decision, action FROM admin_decisions WHERE decision_id = ?", (decision_id,)
            ).fetchone()
            if row != ("approved", "add_to_blacklist"):
                raise PermissionError("an audited approved blacklist decision is required")
            try:
                self._connection.execute(
                    """INSERT INTO blacklist(domain, decision_id, added_at, source, active)
                       VALUES (?, ?, ?, 'approved-blacklist', 1)""",
                    (normalized, decision_id, datetime.now(UTC).isoformat()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise ValueError("domain or decision is already recorded") from exc

    async def close(self) -> None:
        async with self._lock:
            self._connection.close()
