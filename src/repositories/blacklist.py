from __future__ import annotations

import asyncio
import ipaddress
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST
from src.models import (
    AdminDecisionAudit,
    AnalysisCreateRequest,
    AnalysisEvent,
    AnalysisReportRecord,
    AnalysisResponse,
    BlacklistEntry,
    BlacklistLookupEntry,
    ReviewAction,
    ReviewDecision,
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
            """
        )
        columns = {row[1] for row in self._connection.execute("PRAGMA table_info(admin_decisions)").fetchall()}
        if "analysis_id" not in columns:
            self._connection.execute("ALTER TABLE admin_decisions ADD COLUMN analysis_id TEXT")
        self._connection.commit()

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

    async def record_report(
        self,
        *,
        report_id: str,
        analysis_id: str,
        reporter_id: str,
        reason: str,
        comment: str | None,
        created_at: datetime,
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
                self._insert_event(event)
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
                "SELECT owner_id, request_json, response_json FROM analyses WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            if row is None:
                return None
            event_rows = self._connection.execute(
                "SELECT event_json FROM analysis_events WHERE analysis_id = ? ORDER BY event_id",
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
        clauses: list[str] = []
        parameters: list[str] = []
        if owner_id is not None:
            clauses.append("owner_id = ?")
            parameters.append(owner_id)
        if case_status is not None:
            clauses.append("case_status = ?")
            parameters.append(case_status)
        sql = "SELECT response_json FROM analyses"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC"
        async with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return [AnalysisResponse.model_validate_json(row[0]) for row in rows]

    def _insert_event(self, event: AnalysisEvent) -> None:
        self._connection.execute(
            """
            INSERT INTO analysis_events(analysis_id, event_json, occurred_at) VALUES (?, ?, ?)
            """,
            (str(event.analysis_id), event.model_dump_json(), event.occurred_at.isoformat()),
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
