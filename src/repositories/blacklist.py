from __future__ import annotations

import asyncio
import ipaddress
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST
from src.core.errors import PlatformError
from src.models import (
    AdminDecisionAudit,
    AnalysisCreateRequest,
    AnalysisCreateRequestV3,
    AnalysisEvent,
    AnalysisReportRecord,
    AnalysisReportResponse,
    AnalysisResponse,
    AppealOutcome,
    AppealStatus,
    BlacklistEntry,
    BlacklistLookupEntry,
    BrandRecordV4,
    ErrorCode,
    Evidence,
    InvestigationStep,
    ReportReviewDecision,
    ReportStatus,
    ReviewAction,
    ReviewDecision,
    ReviewQueueItem,
    SecurityAdminAuditEventV4,
    SecurityAnalysisEventV4,
    SecurityAppealAdminRecordV4,
    SecurityAppealRecordV4,
    SecurityAuditResourceV4,
    SecurityCampaignAuditRecordV4,
    SecurityCampaignRecordV4,
    SecurityCampaignReviewerStatusV4,
    SecurityConversationV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryAuditRecordV4,
    SecurityMemoryRecordV4,
    SecurityReportAdminRecordV4,
    SecurityReportRecordV4,
    SecurityScopeResponseV4,
    ToolError,
    TrustLifecycleV4,
    WhitelistRecordV4,
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
            CREATE TABLE IF NOT EXISTS security_analyses (
                analysis_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                response_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
                policy_version TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS security_analysis_events (
                analysis_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence >= 1),
                event_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                PRIMARY KEY (analysis_id, sequence),
                FOREIGN KEY (analysis_id) REFERENCES security_analyses(analysis_id)
            );
            CREATE TABLE IF NOT EXISTS security_conversations (
                conversation_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'expired')),
                active_analysis_id TEXT NOT NULL,
                context_version INTEGER NOT NULL CHECK (context_version >= 1),
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_security_conversations_owner_updated
                ON security_conversations(owner_id, updated_at);
            CREATE TABLE IF NOT EXISTS security_conversation_turns (
                conversation_id TEXT NOT NULL,
                context_version INTEGER NOT NULL,
                analysis_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                PRIMARY KEY (conversation_id, context_version),
                FOREIGN KEY (conversation_id) REFERENCES security_conversations(conversation_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS security_analysis_reports_v4 (
                report_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'submitted'
                    CHECK(status IN ('submitted','reviewing','processed')),
                record_json TEXT NOT NULL, created_at TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES security_analyses(analysis_id)
            );
            CREATE TABLE IF NOT EXISTS security_analysis_appeals_v4 (
                appeal_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('submitted','under_review','resolved')),
                record_json TEXT NOT NULL, created_at TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES security_analyses(analysis_id)
            );
            CREATE TABLE IF NOT EXISTS security_tool_executions (
                analysis_id TEXT NOT NULL, step_id TEXT NOT NULL, target_ref TEXT NOT NULL,
                provider TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'skipped')),
                attempt_count INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL,
                PRIMARY KEY (analysis_id, step_id, target_ref, provider)
            );
            CREATE TABLE IF NOT EXISTS security_brands (
                brand_id TEXT PRIMARY KEY, record_json TEXT NOT NULL, lifecycle TEXT NOT NULL,
                effective_from TEXT NOT NULL, effective_until TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_whitelist (
                whitelist_id TEXT PRIMARY KEY, scope TEXT NOT NULL, indicator TEXT NOT NULL,
                record_json TEXT NOT NULL, lifecycle TEXT NOT NULL,
                effective_from TEXT NOT NULL, effective_until TEXT, created_at TEXT NOT NULL,
                UNIQUE(scope, indicator, effective_from)
            );
            CREATE TABLE IF NOT EXISTS security_trust_audit (
                audit_id TEXT PRIMARY KEY, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
                action TEXT NOT NULL, reviewer_id TEXT NOT NULL, occurred_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_memory (
                memory_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL, admin_verdict TEXT NOT NULL,
                first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
                report_count INTEGER NOT NULL DEFAULT 0 CHECK(report_count >= 0),
                fingerprint_version TEXT NOT NULL, risk_policy_version TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES security_analyses(analysis_id)
            );
            CREATE INDEX IF NOT EXISTS ix_security_appeals_v4_status_created
                ON security_analysis_appeals_v4(status, created_at DESC);
            CREATE TABLE IF NOT EXISTS security_feedback_audit_v4 (
                audit_id TEXT PRIMARY KEY, resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL, action TEXT NOT NULL, actor_id TEXT NOT NULL,
                note TEXT, evidence_refs_json TEXT NOT NULL, occurred_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_security_feedback_audit_time
                ON security_feedback_audit_v4(occurred_at DESC);
            CREATE INDEX IF NOT EXISTS ix_security_memory_seen
                ON security_memory(last_seen_at DESC);
            CREATE TABLE IF NOT EXISTS security_memory_audit (
                audit_id TEXT PRIMARY KEY, memory_id TEXT NOT NULL,
                record_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
                FOREIGN KEY (memory_id) REFERENCES security_memory(memory_id)
            );
            CREATE TABLE IF NOT EXISTS security_campaigns (
                campaign_id TEXT PRIMARY KEY, record_json TEXT NOT NULL,
                reviewer_status TEXT NOT NULL CHECK(reviewer_status IN ('pending_review','confirmed','rejected')),
                window_started_at TEXT NOT NULL, window_ended_at TEXT NOT NULL,
                clustering_version TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_security_campaigns_status_window
                ON security_campaigns(reviewer_status, window_ended_at DESC);
            CREATE TABLE IF NOT EXISTS security_campaign_members (
                campaign_id TEXT NOT NULL, analysis_id TEXT NOT NULL,
                PRIMARY KEY(campaign_id, analysis_id),
                FOREIGN KEY (campaign_id) REFERENCES security_campaigns(campaign_id),
                FOREIGN KEY (analysis_id) REFERENCES security_analyses(analysis_id)
            );
            CREATE TABLE IF NOT EXISTS security_campaign_audit (
                audit_id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL,
                record_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES security_campaigns(campaign_id)
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
                decision TEXT,
                reviewer_id TEXT,
                reviewer_note TEXT,
                reviewed_at TEXT,
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
        report_columns = {
            row[1] for row in self._connection.execute("PRAGMA table_info(security_analysis_reports_v4)")
        }
        if "status" not in report_columns:
            self._connection.execute(
                "ALTER TABLE security_analysis_reports_v4 ADD COLUMN status TEXT NOT NULL DEFAULT 'submitted'"
            )
        self._connection.execute(
            """CREATE INDEX IF NOT EXISTS ix_security_reports_v4_status_created
               ON security_analysis_reports_v4(status, created_at DESC)"""
        )
        self._connection.commit()
        self._apply_migrations()

    def _apply_migrations(self) -> None:
        """Apply additive SQLite migrations to existing vertical-slice databases."""
        applied = {row[0] for row in self._connection.execute("SELECT version FROM schema_migrations")}
        if 2 not in applied:
            self._apply_v2_migration()
        if 3 not in applied:
            self._apply_review_queue_migration()

    def _apply_v2_migration(self) -> None:
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

    def _apply_review_queue_migration(self) -> None:
        """Add review audit fields atomically to pre-review-queue SQLite databases."""
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in self._connection.execute("PRAGMA table_info(review_queue_items)").fetchall()}
            for column, definition in (
                ("decision", "TEXT"),
                ("reviewer_id", "TEXT"),
                ("reviewer_note", "TEXT"),
                ("reviewed_at", "TEXT"),
            ):
                if column not in columns:
                    self._connection.execute(f"ALTER TABLE review_queue_items ADD COLUMN {column} {definition}")
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (3, ?)",
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

    async def create_brand(self, record: BrandRecordV4) -> None:
        async with self._lock:
            self._connection.execute(
                """INSERT INTO security_brands(
                       brand_id,record_json,lifecycle,effective_from,effective_until,created_at
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    str(record.brand_id), record.model_dump_json(), record.lifecycle.value,
                    record.effective_from.isoformat(),
                    record.effective_until.isoformat() if record.effective_until else None,
                    record.created_at.isoformat(),
                ),
            )
            self._trust_audit("brand", str(record.brand_id), "created", record.reviewer_id, record.created_at)
            self._connection.commit()

    async def list_brands(self) -> list[BrandRecordV4]:
        async with self._lock:
            rows = self._connection.execute("SELECT record_json FROM security_brands ORDER BY created_at").fetchall()
        return [BrandRecordV4.model_validate_json(row[0]) for row in rows]

    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]:
        return [
            item for item in await self.list_brands()
            if item.lifecycle is TrustLifecycleV4.ACTIVE
            and item.effective_from <= at
            and (item.effective_until is None or at < item.effective_until)
        ]

    async def disable_brand(self, brand_id: str, reviewer_id: str, at: datetime) -> BrandRecordV4 | None:
        async with self._lock:
            row = self._connection.execute(
                "SELECT record_json FROM security_brands WHERE brand_id=?", (brand_id,)
            ).fetchone()
            if row is None:
                return None
            record = BrandRecordV4.model_validate_json(row[0]).model_copy(
                update={"lifecycle": TrustLifecycleV4.DISABLED, "reviewer_id": reviewer_id}
            )
            self._connection.execute(
                "UPDATE security_brands SET record_json=?, lifecycle=? WHERE brand_id=?",
                (record.model_dump_json(), record.lifecycle.value, brand_id),
            )
            self._trust_audit("brand", brand_id, "disabled", reviewer_id, at)
            self._connection.commit()
        return record

    async def create_whitelist(self, record: WhitelistRecordV4) -> None:
        async with self._lock:
            self._connection.execute(
                """INSERT INTO security_whitelist(
                       whitelist_id,scope,indicator,record_json,lifecycle,effective_from,effective_until,created_at
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    str(record.whitelist_id), record.scope.value, record.indicator, record.model_dump_json(),
                    record.lifecycle.value, record.effective_from.isoformat(),
                    record.effective_until.isoformat() if record.effective_until else None,
                    record.created_at.isoformat(),
                ),
            )
            self._trust_audit(
                "whitelist", str(record.whitelist_id), "created", record.reviewer_id, record.created_at
            )
            self._connection.commit()

    async def list_whitelist(self) -> list[WhitelistRecordV4]:
        async with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM security_whitelist ORDER BY created_at"
            ).fetchall()
        return [WhitelistRecordV4.model_validate_json(row[0]) for row in rows]

    async def list_active_whitelist(self, at: datetime) -> list[WhitelistRecordV4]:
        return [
            item for item in await self.list_whitelist()
            if item.lifecycle is TrustLifecycleV4.ACTIVE
            and item.effective_from <= at
            and (item.effective_until is None or at < item.effective_until)
        ]

    async def disable_whitelist(
        self, whitelist_id: str, reviewer_id: str, at: datetime
    ) -> WhitelistRecordV4 | None:
        async with self._lock:
            row = self._connection.execute(
                "SELECT record_json FROM security_whitelist WHERE whitelist_id=?", (whitelist_id,)
            ).fetchone()
            if row is None:
                return None
            record = WhitelistRecordV4.model_validate_json(row[0]).model_copy(
                update={"lifecycle": TrustLifecycleV4.DISABLED, "reviewer_id": reviewer_id}
            )
            self._connection.execute(
                "UPDATE security_whitelist SET record_json=?, lifecycle=? WHERE whitelist_id=?",
                (record.model_dump_json(), record.lifecycle.value, whitelist_id),
            )
            self._trust_audit("whitelist", whitelist_id, "disabled", reviewer_id, at)
            self._connection.commit()
        return record

    def _trust_audit(
        self, resource_type: str, resource_id: str, action: str, reviewer_id: str, occurred_at: datetime
    ) -> None:
        self._connection.execute(
            """INSERT INTO security_trust_audit(
                   audit_id,resource_type,resource_id,action,reviewer_id,occurred_at
               ) VALUES(?,?,?,?,?,?)""",
            (str(uuid4()), resource_type, resource_id, action, reviewer_id, occurred_at.isoformat()),
        )

    async def save_security_analysis(
        self,
        owner_id: str,
        response: SecurityScopeResponseV4,
        events: list[SecurityAnalysisEventV4],
    ) -> None:
        """Persist v4 output separately; raw user messages and credentials are never stored."""
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                self._connection.execute(
                    """INSERT INTO security_analyses(
                           analysis_id, owner_id, response_json, status, policy_version, created_at, completed_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(analysis_id) DO UPDATE SET
                         response_json=excluded.response_json, status=excluded.status,
                         policy_version=excluded.policy_version, completed_at=excluded.completed_at""",
                    (
                        str(response.analysis_id),
                        owner_id,
                        response.model_dump_json(),
                        response.status.value,
                        response.policy_version,
                        response.created_at.isoformat(),
                        response.completed_at.isoformat() if response.completed_at else None,
                    ),
                )
                for event in events:
                    self._connection.execute(
                        """INSERT OR IGNORE INTO security_analysis_events(
                               analysis_id, sequence, event_json, occurred_at
                           ) VALUES (?, ?, ?, ?)""",
                        (
                            str(response.analysis_id),
                            event.sequence,
                            event.model_dump_json(),
                            event.occurred_at.isoformat(),
                        ),
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    async def save_security_conversation(
        self,
        owner_id: str,
        record: SecurityConversationV4,
        *,
        expected_version: int | None,
    ) -> None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                if expected_version is None:
                    cursor = self._connection.execute(
                        """INSERT OR IGNORE INTO security_conversations(
                               conversation_id,owner_id,status,active_analysis_id,context_version,
                               record_json,created_at,updated_at,expires_at
                           ) VALUES(?,?,?,?,?,?,?,?,?)""",
                        (
                            str(record.conversation_id), owner_id, record.status.value,
                            str(record.active_analysis_id), record.context_version, record.model_dump_json(),
                            record.created_at.isoformat(), record.updated_at.isoformat(), record.expires_at.isoformat(),
                        ),
                    )
                else:
                    cursor = self._connection.execute(
                        """UPDATE security_conversations SET status=?,active_analysis_id=?,context_version=?,
                               record_json=?,updated_at=?,expires_at=?
                           WHERE conversation_id=? AND owner_id=? AND context_version=?""",
                        (
                            record.status.value, str(record.active_analysis_id), record.context_version,
                            record.model_dump_json(), record.updated_at.isoformat(), record.expires_at.isoformat(),
                            str(record.conversation_id), owner_id, expected_version,
                        ),
                    )
                if cursor.rowcount != 1:
                    raise RuntimeError("SECURITY_CONVERSATION_VERSION_CONFLICT")
                self._connection.execute(
                    """INSERT INTO security_conversation_turns(
                           conversation_id,context_version,analysis_id,created_at
                       ) VALUES(?,?,?,?)""",
                    (str(record.conversation_id), record.context_version, str(record.active_analysis_id), record.updated_at.isoformat()),
                )
                self._connection.commit()
            except Exception as exc:
                self._connection.rollback()
                if isinstance(exc, RuntimeError) and str(exc) == "SECURITY_CONVERSATION_VERSION_CONFLICT":
                    raise PlatformError(
                        status_code=409, code=ErrorCode.CONFLICT,
                        message="Security conversation was updated by another turn.", retryable=True,
                    ) from exc
                raise

    async def finalize_security_conversation(
        self, owner_id: str, record: SecurityConversationV4
    ) -> None:
        async with self._lock:
            self._connection.execute(
                """UPDATE security_conversations SET record_json=?,updated_at=?
                   WHERE conversation_id=? AND owner_id=? AND context_version=?""",
                (record.model_dump_json(), record.updated_at.isoformat(), str(record.conversation_id), owner_id, record.context_version),
            )
            self._connection.commit()

    async def load_security_conversation(
        self, conversation_id: str
    ) -> tuple[str, SecurityConversationV4] | None:
        async with self._lock:
            row = self._connection.execute(
                "SELECT owner_id,record_json FROM security_conversations WHERE conversation_id=?",
                (conversation_id,),
            ).fetchone()
        if row is None:
            return None
        return row[0], SecurityConversationV4.model_validate_json(row[1])

    async def list_security_conversations(self, owner_id: str) -> list[SecurityConversationV4]:
        async with self._lock:
            rows = self._connection.execute(
                """SELECT record_json FROM security_conversations
                   WHERE owner_id=? ORDER BY updated_at DESC""",
                (owner_id,),
            ).fetchall()
        return [SecurityConversationV4.model_validate_json(row[0]) for row in rows]

    async def expire_security_conversations(self, cutoff: datetime) -> int:
        async with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """DELETE FROM security_conversation_turns WHERE conversation_id IN (
                           SELECT conversation_id FROM security_conversations WHERE expires_at <= ?
                       )""",
                    (cutoff.isoformat(),),
                )
                cursor = self._connection.execute(
                    "DELETE FROM security_conversations WHERE expires_at <= ?", (cutoff.isoformat(),)
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return cursor.rowcount

    async def load_security_analysis(
        self, analysis_id: str
    ) -> tuple[str, SecurityScopeResponseV4, list[SecurityAnalysisEventV4]] | None:
        async with self._lock:
            row = self._connection.execute(
                "SELECT owner_id, response_json FROM security_analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
            if row is None:
                return None
            event_rows = self._connection.execute(
                """SELECT event_json FROM security_analysis_events
                   WHERE analysis_id = ? ORDER BY sequence""",
                (analysis_id,),
            ).fetchall()
        return (
            row[0],
            SecurityScopeResponseV4.model_validate_json(row[1]),
            [SecurityAnalysisEventV4.model_validate_json(item[0]) for item in event_rows],
        )

    async def list_security_analyses(self, owner_id: str) -> list[SecurityScopeResponseV4]:
        async with self._lock:
            rows = self._connection.execute(
                """SELECT response_json FROM security_analyses
                   WHERE owner_id=? ORDER BY created_at DESC""",
                (owner_id,),
            ).fetchall()
        return [SecurityScopeResponseV4.model_validate_json(row[0]) for row in rows]

    async def upsert_security_memory(self, record: SecurityMemoryRecordV4) -> SecurityMemoryRecordV4:
        async with self._lock:
            self._connection.execute(
                """INSERT OR IGNORE INTO security_memory(
                       memory_id,analysis_id,record_json,admin_verdict,first_seen_at,last_seen_at,
                       report_count,fingerprint_version,risk_policy_version
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    str(record.memory_id), str(record.analysis_id), record.model_dump_json(),
                    record.admin_verdict.value, record.first_seen_at.isoformat(), record.last_seen_at.isoformat(),
                    record.report_count, record.fingerprint_version, record.risk_policy_version,
                ),
            )
            row = self._connection.execute(
                "SELECT record_json FROM security_memory WHERE analysis_id=?", (str(record.analysis_id),)
            ).fetchone()
            self._connection.commit()
        assert row is not None
        return SecurityMemoryRecordV4.model_validate_json(row[0])

    async def recent_security_memory(self, since: datetime) -> list[SecurityMemoryRecordV4]:
        async with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM security_memory WHERE last_seen_at>=? ORDER BY last_seen_at",
                (since.isoformat(),),
            ).fetchall()
        return [SecurityMemoryRecordV4.model_validate_json(row[0]) for row in rows]

    async def list_security_memory(self) -> list[SecurityMemoryRecordV4]:
        async with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM security_memory ORDER BY last_seen_at DESC"
            ).fetchall()
        return [SecurityMemoryRecordV4.model_validate_json(row[0]) for row in rows]

    async def correct_security_memory(
        self,
        memory_id: UUID,
        verdict: SecurityMemoryAdminVerdictV4,
        note: str,
        reviewer_id: str,
        occurred_at: datetime,
    ) -> SecurityMemoryRecordV4 | None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT record_json FROM security_memory WHERE memory_id=?", (str(memory_id),)
                ).fetchone()
                if row is None:
                    self._connection.rollback()
                    return None
                current = SecurityMemoryRecordV4.model_validate_json(row[0])
                updated = current.model_copy(update={"admin_verdict": verdict})
                audit = SecurityMemoryAuditRecordV4(
                    memory_id=memory_id,
                    previous_verdict=current.admin_verdict,
                    verdict=verdict,
                    reviewer_id=reviewer_id,
                    note=note,
                    occurred_at=occurred_at,
                    risk_policy_version=current.risk_policy_version,
                    fingerprint_version=current.fingerprint_version,
                    evidence_refs=current.evidence_refs,
                )
                self._connection.execute(
                    "UPDATE security_memory SET record_json=?,admin_verdict=? WHERE memory_id=?",
                    (updated.model_dump_json(), verdict.value, str(memory_id)),
                )
                self._connection.execute(
                    "INSERT INTO security_memory_audit(audit_id,memory_id,record_json,occurred_at) VALUES(?,?,?,?)",
                    (str(audit.audit_id), str(memory_id), audit.model_dump_json(), occurred_at.isoformat()),
                )
                self._connection.commit()
                return updated
            except Exception:
                self._connection.rollback()
                raise

    async def list_security_memory_audit(self, memory_id: UUID) -> list[SecurityMemoryAuditRecordV4]:
        async with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM security_memory_audit WHERE memory_id=? ORDER BY occurred_at",
                (str(memory_id),),
            ).fetchall()
        return [SecurityMemoryAuditRecordV4.model_validate_json(row[0]) for row in rows]

    async def upsert_security_campaign(self, record: SecurityCampaignRecordV4) -> SecurityCampaignRecordV4:
        async with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """INSERT OR IGNORE INTO security_campaigns(
                           campaign_id,record_json,reviewer_status,window_started_at,window_ended_at,
                           clustering_version,created_at
                       ) VALUES(?,?,?,?,?,?,?)""",
                    (
                        str(record.campaign_id), record.model_dump_json(), record.reviewer_status.value,
                        record.window_started_at.isoformat(), record.window_ended_at.isoformat(),
                        record.clustering_version, record.created_at.isoformat(),
                    ),
                )
                for analysis_id in record.analysis_ids:
                    self._connection.execute(
                        "INSERT OR IGNORE INTO security_campaign_members(campaign_id,analysis_id) VALUES(?,?)",
                        (str(record.campaign_id), str(analysis_id)),
                    )
                row = self._connection.execute(
                    "SELECT record_json FROM security_campaigns WHERE campaign_id=?", (str(record.campaign_id),)
                ).fetchone()
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        assert row is not None
        return SecurityCampaignRecordV4.model_validate_json(row[0])

    async def list_security_campaigns(self) -> list[SecurityCampaignRecordV4]:
        async with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM security_campaigns ORDER BY window_ended_at DESC"
            ).fetchall()
        return [SecurityCampaignRecordV4.model_validate_json(row[0]) for row in rows]

    async def get_security_campaign(self, campaign_id: UUID) -> SecurityCampaignRecordV4 | None:
        async with self._lock:
            row = self._connection.execute(
                "SELECT record_json FROM security_campaigns WHERE campaign_id=?", (str(campaign_id),)
            ).fetchone()
        return SecurityCampaignRecordV4.model_validate_json(row[0]) if row else None

    async def review_security_campaign(
        self,
        campaign_id: UUID,
        status: SecurityCampaignReviewerStatusV4,
        note: str,
        reviewer_id: str,
        occurred_at: datetime,
    ) -> SecurityCampaignRecordV4 | None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT record_json FROM security_campaigns WHERE campaign_id=?", (str(campaign_id),)
                ).fetchone()
                if row is None:
                    self._connection.rollback()
                    return None
                current = SecurityCampaignRecordV4.model_validate_json(row[0])
                if current.reviewer_status is not SecurityCampaignReviewerStatusV4.PENDING_REVIEW:
                    raise PlatformError(
                        status_code=409, code=ErrorCode.CONFLICT,
                        message="Security campaign was already reviewed.", retryable=False,
                    )
                updated = current.model_copy(
                    update={
                        "reviewer_status": status,
                        "reviewer_id": reviewer_id,
                        "review_note": note,
                        "reviewed_at": occurred_at,
                    }
                )
                audit = SecurityCampaignAuditRecordV4(
                    campaign_id=campaign_id,
                    previous_status=current.reviewer_status,
                    status=status,
                    reviewer_id=reviewer_id,
                    note=note,
                    occurred_at=occurred_at,
                    clustering_version=current.clustering_version,
                    evidence_refs=current.evidence_refs,
                )
                self._connection.execute(
                    "UPDATE security_campaigns SET record_json=?,reviewer_status=? WHERE campaign_id=?",
                    (updated.model_dump_json(), status.value, str(campaign_id)),
                )
                self._connection.execute(
                    "INSERT INTO security_campaign_audit(audit_id,campaign_id,record_json,occurred_at) VALUES(?,?,?,?)",
                    (str(audit.audit_id), str(campaign_id), audit.model_dump_json(), occurred_at.isoformat()),
                )
                self._connection.commit()
                return updated
            except Exception:
                self._connection.rollback()
                raise

    async def list_security_campaign_audit(self, campaign_id: UUID) -> list[SecurityCampaignAuditRecordV4]:
        async with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM security_campaign_audit WHERE campaign_id=? ORDER BY occurred_at",
                (str(campaign_id),),
            ).fetchall()
        return [SecurityCampaignAuditRecordV4.model_validate_json(row[0]) for row in rows]

    async def save_security_report(self, owner_id: str, record: SecurityReportRecordV4) -> None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """INSERT INTO security_analysis_reports_v4(
                           report_id,analysis_id,owner_id,status,record_json,created_at
                       ) VALUES(?,?,?,?,?,?)""",
                    (str(record.report_id), str(record.analysis_id), owner_id, record.status.value,
                     record.model_dump_json(), record.created_at.isoformat()),
                )
                memory_row = self._connection.execute(
                    "SELECT memory_id,record_json FROM security_memory WHERE analysis_id=?",
                    (str(record.analysis_id),),
                ).fetchone()
                if memory_row is not None:
                    memory = SecurityMemoryRecordV4.model_validate_json(memory_row[1])
                    updated = memory.model_copy(update={"report_count": memory.report_count + 1})
                    self._connection.execute(
                        "UPDATE security_memory SET record_json=?,report_count=? WHERE memory_id=?",
                        (updated.model_dump_json(), updated.report_count, memory_row[0]),
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    async def list_security_reports(
        self, analysis_id: str, owner_id: str
    ) -> list[SecurityReportRecordV4]:
        async with self._lock:
            rows = self._connection.execute(
                """SELECT record_json FROM security_analysis_reports_v4
                   WHERE analysis_id=? AND owner_id=? ORDER BY created_at""",
                (analysis_id, owner_id),
            ).fetchall()
        return [SecurityReportRecordV4.model_validate_json(row[0]) for row in rows]

    async def list_security_reports_admin(
        self, status: str | None = None
    ) -> list[SecurityReportAdminRecordV4]:
        query = "SELECT owner_id,record_json FROM security_analysis_reports_v4"
        params: tuple[str, ...] = ()
        if status is not None:
            query += " WHERE status=?"
            params = (status,)
        query += " ORDER BY created_at DESC"
        async with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [
            SecurityReportAdminRecordV4(
                **SecurityReportRecordV4.model_validate_json(row[1]).model_dump(), owner_id=row[0]
            )
            for row in rows
        ]

    async def decide_security_report(
        self, report_id: UUID, decision: ReportReviewDecision, note: str,
        reviewer_id: str, occurred_at: datetime,
    ) -> SecurityReportAdminRecordV4 | None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT owner_id,status,record_json FROM security_analysis_reports_v4 WHERE report_id=?",
                    (str(report_id),),
                ).fetchone()
                if row is None:
                    self._connection.rollback()
                    return None
                if row[1] == ReportStatus.PROCESSED.value:
                    raise PlatformError(
                        status_code=409, code=ErrorCode.CONFLICT,
                        message="Security report was already processed.", retryable=False,
                    )
                current = SecurityReportRecordV4.model_validate_json(row[2])
                updated = current.model_copy(update={
                    "status": ReportStatus.PROCESSED,
                    "decision": decision,
                    "reviewer_id": reviewer_id,
                    "review_note": note,
                    "reviewed_at": occurred_at,
                })
                audit = SecurityAdminAuditEventV4(
                    resource_type=SecurityAuditResourceV4.REPORT,
                    resource_id=report_id,
                    action=f"report_{decision.value}",
                    actor_id=reviewer_id,
                    note=note,
                    occurred_at=occurred_at,
                )
                self._connection.execute(
                    "UPDATE security_analysis_reports_v4 SET status=?,record_json=? WHERE report_id=?",
                    (updated.status.value, updated.model_dump_json(), str(report_id)),
                )
                self._insert_security_feedback_audit(audit)
                self._connection.commit()
                return SecurityReportAdminRecordV4(**updated.model_dump(), owner_id=row[0])
            except Exception:
                self._connection.rollback()
                raise

    async def save_security_appeal(self, owner_id: str, record: SecurityAppealRecordV4) -> None:
        async with self._lock:
            self._connection.execute(
                """INSERT INTO security_analysis_appeals_v4(
                       appeal_id,analysis_id,owner_id,status,record_json,created_at
                   ) VALUES(?,?,?,?,?,?)""",
                (str(record.appeal_id), str(record.analysis_id), owner_id, record.status.value, record.model_dump_json(), record.created_at.isoformat()),
            )
            self._connection.commit()

    async def list_security_appeals(
        self, analysis_id: str, owner_id: str
    ) -> list[SecurityAppealRecordV4]:
        async with self._lock:
            rows = self._connection.execute(
                """SELECT record_json FROM security_analysis_appeals_v4
                   WHERE analysis_id=? AND owner_id=? ORDER BY created_at""",
                (analysis_id, owner_id),
            ).fetchall()
        return [SecurityAppealRecordV4.model_validate_json(row[0]) for row in rows]

    async def list_security_appeals_admin(
        self, status: str | None = None
    ) -> list[SecurityAppealAdminRecordV4]:
        query = "SELECT owner_id,record_json FROM security_analysis_appeals_v4"
        params: tuple[str, ...] = ()
        if status is not None:
            query += " WHERE status=?"
            params = (status,)
        query += " ORDER BY created_at DESC"
        async with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [
            SecurityAppealAdminRecordV4(
                **SecurityAppealRecordV4.model_validate_json(row[1]).model_dump(), owner_id=row[0]
            )
            for row in rows
        ]

    async def decide_security_appeal(
        self, appeal_id: UUID, outcome: AppealOutcome, note: str,
        reviewer_id: str, occurred_at: datetime,
    ) -> SecurityAppealAdminRecordV4 | None:
        async with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT owner_id,status,record_json FROM security_analysis_appeals_v4 WHERE appeal_id=?",
                    (str(appeal_id),),
                ).fetchone()
                if row is None:
                    self._connection.rollback()
                    return None
                if row[1] == AppealStatus.RESOLVED.value:
                    raise PlatformError(
                        status_code=409, code=ErrorCode.CONFLICT,
                        message="Security appeal was already resolved.", retryable=False,
                    )
                current = SecurityAppealRecordV4.model_validate_json(row[2])
                updated = current.model_copy(update={
                    "status": AppealStatus.RESOLVED,
                    "outcome": outcome,
                    "resolution_note": note,
                    "reviewer_id": reviewer_id,
                    "resolved_at": occurred_at,
                })
                audit = SecurityAdminAuditEventV4(
                    resource_type=SecurityAuditResourceV4.APPEAL,
                    resource_id=appeal_id,
                    action=f"appeal_{outcome.value}",
                    actor_id=reviewer_id,
                    note=note,
                    occurred_at=occurred_at,
                )
                self._connection.execute(
                    "UPDATE security_analysis_appeals_v4 SET status=?,record_json=? WHERE appeal_id=?",
                    (updated.status.value, updated.model_dump_json(), str(appeal_id)),
                )
                self._insert_security_feedback_audit(audit)
                self._connection.commit()
                return SecurityAppealAdminRecordV4(**updated.model_dump(), owner_id=row[0])
            except Exception:
                self._connection.rollback()
                raise

    def _insert_security_feedback_audit(self, audit: SecurityAdminAuditEventV4) -> None:
        self._connection.execute(
            """INSERT INTO security_feedback_audit_v4(
                   audit_id,resource_type,resource_id,action,actor_id,note,evidence_refs_json,occurred_at
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (
                str(audit.audit_id), audit.resource_type.value, str(audit.resource_id), audit.action,
                audit.actor_id, audit.note, json.dumps(audit.evidence_refs), audit.occurred_at.isoformat(),
            ),
        )

    async def list_security_admin_audit(self) -> list[SecurityAdminAuditEventV4]:
        async with self._lock:
            feedback = self._connection.execute(
                """SELECT audit_id,resource_type,resource_id,action,actor_id,note,
                          evidence_refs_json,occurred_at FROM security_feedback_audit_v4"""
            ).fetchall()
            trust = self._connection.execute(
                """SELECT audit_id,resource_type,resource_id,action,reviewer_id,NULL,'[]',occurred_at
                   FROM security_trust_audit"""
            ).fetchall()
            memory = self._connection.execute("SELECT record_json FROM security_memory_audit").fetchall()
            campaigns = self._connection.execute("SELECT record_json FROM security_campaign_audit").fetchall()
        events = [
            SecurityAdminAuditEventV4(
                audit_id=UUID(row[0]), resource_type=SecurityAuditResourceV4(row[1]),
                resource_id=UUID(row[2]), action=row[3], actor_id=row[4], note=row[5],
                evidence_refs=json.loads(row[6]), occurred_at=datetime.fromisoformat(row[7]).astimezone(UTC),
            )
            for row in [*feedback, *trust]
        ]
        for row in memory:
            item = SecurityMemoryAuditRecordV4.model_validate_json(row[0])
            events.append(SecurityAdminAuditEventV4(
                audit_id=item.audit_id, resource_type=SecurityAuditResourceV4.MEMORY,
                resource_id=item.memory_id, action=f"memory_{item.verdict.value}", actor_id=item.reviewer_id,
                note=item.note, occurred_at=item.occurred_at, evidence_refs=item.evidence_refs,
            ))
        for row in campaigns:
            item = SecurityCampaignAuditRecordV4.model_validate_json(row[0])
            events.append(SecurityAdminAuditEventV4(
                audit_id=item.audit_id, resource_type=SecurityAuditResourceV4.CAMPAIGN,
                resource_id=item.campaign_id, action=f"campaign_{item.status.value}", actor_id=item.reviewer_id,
                note=item.note, occurred_at=item.occurred_at, evidence_refs=item.evidence_refs,
            ))
        return sorted(events, key=lambda item: item.occurred_at, reverse=True)

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
            with self._connection:
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
                        json.dumps([e.model_dump(mode="json") for e in evidence_snapshot]),
                        created_at.isoformat(),
                        created_at.isoformat(),
                    ),
                )

    async def list_review_queue_items(self) -> list[ReviewQueueItem]:
        async with self._lock:
            rows = self._connection.execute(
                """
                SELECT r.item_id, r.report_id, r.analysis_id, r.status, r.evidence_snapshot_json,
                       r.decision, r.reviewer_id, r.reviewer_note, r.reviewed_at,
                       r.created_at, r.updated_at, a.reason, a.comment, an.request_json
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
                    decision=ReportReviewDecision(row[5]) if row[5] else None,
                    reviewer_id=row[6],
                    reviewer_note=row[7],
                    reviewed_at=datetime.fromisoformat(row[8]) if row[8] else None,
                    created_at=datetime.fromisoformat(row[9]),
                    updated_at=datetime.fromisoformat(row[10]),
                    reason=row[11],
                    comment=row[12],
                    analysis_content=json.loads(row[13]).get("message"),
                )
                for row in rows
            ]

    async def get_review_queue_item(self, item_id: str) -> ReviewQueueItem | None:
        async with self._lock:
            row = self._connection.execute(
                """
                SELECT r.item_id, r.report_id, r.analysis_id, r.status, r.evidence_snapshot_json,
                       r.decision, r.reviewer_id, r.reviewer_note, r.reviewed_at,
                       r.created_at, r.updated_at, a.reason, a.comment, an.request_json
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
                decision=ReportReviewDecision(row[5]) if row[5] else None,
                reviewer_id=row[6],
                reviewer_note=row[7],
                reviewed_at=datetime.fromisoformat(row[8]) if row[8] else None,
                created_at=datetime.fromisoformat(row[9]),
                updated_at=datetime.fromisoformat(row[10]),
                reason=row[11],
                comment=row[12],
                analysis_content=json.loads(row[13]).get("message"),
            )

    async def start_review_queue_item(self, item_id: str, reviewer_id: str) -> bool:
        async with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE review_queue_items
                SET status = ?, reviewer_id = ?, updated_at = ?
                WHERE item_id = ? AND status = ?
                """,
                (
                    ReportStatus.REVIEWING.value,
                    reviewer_id,
                    datetime.now(UTC).isoformat(),
                    item_id,
                    ReportStatus.SUBMITTED.value,
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    async def decide_review_queue_item(
        self,
        item_id: str,
        *,
        decision: ReportReviewDecision,
        reviewer_id: str,
        note: str,
    ) -> bool:
        now = datetime.now(UTC).isoformat()
        async with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE review_queue_items
                SET status = ?, decision = ?, reviewer_id = ?, reviewer_note = ?,
                    reviewed_at = ?, updated_at = ?
                WHERE item_id = ? AND status = ?
                """,
                (
                    ReportStatus.PROCESSED.value,
                    decision.value,
                    reviewer_id,
                    note.strip(),
                    now,
                    now,
                    item_id,
                    ReportStatus.REVIEWING.value,
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

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

    async def claim_security_tool_execution(
        self, analysis_id: str, step_id: str, target: str, provider: str
    ) -> bool:
        now = datetime.now(UTC).isoformat()
        key = (analysis_id, step_id, target, provider)
        async with self._lock:
            try:
                self._connection.execute("BEGIN")
                row = self._connection.execute(
                    """SELECT status, attempt_count FROM security_tool_executions
                       WHERE analysis_id=? AND step_id=? AND target_ref=? AND provider=?""",
                    key,
                ).fetchone()
                if row is None:
                    self._connection.execute(
                        """INSERT INTO security_tool_executions(
                               analysis_id,step_id,target_ref,provider,status,attempt_count,updated_at
                           ) VALUES(?,?,?,?,'running',1,?)""",
                        (*key, now),
                    )
                elif row[0] == "failed":
                    self._connection.execute(
                        """UPDATE security_tool_executions
                           SET status='running', attempt_count=?, updated_at=?
                           WHERE analysis_id=? AND step_id=? AND target_ref=? AND provider=?""",
                        (int(row[1]) + 1, now, *key),
                    )
                else:
                    self._connection.rollback()
                    return False
                self._connection.commit()
                return True
            except Exception:
                self._connection.rollback()
                raise

    async def finish_security_tool_execution(
        self, analysis_id: str, step_id: str, target: str, provider: str, status: str
    ) -> None:
        if status not in {"completed", "failed", "skipped"}:
            raise ValueError("tool execution status must be terminal")
        async with self._lock:
            cursor = self._connection.execute(
                """UPDATE security_tool_executions SET status=?, updated_at=?
                   WHERE analysis_id=? AND step_id=? AND target_ref=? AND provider=?""",
                (status, datetime.now(UTC).isoformat(), analysis_id, step_id, target, provider),
            )
            if cursor.rowcount != 1:
                self._connection.rollback()
                raise LookupError("security tool execution was not claimed")
            self._connection.commit()

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
            _analysis_request_from_json(row[1]),
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


def _analysis_request_from_json(value: str) -> AnalysisCreateRequest:
    payload = json.loads(value)
    model = AnalysisCreateRequestV3 if "consent_to_capture_screenshot" in payload else AnalysisCreateRequest
    return model.model_validate(payload)
