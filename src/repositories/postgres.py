from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST, normalize_hostname
from src.core.errors import PlatformError
from src.models import (
    AdminActionAuditRecordV3,
    AdminActionDecisionResponseV3,
    AdminActionRecordV3,
    AdminActionStatus,
    AnalysisCreateRequest,
    AnalysisCreateRequestV3,
    AnalysisEvent,
    AnalysisReportRecord,
    AnalysisReportResponse,
    AnalysisResponse,
    AppealAdminRecordV3,
    AppealCreateRequestV3,
    AppealDecisionRequestV3,
    AppealDecisionResponseV3,
    AppealOutcome,
    AppealReceiptV3,
    AppealResponseV3,
    AppealStatus,
    BlacklistLookupEntry,
    CacheMetricV3,
    ErrorCode,
    Evidence,
    FeedbackMetricV3,
    LatencyMetricV3,
    MetricsWindowV3,
    OperationsMetricsResponseV3,
    ReportReviewDecision,
    ReportStatus,
    ReviewDecision,
    ReviewedAction,
    ReviewQueueItem,
    RiskDistributionMetricV3,
    RiskLevel,
    SecurityAdminAuditEventV4,
    SecurityAdminCopilotResponseV4,
    SecurityAnalysisEventKindV4,
    SecurityAnalysisEventV4,
    SecurityAuditResourceV4,
    SecurityConversationV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    ToolError,
    UsageMetricV3,
)
from src.repositories.postgres_feedback import PostgresFeedbackRepositoryMixin
from src.repositories.postgres_jobs import (
    DurableJob,
    LostJobLeaseError,
    PostgresJobsRepositoryMixin,
)
from src.repositories.postgres_jobs import OutboxMessage as OutboxMessage
from src.repositories.postgres_trust import PostgresTrustRepositoryMixin
from src.repositories.postgres_wave2 import PostgresWave2RepositoryMixin


class SecurityAnalysisAlreadyFinalizedError(RuntimeError):
    """Raised when an observer tries to append after a terminal v4 commit.

    Progress is best-effort telemetry.  Callers such as the progress reporter
    deliberately drop this error, while the repository keeps the terminal
    event and its sequence authoritative.
    """


class PostgresPlatformRepository(
    PostgresFeedbackRepositoryMixin,
    PostgresJobsRepositoryMixin,
    PostgresTrustRepositoryMixin,
    PostgresWave2RepositoryMixin,
):
    """PostgreSQL source of truth for Wave 1 analysis/job/event state.

    Redis consumers receive only outbox notifications. Claims and sequence
    allocation always happen in PostgreSQL transactions.
    """

    durable_jobs = True

    def __init__(
        self,
        database_url: str,
        encryption_key: str,
        *,
        pool=None,
        content_retention_days: int = 30,
    ) -> None:
        self._database_url = database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
        self._encryption_key = encryption_key
        self._pool = pool
        self._owns_pool = pool is None
        self._content_retention_days = content_retention_days
        self._active_job: ContextVar[tuple[UUID, str] | None] = ContextVar("active_analysis_job", default=None)

    @contextmanager
    def job_scope(self, job_id: UUID, worker_id: str):
        """Bind terminal persistence to the currently claimed durable job."""
        token = self._active_job.set((job_id, worker_id))
        try:
            yield
        finally:
            self._active_job.reset(token)

    async def _get_pool(self):
        if self._pool is None:
            try:
                import asyncpg
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError("asyncpg is required for PostgreSQL runtime") from exc
            self._pool = await asyncpg.create_pool(self._database_url, min_size=1, max_size=10)
        return self._pool

    async def create_analysis(
        self,
        *,
        owner_id: str,
        request: AnalysisCreateRequest,
        response: AnalysisResponse,
        event: AnalysisEvent,
    ) -> None:
        pool = await self._get_pool()
        analysis_id = response.analysis_id
        event_id = uuid4()
        job_id = uuid4()
        outbox_id = uuid4()
        request_json = request.model_dump_json()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO analyses(
                       id, owner_id, input_ciphertext, input_hash, consent, status,
                       response, created_at, updated_at, content_expires_at
                   ) VALUES ($1, $2, pgp_sym_encrypt($3, $4), $5, $6, $7, $8::jsonb, $9, $9, $10)""",
                analysis_id,
                owner_id,
                request_json,
                self._encryption_key,
                hashlib.sha256(request_json.encode()).hexdigest(),
                request.consent_to_scan_urls,
                response.status.value,
                response.model_dump_json(),
                response.created_at,
                response.created_at + timedelta(days=self._content_retention_days),
            )
            await connection.execute(
                """INSERT INTO analysis_events(
                       event_id, analysis_id, sequence, event_type, payload, occurred_at
                   ) VALUES ($1, $2, 1, 'analysis_status', $3::jsonb, $4)""",
                event_id,
                analysis_id,
                event.model_dump_json(),
                event.occurred_at,
            )
            await connection.execute(
                """INSERT INTO analysis_jobs(
                       id, analysis_id, kind, status, max_attempts, available_at,
                       idempotency_key, created_at, updated_at
                   ) VALUES ($1, $2, 'analyze', 'queued', 3, $3, $4, $3, $3)""",
                job_id,
                analysis_id,
                event.occurred_at,
                f"analysis:{analysis_id}:analyze:v1",
            )
            await connection.execute(
                """INSERT INTO outbox(
                       id, aggregate_type, aggregate_id, event_type, payload,
                       idempotency_key, created_at
                   ) VALUES ($1, 'analysis', $2, 'analysis.queued', $3::jsonb, $4, $5)""",
                outbox_id,
                analysis_id,
                json.dumps({"analysis_id": str(analysis_id), "job_id": str(job_id)}),
                f"analysis:{analysis_id}:queued:v1",
                event.occurred_at,
            )

    async def save_security_analysis(
        self,
        owner_id: str,
        response: SecurityScopeResponseV4,
        events: list[SecurityAnalysisEventV4],
    ) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_analyses(
                       id, owner_id, status, response, policy_version, created_at, updated_at,
                       completed_at, conversation_id, policy_metadata
                   ) VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$7,$8,$9::jsonb)
                   ON CONFLICT(id) DO UPDATE SET status=excluded.status, response=excluded.response,
                       policy_version=excluded.policy_version, updated_at=excluded.updated_at,
                       completed_at=excluded.completed_at, conversation_id=excluded.conversation_id,
                       policy_metadata=excluded.policy_metadata""",
                response.analysis_id,
                owner_id,
                response.status.value,
                response.model_dump_json(),
                response.policy_version,
                response.created_at,
                response.completed_at,
                response.conversation_id,
                response.policy_metadata.model_dump_json() if response.policy_metadata else "{}",
            )
            for event in events:
                await connection.execute(
                    """INSERT INTO security_analysis_events(
                           event_id, analysis_id, sequence, event_type, payload, occurred_at
                       ) VALUES($1,$2,$3,$4,$5::jsonb,$6)
                       ON CONFLICT(analysis_id, sequence) DO NOTHING""",
                    event.event_id,
                    response.analysis_id,
                    event.sequence,
                    event.step,
                    event.model_dump_json(),
                    event.occurred_at,
                )
            await connection.execute(
                """INSERT INTO outbox(
                       id, aggregate_type, aggregate_id, event_type, payload, idempotency_key, created_at
                   ) VALUES($1,'security_analysis',$2,'security_analysis.completed',$3::jsonb,$4,$5)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                response.analysis_id,
                json.dumps({"analysis_id": str(response.analysis_id)}),
                f"security-analysis:{response.analysis_id}:completed:v1",
                response.completed_at,
            )

    async def enqueue_security_analysis(
        self,
        *,
        owner_id: str,
        request: SecurityTriageCreateRequestV4,
        response: SecurityScopeResponseV4,
        conversation: SecurityConversationV4,
        expected_version: int | None,
        idempotency_key: str,
        payload_hash: str,
        events: list[SecurityAnalysisEventV4],
    ) -> SecurityScopeResponseV4:
        """Atomically reserve a conversation turn and enqueue encrypted v4 work."""
        pool = await self._get_pool()
        now = response.created_at
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",
                owner_id,
                idempotency_key,
            )
            existing = await connection.fetchrow(
                """SELECT i.payload_hash,a.response FROM security_analysis_idempotency_v4 i
                   JOIN security_analyses a ON a.id=i.analysis_id
                   WHERE i.owner_id=$1 AND i.idempotency_key=$2""",
                owner_id,
                idempotency_key,
            )
            if existing is not None:
                if existing["payload_hash"] != payload_hash:
                    raise PlatformError(
                        status_code=409,
                        code=ErrorCode.CONFLICT,
                        message="Idempotency-Key was already used with a different Security v4 turn.",
                        retryable=False,
                    )
                return SecurityScopeResponseV4.model_validate_stored(_json_value(existing["response"]))

            if expected_version is None:
                reserved = await connection.execute(
                    """INSERT INTO security_conversations(
                           id,owner_id,status,active_analysis_id,context_version,summary,
                           created_at,updated_at,expires_at
                       ) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
                       ON CONFLICT(id) DO NOTHING""",
                    conversation.conversation_id,
                    owner_id,
                    conversation.status.value,
                    conversation.active_analysis_id,
                    conversation.context_version,
                    conversation.model_dump_json(),
                    conversation.created_at,
                    conversation.updated_at,
                    conversation.expires_at,
                )
                updated = reserved.endswith("1")
            else:
                reserved = await connection.fetchrow(
                    """UPDATE security_conversations SET status=$3,active_analysis_id=$4,
                           context_version=$5,summary=$6::jsonb,updated_at=$7,expires_at=$8
                       WHERE id=$1 AND owner_id=$2 AND context_version=$9 RETURNING id""",
                    conversation.conversation_id,
                    owner_id,
                    conversation.status.value,
                    conversation.active_analysis_id,
                    conversation.context_version,
                    conversation.model_dump_json(),
                    conversation.updated_at,
                    conversation.expires_at,
                    expected_version,
                )
                updated = reserved is not None
            if not updated:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security conversation was updated by another turn.",
                    retryable=True,
                )
            # security_analyses.conversation_id has a foreign key to the
            # conversation. Reserve the parent conversation before creating
            # the queued analysis so a first async turn cannot violate it.
            await connection.execute(
                """INSERT INTO security_analyses(
                       id,owner_id,status,response,policy_version,created_at,updated_at,completed_at,conversation_id
                   ) VALUES($1,$2,'queued',$3::jsonb,NULL,$4,$4,NULL,$5)""",
                response.analysis_id,
                owner_id,
                response.model_dump_json(),
                now,
                response.conversation_id,
            )
            await connection.execute(
                """INSERT INTO security_conversation_turns(
                       conversation_id,context_version,analysis_id,created_at
                   ) VALUES($1,$2,$3,$4)""",
                conversation.conversation_id,
                conversation.context_version,
                conversation.active_analysis_id,
                conversation.updated_at,
            )
            await connection.execute(
                """INSERT INTO security_analysis_payloads_v4(
                       analysis_id,payload_ciphertext,context_snapshot,created_at,expires_at
                   ) VALUES($1,pgp_sym_encrypt($2,$3),$4::jsonb,$5,$6)""",
                response.analysis_id,
                request.model_dump_json(),
                self._encryption_key,
                response.model_dump_json(),
                now,
                now + timedelta(hours=24),
            )
            await connection.execute(
                """INSERT INTO security_analysis_jobs_v4(
                       id,analysis_id,status,max_attempts,available_at,created_at,updated_at
                   ) VALUES($1,$2,'queued',3,$3,$3,$3)""",
                uuid4(),
                response.analysis_id,
                now,
            )
            await connection.execute(
                """INSERT INTO security_analysis_idempotency_v4(
                       owner_id,idempotency_key,payload_hash,analysis_id,created_at
                   ) VALUES($1,$2,$3,$4,$5)""",
                owner_id,
                idempotency_key,
                payload_hash,
                response.analysis_id,
                now,
            )
            for event in events:
                await connection.execute(
                    """INSERT INTO security_analysis_events(
                           event_id,analysis_id,sequence,event_type,payload,occurred_at
                       ) VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                    event.event_id,
                    event.analysis_id,
                    event.sequence,
                    event.kind.value,
                    event.model_dump_json(),
                    event.occurred_at,
                )
                await connection.execute(
                    """INSERT INTO security_analysis_outbox_v4(
                           id,analysis_id,event_type,payload,idempotency_key,created_at
                       ) VALUES($1,$2,$3,$4::jsonb,$5,$6)""",
                    uuid4(),
                    response.analysis_id,
                    f"security_analysis.{event.kind.value}",
                    event.model_dump_json(),
                    f"security-v4-event:{response.analysis_id}:{event.sequence}",
                    event.occurred_at,
                )
        return response

    async def load_security_idempotent(
        self,
        owner_id: str,
        idempotency_key: str,
        payload_hash: str,
    ) -> SecurityScopeResponseV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT i.payload_hash,a.response FROM security_analysis_idempotency_v4 i
                   JOIN security_analyses a ON a.id=i.analysis_id
                   WHERE i.owner_id=$1 AND i.idempotency_key=$2""",
                owner_id,
                idempotency_key,
            )
        if row is None:
            return None
        if row["payload_hash"] != payload_hash:
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONFLICT,
                message="Idempotency-Key was already used with a different Security v4 turn.",
                retryable=False,
            )
        return SecurityScopeResponseV4.model_validate_stored(_json_value(row["response"]))

    async def load_security_job_payload(
        self,
        job: DurableJob,
        worker_id: str,
    ) -> tuple[str, SecurityTriageCreateRequestV4, SecurityScopeResponseV4] | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT a.owner_id,p.context_snapshot,
                          pgp_sym_decrypt(p.payload_ciphertext,$3) AS request_json
                   FROM security_analysis_jobs_v4 j
                   JOIN security_analysis_payloads_v4 p ON p.analysis_id=j.analysis_id
                   JOIN security_analyses a ON a.id=j.analysis_id
                   WHERE j.id=$1 AND j.worker_id=$2 AND j.status='running'
                     AND j.lease_expires_at > now()""",
                job.id,
                worker_id,
                self._encryption_key,
            )
        if row is None:
            return None
        return (
            row["owner_id"],
            SecurityTriageCreateRequestV4.model_validate_json(row["request_json"]),
            SecurityScopeResponseV4.model_validate_stored(_json_value(row["context_snapshot"])),
        )

    async def append_security_analysis_event(self, event: SecurityAnalysisEventV4) -> SecurityAnalysisEventV4:
        if event.kind is not SecurityAnalysisEventKindV4.PROGRESS:
            raise ValueError("security progress appender only accepts progress events")
        active_job = self._active_job.get()
        if active_job is None:
            raise RuntimeError("security progress append requires an active durable job scope")
        job_id, worker_id = active_job
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            owned = await connection.fetchrow(
                """SELECT analysis_id FROM security_analysis_jobs_v4
                   WHERE id=$1 AND worker_id=$2 AND status='running'
                     AND lease_expires_at > now() FOR UPDATE""",
                job_id,
                worker_id,
            )
            if owned is None or owned["analysis_id"] != event.analysis_id:
                raise LostJobLeaseError("security v4 job lease was lost before progress append")
            analysis = await connection.fetchrow(
                "SELECT status FROM security_analyses WHERE id=$1 FOR UPDATE", event.analysis_id
            )
            if analysis is None:
                raise LookupError("security analysis was not found")
            if analysis["status"] in {"completed", "failed"}:
                raise SecurityAnalysisAlreadyFinalizedError("security analysis already has a terminal result")
            sequence = await connection.fetchval(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM security_analysis_events WHERE analysis_id=$1",
                event.analysis_id,
            )
            event = event.model_copy(update={"sequence": sequence})
            await connection.execute(
                """INSERT INTO security_analysis_events(
                       event_id,analysis_id,sequence,event_type,payload,occurred_at
                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                event.event_id,
                event.analysis_id,
                sequence,
                event.kind.value,
                event.model_dump_json(),
                event.occurred_at,
            )
            await connection.execute(
                """INSERT INTO security_analysis_outbox_v4(
                       id,analysis_id,event_type,payload,idempotency_key,created_at
                   ) VALUES($1,$2,$3,$4::jsonb,$5,$6)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                event.analysis_id,
                f"security_analysis.{event.kind.value}",
                event.model_dump_json(),
                f"security-v4-event:{event.analysis_id}:{sequence}",
                event.occurred_at,
            )
        return event

    async def complete_security_analysis_job(
        self,
        job: DurableJob,
        worker_id: str,
        response: SecurityScopeResponseV4,
        final_event: SecurityAnalysisEventV4,
    ) -> SecurityAnalysisEventV4:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            owned = await connection.fetchrow(
                """SELECT id FROM security_analysis_jobs_v4
                   WHERE id=$1 AND worker_id=$2 AND status='running'
                     AND lease_expires_at > now() FOR UPDATE""",
                job.id,
                worker_id,
            )
            if owned is None:
                raise LostJobLeaseError("security v4 job lease was lost before terminal commit")
            await connection.fetchrow("SELECT id FROM security_analyses WHERE id=$1 FOR UPDATE", response.analysis_id)
            sequence = await connection.fetchval(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM security_analysis_events WHERE analysis_id=$1",
                response.analysis_id,
            )
            final_event = final_event.model_copy(update={"sequence": sequence})
            await connection.execute(
                """UPDATE security_analyses SET status=$2,response=$3::jsonb,policy_version=$4,
                          policy_metadata=$5::jsonb,updated_at=$6,completed_at=$6 WHERE id=$1""",
                response.analysis_id,
                response.status.value,
                response.model_dump_json(),
                response.policy_version,
                response.policy_metadata.model_dump_json() if response.policy_metadata else "{}",
                response.completed_at,
            )
            await connection.execute(
                """INSERT INTO security_analysis_events(
                       event_id,analysis_id,sequence,event_type,payload,occurred_at
                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                final_event.event_id,
                final_event.analysis_id,
                sequence,
                final_event.kind.value,
                final_event.model_dump_json(),
                final_event.occurred_at,
            )
            await connection.execute(
                "DELETE FROM security_analysis_payloads_v4 WHERE analysis_id=$1", response.analysis_id
            )
            await connection.execute(
                """UPDATE security_analysis_jobs_v4 SET status='completed',worker_id=NULL,
                          lease_expires_at=NULL,updated_at=$3 WHERE id=$1 AND worker_id=$2""",
                job.id,
                worker_id,
                response.completed_at,
            )
            await connection.execute(
                """INSERT INTO security_analysis_outbox_v4(
                       id,analysis_id,event_type,payload,idempotency_key,created_at
                   ) VALUES($1,$2,'security_analysis.final',$3::jsonb,$4,$5)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                response.analysis_id,
                final_event.model_dump_json(),
                f"security-v4-event:{response.analysis_id}:{sequence}",
                response.completed_at,
            )
        return final_event

    async def save_security_conversation(
        self,
        owner_id: str,
        record: SecurityConversationV4,
        *,
        expected_version: int | None,
    ) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            if expected_version is None:
                status = await connection.execute(
                    """INSERT INTO security_conversations(
                           id,owner_id,status,active_analysis_id,context_version,summary,
                           created_at,updated_at,expires_at
                       ) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
                       ON CONFLICT(id) DO NOTHING""",
                    record.conversation_id,
                    owner_id,
                    record.status.value,
                    record.active_analysis_id,
                    record.context_version,
                    record.model_dump_json(),
                    record.created_at,
                    record.updated_at,
                    record.expires_at,
                )
                updated = status.endswith("1")
            else:
                row = await connection.fetchrow(
                    """UPDATE security_conversations SET status=$3,active_analysis_id=$4,
                           context_version=$5,summary=$6::jsonb,updated_at=$7,expires_at=$8
                       WHERE id=$1 AND owner_id=$2 AND context_version=$9 RETURNING id""",
                    record.conversation_id,
                    owner_id,
                    record.status.value,
                    record.active_analysis_id,
                    record.context_version,
                    record.model_dump_json(),
                    record.updated_at,
                    record.expires_at,
                    expected_version,
                )
                updated = row is not None
            if not updated:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security conversation was updated by another turn.",
                    retryable=True,
                )
            await connection.execute(
                """INSERT INTO security_conversation_turns(
                       conversation_id,context_version,analysis_id,created_at
                   ) VALUES($1,$2,$3,$4)""",
                record.conversation_id,
                record.context_version,
                record.active_analysis_id,
                record.updated_at,
            )

    async def finalize_security_conversation(self, owner_id: str, record: SecurityConversationV4) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """UPDATE security_conversations SET summary=$3::jsonb,updated_at=$4
                   WHERE id=$1 AND owner_id=$2 AND context_version=$5""",
                record.conversation_id,
                owner_id,
                record.model_dump_json(),
                record.updated_at,
                record.context_version,
            )

    async def load_security_conversation(self, conversation_id: str):
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                "SELECT owner_id,summary FROM security_conversations WHERE id=$1", UUID(conversation_id)
            )
        if row is None:
            return None
        return row["owner_id"], SecurityConversationV4.model_validate(_json_value(row["summary"]))

    async def list_security_conversations(self, owner_id: str) -> list[SecurityConversationV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT summary FROM security_conversations WHERE owner_id=$1 ORDER BY updated_at DESC",
                owner_id,
            )
        return [SecurityConversationV4.model_validate(_json_value(row["summary"])) for row in rows]

    async def expire_security_conversations(self, cutoff: datetime) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            result = await connection.execute("DELETE FROM security_conversations WHERE expires_at <= $1", cutoff)
        return int(result.rsplit(" ", 1)[-1])

    async def load_security_analysis(self, analysis_id: str):
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                "SELECT owner_id, response FROM security_analyses WHERE id=$1", UUID(analysis_id)
            )
            if row is None:
                return None
            events = await connection.fetch(
                "SELECT payload FROM security_analysis_events WHERE analysis_id=$1 ORDER BY sequence",
                UUID(analysis_id),
            )
        return (
            row["owner_id"],
            SecurityScopeResponseV4.model_validate_stored(_json_value(row["response"])),
            [SecurityAnalysisEventV4.model_validate(_json_value(item["payload"])) for item in events],
        )

    async def list_security_analyses(self, owner_id: str) -> list[SecurityScopeResponseV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT response FROM security_analyses WHERE owner_id=$1 ORDER BY created_at DESC",
                owner_id,
            )
        return [SecurityScopeResponseV4.model_validate_stored(_json_value(row["response"])) for row in rows]

    async def claim_security_tool_execution(self, analysis_id: str, step_id: str, target: str, provider: str) -> bool:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT status, attempt_count FROM security_tool_executions
                   WHERE analysis_id=$1 AND step_id=$2 AND target_ref=$3 AND provider=$4 FOR UPDATE""",
                UUID(analysis_id),
                step_id,
                target,
                provider,
            )
            if row is None:
                await connection.execute(
                    """INSERT INTO security_tool_executions(
                           analysis_id,step_id,target_ref,provider,status,attempt_count,updated_at
                       ) VALUES($1,$2,$3,$4,'running',1,$5)""",
                    UUID(analysis_id),
                    step_id,
                    target,
                    provider,
                    now,
                )
                return True
            if row["status"] != "failed":
                return False
            await connection.execute(
                """UPDATE security_tool_executions SET status='running', attempt_count=$5, updated_at=$6
                   WHERE analysis_id=$1 AND step_id=$2 AND target_ref=$3 AND provider=$4""",
                UUID(analysis_id),
                step_id,
                target,
                provider,
                row["attempt_count"] + 1,
                now,
            )
            return True

    async def finish_security_tool_execution(
        self, analysis_id: str, step_id: str, target: str, provider: str, status: str
    ) -> None:
        if status not in {"completed", "failed", "skipped"}:
            raise ValueError("tool execution status must be terminal")
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            updated = await connection.execute(
                """UPDATE security_tool_executions SET status=$5, updated_at=$6
                   WHERE analysis_id=$1 AND step_id=$2 AND target_ref=$3 AND provider=$4""",
                UUID(analysis_id),
                step_id,
                target,
                provider,
                status,
                datetime.now(UTC),
            )
        if updated != "UPDATE 1":
            raise LookupError("security tool execution was not claimed")

    async def load_analysis(self, analysis_id: str):
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT owner_id, pgp_sym_decrypt(input_ciphertext, $2) AS request_json,
                          response
                   FROM analyses WHERE id = $1""",
                UUID(analysis_id),
                self._encryption_key,
            )
            if row is None:
                return None
            events = await connection.fetch(
                "SELECT payload FROM analysis_events WHERE analysis_id = $1 ORDER BY sequence",
                UUID(analysis_id),
            )
        return (
            row["owner_id"],
            _analysis_request_from_json(row["request_json"]),
            AnalysisResponse.model_validate(_json_value(row["response"])),
            [AnalysisEvent.model_validate(_json_value(item["payload"])) for item in events],
        )

    async def list_analysis_responses(self, *, owner_id=None, case_status=None):
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            if owner_id is not None and case_status is not None:
                rows = await connection.fetch(
                    """SELECT response FROM analyses
                       WHERE owner_id=$1 AND case_status=$2 ORDER BY created_at DESC""",
                    owner_id,
                    case_status,
                )
            elif owner_id is not None:
                rows = await connection.fetch(
                    "SELECT response FROM analyses WHERE owner_id=$1 ORDER BY created_at DESC",
                    owner_id,
                )
            elif case_status is not None:
                rows = await connection.fetch(
                    "SELECT response FROM analyses WHERE case_status=$1 ORDER BY created_at DESC",
                    case_status,
                )
            else:
                rows = await connection.fetch("SELECT response FROM analyses ORDER BY created_at DESC")
        return [AnalysisResponse.model_validate(_json_value(row["response"])) for row in rows]

    async def append_analysis_event(self, event: AnalysisEvent) -> None:
        await self._write_state_event(None, event)

    async def update_analysis(self, response: AnalysisResponse, event: AnalysisEvent) -> None:
        await self._write_state_event(response, event)

    async def complete_analysis(
        self, response: AnalysisResponse, event: AnalysisEvent, errors: list[ToolError]
    ) -> None:
        del errors
        await self._write_state_event(response, event)

    async def _write_state_event(self, response: AnalysisResponse | None, event: AnalysisEvent) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            parent = await connection.fetchrow("SELECT id FROM analyses WHERE id = $1 FOR UPDATE", event.analysis_id)
            if parent is None:
                raise LookupError("analysis is not persisted")
            sequence = await connection.fetchval(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM analysis_events WHERE analysis_id = $1",
                event.analysis_id,
            )
            if response is not None:
                await connection.execute(
                    """UPDATE analyses SET status=$2, case_status=$3, response=$4::jsonb,
                              completed_at=$5, updated_at=$6, scoring_version=$7,
                              version=version+1 WHERE id=$1""",
                    response.analysis_id,
                    response.status.value,
                    response.case_status.value if response.case_status else None,
                    response.model_dump_json(),
                    response.completed_at,
                    event.occurred_at,
                    response.scoring_version,
                )
                await connection.execute("DELETE FROM investigation_steps WHERE analysis_id=$1", response.analysis_id)
                for step in response.investigation_plan:
                    await connection.execute(
                        """INSERT INTO investigation_steps(
                               analysis_id,step_id,tool,target_ref,reason_code,dependency_ids,
                               status,attempt_count,created_at,updated_at
                           ) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$9)""",
                        response.analysis_id,
                        step.step_id,
                        step.tool.value,
                        _safe_url_or_text(step.target),
                        step.reason_code,
                        json.dumps(step.depends_on),
                        step.status.value,
                        int(step.status.value != "pending"),
                        event.occurred_at,
                    )
                await connection.execute("DELETE FROM evidence WHERE analysis_id=$1", response.analysis_id)
                for evidence in response.evidence or []:
                    safe_url = _safe_url_or_text(evidence.url) if evidence.url else None
                    content_hash = hashlib.sha256(
                        json.dumps(
                            [evidence.type.value, evidence.source, safe_url, evidence.finding],
                            ensure_ascii=False,
                        ).encode()
                    ).hexdigest()
                    await connection.execute(
                        """INSERT INTO evidence(
                               id,analysis_id,type,source,source_version,title,safe_url,
                               finding,observed_at,created_at,content_hash
                           ) VALUES($1,$2,$3,$4,'v1',$5,$6,$7,$8,$9,$10)""",
                        uuid4(),
                        response.analysis_id,
                        evidence.type.value,
                        evidence.source,
                        evidence.title,
                        safe_url,
                        evidence.finding,
                        evidence.observed_at,
                        event.occurred_at,
                        content_hash,
                    )
            await connection.execute(
                """INSERT INTO analysis_events(
                       event_id, analysis_id, sequence, event_type, payload, occurred_at
                   ) VALUES ($1,$2,$3,$4,$5::jsonb,$6)""",
                uuid4(),
                event.analysis_id,
                sequence,
                (
                    "provisional_warning"
                    if event.is_provisional
                    else "step_transition"
                    if event.step_id
                    else "analysis_status"
                ),
                event.model_dump_json(),
                event.occurred_at,
            )
            active_job = self._active_job.get()
            if response is not None and response.status.value in {"completed", "failed"} and active_job:
                job_id, worker_id = active_job
                updated = await connection.execute(
                    """UPDATE analysis_jobs SET status='completed', lease_expires_at=NULL,
                              worker_id=NULL, updated_at=$3
                       WHERE id=$1 AND worker_id=$2 AND status='running'""",
                    job_id,
                    worker_id,
                    event.occurred_at,
                )
                if updated != "UPDATE 1":
                    raise LostJobLeaseError("job lease ownership was lost before terminal commit")
            await connection.execute(
                """INSERT INTO outbox(
                       id, aggregate_type, aggregate_id, event_type, payload,
                       idempotency_key, created_at
                   ) VALUES ($1,'analysis',$2,'analysis.progressed',$3::jsonb,$4,$5)
                   ON CONFLICT (idempotency_key) DO NOTHING""",
                uuid4(),
                event.analysis_id,
                event.model_dump_json(),
                f"analysis-event:{event.analysis_id}:{sequence}",
                event.occurred_at,
            )

    async def latest_security_admin_copilot(
        self, analysis_id: UUID, evidence_snapshot_hash: str
    ) -> SecurityAdminCopilotResponseV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT suggestion FROM security_admin_copilot_suggestions_v4
                   WHERE analysis_id=$1 AND evidence_snapshot_hash=$2
                   ORDER BY completed_at DESC LIMIT 1""",
                analysis_id,
                evidence_snapshot_hash,
            )
        return SecurityAdminCopilotResponseV4.model_validate(row["suggestion"]) if row else None

    async def save_security_admin_copilot(
        self,
        suggestion: SecurityAdminCopilotResponseV4,
        evidence_snapshot_hash: str,
        reviewer_id: str,
        requested_at: datetime,
        completed_at: datetime,
    ) -> None:
        audit = SecurityAdminAuditEventV4(
            resource_type=SecurityAuditResourceV4.COPILOT,
            resource_id=suggestion.suggestion_id,
            action="copilot_suggestion_generated",
            actor_id=reviewer_id,
            note=f"{suggestion.generation_mode.value}:{suggestion.suggestion_version}",
            occurred_at=completed_at,
            evidence_refs=suggestion.evidence_refs,
        )
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_admin_copilot_suggestions_v4(
                       id,analysis_id,reviewer_id,suggestion,usage_metadata,evidence_snapshot_hash,
                       requested_at,completed_at
                   ) VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8)""",
                suggestion.suggestion_id,
                suggestion.analysis_id,
                reviewer_id,
                suggestion.model_dump_json(),
                suggestion.usage.model_dump_json(),
                evidence_snapshot_hash,
                requested_at,
                completed_at,
            )
            await self._insert_security_feedback_audit(connection, audit)

    async def get(self, domain: str):
        normalized = _canonical_domain_or_target(domain)
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT canonical_domain,enabling_decision_id,created_at,active
                   FROM blacklist_entries WHERE canonical_domain=$1 AND active""",
                normalized,
            )
        if row is None:
            return None
        return BlacklistLookupEntry(
            domain=row["canonical_domain"],
            decision_id=str(row["enabling_decision_id"]),
            source="reviewed-action-v3",
            added_at=row["created_at"],
            active=row["active"],
        )

    async def contains(self, domain: str) -> bool:
        return await self.get(domain) is not None

    async def add_approved(self, domain: str, decision_id: str) -> None:
        del domain, decision_id
        raise RuntimeError("direct blacklist mutation is disabled; use an approved admin action")

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
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO analysis_reports(
                       id,analysis_id,reporter_id,reason,comment,created_at
                   ) VALUES($1,$2,$3,$4,$5,$6)""",
                UUID(report_id),
                UUID(analysis_id),
                reporter_id,
                reason.strip(),
                comment,
                created_at,
            )
            await connection.execute(
                """INSERT INTO review_queue_items(
                       id,report_id,analysis_id,status,evidence_snapshot,created_at,updated_at
                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6,$6)""",
                uuid4(),
                UUID(report_id),
                UUID(analysis_id),
                ReportStatus.SUBMITTED.value,
                json.dumps([item.model_dump(mode="json") for item in evidence_snapshot]),
                created_at,
            )

    async def list_reports(self, *, limit: int, offset: int) -> list[AnalysisReportRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT r.id,r.analysis_id,r.reporter_id,r.reason,r.comment,r.created_at,q.status
                   FROM analysis_reports r
                   LEFT JOIN review_queue_items q ON q.report_id=r.id
                   ORDER BY r.created_at DESC LIMIT $1 OFFSET $2""",
                limit,
                offset,
            )
        return [
            AnalysisReportRecord(
                report_id=row["id"],
                analysis_id=row["analysis_id"],
                reporter_id=row["reporter_id"],
                reason=row["reason"],
                comment=row["comment"],
                created_at=row["created_at"],
                status=ReportStatus(row["status"] or ReportStatus.SUBMITTED.value),
            )
            for row in rows
        ]

    async def list_reports_by_analysis(self, analysis_id: str) -> list[AnalysisReportResponse]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT r.id,r.analysis_id,r.created_at,q.status
                   FROM analysis_reports r
                   LEFT JOIN review_queue_items q ON q.report_id=r.id
                   WHERE r.analysis_id=$1 ORDER BY r.created_at DESC""",
                UUID(analysis_id),
            )
        return [
            AnalysisReportResponse(
                report_id=row["id"],
                analysis_id=row["analysis_id"],
                created_at=row["created_at"],
                status=ReportStatus(row["status"] or ReportStatus.SUBMITTED.value),
            )
            for row in rows
        ]

    async def list_review_queue_items(self) -> list[ReviewQueueItem]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT q.id,q.report_id,q.analysis_id,q.status,q.evidence_snapshot,
                          q.decision,q.reviewer_id,q.reviewer_note,q.reviewed_at,
                          q.created_at,q.updated_at,r.reason,r.comment,
                          pgp_sym_decrypt(a.input_ciphertext,$1)::jsonb ->> 'message' AS analysis_content
                   FROM review_queue_items q
                   JOIN analysis_reports r ON r.id=q.report_id
                   JOIN analyses a ON a.id=q.analysis_id
                   ORDER BY q.created_at ASC""",
                self._encryption_key,
            )
        return [self._review_queue_item(row) for row in rows]

    async def get_review_queue_item(self, item_id: str) -> ReviewQueueItem | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT q.id,q.report_id,q.analysis_id,q.status,q.evidence_snapshot,
                          q.decision,q.reviewer_id,q.reviewer_note,q.reviewed_at,
                          q.created_at,q.updated_at,r.reason,r.comment,
                          pgp_sym_decrypt(a.input_ciphertext,$2)::jsonb ->> 'message' AS analysis_content
                   FROM review_queue_items q
                   JOIN analysis_reports r ON r.id=q.report_id
                   JOIN analyses a ON a.id=q.analysis_id
                   WHERE q.id=$1""",
                UUID(item_id),
                self._encryption_key,
            )
        return self._review_queue_item(row) if row is not None else None

    async def start_review_queue_item(self, item_id: str, reviewer_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE review_queue_items
                   SET status=$2,reviewer_id=$3,updated_at=now()
                   WHERE id=$1 AND status=$4""",
                UUID(item_id),
                ReportStatus.REVIEWING.value,
                reviewer_id,
                ReportStatus.SUBMITTED.value,
            )
        return result == "UPDATE 1"

    async def decide_review_queue_item(
        self,
        item_id: str,
        *,
        decision: ReportReviewDecision,
        reviewer_id: str,
        note: str,
    ) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE review_queue_items
                   SET status=$2,decision=$3,reviewer_id=$4,reviewer_note=$5,
                       reviewed_at=now(),updated_at=now()
                   WHERE id=$1 AND status=$6""",
                UUID(item_id),
                ReportStatus.PROCESSED.value,
                decision.value,
                reviewer_id,
                note.strip(),
                ReportStatus.REVIEWING.value,
            )
        return result == "UPDATE 1"

    async def create_appeal(
        self,
        analysis_id: UUID,
        owner_id: str,
        request: AppealCreateRequestV3,
        evidence: list[Evidence],
    ) -> AppealReceiptV3:
        del evidence
        pool = await self._get_pool()
        appeal_id, now = uuid4(), datetime.now(UTC)
        try:
            async with pool.acquire() as connection:
                await connection.execute(
                    """INSERT INTO appeals(
                           id,analysis_id,owner_id,reason,comment,status,created_at,updated_at
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$7)""",
                    appeal_id,
                    analysis_id,
                    owner_id,
                    request.reason.strip(),
                    request.comment,
                    AppealStatus.SUBMITTED.value,
                    now,
                )
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "23505":
                raise _platform_conflict("An active appeal already exists for this analysis.") from exc
            raise
        return AppealReceiptV3(appeal_id=appeal_id, analysis_id=analysis_id, created_at=now)

    async def get_appeal(self, appeal_id: UUID) -> tuple[str, AppealResponseV3] | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow("SELECT * FROM appeals WHERE id=$1", appeal_id)
        return (row["owner_id"], self._appeal_response(row)) if row else None

    async def list_appeals_for_analysis(self, analysis_id: UUID, owner_id: str) -> list[AppealResponseV3]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT * FROM appeals
                   WHERE analysis_id=$1 AND owner_id=$2
                   ORDER BY created_at DESC""",
                analysis_id,
                owner_id,
            )
        return [self._appeal_response(row) for row in rows]

    async def list_appeals(
        self, appeal_status: AppealStatus | None, limit: int, offset: int
    ) -> tuple[list[AppealAdminRecordV3], int]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            if appeal_status is None:
                rows = await connection.fetch(
                    "SELECT * FROM appeals ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset
                )
                total = await connection.fetchval("SELECT count(*) FROM appeals")
            else:
                rows = await connection.fetch(
                    "SELECT * FROM appeals WHERE status=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                    appeal_status.value,
                    limit,
                    offset,
                )
                total = await connection.fetchval("SELECT count(*) FROM appeals WHERE status=$1", appeal_status.value)
        return [self._appeal_admin_response(row) for row in rows], int(total)

    async def decide_appeal(
        self,
        appeal_id: UUID,
        request: AppealDecisionRequestV3,
        reviewer_id: str,
    ) -> AppealDecisionResponseV3 | None:
        pool = await self._get_pool()
        now, decision_id = datetime.now(UTC), uuid4()
        async with pool.acquire() as connection, connection.transaction():
            appeal = await connection.fetchrow("SELECT * FROM appeals WHERE id=$1 FOR UPDATE", appeal_id)
            if appeal is None:
                return None
            if appeal["status"] == AppealStatus.RESOLVED.value:
                raise _platform_conflict("The appeal has already been resolved.")
            snapshot_rows = await connection.fetch(
                """SELECT type,source,title,safe_url,finding,observed_at
                   FROM evidence WHERE analysis_id=$1 ORDER BY created_at""",
                appeal["analysis_id"],
            )
            evidence_snapshot = [
                {
                    "type": row["type"],
                    "source": row["source"],
                    "title": row["title"],
                    "url": row["safe_url"],
                    "finding": row["finding"],
                    "observed_at": row["observed_at"].isoformat(),
                }
                for row in snapshot_rows
            ]
            predecessor = await connection.fetchval(
                "SELECT id FROM review_decisions WHERE appeal_id=$1 ORDER BY decided_at DESC LIMIT 1", appeal_id
            )
            await connection.execute(
                """INSERT INTO review_decisions(
                       id,analysis_id,appeal_id,reviewer_id,decision,outcome,evidence_snapshot,
                       note,decided_at,predecessor_decision_id
                   ) VALUES($1,$2,$3,$4,'resolved',$5,$6::jsonb,$7,$8,$9)""",
                decision_id,
                appeal["analysis_id"],
                appeal_id,
                reviewer_id,
                request.outcome.value,
                json.dumps(evidence_snapshot),
                request.note.strip(),
                now,
                predecessor,
            )
            await connection.execute(
                """UPDATE appeals SET status='resolved',outcome=$2,resolution_note=$3,
                          resolved_at=$4,updated_at=$4,version=version+1 WHERE id=$1""",
                appeal_id,
                request.outcome.value,
                request.note.strip(),
                now,
            )
            if request.outcome is AppealOutcome.OVERTURN:
                await connection.execute(
                    """UPDATE blacklist_entries b SET active=false,disabling_decision_id=$2,
                              updated_at=$3,version=b.version+1
                       FROM review_decisions enabling
                       WHERE b.enabling_decision_id=enabling.id AND enabling.analysis_id=$1 AND b.active""",
                    appeal["analysis_id"],
                    decision_id,
                    now,
                )
            await connection.execute(
                """INSERT INTO user_notifications(
                       id,owner_id,resource_type,resource_id,event_type,payload,created_at,idempotency_key
                   ) VALUES($1,$2,'appeal',$3,'appeal.resolved',$4::jsonb,$5,$6)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                appeal["owner_id"],
                appeal_id,
                json.dumps({"outcome": request.outcome.value}),
                now,
                f"appeal:{appeal_id}:resolved:{decision_id}",
            )
        return AppealDecisionResponseV3(
            appeal_id=appeal_id, decision_id=decision_id, outcome=request.outcome, decided_at=now
        )

    @staticmethod
    def _appeal_response(row) -> AppealResponseV3:
        return AppealResponseV3(
            appeal_id=row["id"],
            analysis_id=row["analysis_id"],
            status=AppealStatus(row["status"]),
            reason=row["reason"],
            comment=row["comment"],
            outcome=AppealOutcome(row["outcome"]) if row["outcome"] else None,
            resolution_note=row["resolution_note"],
            created_at=row["created_at"],
            resolved_at=row["resolved_at"],
        )

    @classmethod
    def _appeal_admin_response(cls, row) -> AppealAdminRecordV3:
        response = cls._appeal_response(row)
        return AppealAdminRecordV3(owner_id=row["owner_id"], **response.model_dump(exclude={"contract_version"}))

    async def propose_admin_action(
        self,
        *,
        analysis_id: UUID | None,
        security_analysis_id: UUID | None = None,
        campaign_id: UUID | None,
        action: ReviewedAction,
        target: str | None,
        evidence: list[Evidence],
    ) -> AdminActionRecordV3:
        action_id, now = uuid4(), datetime.now(UTC)
        canonical = _canonical_domain_or_target(target) if target else None
        record = AdminActionRecordV3(
            action_id=action_id,
            analysis_id=analysis_id,
            security_analysis_id=security_analysis_id,
            campaign_id=campaign_id,
            action=action,
            target=canonical,
            status=AdminActionStatus.PENDING_REVIEW,
            evidence_snapshot=evidence,
            proposed_at=now,
        )
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            existing = await connection.fetchrow(
                """SELECT * FROM admin_actions
                   WHERE status='pending_review'
                     AND security_analysis_id IS NOT DISTINCT FROM $1
                     AND analysis_id IS NOT DISTINCT FROM $2
                     AND campaign_id IS NOT DISTINCT FROM $3
                     AND action=$4 AND canonical_target IS NOT DISTINCT FROM $5
                   ORDER BY proposed_at DESC LIMIT 1""",
                security_analysis_id,
                analysis_id,
                campaign_id,
                action.value,
                canonical,
            )
            if existing is not None:
                return self._admin_action(existing)
            inserted = await connection.fetchrow(
                """INSERT INTO admin_actions(
                       id,analysis_id,security_analysis_id,campaign_id,action,canonical_target,status,
                       evidence_snapshot,proposed_at
                   ) VALUES($1,$2,$3,$4,$5,$6,'pending_review',$7::jsonb,$8)
                   ON CONFLICT(
                     COALESCE(security_analysis_id,'00000000-0000-0000-0000-000000000000'::uuid),
                     action,canonical_target
                   )
                     WHERE status='pending_review' DO NOTHING
                   RETURNING *""",
                action_id,
                analysis_id,
                security_analysis_id,
                campaign_id,
                action.value,
                canonical,
                json.dumps([item.model_dump(mode="json") for item in evidence]),
                now,
            )
            if inserted is None:
                concurrent = await connection.fetchrow(
                    """SELECT * FROM admin_actions
                       WHERE status='pending_review'
                         AND security_analysis_id IS NOT DISTINCT FROM $1
                         AND action=$2 AND canonical_target=$3""",
                    security_analysis_id,
                    action.value,
                    canonical,
                )
                if concurrent is not None:
                    return self._admin_action(concurrent)
                raise _platform_conflict("A matching admin action proposal already exists.")
        return record

    async def list_admin_actions(
        self, action_status: AdminActionStatus | None, limit: int, offset: int
    ) -> tuple[list[AdminActionRecordV3], int]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            if action_status is None:
                rows = await connection.fetch(
                    "SELECT * FROM admin_actions ORDER BY proposed_at DESC LIMIT $1 OFFSET $2", limit, offset
                )
                total = await connection.fetchval("SELECT count(*) FROM admin_actions")
            else:
                rows = await connection.fetch(
                    "SELECT * FROM admin_actions WHERE status=$1 ORDER BY proposed_at DESC LIMIT $2 OFFSET $3",
                    action_status.value,
                    limit,
                    offset,
                )
                total = await connection.fetchval(
                    "SELECT count(*) FROM admin_actions WHERE status=$1", action_status.value
                )
        return [self._admin_action(row) for row in rows], int(total)

    async def get_admin_action(self, action_id: UUID) -> AdminActionRecordV3 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow("SELECT * FROM admin_actions WHERE id=$1", action_id)
        return self._admin_action(row) if row else None

    async def list_admin_action_audit(self, action_id: UUID) -> list[AdminActionAuditRecordV3]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT d.id,d.action_id,d.reviewer_id,d.decision,d.action,d.evidence_snapshot,
                          d.note,d.decided_at,d.execution_status,d.execution_error
                   FROM review_decisions d
                   WHERE d.action_id=$1 ORDER BY d.decided_at""",
                action_id,
            )
        return [
            AdminActionAuditRecordV3(
                decision_id=row["id"],
                action_id=row["action_id"],
                reviewer_id=row["reviewer_id"],
                decision=ReviewDecision(row["decision"]),
                action=ReviewedAction(row["action"]),
                execution_status=AdminActionStatus(row["execution_status"]),
                evidence_snapshot=[Evidence.model_validate(item) for item in _json_value(row["evidence_snapshot"])],
                note=row["note"],
                decided_at=row["decided_at"],
                execution_error=row["execution_error"],
            )
            for row in rows
        ]

    async def decide_admin_action(
        self,
        action_id: UUID,
        decision: ReviewDecision,
        note: str,
        reviewer_id: str,
    ) -> AdminActionDecisionResponseV3 | None:
        pool = await self._get_pool()
        now, decision_id = datetime.now(UTC), uuid4()
        async with pool.acquire() as connection, connection.transaction():
            action = await connection.fetchrow("SELECT * FROM admin_actions WHERE id=$1 FOR UPDATE", action_id)
            if action is None:
                return None
            if action["status"] != AdminActionStatus.PENDING_REVIEW.value:
                raise _platform_conflict("The admin action has already been reviewed.")
            approved = decision is ReviewDecision.APPROVED
            new_status = AdminActionStatus.APPROVED if approved else AdminActionStatus.REJECTED
            executed_at = None
            execution_error = None
            await connection.execute(
                """INSERT INTO review_decisions(
                       id,analysis_id,action_id,reviewer_id,decision,action,evidence_snapshot,note,
                       decided_at,execution_status
                   ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)""",
                decision_id,
                action["analysis_id"],
                action_id,
                reviewer_id,
                decision.value,
                action["action"],
                json.dumps(_json_value(action["evidence_snapshot"])),
                note.strip(),
                now,
                new_status.value,
            )
            await connection.execute(
                """UPDATE admin_actions SET status=$2,reviewer_id=$3,review_note=$4,
                          reviewed_at=$5,approved_decision_id=$6,version=version+1 WHERE id=$1""",
                action_id,
                new_status.value,
                reviewer_id,
                note.strip(),
                now,
                decision_id if approved else None,
            )
            if approved and action["action"] == ReviewedAction.ADD_TO_BLACKLIST.value:
                already_active = await connection.fetchval(
                    "SELECT active FROM blacklist_entries WHERE canonical_domain=$1 FOR UPDATE",
                    action["canonical_target"],
                )
                if already_active:
                    new_status = AdminActionStatus.FAILED
                    executed_at = now
                    execution_error = "BLACKLIST_TARGET_ALREADY_ACTIVE"
                else:
                    await connection.execute(
                        """INSERT INTO blacklist_entries(
                               id,canonical_domain,active,enabling_decision_id,created_at,updated_at
                           ) VALUES($1,$2,true,$3,$4,$4)
                           ON CONFLICT(canonical_domain) DO UPDATE SET
                             active=true,enabling_decision_id=EXCLUDED.enabling_decision_id,
                             disabling_decision_id=NULL,updated_at=EXCLUDED.updated_at,
                             version=blacklist_entries.version+1""",
                        uuid4(),
                        action["canonical_target"],
                        decision_id,
                        now,
                    )
                    new_status = AdminActionStatus.EXECUTED
                    executed_at = now
            elif approved and action["action"] == ReviewedAction.DISABLE_BLACKLIST.value:
                result = await connection.execute(
                    """UPDATE blacklist_entries SET active=false,disabling_decision_id=$2,
                              updated_at=$3,version=version+1
                       WHERE canonical_domain=$1 AND active""",
                    action["canonical_target"],
                    decision_id,
                    now,
                )
                executed_at = now
                if result.endswith(" 0"):
                    new_status = AdminActionStatus.FAILED
                    execution_error = "BLACKLIST_TARGET_NOT_ACTIVE"
                else:
                    new_status = AdminActionStatus.EXECUTED
            elif approved:
                new_status = AdminActionStatus.FAILED
                executed_at = now
                execution_error = "ACTION_SINK_NOT_CONFIGURED"
            if approved:
                await connection.execute(
                    """UPDATE admin_actions SET status=$2,executed_at=$3,execution_error=$4,
                              version=version+1 WHERE id=$1""",
                    action_id,
                    new_status.value,
                    executed_at,
                    execution_error,
                )
            await connection.execute(
                """UPDATE review_decisions SET execution_status=$2,execution_error=$3 WHERE id=$1""",
                decision_id,
                new_status.value,
                execution_error,
            )
            if action["action"] in {
                ReviewedAction.ADD_TO_BLACKLIST.value,
                ReviewedAction.DISABLE_BLACKLIST.value,
            }:
                await self._insert_security_feedback_audit(
                    connection,
                    SecurityAdminAuditEventV4(
                        resource_type=SecurityAuditResourceV4.BLACKLIST,
                        resource_id=action_id,
                        action=f"blacklist_{action['action']}_{new_status.value}",
                        actor_id=reviewer_id,
                        note=note,
                        occurred_at=now,
                        evidence_refs=[
                            item.get("title", "")
                            for item in _json_value(action["evidence_snapshot"])
                            if item.get("title")
                        ],
                    ),
                )
        return AdminActionDecisionResponseV3(
            action_id=action_id,
            decision_id=decision_id,
            action=ReviewedAction(action["action"]),
            status=new_status,
            reviewed_at=now,
            executed_at=executed_at,
            execution_error=execution_error,
        )

    @staticmethod
    def _admin_action(row) -> AdminActionRecordV3:
        return AdminActionRecordV3(
            action_id=row["id"],
            analysis_id=row["analysis_id"],
            security_analysis_id=row["security_analysis_id"],
            campaign_id=row["campaign_id"],
            action=ReviewedAction(row["action"]),
            target=row["canonical_target"],
            status=AdminActionStatus(row["status"]),
            evidence_snapshot=[Evidence.model_validate(item) for item in _json_value(row["evidence_snapshot"])],
            proposed_at=row["proposed_at"],
            reviewer_id=row["reviewer_id"],
            review_note=row["review_note"],
            reviewed_at=row["reviewed_at"],
            executed_at=row["executed_at"],
            execution_error=row["execution_error"],
        )

    async def expire_minimized_content(self, now: datetime) -> int:
        """Cryptographically replace retained user input while preserving immutable audit rows."""
        pool = await self._get_pool()
        tombstone = json.dumps({"message": "[deleted]", "consent_to_scan_urls": False})
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE analyses SET
                     input_ciphertext=pgp_sym_encrypt($1,$2),
                     input_hash=$3,
                     content_deleted_at=$4,
                     version=version+1
                   WHERE content_deleted_at IS NULL AND content_expires_at <= $4""",
                tombstone,
                self._encryption_key,
                hashlib.sha256(tombstone.encode()).hexdigest(),
                now,
            )
        return int(result.removeprefix("UPDATE "))

    async def expire_security_job_payloads(self, now: datetime) -> int:
        """Purge abandoned encrypted v4 input no later than its 24-hour TTL."""
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            rows = await connection.fetch(
                """DELETE FROM security_analysis_payloads_v4
                   WHERE expires_at <= $1 RETURNING analysis_id""",
                now,
            )
            if rows:
                analysis_ids = [row["analysis_id"] for row in rows]
                await connection.execute(
                    """UPDATE security_analysis_jobs_v4 SET status='failed',failure_code='PAYLOAD_EXPIRED',
                              lease_expires_at=NULL,worker_id=NULL,updated_at=$2
                       WHERE analysis_id=ANY($1::uuid[]) AND status IN ('queued','running')""",
                    analysis_ids,
                    now,
                )
                for analysis_id in analysis_ids:
                    stored = await connection.fetchrow(
                        "SELECT response FROM security_analyses WHERE id=$1 FOR UPDATE",
                        analysis_id,
                    )
                    if stored is None:
                        continue
                    response = SecurityScopeResponseV4.model_validate_stored(
                        _json_value(stored["response"])
                    ).model_copy(update={"status": "failed", "completed_at": now})
                    sequence = await connection.fetchval(
                        "SELECT COALESCE(MAX(sequence),0)+1 FROM security_analysis_events WHERE analysis_id=$1",
                        analysis_id,
                    )
                    event = SecurityAnalysisEventV4(
                        analysis_id=analysis_id,
                        sequence=sequence,
                        status="failed",
                        step="payload_expired",
                        kind="final",
                        message="Encrypted Security v4 payload expired before processing completed.",
                        occurred_at=now,
                    )
                    await connection.execute(
                        """UPDATE security_analyses SET status='failed',response=$2::jsonb,
                                  updated_at=$3,completed_at=$3 WHERE id=$1""",
                        analysis_id,
                        response.model_dump_json(),
                        now,
                    )
                    await connection.execute(
                        """INSERT INTO security_analysis_events(
                               event_id,analysis_id,sequence,event_type,payload,occurred_at
                           ) VALUES($1,$2,$3,'final',$4::jsonb,$5)""",
                        event.event_id,
                        analysis_id,
                        sequence,
                        event.model_dump_json(),
                        now,
                    )
                    await connection.execute(
                        """INSERT INTO security_analysis_outbox_v4(
                               id,analysis_id,event_type,payload,idempotency_key,created_at
                           ) VALUES($1,$2,'security_analysis.final',$3::jsonb,$4,$5)
                           ON CONFLICT(idempotency_key) DO NOTHING""",
                        uuid4(),
                        analysis_id,
                        event.model_dump_json(),
                        f"security-v4-event:{analysis_id}:{sequence}",
                        now,
                    )
        return len(rows)

    async def operations_metrics(self, started_at: datetime, ended_at: datetime) -> OperationsMetricsResponseV3:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            latency_rows = await connection.fetch(
                """SELECT operation,count(*) AS calls,
                          percentile_cont(0.5) WITHIN GROUP(ORDER BY latency_ms) AS p50,
                          percentile_cont(0.95) WITHIN GROUP(ORDER BY latency_ms) AS p95,
                          percentile_cont(0.99) WITHIN GROUP(ORDER BY latency_ms) AS p99
                   FROM tool_usage WHERE observed_at >= $1 AND observed_at < $2 GROUP BY operation""",
                started_at,
                ended_at,
            )
            cache_rows = await connection.fetch(
                """SELECT provider,count(*) FILTER(WHERE cache_status='hit') AS hits,
                          count(*) FILTER(WHERE cache_status='miss') AS misses
                   FROM tool_usage WHERE observed_at >= $1 AND observed_at < $2 GROUP BY provider""",
                started_at,
                ended_at,
            )
            usage_rows = await connection.fetch(
                """SELECT provider,model,count(*) AS calls,
                          coalesce(sum(coalesce(input_tokens,0)+coalesce(output_tokens,0)),0) AS tokens,
                          coalesce(sum(estimated_cost),0) AS cost,max(quota_used) AS quota_used,
                          count(*) FILTER(WHERE outcome='rate_limited' OR http_class='429') AS rate_limited,
                          count(*) FILTER(WHERE outcome='timeout') AS timed_out
                   FROM tool_usage WHERE observed_at >= $1 AND observed_at < $2 GROUP BY provider,model""",
                started_at,
                ended_at,
            )
            risk_rows = await connection.fetch(
                """SELECT response->>'risk_level' AS risk_level,count(*) AS count
                   FROM analyses WHERE created_at >= $1 AND created_at < $2
                     AND response->>'risk_level' IS NOT NULL GROUP BY response->>'risk_level'""",
                started_at,
                ended_at,
            )
            reports = await connection.fetchval(
                "SELECT count(*) FROM analysis_reports WHERE created_at >= $1 AND created_at < $2",
                started_at,
                ended_at,
            )
            appeal_rows = await connection.fetchrow(
                """SELECT count(*) AS total,
                          count(*) FILTER(WHERE outcome='uphold') AS upheld,
                          count(*) FILTER(WHERE outcome='overturn') AS overturned,
                          count(*) FILTER(WHERE outcome='inconclusive') AS inconclusive
                   FROM appeals WHERE created_at >= $1 AND created_at < $2""",
                started_at,
                ended_at,
            )
        risk_counts = {row["risk_level"]: row["count"] for row in risk_rows}
        total_appeals = appeal_rows["total"]
        return OperationsMetricsResponseV3(
            window=MetricsWindowV3(started_at=started_at, ended_at=ended_at),
            generated_at=datetime.now(UTC),
            latency=[
                LatencyMetricV3(
                    operation=row["operation"],
                    count=row["calls"],
                    p50_ms=row["p50"],
                    p95_ms=row["p95"],
                    p99_ms=row["p99"],
                )
                for row in latency_rows
            ],
            cache=[
                CacheMetricV3(
                    provider=row["provider"],
                    hits=row["hits"],
                    misses=row["misses"],
                    hit_rate=row["hits"] / (row["hits"] + row["misses"]) if row["hits"] + row["misses"] else None,
                )
                for row in cache_rows
            ],
            usage=[
                UsageMetricV3(
                    provider=row["provider"],
                    model=row["model"],
                    calls=row["calls"],
                    tokens=row["tokens"],
                    estimated_cost_usd=float(row["cost"]),
                    quota_used=float(row["quota_used"]) if row["quota_used"] is not None else None,
                    rate_limited=row["rate_limited"],
                    timed_out=row["timed_out"],
                )
                for row in usage_rows
            ],
            risk_distribution=[
                RiskDistributionMetricV3(risk_level=level, count=risk_counts.get(level.value, 0)) for level in RiskLevel
            ],
            feedback=FeedbackMetricV3(
                reports=reports,
                appeals=total_appeals,
                appeals_upheld=appeal_rows["upheld"],
                appeals_overturned=appeal_rows["overturned"],
                appeals_inconclusive=appeal_rows["inconclusive"],
                false_positive_rate=appeal_rows["overturned"] / total_appeals if total_appeals else None,
            ),
        )

    @staticmethod
    def _review_queue_item(row) -> ReviewQueueItem:
        snapshot = _json_value(row["evidence_snapshot"])
        return ReviewQueueItem(
            item_id=row["id"],
            report_id=row["report_id"],
            analysis_id=row["analysis_id"],
            status=ReportStatus(row["status"]),
            reason=row["reason"],
            comment=row["comment"],
            analysis_content=row["analysis_content"],
            evidence_snapshot=[Evidence.model_validate(item) for item in snapshot],
            decision=ReportReviewDecision(row["decision"]) if row["decision"] else None,
            reviewer_id=row["reviewer_id"],
            reviewer_note=row["reviewer_note"],
            reviewed_at=row["reviewed_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def close(self) -> None:
        if self._owns_pool and self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def healthcheck(self) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            return bool(await connection.fetchval("SELECT 1"))


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _analysis_request_from_json(value: str) -> AnalysisCreateRequest:
    payload = json.loads(value)
    return AnalysisCreateRequestV3.model_validate(payload)


def _safe_url_or_text(value: str) -> str:
    """Remove credentials, query strings, and fragments before persistence."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value[:500]
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return value[:500]
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit((parsed.scheme, f"{parsed.hostname}{port}", parsed.path, "", ""))[:2000]


def _canonical_domain_or_target(value: str) -> str:
    target = value.strip().lower()
    try:
        parsed = urlsplit(target if "://" in target else f"https://{target}")
    except ValueError:
        return target[:500]
    if parsed.hostname is None:
        raise ValueError("admin action target must contain a hostname")
    hostname = normalize_hostname(parsed.hostname)
    if DEFAULT_PUBLIC_SUFFIX_LIST.registrable_domain(hostname) is None:
        raise ValueError("admin action target must be a registrable domain")
    return hostname


def _platform_conflict(message: str) -> PlatformError:
    return PlatformError(
        status_code=409,
        code=ErrorCode.INTERNAL_ERROR,
        message=message,
        retryable=False,
    )
