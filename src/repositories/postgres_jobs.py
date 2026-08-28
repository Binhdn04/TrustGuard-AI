from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from src.models import SecurityAnalysisEventV4, SecurityScopeResponseV4


@dataclass(frozen=True, slots=True)
class DurableJob:
    id: UUID
    analysis_id: UUID
    kind: str
    attempt: int
    max_attempts: int
    lease_expires_at: datetime
    idempotency_key: str = ""


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    id: UUID
    aggregate_id: UUID
    event_type: str
    payload: dict[str, Any]
    idempotency_key: str


class LostJobLeaseError(RuntimeError):
    pass


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class PostgresJobsRepositoryMixin:
    """Durable job leases, retries, and transactional outbox persistence."""

    async def claim_job(self, worker_id: str, lease_seconds: int = 60) -> DurableJob | None:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        lease = now + timedelta(seconds=lease_seconds)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT id, analysis_id, kind, attempt, max_attempts, idempotency_key
                   FROM analysis_jobs
                   WHERE ((status IN ('queued','retry') AND available_at <= $1)
                          OR (status='running' AND lease_expires_at <= $1))
                     AND attempt < max_attempts
                   ORDER BY available_at, created_at
                   FOR UPDATE SKIP LOCKED LIMIT 1""",
                now,
            )
            if row is None:
                return None
            attempt = row["attempt"] + 1
            await connection.execute(
                """UPDATE analysis_jobs SET status='running', attempt=$2, worker_id=$3,
                          claimed_at=$4, lease_expires_at=$5, updated_at=$4 WHERE id=$1""",
                row["id"],
                attempt,
                worker_id,
                now,
                lease,
            )
        return DurableJob(
            row["id"],
            row["analysis_id"],
            row["kind"],
            attempt,
            row["max_attempts"],
            lease,
            row["idempotency_key"],
        )

    async def claim_security_job(self, worker_id: str, lease_seconds: int = 60) -> DurableJob | None:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        lease = now + timedelta(seconds=lease_seconds)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT id,analysis_id,attempt,max_attempts
                   FROM security_analysis_jobs_v4
                   WHERE ((status='queued' AND available_at <= $1)
                          OR (status='running' AND lease_expires_at <= $1))
                     AND attempt < max_attempts
                   ORDER BY available_at,created_at
                   FOR UPDATE SKIP LOCKED LIMIT 1""",
                now,
            )
            if row is None:
                return None
            attempt = row["attempt"] + 1
            await connection.execute(
                """UPDATE security_analysis_jobs_v4 SET status='running',attempt=$2,worker_id=$3,
                          claimed_at=$4,lease_expires_at=$5,updated_at=$4 WHERE id=$1""",
                row["id"],
                attempt,
                worker_id,
                now,
                lease,
            )
        return DurableJob(row["id"], row["analysis_id"], "security_v4", attempt, row["max_attempts"], lease)

    async def renew_security_job(self, job_id: UUID, worker_id: str, lease_seconds: int) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE security_analysis_jobs_v4
                   SET lease_expires_at=now()+($3 * interval '1 second'),updated_at=now()
                   WHERE id=$1 AND worker_id=$2 AND status='running'""",
                job_id,
                worker_id,
                lease_seconds,
            )
        return result == "UPDATE 1"

    async def retry_security_job(self, job: DurableJob, failure_code: str, worker_id: str) -> bool:
        pool = await self._get_pool()
        exhausted = job.attempt >= job.max_attempts
        delay = min(2**job.attempt, 60)
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            owned = await connection.fetchrow(
                """SELECT analysis_id FROM security_analysis_jobs_v4
                   WHERE id=$1 AND worker_id=$2 AND status='running'
                     AND lease_expires_at > now() FOR UPDATE""",
                job.id,
                worker_id,
            )
            if owned is None:
                return False
            if not exhausted:
                await connection.execute(
                    """UPDATE security_analysis_jobs_v4 SET status='queued',failure_code=$2,
                              available_at=$3::timestamptz+($4 * interval '1 second'),lease_expires_at=NULL,
                              worker_id=NULL,updated_at=$3 WHERE id=$1""",
                    job.id,
                    failure_code[:64],
                    now,
                    delay,
                )
                return True
            row = await connection.fetchrow(
                "SELECT response FROM security_analyses WHERE id=$1 FOR UPDATE",
                job.analysis_id,
            )
            if row is None:
                return False
            response = SecurityScopeResponseV4.model_validate_stored(_json_value(row["response"])).model_copy(
                update={"status": "failed", "completed_at": now}
            )
            sequence = await connection.fetchval(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM security_analysis_events WHERE analysis_id=$1",
                job.analysis_id,
            )
            event = SecurityAnalysisEventV4(
                analysis_id=job.analysis_id,
                sequence=sequence,
                status="failed",
                step="failed",
                kind="final",
                message="Security analysis failed after the retry budget was exhausted.",
                occurred_at=now,
            )
            await connection.execute(
                """UPDATE security_analyses SET status='failed',response=$2::jsonb,
                          updated_at=$3,completed_at=$3 WHERE id=$1""",
                job.analysis_id,
                response.model_dump_json(),
                now,
            )
            await connection.execute(
                """INSERT INTO security_analysis_events(
                       event_id,analysis_id,sequence,event_type,payload,occurred_at
                   ) VALUES($1,$2,$3,'final',$4::jsonb,$5)""",
                event.event_id,
                job.analysis_id,
                sequence,
                event.model_dump_json(),
                now,
            )
            await connection.execute("DELETE FROM security_analysis_payloads_v4 WHERE analysis_id=$1", job.analysis_id)
            await connection.execute(
                """UPDATE security_analysis_jobs_v4 SET status='failed',failure_code=$2,
                          lease_expires_at=NULL,worker_id=NULL,updated_at=$3 WHERE id=$1""",
                job.id,
                failure_code[:64],
                now,
            )
            await connection.execute(
                """INSERT INTO security_analysis_outbox_v4(
                       id,analysis_id,event_type,payload,idempotency_key,created_at
                   ) VALUES($1,$2,'security_analysis.final',$3::jsonb,$4,$5)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                job.analysis_id,
                event.model_dump_json(),
                f"security-v4-event:{job.analysis_id}:{sequence}",
                now,
            )
        return True

    async def finish_job(self, job_id: UUID, worker_id: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """UPDATE analysis_jobs SET status='completed', lease_expires_at=NULL,
                          worker_id=NULL, updated_at=now()
                   WHERE id=$1 AND worker_id=$2 AND status='running'""",
                job_id,
                worker_id,
            )

    async def renew_job(self, job_id: UUID, worker_id: str, lease_seconds: int) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE analysis_jobs SET lease_expires_at=now()+($3 * interval '1 second'),
                          updated_at=now() WHERE id=$1 AND worker_id=$2 AND status='running'""",
                job_id,
                worker_id,
                lease_seconds,
            )
        return result == "UPDATE 1"

    async def retry_job(self, job: DurableJob, failure_code: str, worker_id: str) -> bool:
        pool = await self._get_pool()
        exhausted = job.attempt >= job.max_attempts
        delay = min(2**job.attempt, 60)
        async with pool.acquire() as connection:
            updated = await connection.execute(
                """UPDATE analysis_jobs SET status=$2, failure_code=$3,
                          available_at=now()+($4 * interval '1 second'), lease_expires_at=NULL,
                          worker_id=NULL, updated_at=now()
                   WHERE id=$1 AND worker_id=$5 AND status='running'""",
                job.id,
                "failed" if exhausted else "retry",
                failure_code[:64],
                delay,
                worker_id,
            )
        return updated == "UPDATE 1"

    async def claim_outbox(self, worker_id: str, limit: int = 100) -> list[OutboxMessage]:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            rows = await connection.fetch(
                """SELECT id,aggregate_id,event_type,payload,idempotency_key FROM outbox
                   WHERE published_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at<=now())
                   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1""",
                limit,
            )
            ids = [row["id"] for row in rows]
            if ids:
                await connection.execute(
                    """UPDATE outbox SET worker_id=$2, lease_expires_at=now()+interval '30 seconds',
                              attempt_count=attempt_count+1 WHERE id=ANY($1::uuid[])""",
                    ids,
                    worker_id,
                )
        return [
            OutboxMessage(
                row["id"],
                row["aggregate_id"],
                row["event_type"],
                _json_value(row["payload"]),
                row["idempotency_key"],
            )
            for row in rows
        ]

    async def claim_security_outbox(self, worker_id: str, limit: int = 100) -> list[OutboxMessage]:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            rows = await connection.fetch(
                """SELECT id,analysis_id,event_type,payload,idempotency_key
                   FROM security_analysis_outbox_v4
                   WHERE published_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at<=now())
                   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1""",
                limit,
            )
            ids = [row["id"] for row in rows]
            if ids:
                await connection.execute(
                    """UPDATE security_analysis_outbox_v4 SET worker_id=$2,
                              lease_expires_at=now()+interval '30 seconds'
                       WHERE id=ANY($1::uuid[])""",
                    ids,
                    worker_id,
                )
        return [
            OutboxMessage(
                row["id"],
                row["analysis_id"],
                row["event_type"],
                _json_value(row["payload"]),
                row["idempotency_key"],
            )
            for row in rows
        ]

    async def mark_security_outbox_published(self, message_id: UUID) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """UPDATE security_analysis_outbox_v4
                   SET published_at=now(),lease_expires_at=NULL,worker_id=NULL WHERE id=$1""",
                message_id,
            )

    async def mark_outbox_published(self, message_id: UUID) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                "UPDATE outbox SET published_at=now(),lease_expires_at=NULL,worker_id=NULL WHERE id=$1",
                message_id,
            )



__all__ = [
    "DurableJob",
    "LostJobLeaseError",
    "OutboxMessage",
    "PostgresJobsRepositoryMixin",
]
