from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from src.models import (
    AnalysisCreateRequest,
    AnalysisEvent,
    AnalysisReportRecord,
    AnalysisReportResponse,
    AnalysisResponse,
    Evidence,
    ReportReviewDecision,
    ReportStatus,
    ReviewQueueItem,
    ToolError,
)


@dataclass(frozen=True, slots=True)
class DurableJob:
    id: UUID
    analysis_id: UUID
    kind: str
    attempt: int
    max_attempts: int
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    id: UUID
    aggregate_id: UUID
    event_type: str
    payload: dict[str, Any]
    idempotency_key: str


class PostgresPlatformRepository:
    """PostgreSQL source of truth for Wave 1 analysis/job/event state.

    Redis consumers receive only outbox notifications. Claims and sequence
    allocation always happen in PostgreSQL transactions.
    """

    durable_jobs = True

    def __init__(self, database_url: str, encryption_key: str, *, pool=None) -> None:
        self._database_url = database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
        self._encryption_key = encryption_key
        self._pool = pool
        self._owns_pool = pool is None
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
                       response, created_at, updated_at
                   ) VALUES ($1, $2, pgp_sym_encrypt($3, $4), $5, $6, $7, $8::jsonb, $9, $9)""",
                analysis_id,
                owner_id,
                request_json,
                self._encryption_key,
                hashlib.sha256(request_json.encode()).hexdigest(),
                request.consent_to_scan_urls,
                response.status.value,
                response.model_dump_json(),
                response.created_at,
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
            AnalysisCreateRequest.model_validate_json(row["request_json"]),
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
                "step_transition" if event.step_id else "analysis_status",
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

    async def claim_job(self, worker_id: str, lease_seconds: int = 60) -> DurableJob | None:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        lease = now + timedelta(seconds=lease_seconds)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT id, analysis_id, kind, attempt, max_attempts
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
        return DurableJob(row["id"], row["analysis_id"], row["kind"], attempt, row["max_attempts"], lease)

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

    async def mark_outbox_published(self, message_id: UUID) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                "UPDATE outbox SET published_at=now(),lease_expires_at=NULL,worker_id=NULL WHERE id=$1",
                message_id,
            )

    async def get(self, domain: str):
        # Wave 1 core can run before the reviewed-action tables from 0004.
        return None

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


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class LostJobLeaseError(RuntimeError):
    pass


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
