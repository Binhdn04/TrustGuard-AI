from __future__ import annotations

import asyncio
import logging
import socket
from uuid import uuid4

from src.repositories.postgres import DurableJob, LostJobLeaseError, PostgresPlatformRepository
from src.services.analysis import AnalysisService

logger = logging.getLogger(__name__)


class DurableAnalysisWorker:
    """Lease-based worker; a crashed worker's job is reclaimable after expiry."""

    def __init__(
        self,
        repository: PostgresPlatformRepository,
        service: AnalysisService,
        *,
        lease_seconds: int = 60,
        idle_seconds: float = 0.5,
    ) -> None:
        self._repository = repository
        self._service = service
        self._lease_seconds = lease_seconds
        self._idle_seconds = idle_seconds
        self._worker_id = f"{socket.gethostname()}:{uuid4()}"
        self._stopping = asyncio.Event()

    async def run(self) -> None:
        while not self._stopping.is_set():
            job = await self._repository.claim_job(self._worker_id, self._lease_seconds)
            if job is None:
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=self._idle_seconds)
                except TimeoutError:
                    pass
                continue
            try:
                await self._execute_claimed_job(job)
            except LostJobLeaseError:
                # Ownership is uncertain or already transferred. Never update
                # the job or continue analysis under a stale lease.
                logger.warning(
                    "analysis_job_lease_lost",
                    extra={"job_id": str(job.id), "failure_code": "LostJobLeaseError"},
                )
            except Exception as exc:  # failure code is class only; no input/secret leakage
                logger.warning(
                    "analysis_job_failed",
                    extra={"job_id": str(job.id), "failure_code": type(exc).__name__},
                )
                await self._repository.retry_job(job, type(exc).__name__, self._worker_id)
            else:
                # Terminal persistence normally completes the job atomically;
                # this covers idempotent recovery of an already-terminal row.
                await self._repository.finish_job(job.id, self._worker_id)

    async def _execute_claimed_job(self, job: DurableJob) -> None:
        with self._repository.job_scope(job.id, self._worker_id):
            processing = asyncio.create_task(
                self._service.process_durable_job(job.analysis_id), name=f"process-{job.id}"
            )
            heartbeat = asyncio.create_task(self._renew_lease(job.id), name=f"lease-{job.id}")
            done, _ = await asyncio.wait({processing, heartbeat}, return_when=asyncio.FIRST_COMPLETED)
            if processing in done:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
                await processing
                return

            processing.cancel()
            await asyncio.gather(processing, return_exceptions=True)
            try:
                await heartbeat
            except Exception as exc:
                raise LostJobLeaseError("job lease renewal failed") from exc
            raise LostJobLeaseError("job lease renewal stopped unexpectedly")

    async def _renew_lease(self, job_id) -> None:
        interval = max(self._lease_seconds / 3, 1)
        while True:
            await asyncio.sleep(interval)
            renewed = await self._repository.renew_job(job_id, self._worker_id, self._lease_seconds)
            if not renewed:
                raise LostJobLeaseError("job lease ownership was lost")

    def stop(self) -> None:
        self._stopping.set()


class OutboxPublisher:
    """Publish minimized notifications after commit; PostgreSQL remains authoritative."""

    def __init__(self, repository: PostgresPlatformRepository, redis_url: str) -> None:
        try:
            from redis.asyncio import Redis
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("redis is required for outbox publishing") from exc
        self._repository = repository
        self._redis = Redis.from_url(redis_url, decode_responses=True)
        self._worker_id = f"outbox:{socket.gethostname()}:{uuid4()}"
        self._stopping = asyncio.Event()

    async def publish_once(self) -> int:
        messages = await self._repository.claim_outbox(self._worker_id)
        for message in messages:
            # Payloads are already minimized at the transaction boundary.
            await self._redis.publish(f"trustguard:analysis:{message.aggregate_id}", message.event_type)
            await self._repository.mark_outbox_published(message.id)
        return len(messages)

    async def run(self) -> None:
        while not self._stopping.is_set():
            published = await self.publish_once()
            if published == 0:
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=0.5)
                except TimeoutError:
                    pass

    def stop(self) -> None:
        self._stopping.set()

    async def close(self) -> None:
        await self._redis.aclose()
