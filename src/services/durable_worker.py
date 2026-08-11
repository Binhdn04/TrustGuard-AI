from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import uuid4

from src.agents.tools.models import ToolResultStatus
from src.agents.tools.protocols import EmbeddingProvider
from src.repositories.postgres import DurableJob, LostJobLeaseError, PostgresPlatformRepository
from src.services.analysis import AnalysisService
from src.services.platform_wave2 import UsageLedgerEntry

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
        job_handlers: dict[str, Callable[[DurableJob], Awaitable[None]]] | None = None,
        before_analysis: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._repository = repository
        self._service = service
        self._lease_seconds = lease_seconds
        self._idle_seconds = idle_seconds
        self._job_handlers = job_handlers or {}
        self._before_analysis = before_analysis
        self._worker_id = f"{socket.gethostname()}:{uuid4()}"
        self._stopping = asyncio.Event()

    async def run(self) -> None:
        while not self._stopping.is_set():
            try:
                job = await self._repository.claim_job(self._worker_id, self._lease_seconds)
            except Exception as exc:
                logger.warning(
                    "analysis_job_claim_failed",
                    extra={"failure_code": type(exc).__name__},
                )
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=self._idle_seconds)
                except TimeoutError:
                    pass
                continue
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
            if job.kind == "analyze":
                if self._before_analysis is not None:
                    await self._before_analysis()
                operation = self._service.process_durable_job(job.analysis_id)
            else:
                handler = self._job_handlers.get(job.kind)
                if handler is None:
                    raise RuntimeError(f"No durable handler is registered for job kind {job.kind}")
                operation = handler(job)
            processing = asyncio.create_task(operation, name=f"process-{job.id}")
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

    async def close(self) -> None:
        for handler in self._job_handlers.values():
            close = getattr(handler, "close", None)
            if close is not None:
                await close()


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
            try:
                published = await self.publish_once()
            except Exception as exc:
                logger.warning(
                    "outbox_publish_failed",
                    extra={"failure_code": type(exc).__name__},
                )
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=1.0)
                except TimeoutError:
                    pass
                continue
            if published == 0:
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=0.5)
                except TimeoutError:
                    pass

    def stop(self) -> None:
        self._stopping.set()

    async def close(self) -> None:
        await self._redis.aclose()


class RetentionWorker:
    """Delete expired artifact objects, then tombstone minimized retained input."""

    def __init__(
        self,
        repository: PostgresPlatformRepository,
        *,
        delete_object: Callable[[str], Awaitable[None]] | None = None,
        interval_seconds: float = 3600,
    ) -> None:
        self._repository = repository
        self._delete_object = delete_object
        self._interval_seconds = interval_seconds
        self._stopping = asyncio.Event()

    async def run_once(self, now: datetime | None = None) -> tuple[int, int]:
        cutoff = now or datetime.now(UTC)
        storage_keys = await self._repository.expire_artifacts(cutoff)
        if self._delete_object is not None:
            for storage_key in storage_keys:
                await self._delete_object(storage_key)
        minimized = await self._repository.expire_minimized_content(cutoff)
        return len(storage_keys), minimized

    async def run(self) -> None:
        while not self._stopping.is_set():
            try:
                await self.run_once()
            except Exception as exc:
                logger.warning("retention_job_failed", extra={"failure_code": type(exc).__name__})
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._interval_seconds)
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stopping.set()


class ReembeddingJobHandler:
    """Idempotently fill pending result vectors without changing stance or provenance."""

    def __init__(self, repository: PostgresPlatformRepository, provider: EmbeddingProvider) -> None:
        self._repository = repository
        self._provider = provider

    async def __call__(self, job: DurableJob) -> None:
        pending = await self._repository.get_reembedding_claim(job)
        if pending is None:
            return
        result_id, claim = pending
        envelope = await self._provider.embed_batch([claim])
        await self._repository.record_usage(
            UsageLedgerEntry(
                analysis_id=job.analysis_id,
                provider=envelope.usage.provider,
                model=getattr(self._provider, "model", None),
                provider_version=envelope.usage.provider_version,
                operation=envelope.usage.operation,
                units=envelope.usage.network_calls,
                input_tokens=envelope.usage.tokens,
                estimated_cost_usd=envelope.usage.estimated_cost_usd,
                latency_ms=round(envelope.usage.latency_ms),
                cache_status=envelope.cache.status.value,
                outcome=envelope.status.value,
                http_class="429" if envelope.error and envelope.error.code.value == "RATE_LIMITED" else None,
                observed_at=envelope.usage.observed_at,
            )
        )
        if envelope.status is not ToolResultStatus.SUCCESS or envelope.result is None:
            raise RuntimeError("embedding provider did not complete the pending result")
        vector = envelope.result.vectors[0].vector
        await self._repository.complete_reembedding(
            result_id,
            vector=vector,
            model=envelope.result.model,
            model_version=envelope.result.model_version,
            embedding_version="v1",
            embedded_at=datetime.now(UTC),
        )

    async def close(self) -> None:
        close = getattr(self._provider, "aclose", None)
        if close is not None:
            await close()
