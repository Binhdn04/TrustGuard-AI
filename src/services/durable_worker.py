from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from src.agents.tools.models import ToolResultStatus
from src.agents.tools.protocols import EmbeddingProvider
from src.core.auth import Principal, UserRole
from src.models import AnalysisStatus, SecurityAnalysisEventKindV4, SecurityAnalysisEventV4
from src.repositories.postgres import DurableJob, LostJobLeaseError, PostgresPlatformRepository
from src.security_ai.runtime import SecurityAssistantRuntime

if TYPE_CHECKING:
    from src.services.analysis import AnalysisService
from src.services.platform_wave2 import UsageLedgerEntry
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_memory import SecurityMemoryService
from src.services.security_pipeline import SecurityTriagePipeline
from src.services.security_progress import (
    SecurityProgressMessageCode,
    SecurityProgressReporter,
    SecurityProgressUpdate,
)

logger = logging.getLogger(__name__)

class SecurityV4JobHandler:
    """Execute an immutable encrypted Security v4 turn and commit it once."""

    def __init__(
        self,
        repository: PostgresPlatformRepository,
        analyses: SecurityAnalysisService,
        *,
        pipeline_factory: Callable[[SecurityAssistantRuntime], SecurityTriagePipeline],
        runtime_factory: Callable[[], SecurityAssistantRuntime],
        memory: SecurityMemoryService,
        propose_actions: Callable[[object], Awaitable[object]],
    ) -> None:
        self._repository = repository
        self._analyses = analyses
        self._pipeline_factory = pipeline_factory
        self._runtime_factory = runtime_factory
        self._memory = memory
        self._propose_actions = propose_actions

    async def __call__(self, job: DurableJob, worker_id: str) -> None:
        loaded = await self._repository.load_security_job_payload(job, worker_id)
        if loaded is None:
            raise RuntimeError("security v4 encrypted payload is unavailable")
        owner_id, request, scoped = loaded
        principal = Principal(owner_id, UserRole.USER)
        runtime = self._runtime_factory()
        reporter = SecurityProgressReporter(job.analysis_id, self._repository.append_security_analysis_event)
        reporter.start()

        await reporter.emit(
            SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.RUNNING_STARTED)
        )
        try:
            result = await self._pipeline_factory(runtime).process(
                request,
                scoped.model_copy(update={"status": AnalysisStatus.RUNNING}),
                runtime=runtime,
                progress=reporter.emit,
                owner_id=owner_id,
            )
        except BaseException:
            await reporter.quiesce()
            raise
        await reporter.quiesce()
        if result.status is not AnalysisStatus.COMPLETED:
            result = result.model_copy(update={"status": AnalysisStatus.COMPLETED, "completed_at": datetime.now(UTC)})
        if result.risk is not None:
            await self._memory.record(result, owner_id)
            await self._propose_actions(result)
        final = SecurityAnalysisEventV4(
            analysis_id=result.analysis_id,
            sequence=1,
            status=AnalysisStatus.COMPLETED,
            step="completed",
            kind=SecurityAnalysisEventKindV4.FINAL,
            message="Security v4 analysis completed.",
            evidence_refs=list(result.explanation_evidence_refs),
            risk_hint=result.risk,
            occurred_at=result.completed_at or datetime.now(UTC),
        )
        await self._repository.complete_security_analysis_job(job, worker_id, result, final)
        await self._analyses.finalize_durable(result, principal)


class SecurityV4DurableWorker:
    """Lease worker dedicated to the isolated Security v4 job tables."""

    def __init__(
        self,
        repository: PostgresPlatformRepository,
        handler: SecurityV4JobHandler,
        *,
        lease_seconds: int = 60,
        idle_seconds: float = 0.5,
    ) -> None:
        self._repository = repository
        self._handler = handler
        self._lease_seconds = lease_seconds
        self._idle_seconds = idle_seconds
        self._worker_id = f"security-v4:{socket.gethostname()}:{uuid4()}"
        self._stopping = asyncio.Event()

    async def run(self) -> None:
        while not self._stopping.is_set():
            try:
                job = await self._repository.claim_security_job(self._worker_id, self._lease_seconds)
            except Exception as exc:
                logger.warning("security_v4_job_claim_failed", extra={"failure_code": type(exc).__name__})
                await self._idle()
                continue
            if job is None:
                await self._idle()
                continue
            try:
                await self._execute(job)
            except LostJobLeaseError:
                logger.warning("security_v4_job_lease_lost", extra={"job_id": str(job.id)})
            except Exception as exc:
                logger.warning(
                    "security_v4_job_failed",
                    extra={"job_id": str(job.id), "failure_code": type(exc).__name__},
                )
                await self._repository.retry_security_job(job, type(exc).__name__, self._worker_id)

    async def _execute(self, job: DurableJob) -> None:
        processing = asyncio.create_task(self._handler(job, self._worker_id), name=f"security-v4-{job.id}")
        heartbeat = asyncio.create_task(self._renew(job.id), name=f"security-v4-lease-{job.id}")
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
            raise LostJobLeaseError("security v4 lease renewal failed") from exc
        raise LostJobLeaseError("security v4 lease renewal stopped")

    async def _renew(self, job_id) -> None:
        interval = max(self._lease_seconds / 3, 1)
        while True:
            await asyncio.sleep(interval)
            if not await self._repository.renew_security_job(job_id, self._worker_id, self._lease_seconds):
                raise LostJobLeaseError("security v4 job lease ownership was lost")

    async def _idle(self) -> None:
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=self._idle_seconds)
        except TimeoutError:
            pass

    def stop(self) -> None:
        self._stopping.set()


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
        claim_security = getattr(self._repository, "claim_security_outbox", None)
        security_messages = await claim_security(self._worker_id) if claim_security is not None else []
        for message in security_messages:
            await self._redis.publish(f"trustguard:analysis:{message.aggregate_id}", message.event_type)
            mark_security = getattr(self._repository, "mark_security_outbox_published")
            await mark_security(message.id)
        return len(security_messages)

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
    """Tombstone minimized retained input and security payloads."""

    def __init__(
        self,
        repository: PostgresPlatformRepository,
        *,
        interval_seconds: float = 3600,
    ) -> None:
        self._repository = repository
        self._interval_seconds = interval_seconds
        self._stopping = asyncio.Event()

    async def run_once(self, now: datetime | None = None) -> int:
        cutoff = now or datetime.now(UTC)
        expire_conversations = getattr(self._repository, "expire_security_conversations", None)
        if expire_conversations is not None:
            await expire_conversations(cutoff)
        expire_security_payloads = getattr(self._repository, "expire_security_job_payloads", None)
        if expire_security_payloads is not None:
            await expire_security_payloads(cutoff)
        return 0

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
