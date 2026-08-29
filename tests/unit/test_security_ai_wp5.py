from __future__ import annotations

import asyncio
from contextlib import nullcontext
from pathlib import Path
from uuid import uuid4

import pytest

from src.agents.security_risk import assess_security_risk
from src.api.dependencies import get_grounded_security_response_service, get_security_understanding_service
from src.config import Settings
from src.models import AnalysisStatus, SecurityTriageCreateRequestV4
from src.repositories.postgres import DurableJob, LostJobLeaseError
from src.security_ai.runtime import SecurityAssistantRuntime, TurnBudget
from src.services.durable_worker import OutboxPublisher, RetentionWorker, SecurityV4DurableWorker, SecurityV4JobHandler
from src.services.security_progress import SecurityProgressMessageCode, SecurityProgressUpdate
from src.services.security_triage import SecurityTriageScopeService


@pytest.mark.asyncio
async def test_wp1_to_wp4_dependencies_share_one_turn_budget() -> None:
    runtime = SecurityAssistantRuntime(budget=TurnBudget(max_calls=4))
    understanding = await get_security_understanding_service(runtime)
    responses = await get_grounded_security_response_service(runtime)

    assert understanding._runtime is runtime  # noqa: SLF001 - dependency identity is the gate under test
    assert responses._runtime is runtime  # noqa: SLF001 - dependency identity is the gate under test


def test_async_capability_is_truthful_for_postgres_with_a_separate_worker() -> None:
    sqlite = Settings(security_async_execution_enabled=True, _env_file=None)
    api_with_remote_worker = Settings(
        security_async_execution_enabled=True,
        database_url="postgresql://test:test@localhost/test",
        run_durable_worker=False,
        _env_file=None,
    )
    assert sqlite.enabled_security_capabilities()["security_async_execution"] is False
    assert api_with_remote_worker.enabled_security_capabilities()["security_async_execution"] is True


def test_wp5_migration_uses_isolated_encrypted_durable_tables() -> None:
    migration = Path("migrations/versions/0016_security_v4_durable_jobs.py").read_text(encoding="utf-8")
    repository = Path("src/repositories/postgres.py").read_text(encoding="utf-8")
    job_repository = Path("src/repositories/postgres_jobs.py").read_text(encoding="utf-8")
    assert "security_analysis_jobs_v4" in migration
    assert "security_analysis_payloads_v4" in migration
    assert "security_analysis_outbox_v4" in migration
    assert "security_analysis_idempotency_v4" in migration
    assert "payload_ciphertext bytea NOT NULL" in migration
    assert "pgp_sym_encrypt($2,$3)" in repository
    assert "lease_expires_at > now()" in job_repository
    assert "DELETE FROM security_analysis_payloads_v4" in job_repository
    assert "FOR UPDATE SKIP LOCKED" in job_repository


class FakePipeline:
    def __init__(self, result) -> None:
        self.result = result

    async def process(self, request, scoped, *, runtime, progress, owner_id=None):
        del request, scoped, runtime, owner_id
        await progress(SecurityProgressUpdate.for_message_code(SecurityProgressMessageCode.INVESTIGATION_COMPLETED))
        return self.result


class FakeDurableRepository:
    def __init__(self, owner_id, request, scoped) -> None:
        self.payload = (owner_id, request, scoped)
        self.events = []
        self.completed = None
        self.progress_after_final = False

    async def load_security_job_payload(self, job, worker_id):
        del job, worker_id
        return self.payload

    def job_scope(self, job_id, worker_id):
        del job_id, worker_id
        return nullcontext()

    async def append_security_analysis_event(self, event):
        self.progress_after_final = self.completed is not None
        event = event.model_copy(update={"sequence": len(self.events) + 1})
        self.events.append(event)
        return event

    async def complete_security_analysis_job(self, job, worker_id, response, event):
        del job, worker_id
        self.payload = None
        self.completed = response
        self.events.append(event.model_copy(update={"sequence": len(self.events) + 1}))


class ProgressFailingDurableRepository(FakeDurableRepository):
    async def append_security_analysis_event(self, event):
        del event
        raise ConnectionError("progress store unavailable")


class FinalCommitFailsOnceDurableRepository(FakeDurableRepository):
    def __init__(self, owner_id, request, scoped) -> None:
        super().__init__(owner_id, request, scoped)
        self.final_commit_attempts = 0

    async def complete_security_analysis_job(self, job, worker_id, response, event):
        self.final_commit_attempts += 1
        if self.final_commit_attempts == 1:
            raise ConnectionError("terminal store temporarily unavailable")
        await super().complete_security_analysis_job(job, worker_id, response, event)


class LeaseLossDurableRepository(FakeDurableRepository):
    def __init__(self, owner_id, request, scoped) -> None:
        super().__init__(owner_id, request, scoped)
        self.append_started = asyncio.Event()
        self.append_cancelled = asyncio.Event()

    async def append_security_analysis_event(self, event):
        del event
        self.append_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.append_cancelled.set()
            raise

    async def renew_security_job(self, job_id, worker_id, lease_seconds):
        del job_id, worker_id, lease_seconds
        return False


class BlockingPipeline:
    async def process(self, request, scoped, *, runtime, progress, owner_id=None):
        del request, scoped, runtime, progress, owner_id
        await asyncio.Event().wait()


class FakeAnalyses:
    def __init__(self) -> None:
        self.finalized = []

    async def finalize_durable(self, response, principal):
        self.finalized.append((response.analysis_id, principal.user_id))


class IdempotentMemory:
    def __init__(self) -> None:
        self.effects = set()

    async def record(self, response, owner_id=None):
        del owner_id
        self.effects.add(response.analysis_id)


@pytest.mark.asyncio
async def test_durable_handler_emits_progress_purges_payload_and_keeps_side_effects_idempotent() -> None:
    request = SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay", execution_mode="async")
    scoped = SecurityTriageScopeService().assess(request)
    result = assess_security_risk(scoped).model_copy(update={"status": AnalysisStatus.COMPLETED})
    repository = FakeDurableRepository("owner-1", request, scoped)
    analyses = FakeAnalyses()
    memory = IdempotentMemory()
    proposed = set()

    async def propose(response):
        proposed.add(response.analysis_id)

    handler = SecurityV4JobHandler(
        repository,
        analyses,
        pipeline_factory=lambda runtime: FakePipeline(result),
        runtime_factory=SecurityAssistantRuntime,
        memory=memory,
        propose_actions=propose,
    )
    job = DurableJob(uuid4(), scoped.analysis_id, "security_v4", 1, 3, scoped.created_at)

    await handler(job, "worker-1")

    assert repository.payload is None
    assert repository.completed is not None
    assert [event.kind.value for event in repository.events] == ["progress", "progress", "final"]
    assert [event.step for event in repository.events] == ["running", "investigation", "completed"]
    assert [event.progress_state.value if event.progress_state else None for event in repository.events] == [
        "started",
        "completed",
        None,
    ]
    assert repository.progress_after_final is False
    assert memory.effects == {scoped.analysis_id}
    assert proposed == {scoped.analysis_id}
    assert analyses.finalized == [(scoped.analysis_id, "owner-1")]


@pytest.mark.asyncio
async def test_durable_handler_commits_final_when_progress_store_fails() -> None:
    request = SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay", execution_mode="async")
    scoped = SecurityTriageScopeService().assess(request)
    result = assess_security_risk(scoped).model_copy(update={"status": AnalysisStatus.COMPLETED})
    repository = ProgressFailingDurableRepository("owner-1", request, scoped)
    analyses = FakeAnalyses()
    handler = SecurityV4JobHandler(
        repository,
        analyses,
        pipeline_factory=lambda runtime: FakePipeline(result),
        runtime_factory=SecurityAssistantRuntime,
        memory=IdempotentMemory(),
        propose_actions=lambda response: _no_op(response),
    )
    job = DurableJob(uuid4(), scoped.analysis_id, "security_v4", 1, 3, scoped.created_at)

    await handler(job, "worker-1")

    assert repository.completed is not None
    assert [event.kind.value for event in repository.events] == ["final"]
    assert analyses.finalized == [(scoped.analysis_id, "owner-1")]


async def _no_op(response) -> None:
    del response


@pytest.mark.asyncio
async def test_durable_retry_repeats_progress_but_keeps_final_side_effects_idempotent() -> None:
    request = SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay", execution_mode="async")
    scoped = SecurityTriageScopeService().assess(request)
    result = assess_security_risk(scoped).model_copy(update={"status": AnalysisStatus.COMPLETED})
    repository = FinalCommitFailsOnceDurableRepository("owner-1", request, scoped)
    memory = IdempotentMemory()
    proposed: set = set()

    async def propose(response) -> None:
        proposed.add(response.analysis_id)

    handler = SecurityV4JobHandler(
        repository,
        FakeAnalyses(),
        pipeline_factory=lambda runtime: FakePipeline(result),
        runtime_factory=SecurityAssistantRuntime,
        memory=memory,
        propose_actions=propose,
    )
    first_job = DurableJob(uuid4(), scoped.analysis_id, "security_v4", 1, 3, scoped.created_at)
    second_job = DurableJob(first_job.id, scoped.analysis_id, "security_v4", 2, 3, scoped.created_at)

    with pytest.raises(ConnectionError, match="terminal store temporarily unavailable"):
        await handler(first_job, "worker-1")
    await handler(second_job, "worker-2")

    assert repository.final_commit_attempts == 2
    assert repository.completed is not None
    assert memory.effects == {scoped.analysis_id}
    assert proposed == {scoped.analysis_id}
    assert [event.kind.value for event in repository.events].count("final") == 1


@pytest.mark.asyncio
async def test_lost_security_lease_cancels_handler_and_progress_writer() -> None:
    request = SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay", execution_mode="async")
    scoped = SecurityTriageScopeService().assess(request)
    repository = LeaseLossDurableRepository("owner-1", request, scoped)
    handler = SecurityV4JobHandler(
        repository,
        FakeAnalyses(),
        pipeline_factory=lambda runtime: BlockingPipeline(),
        runtime_factory=SecurityAssistantRuntime,
        memory=IdempotentMemory(),
        propose_actions=lambda response: _no_op(response),
    )
    worker = SecurityV4DurableWorker(repository, handler, lease_seconds=1)
    job = DurableJob(uuid4(), scoped.analysis_id, "security_v4", 1, 3, scoped.created_at)

    with pytest.raises(LostJobLeaseError):
        await asyncio.wait_for(worker._execute(job), timeout=4)  # noqa: SLF001 - lifecycle invariant

    assert repository.append_started.is_set()
    assert repository.append_cancelled.is_set()
    assert repository.completed is None


class FailingRedis:
    async def publish(self, channel, event_type):
        del channel, event_type
        raise ConnectionError("redis unavailable")


class OutboxRepository:
    def __init__(self, message) -> None:
        self.message = message
        self.marked = []

    async def claim_security_outbox(self, worker_id):
        del worker_id
        return [self.message]

    async def mark_security_outbox_published(self, message_id):
        self.marked.append(message_id)


@pytest.mark.asyncio
async def test_redis_outage_never_marks_postgres_outbox_as_published() -> None:
    from src.repositories.postgres import OutboxMessage

    message = OutboxMessage(uuid4(), uuid4(), "security_analysis.progress", {}, "event-1")
    repository = OutboxRepository(message)
    publisher = object.__new__(OutboxPublisher)
    publisher._repository = repository  # noqa: SLF001 - isolated publisher failure test
    publisher._redis = FailingRedis()  # noqa: SLF001 - isolated publisher failure test
    publisher._worker_id = "outbox-test"  # noqa: SLF001 - isolated publisher failure test

    with pytest.raises(ConnectionError, match="redis unavailable"):
        await publisher.publish_once()

    assert repository.marked == []


class RetentionRepository:
    def __init__(self) -> None:
        self.security_payloads_expired = False

    async def expire_minimized_content(self, cutoff):
        del cutoff
        return 0

    async def expire_security_conversations(self, cutoff):
        del cutoff
        return 0

    async def expire_security_job_payloads(self, cutoff):
        del cutoff
        self.security_payloads_expired = True
        return 1


@pytest.mark.asyncio
async def test_retention_worker_purges_abandoned_encrypted_security_payloads() -> None:
    repository = RetentionRepository()
    await RetentionWorker(repository).run_once()
    assert repository.security_payloads_expired is True
