from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from src.agents.security_risk import assess_security_risk
from src.api.dependencies import get_grounded_security_response_service, get_security_understanding_service
from src.config import Settings
from src.models import AnalysisStatus, SecurityTriageCreateRequestV4
from src.repositories.postgres import DurableJob
from src.security_ai.runtime import SecurityAssistantRuntime, TurnBudget
from src.services.durable_worker import OutboxPublisher, RetentionWorker, SecurityV4JobHandler
from src.services.security_triage import SecurityTriageScopeService


@pytest.mark.asyncio
async def test_wp1_to_wp4_dependencies_share_one_turn_budget() -> None:
    runtime = SecurityAssistantRuntime(budget=TurnBudget(max_calls=4))
    understanding = await get_security_understanding_service(runtime)
    responses = await get_grounded_security_response_service(runtime)

    assert understanding._runtime is runtime  # noqa: SLF001 - dependency identity is the gate under test
    assert responses._runtime is runtime  # noqa: SLF001 - dependency identity is the gate under test


def test_async_capability_is_truthful_for_postgres_worker_only() -> None:
    sqlite = Settings(security_async_execution_enabled=True, _env_file=None)
    postgres = Settings(
        security_async_execution_enabled=True,
        database_url="postgresql://test:test@localhost/test",
        run_durable_worker=True,
        _env_file=None,
    )
    assert sqlite.enabled_security_capabilities()["security_async_execution"] is False
    assert postgres.enabled_security_capabilities()["security_async_execution"] is True


def test_wp5_migration_uses_isolated_encrypted_durable_tables() -> None:
    migration = Path("migrations/versions/0016_security_v4_durable_jobs.py").read_text(encoding="utf-8")
    repository = Path("src/repositories/postgres.py").read_text(encoding="utf-8")
    assert "security_analysis_jobs_v4" in migration
    assert "security_analysis_payloads_v4" in migration
    assert "security_analysis_outbox_v4" in migration
    assert "security_analysis_idempotency_v4" in migration
    assert "payload_ciphertext bytea NOT NULL" in migration
    assert "pgp_sym_encrypt($2,$3)" in repository
    assert "lease_expires_at > now()" in repository
    assert "DELETE FROM security_analysis_payloads_v4" in repository
    assert "FOR UPDATE SKIP LOCKED" in repository


class FakePipeline:
    def __init__(self, result) -> None:
        self.result = result

    async def process(self, request, scoped, *, runtime, progress, owner_id=None):
        del request, scoped, runtime, owner_id
        await progress("investigation", "progress", [], None)
        return self.result


class FakeDurableRepository:
    def __init__(self, owner_id, request, scoped) -> None:
        self.payload = (owner_id, request, scoped)
        self.events = []
        self.completed = None

    async def load_security_job_payload(self, job, worker_id):
        del job, worker_id
        return self.payload

    async def append_security_analysis_event(self, event):
        event = event.model_copy(update={"sequence": len(self.events) + 1})
        self.events.append(event)
        return event

    async def complete_security_analysis_job(self, job, worker_id, response, event):
        del job, worker_id
        self.payload = None
        self.completed = response
        self.events.append(event.model_copy(update={"sequence": len(self.events) + 1}))


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
    assert memory.effects == {scoped.analysis_id}
    assert proposed == {scoped.analysis_id}
    assert analyses.finalized == [(scoped.analysis_id, "owner-1")]


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
