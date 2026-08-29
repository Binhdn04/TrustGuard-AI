from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from alembic.config import Config
from alembic.script import ScriptDirectory

from src.core.auth import Principal, UserRole
from src.models import (
    AnalysisStatus,
    BrandRecordV4,
    SecurityAnalysisEventKindV4,
    SecurityAnalysisEventV4,
    SecurityTriageCreateRequestV4,
    TrustLifecycleV4,
    WhitelistRecordV4,
    WhitelistScopeV4,
)
from src.repositories.postgres import DurableJob, LostJobLeaseError, PostgresPlatformRepository
from src.services.security_analysis import SecurityAnalysisService
from src.services.security_triage import SecurityTriageScopeService

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def repository() -> PostgresPlatformRepository:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.fail("TEST_DATABASE_URL is required for PostgreSQL integration tests")
    instance = PostgresPlatformRepository(database_url, "integration-encryption-key-at-least-32")
    try:
        yield instance
    finally:
        await instance.close()


@pytest.mark.asyncio
async def test_database_is_migrated_to_the_repository_head(repository: PostgresPlatformRepository) -> None:
    assert await repository.healthcheck() is True
    pool = await repository._get_pool()
    async with pool.acquire() as connection:
        database_heads = {
            row["version_num"] for row in await connection.fetch("SELECT version_num FROM alembic_version")
        }
    migration_heads = set(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())

    assert database_heads == migration_heads


@pytest.mark.asyncio
async def test_first_async_security_turn_creates_conversation_before_analysis_foreign_key(
    repository: PostgresPlatformRepository,
) -> None:
    request = SecurityTriageCreateRequestV4(
        message="Ngân hàng yêu cầu gửi OTP ngay",
        execution_mode="async",
    )
    response = SecurityTriageScopeService().assess(request)
    service = SecurityAnalysisService(repository)

    accepted = await service.enqueue_turn(
        request,
        response,
        Principal(f"async-fk-owner-{uuid4()}", UserRole.USER),
        f"async-fk-turn-{uuid4()}",
    )

    conversation = await repository.load_security_conversation(str(accepted.conversation_id))
    analysis = await repository.load_security_analysis(str(accepted.analysis_id))

    assert conversation is not None
    assert analysis is not None
    assert analysis[1].conversation_id == accepted.conversation_id


@pytest.mark.asyncio
async def test_brand_disable_is_single_winner_and_immutably_audited(
    repository: PostgresPlatformRepository,
) -> None:
    now = datetime.now(UTC)
    suffix = uuid4().hex
    brand = BrandRecordV4(
        name=f"Integration Brand {suffix}",
        official_domains=[f"{suffix}.example.test"],
        provenance="integration-test",
        effective_from=now,
        reviewer_id="integration-admin",
        created_at=now,
    )
    await repository.create_brand(brand)

    results = await asyncio.gather(
        repository.disable_brand(str(brand.brand_id), "reviewer-one", now + timedelta(seconds=1)),
        repository.disable_brand(str(brand.brand_id), "reviewer-two", now + timedelta(seconds=2)),
    )

    disabled = [result for result in results if result is not None]
    assert len(disabled) == 1
    assert disabled[0].lifecycle is TrustLifecycleV4.DISABLED
    assert disabled[0].supersedes == brand.brand_id
    assert brand.brand_id not in {
        item.brand_id for item in await repository.list_active_brands(now + timedelta(minutes=1))
    }

    pool = await repository._get_pool()
    async with pool.acquire() as connection:
        audit = await connection.fetch(
            """SELECT action,reviewer_id FROM security_trust_audit
               WHERE resource_id=$1 OR resource_id=$2 ORDER BY occurred_at""",
            brand.brand_id,
            disabled[0].brand_id,
        )
    assert [(row["action"], row["reviewer_id"]) for row in audit] == [
        ("created", "integration-admin"),
        ("disabled", disabled[0].reviewer_id),
    ]


@pytest.mark.asyncio
async def test_whitelist_lifecycle_round_trips_through_postgres(repository: PostgresPlatformRepository) -> None:
    now = datetime.now(UTC)
    record = WhitelistRecordV4(
        indicator=f"{uuid4().hex}.example.test",
        scope=WhitelistScopeV4.DOMAIN,
        provenance="integration-test",
        effective_from=now,
        reviewer_id="integration-admin",
        created_at=now,
    )

    await repository.create_whitelist(record)
    assert record.whitelist_id in {
        item.whitelist_id for item in await repository.list_active_whitelist(now + timedelta(seconds=1))
    }

    disabled = await repository.disable_whitelist(
        str(record.whitelist_id),
        "integration-reviewer",
        now + timedelta(seconds=2),
    )

    assert disabled is not None
    assert disabled.lifecycle is TrustLifecycleV4.DISABLED
    assert record.whitelist_id not in {
        item.whitelist_id for item in await repository.list_active_whitelist(now + timedelta(minutes=1))
    }


@pytest.mark.asyncio
async def test_security_progress_and_final_commit_serialize_without_post_final_append(
    repository: PostgresPlatformRepository,
) -> None:
    """The analysis-row lock makes sequence allocation and terminality atomic."""
    now = datetime.now(UTC)
    worker_id = f"integration-worker-{uuid4()}"
    scoped = (
        SecurityTriageScopeService()
        .assess(SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay", execution_mode="async"))
        .model_copy(update={"status": AnalysisStatus.RUNNING})
    )
    completed = scoped.model_copy(update={"status": AnalysisStatus.COMPLETED, "completed_at": now})
    progress = SecurityAnalysisEventV4(
        analysis_id=scoped.analysis_id,
        sequence=1,
        status=AnalysisStatus.RUNNING,
        step="investigation",
        kind=SecurityAnalysisEventKindV4.PROGRESS,
        message="progress.investigation.started",
        occurred_at=now,
    )
    final = SecurityAnalysisEventV4(
        analysis_id=scoped.analysis_id,
        sequence=1,
        status=AnalysisStatus.COMPLETED,
        step="completed",
        kind=SecurityAnalysisEventKindV4.FINAL,
        message="Security v4 analysis completed.",
        occurred_at=now,
    )
    job_id = uuid4()
    pool = await repository._get_pool()
    async with pool.acquire() as connection:
        await connection.execute(
            """INSERT INTO security_analyses(
                   id,owner_id,status,response,created_at,updated_at,completed_at
               ) VALUES($1,$2,'running',$3::jsonb,$4,$4,NULL)""",
            scoped.analysis_id,
            "progress-integration-owner",
            scoped.model_dump_json(),
            now,
        )
        await connection.execute(
            """INSERT INTO security_analysis_jobs_v4(
                   id,analysis_id,status,attempt,max_attempts,available_at,claimed_at,
                   lease_expires_at,worker_id,created_at,updated_at
               ) VALUES($1,$2,'running',1,3,$3,$3,$4,$5,$3,$3)""",
            job_id,
            scoped.analysis_id,
            now,
            now + timedelta(minutes=1),
            worker_id,
        )

    job = DurableJob(
        job_id,
        scoped.analysis_id,
        "security_v4",
        1,
        3,
        now + timedelta(minutes=1),
    )
    heartbeat_progress = progress.model_copy(update={"event_id": uuid4()})
    with repository.job_scope(job.id, worker_id):
        appended, renewed = await asyncio.wait_for(
            asyncio.gather(
                repository.append_security_analysis_event(heartbeat_progress),
                repository.renew_security_job(job.id, worker_id, lease_seconds=60),
            ),
            timeout=1,
        )
    assert appended.sequence == 1
    assert renewed is True

    async def append_as_active_worker(event: SecurityAnalysisEventV4) -> SecurityAnalysisEventV4:
        with repository.job_scope(job.id, worker_id):
            return await repository.append_security_analysis_event(event)

    concurrent_results = await asyncio.gather(
        append_as_active_worker(progress),
        repository.complete_security_analysis_job(job, worker_id, completed, final),
        return_exceptions=True,
    )

    assert all(
        not isinstance(item, BaseException) or isinstance(item, LostJobLeaseError) for item in concurrent_results
    )
    loaded = await repository.load_security_analysis(str(scoped.analysis_id))
    assert loaded is not None
    _, persisted, events = loaded
    assert persisted.status is AnalysisStatus.COMPLETED
    assert [event.sequence for event in events] == list(range(1, len(events) + 1))
    assert events[-1].kind is SecurityAnalysisEventKindV4.FINAL

    with pytest.raises(LostJobLeaseError):
        await append_as_active_worker(progress.model_copy(update={"event_id": uuid4()}))

    async with pool.acquire() as connection:
        outbox_keys = await connection.fetch(
            """SELECT idempotency_key FROM security_analysis_outbox_v4
               WHERE analysis_id=$1 ORDER BY created_at,id""",
            scoped.analysis_id,
        )
    assert len(outbox_keys) == len(events)
    assert len({row["idempotency_key"] for row in outbox_keys}) == len(events)


@pytest.mark.asyncio
async def test_security_retry_allows_repeated_progress_but_only_current_attempt_can_finalize(
    repository: PostgresPlatformRepository,
) -> None:
    now = datetime.now(UTC)
    first_worker = f"retry-worker-one-{uuid4()}"
    second_worker = f"retry-worker-two-{uuid4()}"
    scoped = (
        SecurityTriageScopeService()
        .assess(SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay", execution_mode="async"))
        .model_copy(update={"status": AnalysisStatus.RUNNING})
    )
    completed = scoped.model_copy(update={"status": AnalysisStatus.COMPLETED, "completed_at": now})
    job_id = uuid4()
    pool = await repository._get_pool()
    async with pool.acquire() as connection:
        await connection.execute(
            """INSERT INTO security_analyses(
                   id,owner_id,status,response,created_at,updated_at,completed_at
               ) VALUES($1,$2,'running',$3::jsonb,$4,$4,NULL)""",
            scoped.analysis_id,
            "retry-integration-owner",
            scoped.model_dump_json(),
            now,
        )
        await connection.execute(
            """INSERT INTO security_analysis_jobs_v4(
                   id,analysis_id,status,attempt,max_attempts,available_at,claimed_at,
                   lease_expires_at,worker_id,created_at,updated_at
               ) VALUES($1,$2,'running',1,3,$3,$3,$4,$5,$3,$3)""",
            job_id,
            scoped.analysis_id,
            now,
            now + timedelta(minutes=1),
            first_worker,
        )

    first_job = DurableJob(job_id, scoped.analysis_id, "security_v4", 1, 3, now + timedelta(minutes=1))
    first_progress = SecurityAnalysisEventV4(
        analysis_id=scoped.analysis_id,
        sequence=1,
        status=AnalysisStatus.RUNNING,
        step="investigation",
        kind=SecurityAnalysisEventKindV4.PROGRESS,
        message="progress.investigation.started",
        occurred_at=now,
    )
    with repository.job_scope(first_job.id, first_worker):
        await repository.append_security_analysis_event(first_progress)

    assert await repository.retry_security_job(first_job, "TEST_RETRY", first_worker) is True
    async with pool.acquire() as connection:
        await connection.execute(
            "UPDATE security_analysis_jobs_v4 SET available_at=$2 WHERE id=$1",
            job_id,
            now,
        )
    second_job = await repository.claim_security_job(second_worker)
    assert second_job is not None
    assert second_job.id == first_job.id
    assert second_job.attempt == 2

    with repository.job_scope(first_job.id, first_worker), pytest.raises(LostJobLeaseError):
        await repository.append_security_analysis_event(first_progress.model_copy(update={"event_id": uuid4()}))

    second_progress = first_progress.model_copy(update={"event_id": uuid4()})
    with repository.job_scope(second_job.id, second_worker):
        await repository.append_security_analysis_event(second_progress)

    final = SecurityAnalysisEventV4(
        analysis_id=scoped.analysis_id,
        sequence=1,
        status=AnalysisStatus.COMPLETED,
        step="completed",
        kind=SecurityAnalysisEventKindV4.FINAL,
        message="Security v4 analysis completed.",
        occurred_at=now,
    )
    with pytest.raises(LostJobLeaseError):
        await repository.complete_security_analysis_job(first_job, first_worker, completed, final)
    await repository.complete_security_analysis_job(second_job, second_worker, completed, final)

    loaded = await repository.load_security_analysis(str(scoped.analysis_id))
    assert loaded is not None
    _, persisted, events = loaded
    assert persisted.status is AnalysisStatus.COMPLETED
    assert [event.sequence for event in events] == [1, 2, 3]
    assert [event.kind for event in events] == [
        SecurityAnalysisEventKindV4.PROGRESS,
        SecurityAnalysisEventKindV4.PROGRESS,
        SecurityAnalysisEventKindV4.FINAL,
    ]
