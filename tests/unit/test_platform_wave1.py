import asyncio
from contextlib import contextmanager
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from src.core.auth import Principal, UserRole
from src.core.errors import PlatformError
from src.core.logging import redact
from src.core.rate_limit import MemoryRateLimiter
from src.models import AnalysisCreateRequest
from src.repositories.postgres import DurableJob, LostJobLeaseError, PostgresPlatformRepository
from src.services.analysis import AnalysisService
from src.services.durable_worker import DurableAnalysisWorker
from src.services.realtime import MemoryTicketStore, WebSocketTicketManager


@pytest.mark.asyncio
async def test_websocket_ticket_is_bound_expiring_and_single_use() -> None:
    manager = WebSocketTicketManager(MemoryTicketStore(), ttl_seconds=60)
    analysis_id = uuid4()
    principal = Principal("owner-1", UserRole.USER)

    ticket, expires_at = await manager.issue(analysis_id, principal)

    assert expires_at > datetime.now(UTC)
    assert await manager.consume(ticket, analysis_id) == principal
    assert await manager.consume(ticket, analysis_id) is None


@pytest.mark.asyncio
async def test_memory_rate_limit_is_scoped_by_principal() -> None:
    limiter = MemoryRateLimiter()

    assert await limiter.allow("user:a", 2)
    assert await limiter.allow("user:a", 2)
    assert not await limiter.allow("user:a", 2)
    assert await limiter.allow("user:b", 2)


@pytest.mark.asyncio
async def test_report_listing_authorization_is_enforced_in_service() -> None:
    service = AnalysisService()
    owner = Principal("owner-1", UserRole.USER)
    accepted = await service.create(
        AnalysisCreateRequest(message="Owner-only report list", consent_to_scan_urls=False),
        owner,
    )

    with pytest.raises(PlatformError) as error:
        await service.list_reports_by_analysis(
            accepted.analysis_id,
            Principal("other-user", UserRole.USER),
        )

    assert error.value.status_code == 403
    await service.aclose()


def test_structured_log_redaction_recurses() -> None:
    assert redact({"authorization": "Bearer secret", "nested": {"otp": "123456", "ok": 1}}) == {
        "authorization": "[REDACTED]",
        "nested": {"otp": "[REDACTED]", "ok": 1},
    }


class _DurableRepository:
    durable_jobs = True

    def __init__(self) -> None:
        self.created = []

    async def create_analysis(self, **values) -> None:
        self.created.append(values)


class _NeverInlineProcessor:
    def __init__(self) -> None:
        self.called = False

    async def process(self, *args, **kwargs):
        self.called = True
        raise AssertionError("durable work must not run in the API request")


@pytest.mark.asyncio
async def test_durable_create_commits_enqueue_without_inline_processing() -> None:
    repository = _DurableRepository()
    processor = _NeverInlineProcessor()
    service = AnalysisService(
        blacklist=repository,
        processor=processor,
        durable_jobs=True,  # type: ignore[arg-type]
    )

    accepted = await service.create(
        AnalysisCreateRequest(message="Inspect this claim", consent_to_scan_urls=False),
        Principal("owner-1", UserRole.USER),
    )

    assert accepted.analysis_id == repository.created[0]["response"].analysis_id
    assert not processor.called
    assert repository.created[0]["event"].status.value == "queued"


class _LeaseLossRepository:
    @contextmanager
    def job_scope(self, job_id, worker_id):
        del job_id, worker_id
        yield

    async def renew_job(self, job_id, worker_id, lease_seconds):
        del job_id, worker_id, lease_seconds
        return False


class _CancellableService:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    async def process_durable_job(self, analysis_id) -> None:
        del analysis_id
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class _ImmediateLeaseLossWorker(DurableAnalysisWorker):
    async def _renew_lease(self, job_id) -> None:
        del job_id
        await asyncio.sleep(0)
        raise LostJobLeaseError("simulated lease loss")


@pytest.mark.asyncio
async def test_lease_loss_immediately_cancels_in_flight_processing() -> None:
    repository = _LeaseLossRepository()
    service = _CancellableService()
    worker = _ImmediateLeaseLossWorker(
        repository,
        service,  # type: ignore[arg-type]
    )
    job = DurableJob(uuid4(), uuid4(), "analyze", 1, 3, datetime.now(UTC))

    with pytest.raises(LostJobLeaseError):
        await worker._execute_claimed_job(job)

    assert service.started.is_set()
    assert service.cancelled


class _RecordingConnection:
    def __init__(self) -> None:
        self.query = ""
        self.values = ()

    async def fetch(self, query, *values):
        self.query = query
        self.values = values
        return []


class _AcquireConnection:
    def __init__(self, connection) -> None:
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *args):
        return False


class _RecordingPool:
    def __init__(self) -> None:
        self.connection = _RecordingConnection()

    def acquire(self):
        return _AcquireConnection(self.connection)


@pytest.mark.asyncio
async def test_postgres_list_filters_never_interpolate_caller_values() -> None:
    pool = _RecordingPool()
    repository = PostgresPlatformRepository("postgresql://unused", "key", pool=pool)
    malicious = "owner' OR TRUE --"

    assert await repository.list_analysis_responses(owner_id=malicious, case_status="pending_review") == []

    assert malicious not in pool.connection.query
    assert "$1" in pool.connection.query and "$2" in pool.connection.query
    assert pool.connection.values == (malicious, "pending_review")
