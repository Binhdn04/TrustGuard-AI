from datetime import UTC, datetime
from uuid import uuid4

import pytest

from src.core.auth import Principal, UserRole
from src.core.logging import redact
from src.core.rate_limit import MemoryRateLimiter
from src.models import AnalysisCreateRequest
from src.services.analysis import AnalysisService
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
