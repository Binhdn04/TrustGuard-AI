from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from src.core.auth import Principal, UserRole


@dataclass(frozen=True, slots=True)
class TicketGrant:
    analysis_id: UUID
    user_id: str
    role: UserRole
    expires_at: datetime


class TicketStore(Protocol):
    async def put(self, digest: str, grant: TicketGrant, ttl_seconds: int) -> None: ...
    async def pop(self, digest: str) -> TicketGrant | None: ...
    async def close(self) -> None: ...


class EventListener(Protocol):
    async def wait(self, timeout_seconds: float) -> None: ...
    async def close(self) -> None: ...


class EventNotifier(Protocol):
    async def listen(self, analysis_id: UUID) -> EventListener: ...
    async def close(self) -> None: ...


class PollingEventListener:
    """Offline fallback with bounded, low-frequency correctness polling."""

    async def wait(self, timeout_seconds: float) -> None:
        await asyncio.sleep(min(timeout_seconds, 1.0))

    async def close(self) -> None:
        pass


class MemoryEventNotifier:
    async def listen(self, analysis_id: UUID) -> EventListener:
        del analysis_id
        return PollingEventListener()

    async def close(self) -> None:
        pass


class RedisEventListener:
    def __init__(self, notifier: RedisEventNotifier, analysis_id: UUID, event: asyncio.Event) -> None:
        self._notifier = notifier
        self._analysis_id = analysis_id
        self._event = event

    async def wait(self, timeout_seconds: float) -> None:
        if self._event.is_set():
            self._event.clear()
            return
        try:
            await asyncio.wait_for(self._event.wait(), timeout=timeout_seconds)
        except TimeoutError:
            return
        self._event.clear()

    async def close(self) -> None:
        await self._notifier.remove(self._analysis_id, self._event)


class RedisEventNotifier:
    """Wake WebSockets from outbox delivery; PostgreSQL remains replay authority."""

    def __init__(self, redis_url: str) -> None:
        try:
            from redis.asyncio import Redis
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("redis is required for realtime notifications") from exc
        self._redis = Redis.from_url(redis_url, decode_responses=True)
        self._pubsub = self._redis.pubsub()
        self._listeners: dict[UUID, set[asyncio.Event]] = {}
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None

    async def listen(self, analysis_id: UUID) -> EventListener:
        event = asyncio.Event()
        async with self._lock:
            self._listeners.setdefault(analysis_id, set()).add(event)
            if self._task is None:
                await self._pubsub.psubscribe("trustguard:analysis:*")
                self._task = asyncio.create_task(self._dispatch(), name="redis-realtime-dispatch")
        return RedisEventListener(self, analysis_id, event)

    async def remove(self, analysis_id: UUID, event: asyncio.Event) -> None:
        async with self._lock:
            listeners = self._listeners.get(analysis_id)
            if listeners is None:
                return
            listeners.discard(event)
            if not listeners:
                self._listeners.pop(analysis_id, None)

    async def _dispatch(self) -> None:
        while True:
            message = await self._pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if not message:
                continue
            channel = str(message.get("channel", ""))
            try:
                analysis_id = UUID(channel.rsplit(":", 1)[-1])
            except ValueError:
                continue
            async with self._lock:
                listeners = tuple(self._listeners.get(analysis_id, ()))
            for event in listeners:
                event.set()

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        await self._pubsub.punsubscribe("trustguard:analysis:*")
        await self._pubsub.aclose()
        await self._redis.aclose()


class MemoryTicketStore:
    """Single-process test/development ticket store with atomic consumption."""

    def __init__(self) -> None:
        self._items: dict[str, TicketGrant] = {}
        self._lock = asyncio.Lock()

    async def put(self, digest: str, grant: TicketGrant, ttl_seconds: int) -> None:
        del ttl_seconds
        async with self._lock:
            self._items[digest] = grant

    async def pop(self, digest: str) -> TicketGrant | None:
        async with self._lock:
            grant = self._items.pop(digest, None)
        if grant is None or grant.expires_at <= datetime.now(UTC):
            return None
        return grant

    async def close(self) -> None:
        async with self._lock:
            self._items.clear()


class RedisTicketStore:
    """Atomic, expiring ticket storage shared by API replicas."""

    _POP_SCRIPT = """
    local value = redis.call('GET', KEYS[1])
    if value then redis.call('DEL', KEYS[1]) end
    return value
    """

    def __init__(self, redis_url: str) -> None:
        try:
            from redis.asyncio import Redis
        except ImportError as exc:  # pragma: no cover - deployment dependency guard
            raise RuntimeError("redis is required for RedisTicketStore") from exc
        self._redis = Redis.from_url(redis_url, decode_responses=True)

    async def put(self, digest: str, grant: TicketGrant, ttl_seconds: int) -> None:
        payload = json.dumps(
            {
                "analysis_id": str(grant.analysis_id),
                "user_id": grant.user_id,
                "role": grant.role.value,
                "expires_at": grant.expires_at.isoformat(),
            },
            separators=(",", ":"),
        )
        await self._redis.set(f"ws-ticket:{digest}", payload, ex=ttl_seconds, nx=True)

    async def pop(self, digest: str) -> TicketGrant | None:
        payload = await self._redis.eval(self._POP_SCRIPT, 1, f"ws-ticket:{digest}")
        if not payload:
            return None
        value = json.loads(payload)
        grant = TicketGrant(
            analysis_id=UUID(value["analysis_id"]),
            user_id=value["user_id"],
            role=UserRole(value["role"]),
            expires_at=datetime.fromisoformat(value["expires_at"]).astimezone(UTC),
        )
        return grant if grant.expires_at > datetime.now(UTC) else None

    async def close(self) -> None:
        await self._redis.aclose()


class WebSocketTicketManager:
    def __init__(self, store: TicketStore, ttl_seconds: int = 60) -> None:
        self._store = store
        self._ttl_seconds = ttl_seconds

    async def issue(self, analysis_id: UUID, principal: Principal) -> tuple[str, datetime]:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=self._ttl_seconds)
        await self._store.put(
            _ticket_digest(token),
            TicketGrant(analysis_id, principal.user_id, principal.role, expires_at),
            self._ttl_seconds,
        )
        return token, expires_at

    async def consume(self, token: str, analysis_id: UUID) -> Principal | None:
        if not token or len(token) > 256:
            return None
        grant = await self._store.pop(_ticket_digest(token))
        if grant is None or grant.analysis_id != analysis_id:
            return None
        return Principal(grant.user_id, grant.role)

    async def close(self) -> None:
        await self._store.close()


def _ticket_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
