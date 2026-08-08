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
