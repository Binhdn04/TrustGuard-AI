from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Generic, TypeVar

from .models import CacheMetadata, CacheStatus

T = TypeVar("T")


@dataclass(frozen=True)
class CachedValue(Generic[T]):
    value: T
    metadata: CacheMetadata


@dataclass
class _Entry(Generic[T]):
    value: T
    stored_at: datetime
    expires_at: datetime


class VersionedMemoryCache(Generic[T]):
    """Bounded async cache whose key includes provider/schema version."""

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._clock = clock
        self._items: dict[str, _Entry[T]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def key_hash(namespace: str, version: str, target: str) -> str:
        material = f"{namespace}\0{version}\0{target}".encode()
        return hashlib.sha256(material).hexdigest()

    async def get(self, namespace: str, version: str, target: str) -> CachedValue[T] | None:
        key = self.key_hash(namespace, version, target)
        now = self._clock()
        async with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            if item.expires_at <= now:
                self._items.pop(key, None)
                return None
            return CachedValue(
                value=item.value,
                metadata=CacheMetadata(
                    status=CacheStatus.HIT,
                    cache_key_hash=key,
                    stored_at=item.stored_at,
                    expires_at=item.expires_at,
                ),
            )

    async def put(self, namespace: str, version: str, target: str, value: T, ttl: timedelta) -> None:
        if ttl <= timedelta(0):
            return
        now = self._clock()
        key = self.key_hash(namespace, version, target)
        async with self._lock:
            self._items[key] = _Entry(value=value, stored_at=now, expires_at=now + ttl)
            # Opportunistic sweeping prevents expired one-off targets from
            # accumulating forever in a long-running worker.
            expired = [item_key for item_key, item in self._items.items() if item.expires_at <= now]
            for item_key in expired:
                self._items.pop(item_key, None)
            while len(self._items) > self._max_entries:
                self._items.pop(next(iter(self._items)))

    def miss_metadata(self, namespace: str, version: str, target: str) -> CacheMetadata:
        # Pure derivation from immutable string values; it neither reads nor
        # mutates cache state and therefore needs no lock.
        return CacheMetadata(
            status=CacheStatus.MISS,
            cache_key_hash=self.key_hash(namespace, version, target),
        )
