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
    """Small async cache whose key always includes provider/schema version."""

    def __init__(self, *, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
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

    def miss_metadata(self, namespace: str, version: str, target: str) -> CacheMetadata:
        return CacheMetadata(
            status=CacheStatus.MISS,
            cache_key_hash=self.key_hash(namespace, version, target),
        )
