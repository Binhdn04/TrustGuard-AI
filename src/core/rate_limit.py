from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Protocol


class RateLimiter(Protocol):
    async def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool: ...
    async def close(self) -> None: ...


class MemoryRateLimiter:
    def __init__(self) -> None:
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        async with self._lock:
            bucket = self._requests[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

    async def close(self) -> None:
        self._requests.clear()


class RedisRateLimiter:
    """Atomic fixed-window limiter shared across API replicas."""

    _SCRIPT = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
    if current > tonumber(ARGV[1]) then return 0 end
    return 1
    """

    def __init__(self, redis_url: str) -> None:
        from redis.asyncio import Redis

        self._redis = Redis.from_url(redis_url, decode_responses=True)

    async def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        window = int(time.time()) // window_seconds
        result = await self._redis.eval(self._SCRIPT, 1, f"rate:{key}:{window}", limit, window_seconds + 1)
        return bool(result)

    async def close(self) -> None:
        await self._redis.aclose()
