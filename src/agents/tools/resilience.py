from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    pass


class CircuitBreaker:
    """Per-provider failure circuit with one half-open probe."""

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        recovery_timeout: timedelta = timedelta(seconds=30),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be positive")
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._clock = clock
        self._failures = 0
        self._opened_at: datetime | None = None
        self._probe_active = False
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        if self._opened_at is None:
            return CircuitState.CLOSED
        if self._clock() - self._opened_at >= self.recovery_timeout:
            return CircuitState.HALF_OPEN
        return CircuitState.OPEN

    async def before_call(self) -> None:
        async with self._lock:
            state = self.state
            if state is CircuitState.OPEN or (state is CircuitState.HALF_OPEN and self._probe_active):
                raise CircuitOpenError("provider circuit is open")
            if state is CircuitState.HALF_OPEN:
                self._probe_active = True

    async def record_success(self) -> None:
        async with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probe_active = False

    async def record_failure(self) -> None:
        async with self._lock:
            self._probe_active = False
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = self._clock()


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 2
    base_delay_seconds: float = 0.1
    max_delay_seconds: float = 2.0

    def delay(self, failed_attempt: int, retry_after_seconds: float | None = None) -> float:
        if retry_after_seconds is not None:
            return min(max(0.0, retry_after_seconds), self.max_delay_seconds)
        return min(self.base_delay_seconds * (2 ** max(0, failed_attempt - 1)), self.max_delay_seconds)


async def backoff(
    seconds: float,
    *,
    sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    if seconds > 0:
        await sleeper(seconds)
