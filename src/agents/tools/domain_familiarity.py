from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from .cache import VersionedMemoryCache
from .domains import canonicalize_registrable_domain
from .models import (
    DomainFamiliarityResult,
    NormalizedToolError,
    NormalizedToolResult,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UsageMetadata,
)
from .resilience import CircuitBreaker, CircuitOpenError


class CloudflareRadarDomainFamiliarityProvider:
    """Provider-neutral normalization for Cloudflare Radar popularity ranking."""

    provider = "cloudflare-radar"
    provider_version = "domain-ranking-v1"
    operation = "domain_popularity_lookup"
    endpoint = "https://api.cloudflare.com/client/v4/radar/ranking/domain/{domain}"

    def __init__(
        self,
        api_token: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 3.0,
        cache: VersionedMemoryCache[DomainFamiliarityResult] | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not api_token.strip():
            raise ValueError("Cloudflare Radar API token is required")
        self._token = api_token.strip()
        self._client = client
        self._owns_client = client is None
        self._timeout = min(timeout, 3.0)
        self._clock = clock
        self._cache = cache or VersionedMemoryCache(max_entries=10_000, clock=clock)
        self._circuit = circuit_breaker or CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=timedelta(seconds=30),
            clock=clock,
        )

    async def lookup(self, domain: str) -> NormalizedToolResult[DomainFamiliarityResult]:
        started = time.perf_counter()
        try:
            target = canonicalize_registrable_domain(domain)
        except ValueError as exc:
            return self._failure(started, ToolErrorCode.INVALID_TARGET, str(exc), attempts=0, calls=0, retryable=False)

        cached = await self._cache.get(self.provider, self.provider_version, target)
        if cached is not None:
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if cached.value.matched else ToolResultStatus.INCONCLUSIVE,
                result=cached.value.model_copy(deep=True),
                cache=cached.metadata,
                usage=self._usage(started, attempts=0, calls=0),
            )

        try:
            await self._circuit.before_call()
        except CircuitOpenError:
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "Domain familiarity provider circuit is open.",
                attempts=0,
                calls=0,
                retryable=True,
            )
        try:
            response = await self._http().get(
                self.endpoint.format(domain=target),
                params={"rankingType": "POPULAR"},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self._timeout,
            )
            if response.status_code == 429:
                await self._circuit.record_failure()
                return self._failure(
                    started,
                    ToolErrorCode.RATE_LIMITED,
                    "Domain familiarity provider rate limited the request.",
                    attempts=1,
                    calls=1,
                    retryable=False,
                    http_status_code=429,
                )
            response.raise_for_status()
            result = self.normalize_response(target, response.json(), observed_at=self._clock())
            await self._circuit.record_success()
            await self._cache.put(
                self.provider,
                self.provider_version,
                target,
                result,
                timedelta(hours=24) if result.matched else timedelta(hours=1),
            )
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if result.matched else ToolResultStatus.INCONCLUSIVE,
                result=result,
                cache=self._cache.miss_metadata(self.provider, self.provider_version, target),
                usage=self._usage(started, attempts=1, calls=1),
            )
        except httpx.TimeoutException:
            await self._circuit.record_failure()
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_TIMEOUT,
                "Domain familiarity provider timed out.",
                attempts=1,
                calls=1,
                retryable=True,
            )
        except (httpx.HTTPError, ValueError, TypeError):
            await self._circuit.record_failure()
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "Domain familiarity provider failed.",
                attempts=1,
                calls=1,
                retryable=True,
            )

    @staticmethod
    def normalize_response(
        domain: str,
        payload: Any,
        *,
        observed_at: datetime,
    ) -> DomainFamiliarityResult:
        if not isinstance(payload, dict) or payload.get("success") is False:
            raise ValueError("malformed Radar response")
        body = payload.get("result", payload)
        if not isinstance(body, dict):
            raise ValueError("malformed Radar result")
        details = next(
            (value for key, value in body.items() if key.startswith("details_") and isinstance(value, dict)),
            {},
        )
        rank = _positive_int(details.get("rank"))
        bucket = _positive_int(details.get("bucket"))
        if rank is not None and rank > 100:
            if bucket is None:
                raise ValueError("Radar returned an out-of-contract exact rank")
            rank = None
        meta = body.get("meta", {})
        date_ranges = meta.get("dateRange", []) if isinstance(meta, dict) else []
        window_end = (
            _parse_datetime(date_ranges[0].get("endTime")) if date_ranges and isinstance(date_ranges[0], dict) else None
        )
        return DomainFamiliarityResult(
            registrable_domain=canonicalize_registrable_domain(domain),
            matched=rank is not None or bucket is not None,
            popularity_rank=rank,
            popularity_bucket=bucket,
            dataset_window_end=window_end,
            observed_at=observed_at,
        )

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def _usage(self, started: float, *, attempts: int, calls: int) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:domain-familiarity:{uuid4()}",
            provider=self.provider,
            provider_version=self.provider_version,
            operation=self.operation,
            attempts=attempts,
            network_calls=calls,
            latency_ms=(time.perf_counter() - started) * 1000,
            request_units=calls,
            response_units=1 if calls else 0,
            observed_at=self._clock(),
        )

    def _failure(
        self,
        started: float,
        code: ToolErrorCode,
        message: str,
        *,
        attempts: int,
        calls: int,
        retryable: bool,
        http_status_code: int | None = None,
    ) -> NormalizedToolResult[DomainFamiliarityResult]:
        return NormalizedToolResult(
            status=ToolResultStatus.BLOCKED if code is ToolErrorCode.INVALID_TARGET else ToolResultStatus.FAILED,
            error=NormalizedToolError(
                tool=ToolName.DOMAIN_FAMILIARITY,
                code=code,
                message=message,
                retryable=retryable,
                provider=self.provider,
                http_status_code=http_status_code,
            ),
            cache=self._cache.miss_metadata(self.provider, self.provider_version, "invalid-or-redacted-target"),
            usage=self._usage(started, attempts=attempts, calls=calls),
        )

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    match = re.search(r"\d+", str(value)) if value is not None else None
    if match is not None:
        parsed = int(match.group())
        if parsed > 0:
            return parsed
    return None


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(UTC)
    return None


__all__ = ["CloudflareRadarDomainFamiliarityProvider"]
