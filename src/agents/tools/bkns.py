from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any
from uuid import uuid4

import httpx

from src.agents.tools.cache import VersionedMemoryCache
from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST
from src.agents.tools.models import (
    CacheMetadata,
    CacheStatus,
    NormalizedToolError,
    NormalizedToolResult,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UsageMetadata,
)
from src.models import DomainIntelligenceResult

BKNS_WHOIS_ENDPOINT = "https://whois.bkns.vn/api/v2/whois"
BKNS_PROVIDER = "bkns-whois/v2"
BKNS_PROVIDER_VERSION = "v2"
_BKNS_STATUSES = {"registered", "available", "pending", "reserved", "auction"}


def _parse_utc(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("date must be an ISO 8601 string or null")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("date must be a valid ISO 8601 value") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _retry_after_ms(value: str | None, now: datetime) -> int | None:
    if value is None:
        return None
    try:
        return max(0, int(float(value.strip()) * 1000))
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        retry_at = retry_at.astimezone(UTC)
        return max(0, int((retry_at - now).total_seconds() * 1000))


def _contains_key(value: object, expected: str) -> bool:
    if isinstance(value, dict):
        return expected in value or any(_contains_key(item, expected) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, expected) for item in value)
    return False


class BknsWhoisProvider:
    """Privacy-minimizing normalized adapter for the fixed BKNS WHOIS v2 endpoint."""

    provider = BKNS_PROVIDER
    provider_version = BKNS_PROVIDER_VERSION

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
        cache_ttl: timedelta = timedelta(hours=24),
        not_found_ttl: timedelta = timedelta(hours=1),
        max_cache_entries: int = 10_000,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not api_key.strip():
            raise ValueError("BKNS WHOIS requires a non-empty API key")
        self._api_key = api_key.strip()
        self._client = client
        self._owns_client = client is None
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._clock = clock
        self._cache: VersionedMemoryCache[DomainIntelligenceResult] = VersionedMemoryCache(
            max_entries=max_cache_entries,
            clock=clock,
        )

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            # The endpoint is deliberately not configurable: callers can only
            # send a canonical domain to the fixed HTTPS BKNS host.
            self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=False)
        return self._client

    async def lookup(self, domain: str) -> NormalizedToolResult[DomainIntelligenceResult]:
        started = time.perf_counter()
        try:
            registrable = DEFAULT_PUBLIC_SUFFIX_LIST.registrable_domain(domain)
        except ValueError as exc:
            return self._failure(
                started,
                ToolErrorCode.INVALID_TARGET,
                str(exc),
                retryable=False,
                attempts=0,
                calls=0,
            )
        if registrable is None:
            return self._failure(
                started,
                ToolErrorCode.INVALID_TARGET,
                "WHOIS lookup requires a registrable domain.",
                retryable=False,
                attempts=0,
                calls=0,
            )

        cached = await self._cache.get(self.provider, self.provider_version, registrable)
        if cached is not None:
            result = cached.value.model_copy(deep=True)
            return NormalizedToolResult(
                status=self._status(result),
                result=result,
                cache=cached.metadata,
                usage=self._usage(started, attempts=0, calls=0),
            )

        now = self._clock()
        try:
            response = await self._http().get(
                BKNS_WHOIS_ENDPOINT,
                params={"domain": registrable},
                headers={"X-API-Key": self._api_key, "Accept": "application/json"},
            )
        except httpx.TimeoutException:
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_TIMEOUT,
                "BKNS WHOIS provider timed out.",
                retryable=True,
                attempts=1,
                calls=1,
            )
        except httpx.HTTPError:
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "BKNS WHOIS provider request failed.",
                retryable=True,
                attempts=1,
                calls=1,
            )

        if response.status_code == 400:
            return self._failure(
                started,
                ToolErrorCode.INVALID_TARGET,
                "BKNS WHOIS rejected the domain.",
                retryable=False,
                attempts=1,
                calls=1,
                http_status_code=400,
            )
        if response.status_code in {401, 403}:
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "BKNS WHOIS authentication failed.",
                retryable=False,
                attempts=1,
                calls=1,
                http_status_code=response.status_code,
            )
        if response.status_code == 429:
            return self._failure(
                started,
                ToolErrorCode.RATE_LIMITED,
                "BKNS WHOIS provider rate limited the request.",
                retryable=True,
                attempts=1,
                calls=1,
                http_status_code=429,
                retry_after_ms=_retry_after_ms(response.headers.get("Retry-After"), now),
            )
        if response.status_code >= 500:
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "BKNS WHOIS provider is unavailable.",
                retryable=True,
                attempts=1,
                calls=1,
                http_status_code=response.status_code,
            )
        if response.status_code >= 400:
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "BKNS WHOIS provider rejected the request.",
                retryable=False,
                attempts=1,
                calls=1,
                http_status_code=response.status_code,
            )

        try:
            payload: Any = response.json()
            result = self._normalize(registrable, payload, now)
        except (ValueError, TypeError):
            return self._failure(
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "BKNS WHOIS returned an invalid response.",
                retryable=True,
                attempts=1,
                calls=1,
            )

        ttl = self._not_found_ttl if "not_found" in result.signals else self._cache_ttl
        await self._cache.put(self.provider, self.provider_version, registrable, result.model_copy(deep=True), ttl)
        return NormalizedToolResult(
            status=self._status(result),
            result=result,
            cache=self._cache.miss_metadata(self.provider, self.provider_version, registrable),
            usage=self._usage(started, attempts=1, calls=1),
        )

    def _normalize(
        self,
        domain: str,
        payload: Any,
        observed_at: datetime,
    ) -> DomainIntelligenceResult:
        if not isinstance(payload, dict):
            raise ValueError("response must be an object")
        response_domain = payload.get("domain")
        status_value = payload.get("status")
        if not isinstance(response_domain, str) or response_domain.casefold().rstrip(".") != domain:
            raise ValueError("response domain mismatch")
        if not isinstance(status_value, str) or status_value not in _BKNS_STATUSES:
            raise ValueError("invalid WHOIS status")

        registered_at: datetime | None = None
        expires_at: datetime | None = None
        registrar: str | None = None
        epp_status: list[str] = []
        # Inspect field names only. Private field values are never copied into
        # the normalized object, logs, errors, or cache.
        privacy_redacted = _contains_key(payload, "registrant")
        data = payload.get("data")
        if status_value == "registered" and not isinstance(data, dict):
            raise ValueError("registered response requires data")
        if status_value in {"registered", "pending"} and data is not None:
            if not isinstance(data, dict):
                raise ValueError("data must be an object")
            dates = data.get("dates")
            if dates is not None and not isinstance(dates, dict):
                raise ValueError("dates must be an object")
            if isinstance(dates, dict):
                registered_at = _parse_utc(dates.get("created"))
                expires_at = _parse_utc(dates.get("expiry"))
            registrar_data = data.get("registrar")
            if registrar_data is not None and not isinstance(registrar_data, dict):
                raise ValueError("registrar must be an object")
            if isinstance(registrar_data, dict):
                name = registrar_data.get("name")
                registrar = name.strip() if isinstance(name, str) and name.strip() else None
            domain_status = data.get("domainStatus", [])
            if not isinstance(domain_status, list):
                raise ValueError("domainStatus must be an array")
            epp_status = sorted({item.strip() for item in domain_status if isinstance(item, str) and item.strip()})

        signals: list[str] = []
        if status_value == "available":
            signals.append("not_found")
        elif status_value in {"pending", "reserved", "auction"}:
            signals.append(status_value)
        if status_value == "registered" and registered_at is not None:
            age = observed_at - registered_at
            if timedelta(0) <= age < timedelta(days=30):
                signals.append("recent_registration")

        return DomainIntelligenceResult(
            provider=self.provider,
            domain=domain,
            registered_at=registered_at,
            expires_at=expires_at,
            registrar=registrar,
            status=epp_status,
            privacy_redacted=privacy_redacted,
            signals=signals,
            observed_at=observed_at,
        )

    @staticmethod
    def _status(result: DomainIntelligenceResult) -> ToolResultStatus:
        return ToolResultStatus.INCONCLUSIVE if "not_found" in result.signals else ToolResultStatus.SUCCESS

    def _usage(self, started: float, *, attempts: int, calls: int) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:rdap:{uuid4()}",
            provider=self.provider,
            provider_version=self.provider_version,
            operation="whois_lookup",
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
        retryable: bool,
        attempts: int,
        calls: int,
        http_status_code: int | None = None,
        retry_after_ms: int | None = None,
    ) -> NormalizedToolResult[DomainIntelligenceResult]:
        return NormalizedToolResult(
            status=ToolResultStatus.FAILED,
            error=NormalizedToolError(
                tool=ToolName.RDAP,
                code=code,
                message=message,
                retryable=retryable,
                provider=self.provider,
                http_status_code=http_status_code,
                retry_after_ms=retry_after_ms,
            ),
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="invalid_or_failed_lookup"),
            usage=self._usage(started, attempts=attempts, calls=calls),
        )

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()


__all__ = ["BKNS_PROVIDER", "BKNS_WHOIS_ENDPOINT", "BknsWhoisProvider"]
