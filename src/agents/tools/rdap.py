from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urljoin
from uuid import uuid4

import httpx

from src.agents.tools.cache import VersionedMemoryCache
from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST, PSL_VERSION, PublicSuffixList
from src.agents.tools.errors import ToolCallError
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
from src.agents.tools.network import GuardedHttpClient, SsrfGuard
from src.models import DomainIntelligenceResult

RDAP_SCHEMA_VERSION = "rdap-v1"
IANA_DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


@dataclass
class _CacheItem:
    result: DomainIntelligenceResult
    expires_at: datetime


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


class RdapDomainIntelligence:
    """Privacy-minimizing RDAP adapter using the IANA DNS bootstrap registry."""

    provider = f"iana-rdap/{RDAP_SCHEMA_VERSION}/psl-{PSL_VERSION}"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        suffix_list: PublicSuffixList = DEFAULT_PUBLIC_SUFFIX_LIST,
        timeout: float = 5.0,
        positive_ttl: timedelta = timedelta(hours=24),
        not_found_ttl: timedelta = timedelta(hours=1),
        max_cache_entries: int = 10_000,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if max_cache_entries < 1:
            raise ValueError("max_cache_entries must be positive")
        self._client = client
        self._owns_client = client is None
        self._guard = guard or SsrfGuard()
        self._suffix_list = suffix_list
        self._timeout = timeout
        self._positive_ttl = positive_ttl
        self._not_found_ttl = not_found_ttl
        self._max_cache_entries = max_cache_entries
        self._clock = clock
        self._cache: dict[tuple[str, str], _CacheItem] = {}
        self._bootstrap: tuple[dict[str, tuple[str, ...]], datetime] | None = None
        self._lock = asyncio.Lock()

    def registrable_domain(self, domain: str) -> str | None:
        return self._suffix_list.registrable_domain(domain)

    async def _http(self) -> GuardedHttpClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return GuardedHttpClient(self._client, self._guard)

    async def _bootstrap_services(self) -> dict[str, tuple[str, ...]]:
        now = self._clock()
        if self._bootstrap is not None and self._bootstrap[1] > now:
            return self._bootstrap[0]
        client = await self._http()
        try:
            response, _ = await client.get(IANA_DNS_BOOTSTRAP_URL)
            response.raise_for_status()
            payload: Any = response.json()
            services = payload.get("services") if isinstance(payload, dict) else None
            if not isinstance(services, list):
                raise ValueError("missing services")
            mapping: dict[str, tuple[str, ...]] = {}
            for service in services:
                if not isinstance(service, list) or len(service) != 2:
                    continue
                suffixes, urls = service
                if not isinstance(suffixes, list) or not isinstance(urls, list):
                    continue
                safe_urls = tuple(url for url in urls if isinstance(url, str) and url.startswith("https://"))
                for suffix in suffixes:
                    if isinstance(suffix, str) and safe_urls:
                        mapping[suffix.casefold().lstrip(".")] = safe_urls
            if not mapping:
                raise ValueError("empty services")
        except httpx.TimeoutException as exc:
            raise ToolCallError(
                "domain_intelligence", "PROVIDER_TIMEOUT", "RDAP bootstrap timed out", retryable=True
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ToolCallError(
                "domain_intelligence", "PROVIDER_ERROR", "RDAP bootstrap failed", retryable=True
            ) from exc
        self._bootstrap = (mapping, now + timedelta(hours=24))
        return mapping

    async def lookup(self, domain: str) -> DomainIntelligenceResult:
        registrable = self.registrable_domain(domain)
        if registrable is None:
            raise ValueError("RDAP lookup requires a registrable domain, not an IP or public suffix")
        cache_key = (registrable, self.provider)
        now = self._clock()
        cached = self._cache.get(cache_key)
        if cached is not None and cached.expires_at > now:
            return cached.result.model_copy(deep=True)
        if cached is not None:
            self._cache.pop(cache_key, None)

        async with self._lock:
            now = self._clock()
            cached = self._cache.get(cache_key)
            if cached is not None and cached.expires_at > now:
                return cached.result.model_copy(deep=True)
            self._prune_cache(now)
            services = await self._bootstrap_services()
            tld = registrable.rsplit(".", 1)[-1]
            base_urls = services.get(tld)
            if not base_urls:
                raise ToolCallError(
                    "domain_intelligence", "PROVIDER_ERROR", "No RDAP service for domain suffix", retryable=False
                )
            endpoint = urljoin(base_urls[0].rstrip("/") + "/", f"domain/{quote(registrable)}")
            client = await self._http()
            try:
                response, _ = await client.get(endpoint)
                if response.status_code == 404:
                    result = self._not_found(registrable, now)
                    self._store_cache(cache_key, result, now + self._not_found_ttl)
                    return result.model_copy(deep=True)
                if response.status_code == 429:
                    raise ToolCallError(
                        "domain_intelligence", "RATE_LIMITED", "RDAP provider rate limited", retryable=True
                    )
                response.raise_for_status()
                payload: Any = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("RDAP response must be an object")
                result = self._normalize(registrable, payload, now)
            except ToolCallError:
                raise
            except httpx.TimeoutException as exc:
                raise ToolCallError(
                    "domain_intelligence", "PROVIDER_TIMEOUT", "RDAP provider timed out", retryable=True
                ) from exc
            except (httpx.HTTPError, ValueError) as exc:
                raise ToolCallError(
                    "domain_intelligence", "PROVIDER_ERROR", "RDAP provider failed", retryable=True
                ) from exc
            self._store_cache(cache_key, result, now + self._positive_ttl)
            return result.model_copy(deep=True)

    def _prune_cache(self, now: datetime) -> None:
        expired = [key for key, item in self._cache.items() if item.expires_at <= now]
        for key in expired:
            self._cache.pop(key, None)

    def _store_cache(
        self,
        key: tuple[str, str],
        result: DomainIntelligenceResult,
        expires_at: datetime,
    ) -> None:
        self._cache[key] = _CacheItem(result, expires_at)
        while len(self._cache) > self._max_cache_entries:
            self._cache.pop(next(iter(self._cache)))

    def _not_found(self, domain: str, observed_at: datetime) -> DomainIntelligenceResult:
        return DomainIntelligenceResult(
            provider=self.provider,
            domain=domain,
            privacy_redacted=False,
            signals=["not_found"],
            observed_at=observed_at,
        )

    def _normalize(self, domain: str, payload: dict[str, Any], observed_at: datetime) -> DomainIntelligenceResult:
        registered_at: datetime | None = None
        expires_at: datetime | None = None
        events = payload.get("events")
        if isinstance(events, list):
            for event in events:
                if not isinstance(event, dict):
                    continue
                action = str(event.get("eventAction") or "").casefold()
                date = _parse_utc(event.get("eventDate"))
                if action in {"registration", "registered"} and registered_at is None:
                    registered_at = date
                elif action in {"expiration", "expiry", "expires"} and expires_at is None:
                    expires_at = date
        remarks = payload.get("remarks")
        remark_text = (
            " ".join(
                str(description)
                for remark in remarks
                if isinstance(remark, dict)
                for description in remark.get("description", [])
                if isinstance(description, str)
            )
            if isinstance(remarks, list)
            else ""
        )
        privacy_redacted = any(word in remark_text.casefold() for word in ("redact", "privacy", "restricted"))
        status = sorted({str(item) for item in payload.get("status", []) if isinstance(item, str) and item.strip()})
        signals: list[str] = []
        if registered_at is not None:
            age = observed_at - registered_at
            if timedelta(0) <= age < timedelta(days=30):
                signals.append("recent_registration")
        country = payload.get("country")
        country = country.strip().upper() if isinstance(country, str) and country.strip() else None
        registrar = payload.get("registrar")
        registrar = registrar.strip() if isinstance(registrar, str) and registrar.strip() else None
        return DomainIntelligenceResult(
            provider=self.provider,
            domain=domain,
            registered_at=registered_at,
            expires_at=expires_at,
            # Some servers expose a non-standard top-level registrar string.
            # We deliberately never inspect entities/vCard to obtain it.
            registrar=registrar,
            country=country,
            status=status,
            privacy_redacted=privacy_redacted,
            signals=signals,
            observed_at=observed_at,
        )

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()


class NormalizedRdapProvider:
    """v3 envelope over the compatibility RDAP adapter.

    Both this wrapper and ``RdapDomainIntelligence`` are lazy: constructing
    either one creates no HTTP client or network task.  Consent remains an
    executor policy and must be checked before calling ``lookup``.
    """

    provider_version = f"{RDAP_SCHEMA_VERSION}/psl-{PSL_VERSION}"

    def __init__(
        self,
        adapter: RdapDomainIntelligence | None = None,
        *,
        timeout: float = 5.0,
        cache_ttl: timedelta = timedelta(hours=24),
        not_found_ttl: timedelta = timedelta(hours=1),
        max_cache_entries: int = 10_000,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._adapter = adapter
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._clock = clock
        self._cache: VersionedMemoryCache[DomainIntelligenceResult] = VersionedMemoryCache(
            max_entries=max_cache_entries,
            clock=clock,
        )

    @property
    def provider(self) -> str:
        return f"iana-rdap/{self.provider_version}"

    def _get_adapter(self) -> RdapDomainIntelligence:
        if self._adapter is None:
            self._adapter = RdapDomainIntelligence(timeout=self._timeout, clock=self._clock)
        return self._adapter

    async def lookup(self, domain: str) -> NormalizedToolResult[DomainIntelligenceResult]:
        started = time.perf_counter()
        try:
            registrable = DEFAULT_PUBLIC_SUFFIX_LIST.registrable_domain(domain)
        except ValueError as exc:
            return self._failure(started, ToolErrorCode.INVALID_TARGET, str(exc), retryable=False, attempts=0, calls=0)
        if registrable is None:
            return self._failure(
                started,
                ToolErrorCode.INVALID_TARGET,
                "RDAP lookup requires a registrable domain.",
                retryable=False,
                attempts=0,
                calls=0,
            )
        cached = await self._cache.get(self.provider, self.provider_version, registrable)
        if cached is not None:
            result = cached.value.model_copy(deep=True)
            return NormalizedToolResult(
                status=(ToolResultStatus.INCONCLUSIVE if result.signals == ["not_found"] else ToolResultStatus.SUCCESS),
                result=result,
                cache=cached.metadata,
                usage=self._usage(started, attempts=0, calls=0),
            )
        try:
            result = await self._get_adapter().lookup(registrable)
        except ToolCallError as exc:
            code = {
                "RATE_LIMITED": ToolErrorCode.RATE_LIMITED,
                "PROVIDER_TIMEOUT": ToolErrorCode.PROVIDER_TIMEOUT,
            }.get(exc.error.code, ToolErrorCode.PROVIDER_ERROR)
            return self._failure(
                started,
                code,
                exc.error.message,
                retryable=exc.error.retryable,
                attempts=1,
                calls=1,
            )
        ttl = self._not_found_ttl if result.signals == ["not_found"] else self._cache_ttl
        await self._cache.put(
            self.provider,
            self.provider_version,
            registrable,
            result.model_copy(deep=True),
            ttl,
        )
        return NormalizedToolResult(
            status=ToolResultStatus.INCONCLUSIVE if result.signals == ["not_found"] else ToolResultStatus.SUCCESS,
            result=result,
            cache=self._cache.miss_metadata(self.provider, self.provider_version, registrable),
            usage=self._usage(started, attempts=1, calls=1),
        )

    def _usage(self, started: float, *, attempts: int, calls: int) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:rdap:{uuid4()}",
            provider=self.provider,
            provider_version=self.provider_version,
            operation="rdap_lookup",
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
    ) -> NormalizedToolResult[DomainIntelligenceResult]:
        return NormalizedToolResult(
            status=ToolResultStatus.BLOCKED if code is ToolErrorCode.INVALID_TARGET else ToolResultStatus.FAILED,
            error=NormalizedToolError(
                tool=ToolName.RDAP,
                code=code,
                message=message,
                retryable=retryable,
                provider=self.provider,
            ),
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="invalid_or_failed_lookup"),
            usage=self._usage(started, attempts=attempts, calls=calls),
        )

    async def aclose(self) -> None:
        if self._adapter is not None:
            await self._adapter.aclose()
