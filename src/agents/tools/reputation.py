from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from src.models import Verdict

from .cache import VersionedMemoryCache
from .domains import canonicalize_url
from .errors import UnsafeUrlError
from .models import (
    CacheMetadata,
    CacheStatus,
    NormalizedToolError,
    NormalizedToolResult,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UrlReputationCascadeResult,
    UrlReputationFinding,
    UsageMetadata,
)
from .network import SsrfGuard
from .resilience import CircuitBreaker, CircuitOpenError, RetryPolicy, backoff

Sleeper = Callable[[float], Awaitable[None]]


class _NormalizedReputationProvider:
    operation = "url_reputation_lookup"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None,
        guard: SsrfGuard | None,
        timeout: float,
        cache: VersionedMemoryCache[UrlReputationFinding] | None,
        positive_ttl: timedelta,
        no_hit_ttl: timedelta,
        retry_policy: RetryPolicy | None,
        circuit_breaker: CircuitBreaker | None,
        sleeper: Sleeper,
        clock: Callable[[], datetime],
    ) -> None:
        self._client = client
        self._owns_client = client is None
        self._timeout = timeout
        self._guard = guard or SsrfGuard()
        self._cache = cache or VersionedMemoryCache(clock=clock)
        self._positive_ttl = positive_ttl
        self._no_hit_ttl = no_hit_ttl
        self._retry = retry_policy or RetryPolicy()
        self._circuit = circuit_breaker or CircuitBreaker(clock=clock)
        self._sleeper = sleeper
        self._clock = clock

    async def lookup(self, normalized_url: str) -> NormalizedToolResult[UrlReputationFinding]:
        started = time.perf_counter()
        try:
            target = canonicalize_url(normalized_url)
            await self._guard.validate(target)
        except (ValueError, UnsafeUrlError) as exc:
            return self._failure(
                started,
                ToolErrorCode.SSRF_BLOCKED if isinstance(exc, UnsafeUrlError) else ToolErrorCode.INVALID_TARGET,
                str(exc),
                attempts=0,
                calls=0,
                status=ToolResultStatus.BLOCKED,
            )

        cached = await self._cache.get(self.provider, self.provider_version, target)
        if cached is not None:
            finding = cached.value.model_copy(deep=True)
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if finding.matched else ToolResultStatus.INCONCLUSIVE,
                result=finding,
                cache=cached.metadata,
                usage=self._usage(started, attempts=0, calls=0),
            )

        attempts = 0
        calls = 0
        while attempts < self._retry.max_attempts:
            attempts += 1
            try:
                await self._circuit.before_call()
            except CircuitOpenError:
                return self._failure(
                    started,
                    ToolErrorCode.PROVIDER_ERROR,
                    "Reputation provider circuit is open.",
                    attempts=attempts - 1,
                    calls=calls,
                )
            try:
                calls += 1
                finding = await self._request(target)
                await self._circuit.record_success()
                ttl = self._positive_ttl if finding.matched else self._no_hit_ttl
                await self._cache.put(self.provider, self.provider_version, target, finding, ttl)
                return NormalizedToolResult(
                    status=ToolResultStatus.SUCCESS if finding.matched else ToolResultStatus.INCONCLUSIVE,
                    result=finding,
                    cache=self._cache.miss_metadata(self.provider, self.provider_version, target),
                    usage=self._usage(started, attempts=attempts, calls=calls),
                )
            except _RateLimitedError as exc:
                await self._circuit.record_failure()
                if attempts < self._retry.max_attempts:
                    await backoff(self._retry.delay(attempts, exc.retry_after_seconds), sleeper=self._sleeper)
                    continue
                return self._failure(
                    started,
                    ToolErrorCode.RATE_LIMITED,
                    "Reputation provider rate limited the request.",
                    attempts=attempts,
                    calls=calls,
                    retry_after_ms=(
                        round(exc.retry_after_seconds * 1000) if exc.retry_after_seconds is not None else None
                    ),
                )
            except httpx.TimeoutException:
                await self._circuit.record_failure()
                if attempts < self._retry.max_attempts:
                    await backoff(self._retry.delay(attempts), sleeper=self._sleeper)
                    continue
                return self._failure(
                    started,
                    ToolErrorCode.PROVIDER_TIMEOUT,
                    "Reputation provider timed out.",
                    attempts=attempts,
                    calls=calls,
                )
            except (httpx.HTTPError, ValueError, TypeError):
                await self._circuit.record_failure()
                if attempts < self._retry.max_attempts:
                    await backoff(self._retry.delay(attempts), sleeper=self._sleeper)
                    continue
                return self._failure(
                    started,
                    ToolErrorCode.PROVIDER_ERROR,
                    "Reputation provider failed.",
                    attempts=attempts,
                    calls=calls,
                )
        raise AssertionError("retry loop must return")

    async def _request(self, target: str) -> UrlReputationFinding:
        raise NotImplementedError

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def _usage(self, started: float, *, attempts: int, calls: int) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:reputation:{uuid4()}",
            provider=self.provider,
            provider_version=self.provider_version,
            operation=self.operation,
            attempts=attempts,
            network_calls=calls,
            latency_ms=(time.perf_counter() - started) * 1000,
            request_units=calls,
            response_units=1 if calls else 0,
            estimated_cost_usd=calls * self.estimated_cost_per_call,
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
        status: ToolResultStatus = ToolResultStatus.FAILED,
        retry_after_ms: int | None = None,
    ) -> NormalizedToolResult[UrlReputationFinding]:
        target_for_hash = "invalid-or-redacted-target"
        return NormalizedToolResult(
            status=status,
            error=NormalizedToolError(
                tool=ToolName.URL_REPUTATION,
                code=code,
                message=message,
                retryable=code
                in {
                    ToolErrorCode.RATE_LIMITED,
                    ToolErrorCode.PROVIDER_TIMEOUT,
                    ToolErrorCode.PROVIDER_ERROR,
                },
                provider=self.provider,
                retry_after_ms=retry_after_ms,
            ),
            cache=self._cache.miss_metadata(self.provider, self.provider_version, target_for_hash),
            usage=self._usage(started, attempts=attempts, calls=calls),
        )

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()


class _RateLimitedError(RuntimeError):
    def __init__(self, retry_after_seconds: float | None) -> None:
        self.retry_after_seconds = retry_after_seconds


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


class GoogleWebRiskProvider(_NormalizedReputationProvider):
    """Google Web Risk URI search adapter with provider-neutral output."""

    endpoint = "https://webrisk.googleapis.com/v1/uris:search"
    provider = "google-web-risk"
    provider_version = "v1"
    estimated_cost_per_call = 0.0

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        timeout: float = 10.0,
        cache: VersionedMemoryCache[UrlReputationFinding] | None = None,
        positive_ttl: timedelta = timedelta(hours=1),
        no_hit_ttl: timedelta = timedelta(minutes=10),
        retry_policy: RetryPolicy | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        sleeper: Sleeper = asyncio.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not api_key.strip():
            raise ValueError("Google Web Risk API key is required")
        self._api_key = api_key
        super().__init__(
            client=client,
            guard=guard,
            timeout=timeout,
            cache=cache,
            positive_ttl=positive_ttl,
            no_hit_ttl=no_hit_ttl,
            retry_policy=retry_policy,
            circuit_breaker=circuit_breaker,
            sleeper=sleeper,
            clock=clock,
        )

    async def _request(self, target: str) -> UrlReputationFinding:
        response = await self._http().get(
            self.endpoint,
            params=[
                ("key", self._api_key),
                ("uri", target),
                ("threatTypes", "MALWARE"),
                ("threatTypes", "SOCIAL_ENGINEERING"),
                ("threatTypes", "UNWANTED_SOFTWARE"),
            ],
        )
        if response.status_code == 429:
            raise _RateLimitedError(_retry_after(response))
        response.raise_for_status()
        payload: Any = response.json()
        if not isinstance(payload, dict):
            raise ValueError("provider response must be an object")
        threat = payload.get("threat")
        matched = isinstance(threat, dict) and bool(threat)
        types = threat.get("threatTypes", []) if isinstance(threat, dict) else []
        signals = sorted({str(item).casefold() for item in types if str(item).strip()})
        return UrlReputationFinding(
            provider=self.provider,
            provider_version=self.provider_version,
            normalized_url=target,
            matched=matched,
            verdict=Verdict.MALICIOUS if matched else Verdict.INCONCLUSIVE,
            signals=signals or ["no_known_match"],
            observed_at=self._clock(),
        )


class VirusTotalUrlProvider(_NormalizedReputationProvider):
    """VirusTotal v3 URL report adapter, intended as policy-gated secondary."""

    endpoint = "https://www.virustotal.com/api/v3/urls"
    provider = "virustotal"
    provider_version = "v3"
    estimated_cost_per_call = 0.0

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        timeout: float = 10.0,
        cache: VersionedMemoryCache[UrlReputationFinding] | None = None,
        positive_ttl: timedelta = timedelta(hours=1),
        no_hit_ttl: timedelta = timedelta(minutes=10),
        retry_policy: RetryPolicy | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        sleeper: Sleeper = asyncio.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not api_key.strip():
            raise ValueError("VirusTotal API key is required")
        self._api_key = api_key
        super().__init__(
            client=client,
            guard=guard,
            timeout=timeout,
            cache=cache,
            positive_ttl=positive_ttl,
            no_hit_ttl=no_hit_ttl,
            retry_policy=retry_policy,
            circuit_breaker=circuit_breaker,
            sleeper=sleeper,
            clock=clock,
        )

    async def _request(self, target: str) -> UrlReputationFinding:
        url_id = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        response = await self._http().get(f"{self.endpoint}/{url_id}", headers={"x-apikey": self._api_key})
        if response.status_code == 429:
            raise _RateLimitedError(_retry_after(response))
        if response.status_code == 404:
            payload: Any = {}
        else:
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("provider response must be an object")
        data = payload.get("data")
        attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes, dict) else {}
        if not isinstance(stats, dict) or not stats:
            matched = False
            verdict = Verdict.INCONCLUSIVE
            signals = ["no_known_match"]
        else:
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            matched = malicious + suspicious + harmless > 0
            verdict = (
                Verdict.MALICIOUS
                if malicious > 0
                else Verdict.SUSPICIOUS
                if suspicious > 0
                else Verdict.SAFE
                if harmless > 0
                else Verdict.INCONCLUSIVE
            )
            signals = [
                f"malicious_engines:{malicious}",
                f"suspicious_engines:{suspicious}",
                f"harmless_engines:{harmless}",
            ]
        return UrlReputationFinding(
            provider=self.provider,
            provider_version=self.provider_version,
            normalized_url=target,
            matched=matched,
            verdict=verdict,
            signals=signals,
            observed_at=self._clock(),
        )


class ProductionUrlReputationCascade:
    """Web Risk primary with budgeted VirusTotal escalation."""

    provider = "trustguard-reputation-cascade"

    def __init__(
        self,
        primary: _NormalizedReputationProvider,
        secondary: _NormalizedReputationProvider | None = None,
        *,
        policy_version: str = "reputation-policy-v1",
        allow_secondary: bool = True,
        max_network_calls: int = 4,
        cache: VersionedMemoryCache[UrlReputationCascadeResult] | None = None,
        ttl: timedelta = timedelta(minutes=10),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.primary = primary
        self.secondary = secondary
        self.policy_version = policy_version
        self.allow_secondary = allow_secondary
        self.max_network_calls = max_network_calls
        self._cache = cache or VersionedMemoryCache(clock=clock)
        self._ttl = ttl
        self._clock = clock

    async def assess(
        self, normalized_url: str, *, high_risk: bool = False
    ) -> NormalizedToolResult[UrlReputationCascadeResult]:
        started = time.perf_counter()
        try:
            target = canonicalize_url(normalized_url)
        except ValueError as exc:
            return self._failure(started, ToolErrorCode.INVALID_TARGET, str(exc))
        cached = await self._cache.get(self.provider, self.policy_version, target)
        if cached is not None:
            return NormalizedToolResult(
                status=(
                    ToolResultStatus.INCONCLUSIVE
                    if cached.value.verdict is Verdict.INCONCLUSIVE
                    else ToolResultStatus.SUCCESS
                ),
                result=cached.value.model_copy(deep=True),
                cache=cached.metadata,
                usage=self._usage(started, [], attempts=0, calls=0),
            )

        outcomes = [await self.primary.lookup(target)]
        primary_finding = outcomes[0].result
        escalate = high_risk or (
            primary_finding is not None and primary_finding.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
        )
        calls = sum(item.usage.network_calls for item in outcomes)
        if escalate and self.allow_secondary and self.secondary is not None and calls < self.max_network_calls:
            outcomes.append(await self.secondary.lookup(target))

        findings = [item.result for item in outcomes if item.result is not None]
        calls = sum(item.usage.network_calls for item in outcomes)
        attempts = sum(item.usage.attempts for item in outcomes)
        if not findings:
            first_error = next((item.error for item in outcomes if item.error is not None), None)
            return NormalizedToolResult(
                status=ToolResultStatus.FAILED,
                error=first_error
                or NormalizedToolError(
                    tool=ToolName.URL_REPUTATION,
                    code=ToolErrorCode.PROVIDER_ERROR,
                    message="No reputation provider produced a result.",
                    retryable=True,
                    provider=self.provider,
                ),
                cache=self._cache.miss_metadata(self.provider, self.policy_version, target),
                usage=self._usage(started, outcomes, attempts=attempts, calls=calls),
            )

        decisive = {item.verdict for item in findings if item.matched}
        conflict = Verdict.SAFE in decisive and bool(decisive & {Verdict.SUSPICIOUS, Verdict.MALICIOUS})
        if conflict:
            verdict = Verdict.SUSPICIOUS
        elif Verdict.MALICIOUS in decisive:
            verdict = Verdict.MALICIOUS
        elif Verdict.SUSPICIOUS in decisive:
            verdict = Verdict.SUSPICIOUS
        elif Verdict.SAFE in decisive:
            verdict = Verdict.SAFE
        else:
            verdict = Verdict.INCONCLUSIVE
        result = UrlReputationCascadeResult(
            normalized_url=target,
            findings=findings,
            verdict=verdict,
            provider_conflict=conflict,
            policy_version=self.policy_version,
        )
        await self._cache.put(self.provider, self.policy_version, target, result, self._ttl)
        return NormalizedToolResult(
            status=ToolResultStatus.INCONCLUSIVE if verdict is Verdict.INCONCLUSIVE else ToolResultStatus.SUCCESS,
            result=result,
            cache=self._cache.miss_metadata(self.provider, self.policy_version, target),
            usage=self._usage(started, outcomes, attempts=attempts, calls=calls),
        )

    def _usage(
        self,
        started: float,
        outcomes: list[NormalizedToolResult[UrlReputationFinding]],
        *,
        attempts: int,
        calls: int,
    ) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:reputation-cascade:{uuid4()}",
            provider=self.provider,
            provider_version=self.policy_version,
            operation="url_reputation_cascade",
            attempts=attempts,
            network_calls=calls,
            latency_ms=(time.perf_counter() - started) * 1000,
            request_units=sum(item.usage.request_units for item in outcomes),
            response_units=sum(item.usage.response_units for item in outcomes),
            estimated_cost_usd=sum(item.usage.estimated_cost_usd for item in outcomes),
            observed_at=self._clock(),
        )

    def _failure(
        self, started: float, code: ToolErrorCode, message: str
    ) -> NormalizedToolResult[UrlReputationCascadeResult]:
        return NormalizedToolResult(
            status=ToolResultStatus.BLOCKED,
            error=NormalizedToolError(
                tool=ToolName.URL_REPUTATION,
                code=code,
                message=message,
                retryable=False,
                provider=self.provider,
            ),
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="invalid_target"),
            usage=UsageMetadata(
                usage_ref=f"usage:reputation-cascade:{uuid4()}",
                provider=self.provider,
                provider_version=self.policy_version,
                operation="url_reputation_cascade",
                attempts=0,
                network_calls=0,
                latency_ms=(time.perf_counter() - started) * 1000,
                observed_at=self._clock(),
            ),
        )

    async def aclose(self) -> None:
        await self.primary.aclose()
        if self.secondary is not None:
            await self.secondary.aclose()


class UrlReputationService:
    """Compatibility cascade with service-level retry, circuit breaking and cache.

    Providers can be lightweight protocol implementations that already return a
    normalized envelope; unlike ``ProductionUrlReputationCascade`` they do not
    need to own their retry/circuit policy.
    """

    provider = "trustguard-reputation-service"

    def __init__(
        self,
        primary: Any,
        secondary: Any | None = None,
        *,
        policy_version: str = "reputation-policy-v1",
        max_attempts: int = 2,
        backoff_seconds: float = 0.1,
        failure_threshold: int = 3,
        circuit_cooldown: timedelta = timedelta(seconds=30),
        ttl: timedelta = timedelta(minutes=10),
        sleeper: Sleeper = asyncio.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.primary = primary
        self.secondary = secondary
        self.policy_version = policy_version
        self._retry = RetryPolicy(max_attempts=max_attempts, base_delay_seconds=backoff_seconds)
        self._circuits = {
            id(provider): CircuitBreaker(
                failure_threshold=failure_threshold,
                recovery_timeout=circuit_cooldown,
                clock=clock,
            )
            for provider in (primary, secondary)
            if provider is not None
        }
        self._cache: VersionedMemoryCache[UrlReputationCascadeResult] = VersionedMemoryCache(clock=clock)
        self._ttl = ttl
        self._sleeper = sleeper
        self._clock = clock

    @property
    def _cache_version(self) -> str:
        versions = [f"{self.primary.provider}:{self.primary.provider_version}"]
        if self.secondary is not None:
            versions.append(f"{self.secondary.provider}:{self.secondary.provider_version}")
        return f"{self.policy_version}|{'|'.join(versions)}"

    async def _lookup(self, provider: Any, target: str) -> NormalizedToolResult[UrlReputationFinding]:
        circuit = self._circuits[id(provider)]
        last: NormalizedToolResult[UrlReputationFinding] | None = None
        for attempt in range(1, self._retry.max_attempts + 1):
            try:
                await circuit.before_call()
            except CircuitOpenError:
                return NormalizedToolResult(
                    status=ToolResultStatus.FAILED,
                    error=NormalizedToolError(
                        tool=ToolName.URL_REPUTATION,
                        code=ToolErrorCode.PROVIDER_ERROR,
                        message="Reputation provider circuit is open.",
                        retryable=True,
                        provider=provider.provider,
                    ),
                    cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="circuit_open"),
                    usage=UsageMetadata(
                        usage_ref=f"usage:reputation-service:{uuid4()}",
                        provider=provider.provider,
                        provider_version=provider.provider_version,
                        operation="lookup",
                        attempts=0,
                        network_calls=0,
                        latency_ms=0,
                        observed_at=self._clock(),
                    ),
                )
            last = await provider.lookup(target)
            if last.status in {ToolResultStatus.SUCCESS, ToolResultStatus.INCONCLUSIVE}:
                await circuit.record_success()
                return last
            await circuit.record_failure()
            if not (last.error and last.error.retryable) or attempt == self._retry.max_attempts:
                return last
            retry_after = (last.error.retry_after_ms / 1000) if last.error.retry_after_ms is not None else None
            await backoff(self._retry.delay(attempt, retry_after), sleeper=self._sleeper)
        assert last is not None
        return last

    async def assess(
        self,
        normalized_url: str,
        *,
        high_risk: bool = False,
        secondary_budget_remaining: int = 1,
    ) -> NormalizedToolResult[UrlReputationCascadeResult]:
        started = time.perf_counter()
        try:
            target = canonicalize_url(normalized_url)
        except ValueError as exc:
            return ProductionUrlReputationCascade._failure(self, started, ToolErrorCode.INVALID_TARGET, str(exc))
        cached = await self._cache.get(self.provider, self._cache_version, target)
        if cached is not None:
            return NormalizedToolResult(
                status=(
                    ToolResultStatus.INCONCLUSIVE
                    if cached.value.verdict is Verdict.INCONCLUSIVE
                    else ToolResultStatus.SUCCESS
                ),
                result=cached.value.model_copy(deep=True),
                cache=cached.metadata,
                usage=self._usage(started, [], attempts=0, calls=0),
            )

        outcomes = [await self._lookup(self.primary, target)]
        primary_finding = outcomes[0].result
        escalate = high_risk or (
            primary_finding is not None and primary_finding.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
        )
        if escalate and self.secondary is not None and secondary_budget_remaining > 0:
            outcomes.append(await self._lookup(self.secondary, target))
        findings = [outcome.result for outcome in outcomes if outcome.result is not None]
        attempts = sum(outcome.usage.attempts for outcome in outcomes)
        calls = sum(outcome.usage.network_calls for outcome in outcomes)
        if not findings:
            error = next((outcome.error for outcome in outcomes if outcome.error), None)
            return NormalizedToolResult(
                status=ToolResultStatus.FAILED,
                error=error,
                cache=self._cache.miss_metadata(self.provider, self._cache_version, target),
                usage=self._usage(started, outcomes, attempts=attempts, calls=calls),
            )
        verdicts = {finding.verdict for finding in findings}
        conflict = len(verdicts) > 1
        verdict = (
            Verdict.MALICIOUS
            if Verdict.MALICIOUS in verdicts
            else Verdict.SUSPICIOUS
            if Verdict.SUSPICIOUS in verdicts
            else Verdict.SAFE
            if Verdict.SAFE in verdicts
            else Verdict.INCONCLUSIVE
        )
        result = UrlReputationCascadeResult(
            normalized_url=target,
            findings=findings,
            verdict=verdict,
            provider_conflict=conflict,
            policy_version=self.policy_version,
        )
        await self._cache.put(self.provider, self._cache_version, target, result, self._ttl)
        return NormalizedToolResult(
            status=ToolResultStatus.INCONCLUSIVE if verdict is Verdict.INCONCLUSIVE else ToolResultStatus.SUCCESS,
            result=result,
            cache=self._cache.miss_metadata(self.provider, self._cache_version, target),
            usage=self._usage(started, outcomes, attempts=attempts, calls=calls),
        )

    def _usage(self, started: float, outcomes: list[Any], *, attempts: int, calls: int) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:reputation-service:{uuid4()}",
            provider=self.provider,
            provider_version=self._cache_version,
            operation="url_reputation_cascade",
            attempts=attempts,
            network_calls=calls,
            latency_ms=(time.perf_counter() - started) * 1000,
            request_units=sum(item.usage.request_units for item in outcomes),
            response_units=sum(item.usage.response_units for item in outcomes),
            estimated_cost_usd=sum(item.usage.estimated_cost_usd for item in outcomes),
            observed_at=self._clock(),
        )
