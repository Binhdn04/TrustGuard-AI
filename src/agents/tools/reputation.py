from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import httpx

from src.models import Verdict

from .domains import normalize_hostname
from .models import (
    CacheMetadata,
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


def canonicalize_url(value: str) -> str:
    """Return the stable URL form used by redirects, caches, and providers."""
    parsed = urlsplit(value.strip())
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("an absolute HTTP(S) URL is required")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are not allowed")
    host = normalize_hostname(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL has an invalid port") from exc
    if port in {80 if scheme == "http" else 443, None}:
        authority = host
    else:
        authority = f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, authority, path, parsed.query, ""))


def _usage(provider: str, version: str, operation: str, started: float, calls: int) -> UsageMetadata:
    return UsageMetadata(
        usage_ref=f"usage:{uuid4()}", provider=provider, provider_version=version,
        operation=operation, attempts=max(calls, 1), network_calls=calls,
        latency_ms=(time.monotonic() - started) * 1000, observed_at=datetime.now(UTC),
    )


class _HttpReputationProvider:
    provider: str
    provider_version: str
    endpoint: str

    def __init__(self, api_key: str, *, client: httpx.AsyncClient | None = None,
                 guard: SsrfGuard | None = None, timeout: float = 10) -> None:
        if not api_key.strip():
            raise ValueError("provider API key is required")
        self._api_key = api_key
        self._client = client
        self._timeout = timeout
        self._owns_client = client is None
        self._guard = guard or SsrfGuard()

    async def _request(self, normalized_url: str) -> httpx.Response:
        raise NotImplementedError

    def _http(self) -> httpx.AsyncClient:
        # Creating a configured adapter is safe before consent: sockets and
        # external clients do not exist until lookup crosses the consent gate.
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def _normalize(self, normalized_url: str, payload: object) -> tuple[bool, list[str]]:
        raise NotImplementedError

    async def lookup(self, normalized_url: str) -> NormalizedToolResult[UrlReputationFinding]:
        normalized_url = canonicalize_url(normalized_url)
        await self._guard.validate(normalized_url)
        started = time.monotonic()
        try:
            response = await self._request(normalized_url)
            if response.status_code == 429:
                retry = response.headers.get("retry-after")
                retry_ms = int(float(retry) * 1000) if retry else None
                return self._error(ToolErrorCode.RATE_LIMITED, "provider rate limited", started, retry_ms)
            response.raise_for_status()
            payload = response.json()
            matched, signals = self._normalize(normalized_url, payload)
        except httpx.TimeoutException:
            return self._error(ToolErrorCode.PROVIDER_TIMEOUT, "provider timed out", started)
        except (httpx.HTTPError, ValueError, TypeError):
            return self._error(ToolErrorCode.PROVIDER_ERROR, "provider failed", started)
        finding = UrlReputationFinding(
            provider=self.provider, provider_version=self.provider_version,
            normalized_url=normalized_url, matched=matched,
            verdict=Verdict.MALICIOUS if matched else Verdict.INCONCLUSIVE,
            signals=signals or (["no_known_threat_match"] if not matched else []), observed_at=datetime.now(UTC),
        )
        return NormalizedToolResult(
            status=ToolResultStatus.SUCCESS if matched else ToolResultStatus.INCONCLUSIVE,
            result=finding, cache=CacheMetadata(status="miss"),
            usage=_usage(self.provider, self.provider_version, "lookup", started, 1),
        )

    def _error(self, code: ToolErrorCode, message: str, started: float,
               retry_after_ms: int | None = None) -> NormalizedToolResult[UrlReputationFinding]:
        return NormalizedToolResult(
            status=ToolResultStatus.FAILED,
            error=NormalizedToolError(tool=ToolName.URL_REPUTATION, code=code, message=message,
                                      retryable=True, provider=self.provider, retry_after_ms=retry_after_ms),
            cache=CacheMetadata(status="miss"),
            usage=_usage(self.provider, self.provider_version, "lookup", started, 1),
        )

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()


class GoogleWebRiskProvider(_HttpReputationProvider):
    provider = "google-web-risk"
    provider_version = "v1"
    endpoint = "https://webrisk.googleapis.com/v1/uris:search"

    async def _request(self, normalized_url: str) -> httpx.Response:
        return await self._http().get(self.endpoint, params={
            "key": self._api_key, "uri": normalized_url,
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        })

    def _normalize(self, _url: str, payload: object) -> tuple[bool, list[str]]:
        if not isinstance(payload, dict):
            raise ValueError("provider response must be an object")
        threat = payload.get("threat")
        types = threat.get("threatTypes", []) if isinstance(threat, dict) else []
        signals = sorted({str(item).casefold() for item in types})
        return bool(signals), signals


class VirusTotalUrlProvider(_HttpReputationProvider):
    provider = "virustotal"
    provider_version = "v3"
    endpoint = "https://www.virustotal.com/api/v3/urls"

    async def _request(self, normalized_url: str) -> httpx.Response:
        identifier = __import__("base64").urlsafe_b64encode(normalized_url.encode()).decode().rstrip("=")
        return await self._http().get(f"{self.endpoint}/{identifier}", headers={"x-apikey": self._api_key})

    def _normalize(self, _url: str, payload: object) -> tuple[bool, list[str]]:
        if not isinstance(payload, dict):
            raise ValueError("provider response must be an object")
        data = payload.get("data")
        attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
        malicious = int(stats.get("malicious", 0)) if isinstance(stats, dict) else 0
        suspicious = int(stats.get("suspicious", 0)) if isinstance(stats, dict) else 0
        signals = ([f"malicious_engines:{malicious}"] if malicious else []) + (
            [f"suspicious_engines:{suspicious}"] if suspicious else [])
        return malicious > 0 or suspicious > 1, signals


@dataclass
class _CacheItem:
    result: UrlReputationCascadeResult
    stored_at: datetime
    expires_at: datetime


class UrlReputationService:
    """Policy-limited provider cascade with versioned cache and circuit breaker."""

    def __init__(self, primary: object, secondary: object | None = None, *, policy_version: str = "reputation-v1",
                 ttl: timedelta = timedelta(minutes=15), failure_threshold: int = 3,
                 circuit_cooldown: timedelta = timedelta(seconds=30), max_attempts: int = 2,
                 backoff_seconds: float = .05, secondary_call_budget: int = 1,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.primary, self.secondary = primary, secondary
        self.policy_version, self.ttl, self.failure_threshold = policy_version, ttl, failure_threshold
        self.circuit_cooldown, self.max_attempts, self.backoff_seconds = circuit_cooldown, max_attempts, backoff_seconds
        self.secondary_call_budget = max(0, secondary_call_budget)
        self.clock = clock
        self._cache: dict[str, _CacheItem] = {}
        self._failures: dict[str, int] = {}
        self._open_until: dict[str, datetime] = {}

    def _key(self, url: str) -> str:
        versions = ",".join(f"{p.provider}:{p.provider_version}" for p in (self.primary, self.secondary) if p)
        return hashlib.sha256(f"{self.policy_version}|{versions}|{url}".encode()).hexdigest()

    async def _call(self, provider: object, url: str) -> NormalizedToolResult[UrlReputationFinding] | None:
        name = provider.provider
        now = self.clock()
        if self._open_until.get(name, now) > now:
            return None
        result = None
        for attempt in range(self.max_attempts):
            result = await provider.lookup(url)
            if result.status is not ToolResultStatus.FAILED or not result.error or not result.error.retryable:
                break
            if attempt + 1 < self.max_attempts:
                delay = self.backoff_seconds * (2 ** attempt)
                if result.error.retry_after_ms is not None:
                    delay = max(delay, result.error.retry_after_ms / 1000)
                await asyncio.sleep(delay)
        if result and result.status is ToolResultStatus.FAILED:
            self._failures[name] = self._failures.get(name, 0) + 1
            if self._failures[name] >= self.failure_threshold:
                self._open_until[name] = now + self.circuit_cooldown
        else:
            self._failures[name] = 0
        return result

    async def assess(self, normalized_url: str, *, allow_secondary: bool = True,
                     high_risk: bool = False,
                     secondary_budget_remaining: int | None = None) -> NormalizedToolResult[UrlReputationCascadeResult]:
        url = canonicalize_url(normalized_url)
        key = self._key(url)
        now = self.clock()
        cached = self._cache.get(key)
        if cached and cached.expires_at > now:
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if cached.result.verdict is Verdict.MALICIOUS else ToolResultStatus.INCONCLUSIVE,
                result=cached.result.model_copy(deep=True),
                cache=CacheMetadata(status="hit", cache_key_hash=key, stored_at=cached.stored_at,
                                    expires_at=cached.expires_at),
                usage=UsageMetadata(usage_ref=f"usage:{uuid4()}", provider="reputation-cache",
                                    provider_version=self.policy_version, operation="assess", attempts=0,
                                    network_calls=0, latency_ms=0, observed_at=now),
            )
        started = time.monotonic()
        findings: list[UrlReputationFinding] = []
        calls = 0
        primary = await self._call(self.primary, url)
        if primary:
            calls += primary.usage.network_calls
            if primary.result:
                findings.append(primary.result)
        budget = self.secondary_call_budget if secondary_budget_remaining is None else secondary_budget_remaining
        use_secondary = (
            self.secondary is not None
            and allow_secondary
            and budget > 0
            and (high_risk or not findings or findings[0].matched)
        )
        if use_secondary:
            secondary = await self._call(self.secondary, url)
            if secondary:
                calls += secondary.usage.network_calls
                if secondary.result:
                    findings.append(secondary.result)
        if not findings:
            return NormalizedToolResult(
                status=ToolResultStatus.FAILED,
                error=NormalizedToolError(tool=ToolName.URL_REPUTATION, code=ToolErrorCode.PROVIDER_ERROR,
                                          message="no reputation provider available", retryable=True),
                cache=CacheMetadata(status="miss"),
                usage=_usage("reputation-cascade", self.policy_version, "assess", started, calls),
            )
        verdicts = {finding.verdict for finding in findings}
        conflict = len(verdicts) > 1
        verdict = Verdict.MALICIOUS if Verdict.MALICIOUS in verdicts else Verdict.INCONCLUSIVE
        result = UrlReputationCascadeResult(normalized_url=url, findings=findings, verdict=verdict,
                                            provider_conflict=conflict, policy_version=self.policy_version)
        self._cache[key] = _CacheItem(result.model_copy(deep=True), now, now + self.ttl)
        return NormalizedToolResult(
            status=ToolResultStatus.SUCCESS if verdict is Verdict.MALICIOUS else ToolResultStatus.INCONCLUSIVE,
            result=result, cache=CacheMetadata(status="miss"),
            usage=_usage("reputation-cascade", self.policy_version, "assess", started, calls),
        )
