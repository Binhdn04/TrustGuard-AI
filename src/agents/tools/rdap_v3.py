from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from src.models import DomainIntelligenceResult

from .errors import ToolCallError
from .models import (
    CacheMetadata,
    NormalizedToolError,
    NormalizedToolResult,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UsageMetadata,
)
from .rdap import RdapDomainIntelligence


class NormalizedRdapProvider:
    """v3 envelope around the backwards-compatible RDAP implementation."""

    provider_version = "rdap-v3"

    def __init__(
        self,
        adapter: RdapDomainIntelligence | None = None,
        *,
        cache_ttl: timedelta = timedelta(hours=24),
        **adapter_options: object,
    ) -> None:
        self._adapter = adapter or RdapDomainIntelligence(**adapter_options)
        self.provider = self._adapter.provider
        self._cache_ttl = cache_ttl
        self._seen: dict[str, tuple[datetime, DomainIntelligenceResult]] = {}

    async def lookup(self, domain: str) -> NormalizedToolResult[DomainIntelligenceResult]:
        started = time.monotonic()
        registrable = self._adapter.registrable_domain(domain)
        if registrable is None:
            return self._error(ToolErrorCode.INVALID_TARGET, "RDAP requires a registrable domain", started, False)
        key = hashlib.sha256(f"{self.provider}|{self.provider_version}|{registrable}".encode()).hexdigest()
        now = datetime.now(UTC)
        cached = self._seen.get(key)
        if cached and cached[0] > now:
            stored_at = cached[0] - self._cache_ttl
            return NormalizedToolResult(
                status=ToolResultStatus.INCONCLUSIVE if "not_found" in cached[1].signals else ToolResultStatus.SUCCESS,
                result=cached[1].model_copy(deep=True),
                cache=CacheMetadata(status="hit", cache_key_hash=key, stored_at=stored_at, expires_at=cached[0]),
                usage=self._usage(started, 0, now),
            )
        try:
            result = await self._adapter.lookup(registrable)
        except ToolCallError as exc:
            source = exc.error
            aliases = {
                "PROVIDER_TIMEOUT": ToolErrorCode.PROVIDER_TIMEOUT,
                "RATE_LIMITED": ToolErrorCode.RATE_LIMITED,
                "SSRF_BLOCKED": ToolErrorCode.SSRF_BLOCKED,
            }
            return self._error(
                aliases.get(source.code, ToolErrorCode.PROVIDER_ERROR), source.message, started, source.retryable
            )
        except ValueError:
            return self._error(ToolErrorCode.INVALID_TARGET, "RDAP target is invalid", started, False)
        self._seen[key] = (now + self._cache_ttl, result.model_copy(deep=True))
        return NormalizedToolResult(
            status=ToolResultStatus.INCONCLUSIVE if "not_found" in result.signals else ToolResultStatus.SUCCESS,
            result=result,
            cache=CacheMetadata(status="miss"),
            usage=self._usage(started, 1, now),
        )

    def _usage(self, started: float, calls: int, observed_at: datetime) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:{uuid4()}",
            provider=self.provider,
            provider_version=self.provider_version,
            operation="lookup",
            attempts=1 if calls else 0,
            network_calls=calls,
            latency_ms=(time.monotonic() - started) * 1000,
            observed_at=observed_at,
        )

    def _error(
        self, code: ToolErrorCode, message: str, started: float, retryable: bool
    ) -> NormalizedToolResult[DomainIntelligenceResult]:
        return NormalizedToolResult(
            status=ToolResultStatus.BLOCKED if code is ToolErrorCode.SSRF_BLOCKED else ToolResultStatus.FAILED,
            error=NormalizedToolError(
                tool=ToolName.RDAP, code=code, message=message, retryable=retryable, provider=self.provider
            ),
            cache=CacheMetadata(status="miss"),
            usage=self._usage(started, 1, datetime.now(UTC)),
        )

    async def aclose(self) -> None:
        await self._adapter.aclose()
