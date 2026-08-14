from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from src.agents.tools.errors import ToolCallError, UnsafeUrlError
from src.agents.tools.models import (
    CacheMetadata,
    CacheStatus,
    DnsResolutionEnvelope,
    DnsResolutionError,
    DnsResolutionResult,
    ToolErrorCode,
    ToolResultStatus,
    UsageMetadata,
)
from src.agents.tools.network import SsrfGuard


class SafeDnsEvidenceResolver:
    """Expose privacy-minimized DNS evidence through the existing SSRF policy."""

    provider = "trustguard-safe-dns"
    provider_version = "v1"

    def __init__(
        self,
        guard: SsrfGuard | None = None,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._guard = guard or SsrfGuard()
        self._clock = clock

    def _usage(self, started: float, calls: int) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:dns:{uuid4()}",
            provider=self.provider,
            provider_version=self.provider_version,
            operation="dns_safety_resolution",
            attempts=1,
            network_calls=calls,
            latency_ms=(time.perf_counter() - started) * 1000,
            request_units=calls,
            observed_at=self._clock(),
        )

    async def resolve(self, normalized_url: str) -> DnsResolutionEnvelope:
        started = time.perf_counter()
        try:
            target = await self._guard.validate(normalized_url)
        except UnsafeUrlError as exc:
            return self._error(
                started,
                ToolResultStatus.BLOCKED,
                ToolErrorCode.SSRF_BLOCKED,
                str(exc),
                retryable=False,
                calls=0,
            )
        except ToolCallError as exc:
            code = (
                ToolErrorCode.PROVIDER_TIMEOUT if exc.error.code == "PROVIDER_TIMEOUT" else ToolErrorCode.PROVIDER_ERROR
            )
            return self._error(
                started,
                ToolResultStatus.FAILED,
                code,
                exc.error.message,
                retryable=exc.error.retryable,
                calls=getattr(exc, "network_calls", 1),
            )
        ipv4_count = sum(ipaddress.ip_address(value.split("%", 1)[0]).version == 4 for value in target.addresses)
        result = DnsResolutionResult(
            normalized_url=target.url,
            domain=target.host,
            address_count=len(target.addresses),
            ipv4_count=ipv4_count,
            ipv6_count=len(target.addresses) - ipv4_count,
            observed_at=self._clock(),
        )
        return DnsResolutionEnvelope(
            status=ToolResultStatus.SUCCESS,
            result=result,
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="live_dns_validation"),
            usage=self._usage(started, 1),
        )

    def _error(
        self,
        started: float,
        status: ToolResultStatus,
        code: ToolErrorCode,
        message: str,
        *,
        retryable: bool,
        calls: int,
    ) -> DnsResolutionEnvelope:
        return DnsResolutionEnvelope(
            status=status,
            error=DnsResolutionError(
                code=code,
                message=message,
                retryable=retryable,
                provider=self.provider,
            ),
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="security_or_resolution_failure"),
            usage=self._usage(started, calls),
        )


__all__ = ["SafeDnsEvidenceResolver"]
