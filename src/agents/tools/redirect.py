from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

import httpx

from .domains import canonicalize_registrable_domain, canonicalize_url
from .errors import ToolCallError, UnsafeUrlError
from .models import (
    CacheMetadata,
    CacheStatus,
    NormalizedToolError,
    NormalizedToolResult,
    RedirectResolutionResult,
    RedirectResolutionStatus,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UsageMetadata,
)
from .network import GuardedHttpClient, SsrfGuard


class GuardedRedirectResolver:
    """Resolve redirects with DNS pinning and SSRF validation at every hop."""

    provider = "trustguard-guarded-redirect"
    provider_version = "v1"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        timeout: float = 5.0,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._client = client
        self._owns_client = client is None
        self._timeout = timeout
        self._guard = guard
        self._clock = clock

    def _http(self) -> GuardedHttpClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return GuardedHttpClient(self._client, self._guard)

    def _usage(self, started: float, calls: int) -> UsageMetadata:
        return UsageMetadata(
            usage_ref=f"usage:redirect:{uuid4()}",
            provider=self.provider,
            provider_version=self.provider_version,
            operation="resolve_redirects",
            attempts=1,
            network_calls=calls,
            latency_ms=(time.perf_counter() - started) * 1000,
            request_units=calls,
            observed_at=self._clock(),
        )

    async def resolve(self, normalized_url: str) -> NormalizedToolResult[RedirectResolutionResult]:
        started = time.perf_counter()
        try:
            target = canonicalize_url(normalized_url)
            _response, chain = await self._http().get(target)
            calls = len(chain)
            # Redirect discovery does not treat a 4xx/5xx landing response as a
            # resolver failure: the observed chain remains useful evidence.
            canonical_chain = [canonicalize_url(item) for item in chain]
            signals: list[str] = []
            if len(canonical_chain) > 1:
                try:
                    first = canonicalize_registrable_domain(canonical_chain[0])
                    last = canonicalize_registrable_domain(canonical_chain[-1])
                    if first != last:
                        signals.append("cross_registrable_domain")
                except ValueError:
                    pass
            result = RedirectResolutionResult(
                normalized_url=canonical_chain[0],
                final_url=canonical_chain[-1],
                redirect_chain=canonical_chain,
                status=(
                    RedirectResolutionStatus.NO_REDIRECT
                    if len(canonical_chain) == 1
                    else RedirectResolutionStatus.RESOLVED
                ),
                signals=signals,
                observed_at=self._clock(),
            )
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS,
                result=result,
                cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="live_resolution"),
                usage=self._usage(started, calls),
            )
        except (UnsafeUrlError, ValueError) as exc:
            return self._error(
                started,
                ToolResultStatus.BLOCKED,
                ToolErrorCode.SSRF_BLOCKED if isinstance(exc, UnsafeUrlError) else ToolErrorCode.INVALID_TARGET,
                str(exc),
                calls=getattr(exc, "network_calls", 0),
            )
        except ToolCallError as exc:
            code = (
                ToolErrorCode.REDIRECT_LOOP
                if exc.error.code in {"REDIRECT_LOOP", "TOO_MANY_REDIRECTS"}
                else ToolErrorCode.RESPONSE_TOO_LARGE
                if exc.error.code == "RESPONSE_TOO_LARGE"
                else ToolErrorCode.PROVIDER_ERROR
            )
            return self._error(
                started,
                ToolResultStatus.FAILED,
                code,
                exc.error.message,
                calls=getattr(exc, "network_calls", 0),
            )
        except httpx.TimeoutException:
            return self._error(
                started,
                ToolResultStatus.FAILED,
                ToolErrorCode.PROVIDER_TIMEOUT,
                "Redirect resolution timed out.",
                calls=0,
                retryable=True,
            )
        except httpx.HTTPError:
            return self._error(
                started,
                ToolResultStatus.FAILED,
                ToolErrorCode.PROVIDER_ERROR,
                "Redirect resolution failed.",
                calls=0,
                retryable=True,
            )

    def _error(
        self,
        started: float,
        status: ToolResultStatus,
        code: ToolErrorCode,
        message: str,
        *,
        calls: int,
        retryable: bool = False,
    ) -> NormalizedToolResult[RedirectResolutionResult]:
        return NormalizedToolResult(
            status=status,
            error=NormalizedToolError(
                tool=ToolName.REDIRECT_RESOLVER,
                code=code,
                message=message,
                retryable=retryable,
                provider=self.provider,
            ),
            cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="security_or_transport_failure"),
            usage=self._usage(started, calls),
        )

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
