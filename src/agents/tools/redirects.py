from __future__ import annotations

import time
from datetime import UTC, datetime
from uuid import uuid4

import httpx

from .models import (
    CacheMetadata,
    NormalizedToolError,
    NormalizedToolResult,
    RedirectResolutionResult,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UsageMetadata,
)
from .network import GuardedHttpClient, SsrfGuard
from .reputation import canonicalize_url


class GuardedRedirectResolver:
    provider = "guarded-redirect-resolver"
    provider_version = "v1"

    def __init__(self, *, client: httpx.AsyncClient | None = None, guard: SsrfGuard | None = None,
                 timeout: float = 5) -> None:
        self._client = client
        self._timeout = timeout
        self._owns_client = client is None
        self._guard = guard

    def _http(self) -> GuardedHttpClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return GuardedHttpClient(self._client, self._guard)

    async def resolve(self, normalized_url: str) -> NormalizedToolResult[RedirectResolutionResult]:
        started = time.monotonic()
        url = canonicalize_url(normalized_url)
        try:
            _response, raw_chain = await self._http().get(url)
            chain = [canonicalize_url(item) for item in raw_chain]
        except Exception as exc:
            embedded = getattr(exc, "error", None)
            code_value = getattr(embedded, "code", "PROVIDER_ERROR")
            aliases = {"TOO_MANY_REDIRECTS": ToolErrorCode.REDIRECT_LOOP, "SSRF_BLOCKED": ToolErrorCode.SSRF_BLOCKED,
                       "RESPONSE_TOO_LARGE": ToolErrorCode.RESPONSE_TOO_LARGE}
            code = aliases.get(code_value, ToolErrorCode.PROVIDER_ERROR)
            return NormalizedToolResult(
                status=ToolResultStatus.BLOCKED if code is ToolErrorCode.SSRF_BLOCKED else ToolResultStatus.FAILED,
                error=NormalizedToolError(tool=ToolName.REDIRECT_RESOLVER, code=code,
                                          message="redirect resolution blocked or failed", retryable=False),
                cache=CacheMetadata(status="bypass", bypass_reason="redirects are resolved live"),
                usage=self._usage(started, 1),
            )
        result = RedirectResolutionResult(normalized_url=url, final_url=chain[-1], redirect_chain=chain,
                                          status="no_redirect" if len(chain) == 1 else "resolved",
                                          observed_at=datetime.now(UTC))
        return NormalizedToolResult(status=ToolResultStatus.SUCCESS, result=result,
                                    cache=CacheMetadata(status="bypass", bypass_reason="redirects are resolved live"),
                                    usage=self._usage(started, 1))

    def _usage(self, started: float, calls: int) -> UsageMetadata:
        return UsageMetadata(usage_ref=f"usage:{uuid4()}", provider=self.provider,
                             provider_version=self.provider_version, operation="resolve", attempts=1,
                             network_calls=calls, latency_ms=(time.monotonic() - started) * 1000,
                             observed_at=datetime.now(UTC))

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
