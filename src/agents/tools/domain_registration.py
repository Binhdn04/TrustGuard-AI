from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from src.agents.tools.bkns import BknsWhoisProvider
from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST
from src.agents.tools.models import CacheMetadata, CacheStatus, NormalizedToolResult, UsageMetadata
from src.agents.tools.rdap import NormalizedRdapProvider
from src.models import DomainIntelligenceResult


class _Provider(Protocol):
    async def lookup(self, domain: str) -> NormalizedToolResult[DomainIntelligenceResult]: ...

    async def aclose(self) -> None: ...


class DomainRegistrationProvider:
    """Route domain registration lookup while preserving the public RDAP tool contract."""

    provider = "domain-registration/rdap+bkns-v1"

    def __init__(
        self,
        bkns_api_key: str = "",
        *,
        rdap: _Provider | None = None,
        bkns: _Provider | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._bkns_api_key = bkns_api_key.strip()
        self._rdap = rdap
        self._bkns = bkns
        self._timeout = timeout

    def _get_rdap(self) -> _Provider:
        if self._rdap is None:
            self._rdap = NormalizedRdapProvider(timeout=self._timeout)
        return self._rdap

    def _get_bkns(self) -> _Provider:
        if self._bkns is None:
            self._bkns = BknsWhoisProvider(self._bkns_api_key, timeout=self._timeout)
        return self._bkns

    async def lookup(self, domain: str) -> NormalizedToolResult[DomainIntelligenceResult]:
        if not self._bkns_api_key:
            return await self._get_rdap().lookup(domain)
        try:
            registrable = DEFAULT_PUBLIC_SUFFIX_LIST.registrable_domain(domain)
        except ValueError:
            return await self._get_rdap().lookup(domain)
        if registrable is not None and registrable.endswith(".vn"):
            return await self._get_bkns().lookup(registrable)

        rdap_result = await self._get_rdap().lookup(domain)
        if rdap_result.result is None:
            return rdap_result
        if "service_unavailable" not in rdap_result.result.signals:
            return rdap_result

        bkns_result = await self._get_bkns().lookup(registrable or domain)
        return self._merge_fallback_usage(rdap_result, bkns_result)

    @staticmethod
    def _merge_fallback_usage(
        rdap_result: NormalizedToolResult[DomainIntelligenceResult],
        bkns_result: NormalizedToolResult[DomainIntelligenceResult],
    ) -> NormalizedToolResult[DomainIntelligenceResult]:
        rdap_usage = rdap_result.usage
        bkns_usage = bkns_result.usage
        calls = rdap_usage.network_calls + bkns_usage.network_calls
        usage = UsageMetadata(
            usage_ref=f"usage:rdap:{uuid4()}",
            provider=bkns_usage.provider,
            provider_version=bkns_usage.provider_version,
            operation="rdap_capability_then_whois_lookup",
            attempts=rdap_usage.attempts + bkns_usage.attempts,
            network_calls=calls,
            latency_ms=rdap_usage.latency_ms + bkns_usage.latency_ms,
            request_units=rdap_usage.request_units + bkns_usage.request_units,
            response_units=rdap_usage.response_units + bkns_usage.response_units,
            tokens=rdap_usage.tokens + bkns_usage.tokens,
            estimated_cost_usd=rdap_usage.estimated_cost_usd + bkns_usage.estimated_cost_usd,
            observed_at=datetime.now(UTC),
        )
        cache = bkns_result.cache
        if calls and cache.status is CacheStatus.HIT:
            # This lookup was not an end-to-end cache hit because the RDAP
            # capability check used the network.
            cache = CacheMetadata(status=CacheStatus.MISS, cache_key_hash=cache.cache_key_hash)
        return bkns_result.model_copy(update={"usage": usage, "cache": cache})

    async def aclose(self) -> None:
        seen: set[int] = set()
        for provider in (self._rdap, self._bkns):
            if provider is None or id(provider) in seen:
                continue
            seen.add(id(provider))
            await provider.aclose()


__all__ = ["DomainRegistrationProvider"]
