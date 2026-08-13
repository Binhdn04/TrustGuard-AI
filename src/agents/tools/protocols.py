from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from src.models import BlacklistLookupEntry, ClaimEvidence, DomainIntelligenceResult, UrlScanResult

from .models import (
    DnsResolutionEnvelope,
    FactCheckSearchResult,
    NormalizedToolResult,
    RedirectResolutionResult,
    ScreenshotResult,
    UrlReputationCascadeResult,
    UrlReputationFinding,
)


class UrlReputationProvider(Protocol):
    provider: str
    provider_version: str

    async def lookup(self, normalized_url: str) -> NormalizedToolResult[UrlReputationFinding]: ...


class UrlReputationCascade(Protocol):
    async def assess(self, normalized_url: str) -> NormalizedToolResult[UrlReputationCascadeResult]: ...


class RedirectResolver(Protocol):
    async def resolve(self, normalized_url: str) -> NormalizedToolResult[RedirectResolutionResult]: ...


class DnsEvidenceProvider(Protocol):
    async def resolve(self, normalized_url: str) -> DnsResolutionEnvelope: ...


class RdapProvider(Protocol):
    async def lookup(self, domain: str) -> NormalizedToolResult[DomainIntelligenceResult]: ...


class FactCheckCorpus(Protocol):
    async def search(self, claim: str, limit: int = 5) -> NormalizedToolResult[FactCheckSearchResult]: ...


class ScreenshotRenderer(Protocol):
    async def render(self, normalized_url: str) -> NormalizedToolResult[ScreenshotResult]: ...


class EmbeddingProvider(Protocol):
    async def embed_batch(self, claims: Sequence[str]) -> Any: ...


class GoogleClaimSearch(Protocol):
    async def search(self, claim: Any) -> Any: ...


class HybridCorpusRetriever(Protocol):
    async def search(self, claim: Any, *, vector: Sequence[float] | None = None) -> Any: ...


class TavilySearch(Protocol):
    async def search(self, claim: Any, *, max_results: int = 10) -> Any: ...


class TavilyExtract(Protocol):
    async def extract(self, claim: Any, candidates: Sequence[Any]) -> Any: ...


class UrlScanner(Protocol):
    async def scan(self, normalized_url: str) -> UrlScanResult: ...


class ClaimRetriever(Protocol):
    async def search(self, claim: str, limit: int = 5) -> list[ClaimEvidence]: ...


class DomainIntelligence(Protocol):
    async def lookup(self, domain: str) -> DomainIntelligenceResult: ...


class ToolExecutionLedger(Protocol):
    async def claim_tool_execution(self, analysis_id: str, step_id: str, target: str, provider: str) -> bool: ...

    async def finish_tool_execution(
        self, analysis_id: str, step_id: str, target: str, provider: str, status: str
    ) -> None: ...


class BlacklistRepository(Protocol):
    async def get(self, domain: str) -> BlacklistLookupEntry | None: ...

    async def contains(self, domain: str) -> bool: ...

    async def add_approved(self, domain: str, decision_id: str) -> None: ...
