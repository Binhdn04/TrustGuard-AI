from __future__ import annotations

from typing import Protocol

from src.models import BlacklistLookupEntry, ClaimEvidence, DomainIntelligenceResult, UrlScanResult


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
