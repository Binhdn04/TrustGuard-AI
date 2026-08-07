from __future__ import annotations

from typing import Protocol

from src.models import ClaimEvidence, DomainIntelligenceResult, UrlScanResult


class UrlScanner(Protocol):
    async def scan(self, normalized_url: str) -> UrlScanResult: ...


class ClaimRetriever(Protocol):
    async def search(self, claim: str, limit: int = 5) -> list[ClaimEvidence]: ...


class DomainIntelligence(Protocol):
    async def lookup(self, domain: str) -> DomainIntelligenceResult: ...


class BlacklistRepository(Protocol):
    async def get(self, domain: str) -> BlacklistEntry | None: ...

    async def contains(self, domain: str) -> bool: ...

    async def add_approved(self, domain: str, decision_id: str) -> None: ...
