from __future__ import annotations

from collections.abc import Mapping, Sequence

from src.models import ClaimEvidence, ToolError, UrlScanResult


class FakeToolCallError(RuntimeError):
    def __init__(self, error: ToolError) -> None:
        super().__init__(error.message)
        self.error = error


class FakeUrlScanner:
    """Offline URL scanner selected by a fixture response ID."""

    def __init__(
        self,
        responses: Mapping[str, UrlScanResult | ToolError],
        response_id: str,
    ) -> None:
        self._responses = dict(responses)
        self._response_id = response_id
        self.calls: list[str] = []

    async def scan(self, normalized_url: str) -> UrlScanResult:
        self.calls.append(normalized_url)
        if self._response_id not in self._responses:
            raise ValueError(
                f"URL scanner fixture response ID {self._response_id!r} is not configured"
            )
        result = self._responses[self._response_id]
        if isinstance(result, ToolError):
            raise FakeToolCallError(result)
        if result.normalized_url != normalized_url:
            return result.model_copy(update={"normalized_url": normalized_url})
        return result.model_copy(deep=True)


class FakeClaimRetriever:
    """Offline claim retriever selected by a fixture response ID."""

    def __init__(
        self,
        responses: Mapping[str, Sequence[ClaimEvidence] | ToolError],
        response_id: str,
    ) -> None:
        self._responses = {
            key: value if isinstance(value, ToolError) else list(value)
            for key, value in responses.items()
        }
        self._response_id = response_id
        self.calls: list[tuple[str, int]] = []

    async def search(self, claim: str, limit: int = 5) -> list[ClaimEvidence]:
        self.calls.append((claim, limit))
        result = self._responses[self._response_id]
        if isinstance(result, ToolError):
            raise FakeToolCallError(result)
        return [item.model_copy(deep=True) for item in result[:limit]]


class FakeBlacklistRepository:
    """In-memory blacklist fake; it never accesses a database or provider."""

    def __init__(self, domains: Sequence[str] = ()) -> None:
        self._domains = {domain.casefold() for domain in domains}
        self.approved_writes: list[tuple[str, str]] = []

    async def contains(self, domain: str) -> bool:
        return domain.casefold() in self._domains

    async def add_approved(self, domain: str, decision_id: str) -> None:
        if not domain.strip() or not decision_id.strip():
            raise ValueError("domain and decision_id are required")
        normalized_domain = domain.casefold()
        self._domains.add(normalized_domain)
        self.approved_writes.append((normalized_domain, decision_id))
