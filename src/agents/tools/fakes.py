from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from src.models import (
    BlacklistLookupEntry,
    ClaimEvidence,
    ClaimStance,
    DomainIntelligenceResult,
    ToolError,
    UrlScanResult,
)

from .fact_check import normalize_claim_rating


class FakeToolCallError(RuntimeError):
    def __init__(self, error: ToolError) -> None:
        super().__init__(error.message)
        self.error = error


class FakeUrlScanner:
    """Offline URL scanner selected by a fixture response ID."""

    provider = "fixture-url-reputation"

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
            raise ValueError(f"URL scanner fixture response ID {self._response_id!r} is not configured")
        result = self._responses[self._response_id]
        if isinstance(result, ToolError):
            raise FakeToolCallError(result)
        if result.normalized_url != normalized_url:
            return result.model_copy(update={"normalized_url": normalized_url})
        return result.model_copy(deep=True)


class FakeClaimRetriever:
    """Offline claim retriever selected by a fixture response ID."""

    provider = "fixture-fact-check"

    def __init__(
        self,
        responses: Mapping[str, Sequence[ClaimEvidence] | ToolError],
        response_id: str,
    ) -> None:
        self._responses = {
            key: value if isinstance(value, ToolError) else list(value) for key, value in responses.items()
        }
        self._response_id = response_id
        self.calls: list[tuple[str, int]] = []

    async def search(self, claim: str, limit: int = 5) -> list[ClaimEvidence]:
        self.calls.append((claim, limit))
        if self._response_id not in self._responses:
            raise ValueError(f"Claim retriever fixture response ID {self._response_id!r} is not configured")
        result = self._responses[self._response_id]
        if isinstance(result, ToolError):
            raise FakeToolCallError(result)
        return [
            item.model_copy(
                update={
                    "stance": (
                        normalize_claim_rating(item.finding) if item.stance is ClaimStance.UNRATED else item.stance
                    )
                },
                deep=True,
            )
            for item in result[:limit]
        ]


class FakeDomainIntelligence:
    """Offline domain intelligence selected by a fixture response ID."""

    provider = "fixture-rdap"

    def __init__(
        self,
        responses: Mapping[str, DomainIntelligenceResult | ToolError],
        response_id: str,
    ) -> None:
        self._responses = dict(responses)
        self._response_id = response_id
        self.calls: list[str] = []

    async def lookup(self, domain: str) -> DomainIntelligenceResult:
        self.calls.append(domain)
        if self._response_id not in self._responses:
            raise ValueError(f"Domain fixture response ID {self._response_id!r} is not configured")
        result = self._responses[self._response_id]
        if isinstance(result, ToolError):
            raise FakeToolCallError(result)
        return result.model_copy(update={"domain": domain}, deep=True)


class FakeBlacklistRepository:
    """In-memory blacklist fake; it never accesses a database or provider."""

    def __init__(self, domains: Sequence[str] = ()) -> None:
        self._domains = {domain.casefold(): None for domain in domains}
        self.approved_writes: list[tuple[str, str]] = []
        self.decisions: list[dict[str, str]] = []
        self.tool_executions: dict[tuple[str, str, str, str], str] = {}

    async def get(self, domain: str) -> BlacklistLookupEntry | None:
        normalized = domain.casefold()
        if normalized not in self._domains:
            return None
        decision_id = self._domains[normalized] or "fixture-approved"
        return BlacklistLookupEntry(
            domain=normalized,
            decision_id=decision_id,
            source="approved-blacklist",
            added_at=datetime(2000, 1, 1, tzinfo=UTC),
            active=True,
        )

    async def contains(self, domain: str) -> bool:
        return await self.get(domain) is not None

    async def add_approved(self, domain: str, decision_id: str) -> None:
        if not domain.strip() or not decision_id.strip():
            raise ValueError("domain and decision_id are required")
        normalized_domain = domain.casefold()
        self._domains[normalized_domain] = decision_id
        self.approved_writes.append((normalized_domain, decision_id))

    async def record_decision(
        self,
        *,
        decision_id: str,
        reviewer_id: str,
        decision: str,
        action: str,
        note: str,
    ) -> None:
        self.decisions.append(
            {
                "decision_id": decision_id,
                "reviewer_id": reviewer_id,
                "decision": decision,
                "action": action,
                "note": note,
            }
        )

    async def apply_decision(
        self,
        *,
        decision_id: str,
        analysis_id: str | None,
        reviewer_id: str,
        decision: str,
        action: str,
        note: str,
        domains: Sequence[str],
    ) -> None:
        await self.record_decision(
            decision_id=decision_id,
            reviewer_id=reviewer_id,
            decision=decision,
            action=action,
            note=note,
        )
        self.decisions[-1]["analysis_id"] = analysis_id or ""
        for domain in domains:
            await self.add_approved(domain, decision_id)

    async def apply_review_decision(
        self,
        *,
        decision_id: str,
        analysis_id: str,
        reviewer_id: str,
        decision: str,
        action: str,
        note: str,
        domains: Sequence[str],
        response,
        event,
    ) -> None:
        await self.apply_decision(
            decision_id=decision_id,
            analysis_id=analysis_id,
            reviewer_id=reviewer_id,
            decision=decision,
            action=action,
            note=note,
            domains=domains,
        )

    async def claim_tool_execution(self, analysis_id: str, step_id: str, target: str, provider: str) -> bool:
        key = (analysis_id, step_id, target, provider)
        status = self.tool_executions.get(key)
        if status in {"running", "completed"}:
            return False
        self.tool_executions[key] = "running"
        return True

    async def finish_tool_execution(
        self, analysis_id: str, step_id: str, target: str, provider: str, status: str
    ) -> None:
        self.tool_executions[(analysis_id, step_id, target, provider)] = status
