from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from src.agents.campaign import (
    SecurityCampaignConfig,
    build_security_memory_record,
    cluster_security_memory,
)
from src.core.auth import Principal, require_security_admin
from src.core.errors import PlatformError
from src.models import (
    ErrorCode,
    PotentialThreatV4,
    SecurityCampaignAuditRecordV4,
    SecurityCampaignRecordV4,
    SecurityCampaignReviewerStatusV4,
    SecurityDomainIntelligenceV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryAuditRecordV4,
    SecurityMemoryRecordV4,
    SecurityScopeResponseV4,
    SecurityThreatIntelligenceV4,
)


def _not_found(resource: str) -> PlatformError:
    return PlatformError(
        status_code=404,
        code=ErrorCode.NOT_FOUND,
        message=f"{resource} was not found.",
        retryable=False,
    )


def _conflict(message: str) -> PlatformError:
    return PlatformError(
        status_code=409,
        code=ErrorCode.CONFLICT,
        message=message,
        retryable=False,
    )


@dataclass(slots=True)
class _MemoryStore:
    records: dict[UUID, SecurityMemoryRecordV4] = field(default_factory=dict)
    owners: dict[UUID, str] = field(default_factory=dict)
    campaigns: dict[UUID, SecurityCampaignRecordV4] = field(default_factory=dict)
    memory_audit: dict[UUID, list[SecurityMemoryAuditRecordV4]] = field(default_factory=dict)
    campaign_audit: dict[UUID, list[SecurityCampaignAuditRecordV4]] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass(frozen=True, slots=True)
class ReviewedMemoryCandidate:
    record: SecurityMemoryRecordV4
    reviewed_at: datetime


@dataclass(frozen=True, slots=True)
class ReviewedCampaignCandidate:
    record: SecurityCampaignRecordV4


class SecurityMemoryService:
    """Structured, privacy-minimized security intelligence and reviewer-gated campaigns."""

    def __init__(
        self,
        repository=None,
        *,
        config: SecurityCampaignConfig = SecurityCampaignConfig(),
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self._repository = repository
        self._config = config
        self._clock = clock
        self._memory = _MemoryStore()

    async def record(
        self,
        response: SecurityScopeResponseV4,
        owner_id: str | None = None,
    ) -> SecurityMemoryRecordV4 | None:
        if response.security_context is None or response.risk is None or response.threat_type is None:
            return None
        record = build_security_memory_record(response, config=self._config)
        save = getattr(self._repository, "upsert_security_memory", None)
        if save is not None:
            record = await save(record)
        else:
            async with self._memory.lock:
                existing = self._memory.records.get(record.memory_id)
                if existing is None:
                    self._memory.records[record.memory_id] = record
                else:
                    record = existing
                if owner_id is not None:
                    self._memory.owners[record.analysis_id] = owner_id

        since = record.last_seen_at - self._config.window
        recent_loader = getattr(self._repository, "recent_security_memory", None)
        if recent_loader is not None:
            recent = await recent_loader(since)
        else:
            async with self._memory.lock:
                recent = [item for item in self._memory.records.values() if item.last_seen_at >= since]
        for campaign in cluster_security_memory(recent, config=self._config):
            persist_campaign = getattr(self._repository, "upsert_security_campaign", None)
            if persist_campaign is not None:
                await persist_campaign(campaign)
            else:
                async with self._memory.lock:
                    self._memory.campaigns.setdefault(campaign.campaign_id, campaign)
        return record.model_copy(deep=True)

    async def reviewed_candidates(
        self,
        owner_id: str,
        current_analysis_id: UUID,
    ) -> tuple[list[ReviewedMemoryCandidate], list[ReviewedCampaignCandidate]]:
        """Load only reviewer-approved, owner-isolated, non-self intelligence."""
        load = getattr(self._repository, "load_reviewed_security_memory", None)
        if load is not None:
            memories, campaigns = await load(owner_id, current_analysis_id)
            return (
                [ReviewedMemoryCandidate(record=item, reviewed_at=reviewed_at) for item, reviewed_at in memories],
                [ReviewedCampaignCandidate(record=item) for item in campaigns],
            )

        allowed = {
            SecurityMemoryAdminVerdictV4.MALICIOUS,
            SecurityMemoryAdminVerdictV4.SAFE,
            SecurityMemoryAdminVerdictV4.FALSE_POSITIVE,
        }
        async with self._memory.lock:
            memories: list[ReviewedMemoryCandidate] = []
            for record in self._memory.records.values():
                if (
                    record.analysis_id == current_analysis_id
                    or self._memory.owners.get(record.analysis_id) != owner_id
                    or record.admin_verdict not in allowed
                ):
                    continue
                audit = self._memory.memory_audit.get(record.memory_id, [])
                if not audit:
                    continue
                memories.append(ReviewedMemoryCandidate(record.model_copy(deep=True), audit[-1].occurred_at))
            campaigns = [
                ReviewedCampaignCandidate(record.model_copy(deep=True))
                for record in self._memory.campaigns.values()
                if record.reviewer_status is SecurityCampaignReviewerStatusV4.CONFIRMED
                and current_analysis_id not in record.analysis_ids
                and all(self._memory.owners.get(item) == owner_id for item in record.analysis_ids)
            ]
        return memories, campaigns

    async def list_memory(self, principal: Principal) -> list[SecurityMemoryRecordV4]:
        require_security_admin(principal)
        load = getattr(self._repository, "list_security_memory", None)
        if load is not None:
            return await load()
        async with self._memory.lock:
            return sorted(
                (item.model_copy(deep=True) for item in self._memory.records.values()),
                key=lambda item: item.last_seen_at,
                reverse=True,
            )

    async def memory_for_analysis(
        self, analysis_id: UUID, principal: Principal
    ) -> SecurityMemoryRecordV4 | None:
        require_security_admin(principal)
        return next((item for item in await self.list_memory(principal) if item.analysis_id == analysis_id), None)

    async def domain_intelligence(self, principal: Principal) -> list[SecurityDomainIntelligenceV4]:
        records = await self.list_memory(principal)
        aggregates: dict[str, dict] = {}
        for record in records:
            for domain in record.canonical_domains:
                item = aggregates.setdefault(
                    domain,
                    {
                        "analysis_ids": set(),
                        "report_count": 0,
                        "risks": {},
                        "threats": {},
                        "first_seen_at": record.first_seen_at,
                        "last_seen_at": record.last_seen_at,
                        "evidence_refs": [],
                    },
                )
                item["analysis_ids"].add(record.analysis_id)
                item["report_count"] += record.report_count
                item["risks"][record.risk] = item["risks"].get(record.risk, 0) + 1
                item["threats"][record.threat_type] = item["threats"].get(record.threat_type, 0) + 1
                item["first_seen_at"] = min(item["first_seen_at"], record.first_seen_at)
                item["last_seen_at"] = max(item["last_seen_at"], record.last_seen_at)
                item["evidence_refs"] = list(dict.fromkeys([*item["evidence_refs"], *record.evidence_refs]))[:100]
        return sorted(
            (
                SecurityDomainIntelligenceV4(
                    domain=domain,
                    analysis_count=len(item["analysis_ids"]),
                    report_count=item["report_count"],
                    risk_distribution=item["risks"],
                    threat_distribution=item["threats"],
                    first_seen_at=item["first_seen_at"],
                    last_seen_at=item["last_seen_at"],
                    evidence_refs=item["evidence_refs"],
                )
                for domain, item in aggregates.items()
            ),
            key=lambda item: (-item.analysis_count, item.domain),
        )

    async def threat_intelligence(self, principal: Principal) -> list[SecurityThreatIntelligenceV4]:
        records = await self.list_memory(principal)
        aggregates: dict[PotentialThreatV4, dict] = {}
        for record in records:
            item = aggregates.setdefault(
                record.threat_type,
                {
                    "analysis_ids": set(),
                    "report_count": 0,
                    "risks": {},
                    "domains": [],
                    "first_seen_at": record.first_seen_at,
                    "last_seen_at": record.last_seen_at,
                    "evidence_refs": [],
                },
            )
            item["analysis_ids"].add(record.analysis_id)
            item["report_count"] += record.report_count
            item["risks"][record.risk] = item["risks"].get(record.risk, 0) + 1
            item["domains"] = list(dict.fromkeys([*item["domains"], *record.canonical_domains]))[:100]
            item["first_seen_at"] = min(item["first_seen_at"], record.first_seen_at)
            item["last_seen_at"] = max(item["last_seen_at"], record.last_seen_at)
            item["evidence_refs"] = list(dict.fromkeys([*item["evidence_refs"], *record.evidence_refs]))[:100]
        return sorted(
            (
                SecurityThreatIntelligenceV4(
                    threat_type=threat,
                    analysis_count=len(item["analysis_ids"]),
                    report_count=item["report_count"],
                    risk_distribution=item["risks"],
                    domains=item["domains"],
                    first_seen_at=item["first_seen_at"],
                    last_seen_at=item["last_seen_at"],
                    evidence_refs=item["evidence_refs"],
                )
                for threat, item in aggregates.items()
            ),
            key=lambda item: (-item.analysis_count, item.threat_type.value),
        )

    async def correct_memory(
        self,
        memory_id: UUID,
        verdict: SecurityMemoryAdminVerdictV4,
        note: str,
        principal: Principal,
    ) -> SecurityMemoryRecordV4:
        require_security_admin(principal)
        if verdict is SecurityMemoryAdminVerdictV4.UNREVIEWED:
            raise ValueError("admin correction requires a reviewed verdict")
        now = self._clock()
        update = getattr(self._repository, "correct_security_memory", None)
        if update is not None:
            result = await update(memory_id, verdict, note.strip(), principal.user_id, now)
            if result is None:
                raise _not_found("Security memory record")
            return result
        async with self._memory.lock:
            current = self._memory.records.get(memory_id)
            if current is None:
                raise _not_found("Security memory record")
            updated = current.model_copy(update={"admin_verdict": verdict})
            audit = SecurityMemoryAuditRecordV4(
                memory_id=memory_id,
                previous_verdict=current.admin_verdict,
                verdict=verdict,
                reviewer_id=principal.user_id,
                note=note.strip(),
                occurred_at=now,
                risk_policy_version=current.risk_policy_version,
                fingerprint_version=current.fingerprint_version,
                evidence_refs=current.evidence_refs,
            )
            self._memory.records[memory_id] = updated
            self._memory.memory_audit.setdefault(memory_id, []).append(audit)
            return updated.model_copy(deep=True)

    async def memory_audit(self, memory_id: UUID, principal: Principal) -> list[SecurityMemoryAuditRecordV4]:
        require_security_admin(principal)
        load = getattr(self._repository, "list_security_memory_audit", None)
        if load is not None:
            return await load(memory_id)
        async with self._memory.lock:
            if memory_id not in self._memory.records:
                raise _not_found("Security memory record")
            return [item.model_copy(deep=True) for item in self._memory.memory_audit.get(memory_id, [])]

    async def list_campaigns(self, principal: Principal) -> list[SecurityCampaignRecordV4]:
        require_security_admin(principal)
        load = getattr(self._repository, "list_security_campaigns", None)
        if load is not None:
            return await load()
        async with self._memory.lock:
            return sorted(
                (item.model_copy(deep=True) for item in self._memory.campaigns.values()),
                key=lambda item: item.window_ended_at,
                reverse=True,
            )

    async def get_campaign(self, campaign_id: UUID, principal: Principal) -> SecurityCampaignRecordV4:
        require_security_admin(principal)
        load = getattr(self._repository, "get_security_campaign", None)
        result = await load(campaign_id) if load is not None else self._memory.campaigns.get(campaign_id)
        if result is None:
            raise _not_found("Security campaign")
        return result.model_copy(deep=True)

    async def review_campaign(
        self,
        campaign_id: UUID,
        status: SecurityCampaignReviewerStatusV4,
        note: str,
        principal: Principal,
    ) -> SecurityCampaignRecordV4:
        require_security_admin(principal)
        if status is SecurityCampaignReviewerStatusV4.PENDING_REVIEW:
            raise ValueError("campaign decision must be confirmed or rejected")
        now = self._clock()
        update = getattr(self._repository, "review_security_campaign", None)
        if update is not None:
            result = await update(campaign_id, status, note.strip(), principal.user_id, now)
            if result is None:
                raise _not_found("Security campaign")
            return result
        async with self._memory.lock:
            current = self._memory.campaigns.get(campaign_id)
            if current is None:
                raise _not_found("Security campaign")
            if current.reviewer_status is not SecurityCampaignReviewerStatusV4.PENDING_REVIEW:
                raise _conflict("Security campaign was already reviewed.")
            updated = current.model_copy(
                update={
                    "reviewer_status": status,
                    "reviewer_id": principal.user_id,
                    "review_note": note.strip(),
                    "reviewed_at": now,
                }
            )
            audit = SecurityCampaignAuditRecordV4(
                audit_id=uuid4(),
                campaign_id=campaign_id,
                previous_status=current.reviewer_status,
                status=status,
                reviewer_id=principal.user_id,
                note=note.strip(),
                occurred_at=now,
                clustering_version=current.clustering_version,
                evidence_refs=current.evidence_refs,
            )
            self._memory.campaigns[campaign_id] = updated
            self._memory.campaign_audit.setdefault(campaign_id, []).append(audit)
            return updated.model_copy(deep=True)

    async def campaign_audit(self, campaign_id: UUID, principal: Principal) -> list[SecurityCampaignAuditRecordV4]:
        require_security_admin(principal)
        load = getattr(self._repository, "list_security_campaign_audit", None)
        if load is not None:
            return await load(campaign_id)
        async with self._memory.lock:
            if campaign_id not in self._memory.campaigns:
                raise _not_found("Security campaign")
            return [item.model_copy(deep=True) for item in self._memory.campaign_audit.get(campaign_id, [])]


__all__ = ["ReviewedCampaignCandidate", "ReviewedMemoryCandidate", "SecurityMemoryService"]
