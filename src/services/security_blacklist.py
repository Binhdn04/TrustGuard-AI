from __future__ import annotations

from datetime import UTC, datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from src.core.auth import Principal, require_security_admin
from src.core.errors import PlatformError
from src.models import (
    AdminActionRecordV3,
    AdminActionStatus,
    ClaimStance,
    ErrorCode,
    Evidence,
    EvidenceType,
    ReviewDecision,
    ReviewedAction,
    SecurityBlacklistActionProposalV4,
    SecurityBlacklistActionStatusV4,
    SecurityBlacklistActionV4,
    SecurityBlacklistAuditRecordV4,
    SecurityBlacklistDecisionResponseV4,
    SecurityBlacklistDisableRequestV4,
    SecurityBlacklistLifecycleV4,
    SecurityBlacklistPageV4,
    SecurityBlacklistProposalRequestV4,
    SecurityBlacklistRecordV4,
    SecurityBlacklistReviewDecisionV4,
)
from src.repositories.blacklist import normalize_domain
from src.services.platform_wave2 import Wave2PlatformService


def _conflict(message: str) -> PlatformError:
    return PlatformError(status_code=409, code=ErrorCode.CONFLICT, message=message, retryable=False)


def _not_found(message: str) -> PlatformError:
    return PlatformError(status_code=404, code=ErrorCode.NOT_FOUND, message=message, retryable=False)


class SecurityBlacklistAdminService:
    """V4 blacklist lifecycle projected from reviewer-gated admin actions."""

    def __init__(self, wave2: Wave2PlatformService) -> None:
        self._wave2 = wave2

    async def list_records(
        self,
        principal: Principal,
        *,
        q: str | None = None,
        lifecycle: SecurityBlacklistLifecycleV4 | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> SecurityBlacklistPageV4:
        require_security_admin(principal)
        records = await self._records()
        if q:
            needle = q.casefold().strip()
            records = [item for item in records if needle in item.canonical_domain.casefold()]
        if lifecycle is not None:
            records = [item for item in records if item.lifecycle is lifecycle]
        records.sort(key=lambda item: item.updated_at, reverse=True)
        return SecurityBlacklistPageV4(
            items=records[offset : offset + limit], total=len(records), limit=limit, offset=offset
        )

    async def get_record(self, blacklist_id: UUID, principal: Principal) -> SecurityBlacklistRecordV4:
        require_security_admin(principal)
        record = next((item for item in await self._records() if item.blacklist_id == blacklist_id), None)
        if record is None:
            raise _not_found("Security blacklist record was not found.")
        return record

    async def propose_add(
        self, request: SecurityBlacklistProposalRequestV4, principal: Principal
    ) -> SecurityBlacklistActionProposalV4:
        require_security_admin(principal)
        domain = normalize_domain(request.canonical_domain)
        current = await self._record_for_domain(domain)
        if current is not None and current.lifecycle is SecurityBlacklistLifecycleV4.ACTIVE:
            raise _conflict("The domain is already active in the security blacklist.")
        action = await self._wave2.repository.propose_admin_action(
            analysis_id=None,
            security_analysis_id=request.source_analysis_id,
            campaign_id=None,
            action=ReviewedAction.ADD_TO_BLACKLIST,
            target=domain,
            evidence=self._evidence(request.reason, request.provenance, request.evidence_refs, domain),
        )
        return self._proposal(action, request.source_report_id)

    async def propose_disable(
        self,
        blacklist_id: UUID,
        request: SecurityBlacklistDisableRequestV4,
        principal: Principal,
    ) -> SecurityBlacklistActionProposalV4:
        record = await self.get_record(blacklist_id, principal)
        if record.lifecycle is not SecurityBlacklistLifecycleV4.ACTIVE:
            raise _conflict("The security blacklist record is already disabled.")
        action = await self._wave2.repository.propose_admin_action(
            analysis_id=None,
            security_analysis_id=None,
            campaign_id=None,
            action=ReviewedAction.DISABLE_BLACKLIST,
            target=record.canonical_domain,
            evidence=self._evidence(
                request.reason, request.provenance, request.evidence_refs, record.canonical_domain
            ),
        )
        return self._proposal(action, None)

    async def decide(
        self,
        action_id: UUID,
        decision: SecurityBlacklistReviewDecisionV4,
        note: str,
        principal: Principal,
    ) -> SecurityBlacklistDecisionResponseV4:
        require_security_admin(principal)
        action = await self._wave2.get_admin_action(action_id)
        self._require_blacklist_action(action)
        result = await self._wave2.decide_admin_action(
            action_id, ReviewDecision(decision.value), note, principal.user_id
        )
        record = await self._record_for_domain(action.target or "")
        return SecurityBlacklistDecisionResponseV4(
            action_id=result.action_id,
            action=SecurityBlacklistActionV4(result.action.value),
            status=SecurityBlacklistActionStatusV4(result.status.value),
            record=record,
            reviewed_at=result.reviewed_at,
            executed_at=result.executed_at,
            execution_error=result.execution_error,
        )

    async def list_audit(
        self, blacklist_id: UUID, principal: Principal
    ) -> list[SecurityBlacklistAuditRecordV4]:
        record = await self.get_record(blacklist_id, principal)
        actions = [
            item
            for item in await self._all_actions()
            if item.target == record.canonical_domain
            and item.action in {ReviewedAction.ADD_TO_BLACKLIST, ReviewedAction.DISABLE_BLACKLIST}
        ]
        rows = []
        for action in actions:
            for audit in await self._wave2.list_admin_action_audit(action.action_id):
                rows.append(
                    SecurityBlacklistAuditRecordV4(
                        decision_id=audit.decision_id,
                        action_id=audit.action_id,
                        decision=SecurityBlacklistReviewDecisionV4(audit.decision.value),
                        action=SecurityBlacklistActionV4(audit.action.value),
                        status=SecurityBlacklistActionStatusV4(audit.execution_status.value),
                        note=audit.note,
                        evidence_refs=[item.title for item in audit.evidence_snapshot],
                        decided_at=audit.decided_at,
                        execution_error=audit.execution_error,
                    )
                )
        return sorted(rows, key=lambda item: item.decided_at)

    async def _all_actions(self) -> list[AdminActionRecordV3]:
        records: list[AdminActionRecordV3] = []
        offset = 0
        while True:
            page, total = await self._wave2.repository.list_admin_actions(None, 100, offset)
            records.extend(page)
            offset += len(page)
            if not page or offset >= total:
                return records

    async def _records(self) -> list[SecurityBlacklistRecordV4]:
        by_domain: dict[str, list[AdminActionRecordV3]] = {}
        for action in await self._all_actions():
            if (
                action.target
                and action.status is AdminActionStatus.EXECUTED
                and action.action in {ReviewedAction.ADD_TO_BLACKLIST, ReviewedAction.DISABLE_BLACKLIST}
            ):
                by_domain.setdefault(action.target, []).append(action)
        records = []
        for domain, actions in by_domain.items():
            actions.sort(key=lambda item: item.executed_at or item.proposed_at)
            add_actions = [item for item in actions if item.action is ReviewedAction.ADD_TO_BLACKLIST]
            if not add_actions:
                continue
            latest = actions[-1]
            enabling = add_actions[-1]
            disabled = latest.action is ReviewedAction.DISABLE_BLACKLIST
            evidence = enabling.evidence_snapshot
            records.append(
                SecurityBlacklistRecordV4(
                    blacklist_id=uuid5(NAMESPACE_URL, f"trustguard:blacklist:{domain}"),
                    canonical_domain=domain,
                    lifecycle=(
                        SecurityBlacklistLifecycleV4.DISABLED
                        if disabled
                        else SecurityBlacklistLifecycleV4.ACTIVE
                    ),
                    enabling_action_id=enabling.action_id,
                    disabling_action_id=latest.action_id if disabled else None,
                    reason=evidence[0].finding if evidence else "Reviewed blacklist action",
                    provenance=evidence[0].source if evidence else "reviewed-admin-action",
                    evidence_refs=[item.title for item in evidence],
                    created_at=add_actions[0].executed_at or add_actions[0].proposed_at,
                    updated_at=latest.executed_at or latest.proposed_at,
                    version=len(actions),
                )
            )
        return records

    async def _record_for_domain(self, domain: str) -> SecurityBlacklistRecordV4 | None:
        normalized = normalize_domain(domain)
        return next((item for item in await self._records() if item.canonical_domain == normalized), None)

    @staticmethod
    def _evidence(reason: str, provenance: str, refs: list[str], domain: str) -> list[Evidence]:
        now = datetime.now(UTC)
        return [
            Evidence(
                type=EvidenceType.BLACKLIST,
                source=provenance,
                title=ref,
                url=f"https://{domain}/",
                finding=reason,
                stance=ClaimStance.SUPPORTS,
                observed_at=now,
            )
            for ref in refs
        ]

    @staticmethod
    def _proposal(
        action: AdminActionRecordV3, source_report_id: UUID | None
    ) -> SecurityBlacklistActionProposalV4:
        return SecurityBlacklistActionProposalV4(
            action_id=action.action_id,
            action=SecurityBlacklistActionV4(action.action.value),
            canonical_domain=action.target or "",
            status=SecurityBlacklistActionStatusV4(action.status.value),
            source_analysis_id=action.security_analysis_id,
            source_report_id=source_report_id,
            proposed_at=action.proposed_at,
        )

    @staticmethod
    def _require_blacklist_action(action: AdminActionRecordV3) -> None:
        if action.action not in {ReviewedAction.ADD_TO_BLACKLIST, ReviewedAction.DISABLE_BLACKLIST}:
            raise _conflict("The admin action is not a security blacklist action.")
