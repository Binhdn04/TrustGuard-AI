from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from src.core.errors import PlatformError
from src.models import (
    AppealOutcome,
    AppealStatus,
    ErrorCode,
    ReportStatus,
    SecurityAdminAuditEventV4,
    SecurityAppealAdminRecordV4,
    SecurityAppealRecordV4,
    SecurityAuditResourceV4,
    SecurityCampaignAuditRecordV4,
    SecurityCampaignRecordV4,
    SecurityCampaignReviewerStatusV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryAuditRecordV4,
    SecurityMemoryRecordV4,
    SecurityReportAdminRecordV4,
    SecurityReportAuditDetailsV4,
    SecurityReportDecisionRequestV4,
    SecurityReportRecordV4,
    SecurityReportRemediationActionV4,
    SecurityReportRemediationReferenceV4,
    SecurityReportRemediationStatusV4,
    SecurityReportRemediationUpdateV4,
)


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class PostgresFeedbackRepositoryMixin:
    """Reviewed memory, campaigns, reports, appeals, and immutable audit."""

    async def upsert_security_memory(self, record: SecurityMemoryRecordV4) -> SecurityMemoryRecordV4:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """INSERT INTO security_memory(
                       id,analysis_id,record,admin_verdict,first_seen_at,last_seen_at,report_count,
                       fingerprint_version,risk_policy_version
                   ) VALUES($1,$2,$3::jsonb,$4,$5,$6,$7,$8,$9)
                   ON CONFLICT(analysis_id) DO UPDATE SET analysis_id=EXCLUDED.analysis_id
                   RETURNING record""",
                record.memory_id,
                record.analysis_id,
                record.model_dump_json(),
                record.admin_verdict.value,
                record.first_seen_at,
                record.last_seen_at,
                record.report_count,
                record.fingerprint_version,
                record.risk_policy_version,
            )
        return SecurityMemoryRecordV4.model_validate(_json_value(row["record"]))

    async def recent_security_memory(self, since: datetime) -> list[SecurityMemoryRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT record FROM security_memory WHERE last_seen_at >= $1 ORDER BY last_seen_at", since
            )
        return [SecurityMemoryRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def list_security_memory(self) -> list[SecurityMemoryRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT record FROM security_memory ORDER BY last_seen_at DESC")
        return [SecurityMemoryRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def load_reviewed_security_memory(
        self,
        owner_id: str,
        current_analysis_id: UUID,
    ) -> tuple[list[tuple[SecurityMemoryRecordV4, datetime]], list[SecurityCampaignRecordV4]]:
        """Return owner-isolated reviewed intelligence without the current analysis."""
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            memory_rows = await connection.fetch(
                """SELECT m.record,
                          (SELECT max(a.occurred_at) FROM security_memory_audit a
                           WHERE a.memory_id=m.id) AS reviewed_at
                   FROM security_memory m
                   JOIN security_analyses s ON s.id=m.analysis_id
                   WHERE s.owner_id=$1 AND m.analysis_id<>$2
                     AND m.admin_verdict IN ('malicious','safe','false_positive')
                     AND EXISTS(SELECT 1 FROM security_memory_audit a WHERE a.memory_id=m.id)
                   ORDER BY reviewed_at DESC LIMIT 100""",
                owner_id,
                current_analysis_id,
            )
            campaign_rows = await connection.fetch(
                """SELECT c.record FROM security_campaigns_v4 c
                   WHERE c.reviewer_status='confirmed'
                     AND NOT EXISTS(
                       SELECT 1 FROM security_campaign_members_v4 self_member
                       WHERE self_member.campaign_id=c.id AND self_member.analysis_id=$2
                     )
                     AND EXISTS(SELECT 1 FROM security_campaign_members_v4 member WHERE member.campaign_id=c.id)
                     AND NOT EXISTS(
                       SELECT 1 FROM security_campaign_members_v4 member
                       JOIN security_analyses analysis ON analysis.id=member.analysis_id
                       WHERE member.campaign_id=c.id AND analysis.owner_id<>$1
                     )
                   ORDER BY c.reviewed_at DESC LIMIT 100""",
                owner_id,
                current_analysis_id,
            )
        memories = [
            (SecurityMemoryRecordV4.model_validate(_json_value(row["record"])), row["reviewed_at"])
            for row in memory_rows
        ]
        campaigns = [SecurityCampaignRecordV4.model_validate(_json_value(row["record"])) for row in campaign_rows]
        return memories, campaigns

    async def correct_security_memory(
        self,
        memory_id: UUID,
        verdict: SecurityMemoryAdminVerdictV4,
        note: str,
        reviewer_id: str,
        occurred_at: datetime,
    ) -> SecurityMemoryRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow("SELECT record FROM security_memory WHERE id=$1 FOR UPDATE", memory_id)
            if row is None:
                return None
            current = SecurityMemoryRecordV4.model_validate(_json_value(row["record"]))
            updated = current.model_copy(update={"admin_verdict": verdict})
            audit = SecurityMemoryAuditRecordV4(
                memory_id=memory_id,
                previous_verdict=current.admin_verdict,
                verdict=verdict,
                reviewer_id=reviewer_id,
                note=note,
                occurred_at=occurred_at,
                risk_policy_version=current.risk_policy_version,
                fingerprint_version=current.fingerprint_version,
                evidence_refs=current.evidence_refs,
            )
            await connection.execute(
                "UPDATE security_memory SET record=$2::jsonb,admin_verdict=$3 WHERE id=$1",
                memory_id,
                updated.model_dump_json(),
                verdict.value,
            )
            await connection.execute(
                "INSERT INTO security_memory_audit(id,memory_id,record,occurred_at) VALUES($1,$2,$3::jsonb,$4)",
                audit.audit_id,
                memory_id,
                audit.model_dump_json(),
                occurred_at,
            )
        return updated

    async def list_security_memory_audit(self, memory_id: UUID) -> list[SecurityMemoryAuditRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT record FROM security_memory_audit WHERE memory_id=$1 ORDER BY occurred_at", memory_id
            )
        return [SecurityMemoryAuditRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def upsert_security_campaign(self, record: SecurityCampaignRecordV4) -> SecurityCampaignRecordV4:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """INSERT INTO security_campaigns_v4(
                       id,record,reviewer_status,window_started_at,window_ended_at,
                       clustering_version,created_at
                   ) VALUES($1,$2::jsonb,$3,$4,$5,$6,$7)
                   ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id RETURNING record""",
                record.campaign_id,
                record.model_dump_json(),
                record.reviewer_status.value,
                record.window_started_at,
                record.window_ended_at,
                record.clustering_version,
                record.created_at,
            )
            for analysis_id in record.analysis_ids:
                await connection.execute(
                    """INSERT INTO security_campaign_members_v4(campaign_id,analysis_id)
                       VALUES($1,$2) ON CONFLICT DO NOTHING""",
                    record.campaign_id,
                    analysis_id,
                )
        return SecurityCampaignRecordV4.model_validate(_json_value(row["record"]))

    async def list_security_campaigns(self) -> list[SecurityCampaignRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT record FROM security_campaigns_v4 ORDER BY window_ended_at DESC")
        return [SecurityCampaignRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def get_security_campaign(self, campaign_id: UUID) -> SecurityCampaignRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow("SELECT record FROM security_campaigns_v4 WHERE id=$1", campaign_id)
        return SecurityCampaignRecordV4.model_validate(_json_value(row["record"])) if row else None

    async def review_security_campaign(
        self,
        campaign_id: UUID,
        status: SecurityCampaignReviewerStatusV4,
        note: str,
        reviewer_id: str,
        occurred_at: datetime,
    ) -> SecurityCampaignRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT record,reviewer_status FROM security_campaigns_v4 WHERE id=$1 FOR UPDATE",
                campaign_id,
            )
            if row is None:
                return None
            if row["reviewer_status"] != SecurityCampaignReviewerStatusV4.PENDING_REVIEW.value:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security campaign was already reviewed.",
                    retryable=False,
                )
            current = SecurityCampaignRecordV4.model_validate(_json_value(row["record"]))
            updated = current.model_copy(
                update={
                    "reviewer_status": status,
                    "reviewer_id": reviewer_id,
                    "review_note": note,
                    "reviewed_at": occurred_at,
                }
            )
            audit = SecurityCampaignAuditRecordV4(
                campaign_id=campaign_id,
                previous_status=current.reviewer_status,
                status=status,
                reviewer_id=reviewer_id,
                note=note,
                occurred_at=occurred_at,
                clustering_version=current.clustering_version,
                evidence_refs=current.evidence_refs,
            )
            await connection.execute(
                """UPDATE security_campaigns_v4 SET record=$2::jsonb,reviewer_status=$3,
                       reviewer_id=$4,review_note=$5,reviewed_at=$6 WHERE id=$1""",
                campaign_id,
                updated.model_dump_json(),
                status.value,
                reviewer_id,
                note,
                occurred_at,
            )
            await connection.execute(
                """INSERT INTO security_campaign_audit(id,campaign_id,record,occurred_at)
                   VALUES($1,$2,$3::jsonb,$4)""",
                audit.audit_id,
                campaign_id,
                audit.model_dump_json(),
                occurred_at,
            )
        return updated

    async def list_security_campaign_audit(self, campaign_id: UUID) -> list[SecurityCampaignAuditRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT record FROM security_campaign_audit WHERE campaign_id=$1 ORDER BY occurred_at",
                campaign_id,
            )
        return [SecurityCampaignAuditRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def save_security_report(self, owner_id: str, record: SecurityReportRecordV4) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_analysis_reports_v4(
                       id,analysis_id,owner_id,status,record,created_at
                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                record.report_id,
                record.analysis_id,
                owner_id,
                record.status.value,
                record.model_dump_json(),
                record.created_at,
            )
            row = await connection.fetchrow(
                "SELECT id,record FROM security_memory WHERE analysis_id=$1 FOR UPDATE", record.analysis_id
            )
            if row is not None:
                memory = SecurityMemoryRecordV4.model_validate(_json_value(row["record"]))
                updated = memory.model_copy(update={"report_count": memory.report_count + 1})
                await connection.execute(
                    "UPDATE security_memory SET record=$2::jsonb,report_count=$3 WHERE id=$1",
                    row["id"],
                    updated.model_dump_json(),
                    updated.report_count,
                )

    async def list_security_reports(self, analysis_id: str, owner_id: str) -> list[SecurityReportRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT record FROM security_analysis_reports_v4
                   WHERE analysis_id=$1 AND owner_id=$2 ORDER BY created_at""",
                UUID(analysis_id),
                owner_id,
            )
        return [SecurityReportRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def list_security_reports_admin(self, status: str | None = None) -> list[SecurityReportAdminRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT owner_id,record FROM security_analysis_reports_v4
                   WHERE ($1::text IS NULL OR status=$1) ORDER BY created_at DESC""",
                status,
            )
        return [
            SecurityReportAdminRecordV4(
                **SecurityReportRecordV4.model_validate(_json_value(row["record"])).model_dump(),
                owner_id=row["owner_id"],
            )
            for row in rows
        ]

    async def decide_security_report(
        self,
        report_id: UUID,
        request: SecurityReportDecisionRequestV4,
        reviewer_id: str,
        occurred_at: datetime,
    ) -> SecurityReportAdminRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT owner_id,status,record FROM security_analysis_reports_v4 WHERE id=$1 FOR UPDATE",
                report_id,
            )
            if row is None:
                return None
            if row["status"] == ReportStatus.PROCESSED.value:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security report was already processed.",
                    retryable=False,
                )
            current = SecurityReportRecordV4.model_validate(_json_value(row["record"]))
            updated = SecurityReportRecordV4.model_validate(
                {
                    **current.model_dump(),
                    "status": ReportStatus.PROCESSED,
                    "decision": request.decision,
                    "resolution": request.resolution,
                    "remediation_action": request.remediation_action,
                    "whitelist_entry": request.whitelist_entry,
                    "blacklist_proposal": request.blacklist_proposal,
                    "remediation_status": (
                        SecurityReportRemediationStatusV4.NOT_REQUESTED
                        if request.remediation_action is SecurityReportRemediationActionV4.NONE
                        else SecurityReportRemediationStatusV4.PENDING
                    ),
                    "reviewer_id": reviewer_id,
                    "review_note": request.note,
                    "reviewed_at": occurred_at,
                }
            )
            audit = SecurityAdminAuditEventV4(
                resource_type=SecurityAuditResourceV4.REPORT,
                resource_id=report_id,
                action=f"report_{request.decision.value}",
                actor_id=reviewer_id,
                note=request.note,
                occurred_at=occurred_at,
                evidence_refs=request.audit_evidence_refs(),
                report_details=SecurityReportAuditDetailsV4.from_record(updated),
            )
            await connection.execute(
                "UPDATE security_analysis_reports_v4 SET status=$2,record=$3::jsonb WHERE id=$1",
                report_id,
                updated.status.value,
                updated.model_dump_json(),
            )
            await self._insert_security_feedback_audit(connection, audit)
        return SecurityReportAdminRecordV4(**updated.model_dump(), owner_id=row["owner_id"])

    async def complete_security_report_remediation(
        self,
        report_id: UUID,
        request: SecurityReportRemediationUpdateV4,
        actor_id: str,
        occurred_at: datetime,
    ) -> SecurityReportAdminRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT owner_id,record FROM security_analysis_reports_v4 WHERE id=$1 FOR UPDATE",
                report_id,
            )
            if row is None:
                return None
            current = SecurityReportRecordV4.model_validate(_json_value(row["record"]))
            if current.remediation_status is not SecurityReportRemediationStatusV4.PENDING:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security report remediation is not pending.",
                    retryable=False,
                )
            updated = SecurityReportRecordV4.model_validate(
                {
                    **current.model_dump(),
                    "remediation_status": request.status,
                    "remediation_reference": request.reference,
                }
            )
            audit = SecurityAdminAuditEventV4(
                resource_type=SecurityAuditResourceV4.REPORT,
                resource_id=report_id,
                action=f"report_remediation_{request.status.value}",
                actor_id=actor_id,
                note=request.note,
                occurred_at=occurred_at,
                evidence_refs=request.evidence_refs,
                report_details=SecurityReportAuditDetailsV4.from_record(updated),
            )
            await connection.execute(
                "UPDATE security_analysis_reports_v4 SET record=$2::jsonb WHERE id=$1",
                report_id,
                updated.model_dump_json(),
            )
            await self._insert_security_feedback_audit(connection, audit)
        return SecurityReportAdminRecordV4(**updated.model_dump(), owner_id=row["owner_id"])

    async def link_security_report_remediation(
        self,
        report_id: UUID,
        reference: SecurityReportRemediationReferenceV4,
        note: str,
        evidence_refs: list[str],
        actor_id: str,
        occurred_at: datetime,
    ) -> SecurityReportAdminRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT owner_id,record FROM security_analysis_reports_v4 WHERE id=$1 FOR UPDATE",
                report_id,
            )
            if row is None:
                return None
            current = SecurityReportRecordV4.model_validate(_json_value(row["record"]))
            if current.remediation_status is not SecurityReportRemediationStatusV4.PENDING:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security report remediation is not pending.",
                    retryable=False,
                )
            updated = SecurityReportRecordV4.model_validate(
                {**current.model_dump(), "remediation_reference": reference}
            )
            audit = SecurityAdminAuditEventV4(
                resource_type=SecurityAuditResourceV4.REPORT,
                resource_id=report_id,
                action="report_remediation_proposed",
                actor_id=actor_id,
                note=note,
                occurred_at=occurred_at,
                evidence_refs=evidence_refs,
                report_details=SecurityReportAuditDetailsV4.from_record(updated),
            )
            await connection.execute(
                "UPDATE security_analysis_reports_v4 SET record=$2::jsonb WHERE id=$1",
                report_id,
                updated.model_dump_json(),
            )
            await self._insert_security_feedback_audit(connection, audit)
        return SecurityReportAdminRecordV4(**updated.model_dump(), owner_id=row["owner_id"])

    async def save_security_appeal(self, owner_id: str, record: SecurityAppealRecordV4) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """INSERT INTO security_analysis_appeals_v4(
                       id,analysis_id,owner_id,status,record,created_at
                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                record.appeal_id,
                record.analysis_id,
                owner_id,
                record.status.value,
                record.model_dump_json(),
                record.created_at,
            )

    async def list_security_appeals(self, analysis_id: str, owner_id: str) -> list[SecurityAppealRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT record FROM security_analysis_appeals_v4
                   WHERE analysis_id=$1 AND owner_id=$2 ORDER BY created_at""",
                UUID(analysis_id),
                owner_id,
            )
        return [SecurityAppealRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def list_security_appeals_admin(self, status: str | None = None) -> list[SecurityAppealAdminRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT owner_id,record FROM security_analysis_appeals_v4
                   WHERE ($1::text IS NULL OR status=$1) ORDER BY created_at DESC""",
                status,
            )
        return [
            SecurityAppealAdminRecordV4(
                **SecurityAppealRecordV4.model_validate(_json_value(row["record"])).model_dump(),
                owner_id=row["owner_id"],
            )
            for row in rows
        ]

    async def decide_security_appeal(
        self,
        appeal_id: UUID,
        outcome: AppealOutcome,
        note: str,
        reviewer_id: str,
        occurred_at: datetime,
    ) -> SecurityAppealAdminRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT owner_id,status,record FROM security_analysis_appeals_v4 WHERE id=$1 FOR UPDATE",
                appeal_id,
            )
            if row is None:
                return None
            if row["status"] == AppealStatus.RESOLVED.value:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security appeal was already resolved.",
                    retryable=False,
                )
            current = SecurityAppealRecordV4.model_validate(_json_value(row["record"]))
            updated = current.model_copy(
                update={
                    "status": AppealStatus.RESOLVED,
                    "outcome": outcome,
                    "resolution_note": note,
                    "reviewer_id": reviewer_id,
                    "resolved_at": occurred_at,
                }
            )
            audit = SecurityAdminAuditEventV4(
                resource_type=SecurityAuditResourceV4.APPEAL,
                resource_id=appeal_id,
                action=f"appeal_{outcome.value}",
                actor_id=reviewer_id,
                note=note,
                occurred_at=occurred_at,
            )
            await connection.execute(
                "UPDATE security_analysis_appeals_v4 SET status=$2,record=$3::jsonb WHERE id=$1",
                appeal_id,
                updated.status.value,
                updated.model_dump_json(),
            )
            await self._insert_security_feedback_audit(connection, audit)
        return SecurityAppealAdminRecordV4(**updated.model_dump(), owner_id=row["owner_id"])

    async def _insert_security_feedback_audit(self, connection, audit: SecurityAdminAuditEventV4) -> None:
        await connection.execute(
            """INSERT INTO security_feedback_audit_v4(
                   id,resource_type,resource_id,action,actor_id,note,evidence_refs,details,occurred_at
               ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)""",
            audit.audit_id,
            audit.resource_type.value,
            audit.resource_id,
            audit.action,
            audit.actor_id,
            audit.note,
            json.dumps(audit.evidence_refs),
            audit.report_details.model_dump_json() if audit.report_details is not None else "{}",
            audit.occurred_at,
        )

    async def list_security_admin_audit(self) -> list[SecurityAdminAuditEventV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            feedback = await connection.fetch(
                """SELECT id,resource_type,resource_id,action,actor_id,note,evidence_refs,occurred_at,details
                   FROM security_feedback_audit_v4"""
            )
            trust = await connection.fetch(
                """SELECT id,resource_type,resource_id,action,reviewer_id AS actor_id,
                          NULL::text AS note,'[]'::jsonb AS evidence_refs,occurred_at,'{}'::jsonb AS details
                   FROM security_trust_audit"""
            )
            memory = await connection.fetch("SELECT record FROM security_memory_audit")
            campaigns = await connection.fetch("SELECT record FROM security_campaign_audit")
        events = [
            SecurityAdminAuditEventV4(
                audit_id=row["id"],
                resource_type=SecurityAuditResourceV4(row["resource_type"]),
                resource_id=row["resource_id"],
                action=row["action"],
                actor_id=row["actor_id"],
                note=row["note"],
                evidence_refs=list(_json_value(row["evidence_refs"])),
                occurred_at=row["occurred_at"],
                report_details=(
                    SecurityReportAuditDetailsV4.model_validate(_json_value(row["details"]))
                    if _json_value(row["details"])
                    else None
                ),
            )
            for row in [*feedback, *trust]
        ]
        for row in memory:
            item = SecurityMemoryAuditRecordV4.model_validate(_json_value(row["record"]))
            events.append(
                SecurityAdminAuditEventV4(
                    audit_id=item.audit_id,
                    resource_type=SecurityAuditResourceV4.MEMORY,
                    resource_id=item.memory_id,
                    action=f"memory_{item.verdict.value}",
                    actor_id=item.reviewer_id,
                    note=item.note,
                    occurred_at=item.occurred_at,
                    evidence_refs=item.evidence_refs,
                )
            )
        for row in campaigns:
            item = SecurityCampaignAuditRecordV4.model_validate(_json_value(row["record"]))
            events.append(
                SecurityAdminAuditEventV4(
                    audit_id=item.audit_id,
                    resource_type=SecurityAuditResourceV4.CAMPAIGN,
                    resource_id=item.campaign_id,
                    action=f"campaign_{item.status.value}",
                    actor_id=item.reviewer_id,
                    note=item.note,
                    occurred_at=item.occurred_at,
                    evidence_refs=item.evidence_refs,
                )
            )
        return sorted(events, key=lambda item: item.occurred_at, reverse=True)


__all__ = ["PostgresFeedbackRepositoryMixin"]
