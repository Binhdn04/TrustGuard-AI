from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST, normalize_hostname
from src.core.errors import PlatformError
from src.models import (
    AdminActionAuditRecordV3,
    AdminActionDecisionResponseV3,
    AdminActionRecordV3,
    AdminActionStatus,
    AnalysisCreateRequest,
    AnalysisCreateRequestV3,
    AnalysisEvent,
    AnalysisReportRecord,
    AnalysisReportResponse,
    AnalysisResponse,
    AppealAdminRecordV3,
    AppealCreateRequestV3,
    AppealDecisionRequestV3,
    AppealDecisionResponseV3,
    AppealOutcome,
    AppealReceiptV3,
    AppealResponseV3,
    AppealStatus,
    BlacklistLookupEntry,
    BrandRecordV4,
    CacheMetricV3,
    CampaignAggregateSignalV3,
    CampaignDetailV3,
    CampaignReviewerStatus,
    CampaignSummaryV3,
    ErrorCode,
    Evidence,
    FeedbackMetricV3,
    IdentityCandidateDecisionV4,
    IdentityCandidateV4,
    LatencyMetricV3,
    MetricsWindowV3,
    OperationsMetricsResponseV3,
    ReportReviewDecision,
    ReportStatus,
    ReviewDecision,
    ReviewedAction,
    ReviewQueueItem,
    RiskDistributionMetricV3,
    RiskLevel,
    SecurityAdminAuditEventV4,
    SecurityAdminCopilotResponseV4,
    SecurityAnalysisEventV4,
    SecurityAppealAdminRecordV4,
    SecurityAppealRecordV4,
    SecurityAuditResourceV4,
    SecurityCampaignAuditRecordV4,
    SecurityCampaignRecordV4,
    SecurityCampaignReviewerStatusV4,
    SecurityConversationV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryAuditRecordV4,
    SecurityMemoryRecordV4,
    SecurityReportAdminRecordV4,
    SecurityReportRecordV4,
    SecurityScopeResponseV4,
    SecurityTriageCreateRequestV4,
    ToolError,
    TrustLifecycleV4,
    UsageMetricV3,
    WhitelistRecordV4,
)
from src.services.platform_wave2 import (
    CampaignWrite,
    FactCheckCorpusRecordWrite,
    FactCheckResultWrite,
    SourceDiscoveryRecord,
    SourceRegistryEntry,
    SourceTier,
    UsageLedgerEntry,
)


@dataclass(frozen=True, slots=True)
class DurableJob:
    id: UUID
    analysis_id: UUID
    kind: str
    attempt: int
    max_attempts: int
    lease_expires_at: datetime
    idempotency_key: str = ""


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    id: UUID
    aggregate_id: UUID
    event_type: str
    payload: dict[str, Any]
    idempotency_key: str


class PostgresPlatformRepository:
    """PostgreSQL source of truth for Wave 1 analysis/job/event state.

    Redis consumers receive only outbox notifications. Claims and sequence
    allocation always happen in PostgreSQL transactions.
    """

    durable_jobs = True

    def __init__(
        self,
        database_url: str,
        encryption_key: str,
        *,
        pool=None,
        content_retention_days: int = 30,
    ) -> None:
        self._database_url = database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
        self._encryption_key = encryption_key
        self._pool = pool
        self._owns_pool = pool is None
        self._content_retention_days = content_retention_days
        self._active_job: ContextVar[tuple[UUID, str] | None] = ContextVar("active_analysis_job", default=None)

    @contextmanager
    def job_scope(self, job_id: UUID, worker_id: str):
        """Bind terminal persistence to the currently claimed durable job."""
        token = self._active_job.set((job_id, worker_id))
        try:
            yield
        finally:
            self._active_job.reset(token)

    async def _get_pool(self):
        if self._pool is None:
            try:
                import asyncpg
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError("asyncpg is required for PostgreSQL runtime") from exc
            self._pool = await asyncpg.create_pool(self._database_url, min_size=1, max_size=10)
        return self._pool

    async def create_analysis(
        self,
        *,
        owner_id: str,
        request: AnalysisCreateRequest,
        response: AnalysisResponse,
        event: AnalysisEvent,
    ) -> None:
        pool = await self._get_pool()
        analysis_id = response.analysis_id
        event_id = uuid4()
        job_id = uuid4()
        outbox_id = uuid4()
        request_json = request.model_dump_json()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO analyses(
                       id, owner_id, input_ciphertext, input_hash, consent, status,
                       response, created_at, updated_at, content_expires_at
                   ) VALUES ($1, $2, pgp_sym_encrypt($3, $4), $5, $6, $7, $8::jsonb, $9, $9, $10)""",
                analysis_id,
                owner_id,
                request_json,
                self._encryption_key,
                hashlib.sha256(request_json.encode()).hexdigest(),
                request.consent_to_scan_urls,
                response.status.value,
                response.model_dump_json(),
                response.created_at,
                response.created_at + timedelta(days=self._content_retention_days),
            )
            await connection.execute(
                """INSERT INTO analysis_events(
                       event_id, analysis_id, sequence, event_type, payload, occurred_at
                   ) VALUES ($1, $2, 1, 'analysis_status', $3::jsonb, $4)""",
                event_id,
                analysis_id,
                event.model_dump_json(),
                event.occurred_at,
            )
            await connection.execute(
                """INSERT INTO analysis_jobs(
                       id, analysis_id, kind, status, max_attempts, available_at,
                       idempotency_key, created_at, updated_at
                   ) VALUES ($1, $2, 'analyze', 'queued', 3, $3, $4, $3, $3)""",
                job_id,
                analysis_id,
                event.occurred_at,
                f"analysis:{analysis_id}:analyze:v1",
            )
            await connection.execute(
                """INSERT INTO outbox(
                       id, aggregate_type, aggregate_id, event_type, payload,
                       idempotency_key, created_at
                   ) VALUES ($1, 'analysis', $2, 'analysis.queued', $3::jsonb, $4, $5)""",
                outbox_id,
                analysis_id,
                json.dumps({"analysis_id": str(analysis_id), "job_id": str(job_id)}),
                f"analysis:{analysis_id}:queued:v1",
                event.occurred_at,
            )

    async def create_brand(self, record: BrandRecordV4, *, audit_action: str = "created") -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_brands(
                       id,name,aliases,official_domains,official_contacts,provenance,policy_version,
                       lifecycle,effective_from,effective_until,reviewer_id,created_at,record
                   ) VALUES($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)""",
                record.brand_id,
                record.name,
                json.dumps(record.aliases),
                json.dumps(record.official_domains),
                json.dumps(record.official_contacts),
                record.provenance,
                record.policy_version,
                record.lifecycle.value,
                record.effective_from,
                record.effective_until,
                record.reviewer_id,
                record.created_at,
                record.model_dump_json(),
            )
            await self._insert_trust_audit(
                connection,
                "brand",
                record.brand_id,
                audit_action,
                record.reviewer_id,
                record.created_at,
            )

    async def list_brands(self) -> list[BrandRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT record FROM security_brands ORDER BY created_at")
        return [BrandRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]:
        effective = [
            item
            for item in await self.list_brands()
            if item.effective_from <= at and (item.effective_until is None or at < item.effective_until)
        ]
        superseded = {item.supersedes for item in effective if item.supersedes is not None}
        return [
            item for item in effective if item.lifecycle is TrustLifecycleV4.ACTIVE and item.brand_id not in superseded
        ]

    async def save_identity_candidate(self, record: IdentityCandidateV4) -> IdentityCandidateV4:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            previous = await connection.fetchrow(
                """SELECT id,version FROM security_identity_candidates
                   WHERE entity_name=$1 AND canonical_domain=$2 AND relationship=$3
                   ORDER BY version DESC LIMIT 1 FOR UPDATE""",
                record.entity_name,
                record.canonical_domain,
                record.relationship.value,
            )
            version = max(record.version, (previous["version"] if previous else 0) + 1)
            stored = record.model_copy(
                update={"version": version, "supersedes": previous["id"] if previous else record.supersedes}
            )
            await connection.execute(
                """INSERT INTO security_identity_candidates(
                       id,entity_name,canonical_url,canonical_domain,relationship,assurance,
                       confidence,version,expires_at,terminal_decision_id,record,created_at
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)""",
                stored.association_id,
                stored.entity_name,
                stored.canonical_url,
                stored.canonical_domain,
                stored.relationship.value,
                stored.assurance.value,
                stored.confidence,
                stored.version,
                stored.expires_at,
                stored.terminal_decision_id,
                stored.model_dump_json(),
                stored.discovered_at,
            )
            for observation in stored.observations:
                await connection.execute(
                    """INSERT INTO security_identity_evidence(
                           evidence_ref,candidate_id,source_host,family,canonical_url,content_hash,
                           observation,observed_at
                       ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8) ON CONFLICT DO NOTHING""",
                    observation.evidence_ref,
                    stored.association_id,
                    observation.source_host,
                    observation.family.value,
                    observation.canonical_url,
                    observation.content_hash,
                    observation.model_dump_json(),
                    observation.observed_at,
                )
        return stored

    async def list_identity_candidates(self) -> list[IdentityCandidateV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT record FROM security_identity_candidates ORDER BY created_at DESC")
        return [IdentityCandidateV4.model_validate(_json_value(row["record"])) for row in rows]

    async def create_identity_decision(
        self, decision: IdentityCandidateDecisionV4, updated: IdentityCandidateV4
    ) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT terminal_decision_id FROM security_identity_candidates WHERE id=$1 FOR UPDATE",
                decision.candidate_id,
            )
            if row is None:
                raise LookupError("identity candidate not found")
            if row["terminal_decision_id"] is not None:
                raise ValueError("identity candidate already has a terminal decision")
            await connection.execute(
                """INSERT INTO security_identity_decisions(
                       id,candidate_id,action,reviewer_id,note,target_brand_id,relationship,
                       identity_type,evidence_refs,decision,decided_at
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11)""",
                decision.decision_id,
                decision.candidate_id,
                decision.action.value,
                decision.reviewer_id,
                decision.note,
                decision.target_brand_id,
                decision.relationship.value if decision.relationship else None,
                decision.identity_type.value if decision.identity_type else None,
                json.dumps(decision.evidence_refs),
                decision.model_dump_json(),
                decision.decided_at,
            )
            await connection.execute(
                """UPDATE security_identity_candidates
                   SET assurance=$1,terminal_decision_id=$2,record=$3::jsonb WHERE id=$4""",
                updated.assurance.value,
                decision.decision_id,
                updated.model_dump_json(),
                updated.association_id,
            )
            await self._insert_trust_audit(
                connection,
                "identity_candidate",
                updated.association_id,
                decision.action.value,
                decision.reviewer_id,
                decision.decided_at,
            )

    async def disable_brand(self, brand_id: str, reviewer_id: str, at: datetime) -> BrandRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow("SELECT record FROM security_brands WHERE id=$1 FOR UPDATE", UUID(brand_id))
            if row is None:
                return None
            already_superseded = await connection.fetchval(
                "SELECT EXISTS(SELECT 1 FROM security_brands WHERE record->>'supersedes'=$1)",
                brand_id,
            )
            if already_superseded:
                return None
            previous = BrandRecordV4.model_validate(_json_value(row["record"]))
            record = BrandRecordV4.model_validate(
                {
                    **previous.model_dump(),
                    "brand_id": uuid4(),
                    "supersedes": previous.brand_id,
                    "lifecycle": TrustLifecycleV4.DISABLED,
                    "effective_from": at,
                    "effective_until": None,
                    "reviewer_id": reviewer_id,
                    "created_at": at,
                }
            )
            await connection.execute(
                """INSERT INTO security_brands(
                       id,name,aliases,official_domains,official_contacts,provenance,policy_version,
                       lifecycle,effective_from,effective_until,reviewer_id,created_at,record
                   ) VALUES($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)""",
                record.brand_id,
                record.name,
                json.dumps(record.aliases),
                json.dumps(record.official_domains),
                json.dumps(record.official_contacts),
                record.provenance,
                record.policy_version,
                record.lifecycle.value,
                record.effective_from,
                record.effective_until,
                record.reviewer_id,
                record.created_at,
                record.model_dump_json(),
            )
            await self._insert_trust_audit(
                connection,
                "brand",
                record.brand_id,
                "disabled",
                reviewer_id,
                at,
            )
        return record

    async def create_whitelist(self, record: WhitelistRecordV4) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_whitelist(
                       id,scope,indicator,provenance,policy_version,lifecycle,effective_from,
                       effective_until,reviewer_id,created_at,record
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)""",
                record.whitelist_id,
                record.scope.value,
                record.indicator,
                record.provenance,
                record.policy_version,
                record.lifecycle.value,
                record.effective_from,
                record.effective_until,
                record.reviewer_id,
                record.created_at,
                record.model_dump_json(),
            )
            await self._insert_trust_audit(
                connection, "whitelist", record.whitelist_id, "created", record.reviewer_id, record.created_at
            )

    async def list_whitelist(self) -> list[WhitelistRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT record FROM security_whitelist ORDER BY created_at")
        return [WhitelistRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def list_active_whitelist(self, at: datetime) -> list[WhitelistRecordV4]:
        return [
            item
            for item in await self.list_whitelist()
            if item.lifecycle is TrustLifecycleV4.ACTIVE
            and item.effective_from <= at
            and (item.effective_until is None or at < item.effective_until)
        ]

    async def disable_whitelist(self, whitelist_id: str, reviewer_id: str, at: datetime) -> WhitelistRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT record FROM security_whitelist WHERE id=$1 FOR UPDATE", UUID(whitelist_id)
            )
            if row is None:
                return None
            record = WhitelistRecordV4.model_validate(_json_value(row["record"])).model_copy(
                update={"lifecycle": TrustLifecycleV4.DISABLED, "reviewer_id": reviewer_id}
            )
            await connection.execute(
                "UPDATE security_whitelist SET lifecycle='disabled', reviewer_id=$2, record=$3::jsonb WHERE id=$1",
                UUID(whitelist_id),
                reviewer_id,
                record.model_dump_json(),
            )
            await self._insert_trust_audit(connection, "whitelist", UUID(whitelist_id), "disabled", reviewer_id, at)
        return record

    async def _insert_trust_audit(
        self, connection, resource_type: str, resource_id: UUID, action: str, reviewer_id: str, at: datetime
    ) -> None:
        await connection.execute(
            """INSERT INTO security_trust_audit(
                   id,resource_type,resource_id,action,reviewer_id,occurred_at
               ) VALUES($1,$2,$3,$4,$5,$6)""",
            uuid4(),
            resource_type,
            resource_id,
            action,
            reviewer_id,
            at,
        )

    async def save_security_analysis(
        self,
        owner_id: str,
        response: SecurityScopeResponseV4,
        events: list[SecurityAnalysisEventV4],
    ) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_analyses(
                       id, owner_id, status, response, policy_version, created_at, updated_at,
                       completed_at, conversation_id
                   ) VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$7,$8)
                   ON CONFLICT(id) DO UPDATE SET status=excluded.status, response=excluded.response,
                       policy_version=excluded.policy_version, updated_at=excluded.updated_at,
                       completed_at=excluded.completed_at, conversation_id=excluded.conversation_id""",
                response.analysis_id,
                owner_id,
                response.status.value,
                response.model_dump_json(),
                response.policy_version,
                response.created_at,
                response.completed_at,
                response.conversation_id,
            )
            for event in events:
                await connection.execute(
                    """INSERT INTO security_analysis_events(
                           event_id, analysis_id, sequence, event_type, payload, occurred_at
                       ) VALUES($1,$2,$3,$4,$5::jsonb,$6)
                       ON CONFLICT(analysis_id, sequence) DO NOTHING""",
                    event.event_id,
                    response.analysis_id,
                    event.sequence,
                    event.step,
                    event.model_dump_json(),
                    event.occurred_at,
                )
            await connection.execute(
                """INSERT INTO outbox(
                       id, aggregate_type, aggregate_id, event_type, payload, idempotency_key, created_at
                   ) VALUES($1,'security_analysis',$2,'security_analysis.completed',$3::jsonb,$4,$5)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                response.analysis_id,
                json.dumps({"analysis_id": str(response.analysis_id)}),
                f"security-analysis:{response.analysis_id}:completed:v1",
                response.completed_at,
            )

    async def enqueue_security_analysis(
        self,
        *,
        owner_id: str,
        request: SecurityTriageCreateRequestV4,
        response: SecurityScopeResponseV4,
        conversation: SecurityConversationV4,
        expected_version: int | None,
        idempotency_key: str,
        payload_hash: str,
        events: list[SecurityAnalysisEventV4],
    ) -> SecurityScopeResponseV4:
        """Atomically reserve a conversation turn and enqueue encrypted v4 work."""
        pool = await self._get_pool()
        now = response.created_at
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",
                owner_id,
                idempotency_key,
            )
            existing = await connection.fetchrow(
                """SELECT i.payload_hash,a.response FROM security_analysis_idempotency_v4 i
                   JOIN security_analyses a ON a.id=i.analysis_id
                   WHERE i.owner_id=$1 AND i.idempotency_key=$2""",
                owner_id,
                idempotency_key,
            )
            if existing is not None:
                if existing["payload_hash"] != payload_hash:
                    raise PlatformError(
                        status_code=409,
                        code=ErrorCode.CONFLICT,
                        message="Idempotency-Key was already used with a different Security v4 turn.",
                        retryable=False,
                    )
                return SecurityScopeResponseV4.model_validate(_json_value(existing["response"]))

            await connection.execute(
                """INSERT INTO security_analyses(
                       id,owner_id,status,response,policy_version,created_at,updated_at,completed_at,conversation_id
                   ) VALUES($1,$2,'queued',$3::jsonb,NULL,$4,$4,NULL,$5)""",
                response.analysis_id,
                owner_id,
                response.model_dump_json(),
                now,
                response.conversation_id,
            )
            if expected_version is None:
                reserved = await connection.execute(
                    """INSERT INTO security_conversations(
                           id,owner_id,status,active_analysis_id,context_version,summary,
                           created_at,updated_at,expires_at
                       ) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
                       ON CONFLICT(id) DO NOTHING""",
                    conversation.conversation_id,
                    owner_id,
                    conversation.status.value,
                    conversation.active_analysis_id,
                    conversation.context_version,
                    conversation.model_dump_json(),
                    conversation.created_at,
                    conversation.updated_at,
                    conversation.expires_at,
                )
                updated = reserved.endswith("1")
            else:
                reserved = await connection.fetchrow(
                    """UPDATE security_conversations SET status=$3,active_analysis_id=$4,
                           context_version=$5,summary=$6::jsonb,updated_at=$7,expires_at=$8
                       WHERE id=$1 AND owner_id=$2 AND context_version=$9 RETURNING id""",
                    conversation.conversation_id,
                    owner_id,
                    conversation.status.value,
                    conversation.active_analysis_id,
                    conversation.context_version,
                    conversation.model_dump_json(),
                    conversation.updated_at,
                    conversation.expires_at,
                    expected_version,
                )
                updated = reserved is not None
            if not updated:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security conversation was updated by another turn.",
                    retryable=True,
                )
            await connection.execute(
                """INSERT INTO security_conversation_turns(
                       conversation_id,context_version,analysis_id,created_at
                   ) VALUES($1,$2,$3,$4)""",
                conversation.conversation_id,
                conversation.context_version,
                conversation.active_analysis_id,
                conversation.updated_at,
            )
            await connection.execute(
                """INSERT INTO security_analysis_payloads_v4(
                       analysis_id,payload_ciphertext,context_snapshot,created_at,expires_at
                   ) VALUES($1,pgp_sym_encrypt($2,$3),$4::jsonb,$5,$6)""",
                response.analysis_id,
                request.model_dump_json(),
                self._encryption_key,
                response.model_dump_json(),
                now,
                now + timedelta(hours=24),
            )
            await connection.execute(
                """INSERT INTO security_analysis_jobs_v4(
                       id,analysis_id,status,max_attempts,available_at,created_at,updated_at
                   ) VALUES($1,$2,'queued',3,$3,$3,$3)""",
                uuid4(),
                response.analysis_id,
                now,
            )
            await connection.execute(
                """INSERT INTO security_analysis_idempotency_v4(
                       owner_id,idempotency_key,payload_hash,analysis_id,created_at
                   ) VALUES($1,$2,$3,$4,$5)""",
                owner_id,
                idempotency_key,
                payload_hash,
                response.analysis_id,
                now,
            )
            for event in events:
                await connection.execute(
                    """INSERT INTO security_analysis_events(
                           event_id,analysis_id,sequence,event_type,payload,occurred_at
                       ) VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                    event.event_id,
                    event.analysis_id,
                    event.sequence,
                    event.kind.value,
                    event.model_dump_json(),
                    event.occurred_at,
                )
                await connection.execute(
                    """INSERT INTO security_analysis_outbox_v4(
                           id,analysis_id,event_type,payload,idempotency_key,created_at
                       ) VALUES($1,$2,$3,$4::jsonb,$5,$6)""",
                    uuid4(),
                    response.analysis_id,
                    f"security_analysis.{event.kind.value}",
                    event.model_dump_json(),
                    f"security-v4-event:{response.analysis_id}:{event.sequence}",
                    event.occurred_at,
                )
        return response

    async def load_security_idempotent(
        self,
        owner_id: str,
        idempotency_key: str,
        payload_hash: str,
    ) -> SecurityScopeResponseV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT i.payload_hash,a.response FROM security_analysis_idempotency_v4 i
                   JOIN security_analyses a ON a.id=i.analysis_id
                   WHERE i.owner_id=$1 AND i.idempotency_key=$2""",
                owner_id,
                idempotency_key,
            )
        if row is None:
            return None
        if row["payload_hash"] != payload_hash:
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONFLICT,
                message="Idempotency-Key was already used with a different Security v4 turn.",
                retryable=False,
            )
        return SecurityScopeResponseV4.model_validate(_json_value(row["response"]))

    async def load_security_job_payload(
        self,
        job: DurableJob,
        worker_id: str,
    ) -> tuple[str, SecurityTriageCreateRequestV4, SecurityScopeResponseV4] | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT a.owner_id,p.context_snapshot,
                          pgp_sym_decrypt(p.payload_ciphertext,$3) AS request_json
                   FROM security_analysis_jobs_v4 j
                   JOIN security_analysis_payloads_v4 p ON p.analysis_id=j.analysis_id
                   JOIN security_analyses a ON a.id=j.analysis_id
                   WHERE j.id=$1 AND j.worker_id=$2 AND j.status='running'
                     AND j.lease_expires_at > now()""",
                job.id,
                worker_id,
                self._encryption_key,
            )
        if row is None:
            return None
        return (
            row["owner_id"],
            SecurityTriageCreateRequestV4.model_validate_json(row["request_json"]),
            SecurityScopeResponseV4.model_validate(_json_value(row["context_snapshot"])),
        )

    async def append_security_analysis_event(self, event: SecurityAnalysisEventV4) -> SecurityAnalysisEventV4:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.fetchrow("SELECT id FROM security_analyses WHERE id=$1 FOR UPDATE", event.analysis_id)
            sequence = await connection.fetchval(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM security_analysis_events WHERE analysis_id=$1",
                event.analysis_id,
            )
            event = event.model_copy(update={"sequence": sequence})
            await connection.execute(
                """INSERT INTO security_analysis_events(
                       event_id,analysis_id,sequence,event_type,payload,occurred_at
                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                event.event_id,
                event.analysis_id,
                sequence,
                event.kind.value,
                event.model_dump_json(),
                event.occurred_at,
            )
            await connection.execute(
                """INSERT INTO security_analysis_outbox_v4(
                       id,analysis_id,event_type,payload,idempotency_key,created_at
                   ) VALUES($1,$2,$3,$4::jsonb,$5,$6)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                event.analysis_id,
                f"security_analysis.{event.kind.value}",
                event.model_dump_json(),
                f"security-v4-event:{event.analysis_id}:{sequence}",
                event.occurred_at,
            )
        return event

    async def complete_security_analysis_job(
        self,
        job: DurableJob,
        worker_id: str,
        response: SecurityScopeResponseV4,
        final_event: SecurityAnalysisEventV4,
    ) -> SecurityAnalysisEventV4:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            owned = await connection.fetchrow(
                """SELECT id FROM security_analysis_jobs_v4
                   WHERE id=$1 AND worker_id=$2 AND status='running'
                     AND lease_expires_at > now() FOR UPDATE""",
                job.id,
                worker_id,
            )
            if owned is None:
                raise LostJobLeaseError("security v4 job lease was lost before terminal commit")
            await connection.fetchrow("SELECT id FROM security_analyses WHERE id=$1 FOR UPDATE", response.analysis_id)
            sequence = await connection.fetchval(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM security_analysis_events WHERE analysis_id=$1",
                response.analysis_id,
            )
            final_event = final_event.model_copy(update={"sequence": sequence})
            await connection.execute(
                """UPDATE security_analyses SET status=$2,response=$3::jsonb,policy_version=$4,
                          updated_at=$5,completed_at=$5 WHERE id=$1""",
                response.analysis_id,
                response.status.value,
                response.model_dump_json(),
                response.policy_version,
                response.completed_at,
            )
            await connection.execute(
                """INSERT INTO security_analysis_events(
                       event_id,analysis_id,sequence,event_type,payload,occurred_at
                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6)""",
                final_event.event_id,
                final_event.analysis_id,
                sequence,
                final_event.kind.value,
                final_event.model_dump_json(),
                final_event.occurred_at,
            )
            await connection.execute(
                "DELETE FROM security_analysis_payloads_v4 WHERE analysis_id=$1", response.analysis_id
            )
            await connection.execute(
                """UPDATE security_analysis_jobs_v4 SET status='completed',worker_id=NULL,
                          lease_expires_at=NULL,updated_at=$3 WHERE id=$1 AND worker_id=$2""",
                job.id,
                worker_id,
                response.completed_at,
            )
            await connection.execute(
                """INSERT INTO security_analysis_outbox_v4(
                       id,analysis_id,event_type,payload,idempotency_key,created_at
                   ) VALUES($1,$2,'security_analysis.final',$3::jsonb,$4,$5)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                response.analysis_id,
                final_event.model_dump_json(),
                f"security-v4-event:{response.analysis_id}:{sequence}",
                response.completed_at,
            )
        return final_event

    async def save_security_conversation(
        self,
        owner_id: str,
        record: SecurityConversationV4,
        *,
        expected_version: int | None,
    ) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            if expected_version is None:
                status = await connection.execute(
                    """INSERT INTO security_conversations(
                           id,owner_id,status,active_analysis_id,context_version,summary,
                           created_at,updated_at,expires_at
                       ) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
                       ON CONFLICT(id) DO NOTHING""",
                    record.conversation_id,
                    owner_id,
                    record.status.value,
                    record.active_analysis_id,
                    record.context_version,
                    record.model_dump_json(),
                    record.created_at,
                    record.updated_at,
                    record.expires_at,
                )
                updated = status.endswith("1")
            else:
                row = await connection.fetchrow(
                    """UPDATE security_conversations SET status=$3,active_analysis_id=$4,
                           context_version=$5,summary=$6::jsonb,updated_at=$7,expires_at=$8
                       WHERE id=$1 AND owner_id=$2 AND context_version=$9 RETURNING id""",
                    record.conversation_id,
                    owner_id,
                    record.status.value,
                    record.active_analysis_id,
                    record.context_version,
                    record.model_dump_json(),
                    record.updated_at,
                    record.expires_at,
                    expected_version,
                )
                updated = row is not None
            if not updated:
                raise PlatformError(
                    status_code=409,
                    code=ErrorCode.CONFLICT,
                    message="Security conversation was updated by another turn.",
                    retryable=True,
                )
            await connection.execute(
                """INSERT INTO security_conversation_turns(
                       conversation_id,context_version,analysis_id,created_at
                   ) VALUES($1,$2,$3,$4)""",
                record.conversation_id,
                record.context_version,
                record.active_analysis_id,
                record.updated_at,
            )

    async def finalize_security_conversation(self, owner_id: str, record: SecurityConversationV4) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """UPDATE security_conversations SET summary=$3::jsonb,updated_at=$4
                   WHERE id=$1 AND owner_id=$2 AND context_version=$5""",
                record.conversation_id,
                owner_id,
                record.model_dump_json(),
                record.updated_at,
                record.context_version,
            )

    async def load_security_conversation(self, conversation_id: str):
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                "SELECT owner_id,summary FROM security_conversations WHERE id=$1", UUID(conversation_id)
            )
        if row is None:
            return None
        return row["owner_id"], SecurityConversationV4.model_validate(_json_value(row["summary"]))

    async def list_security_conversations(self, owner_id: str) -> list[SecurityConversationV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT summary FROM security_conversations WHERE owner_id=$1 ORDER BY updated_at DESC",
                owner_id,
            )
        return [SecurityConversationV4.model_validate(_json_value(row["summary"])) for row in rows]

    async def expire_security_conversations(self, cutoff: datetime) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            result = await connection.execute("DELETE FROM security_conversations WHERE expires_at <= $1", cutoff)
        return int(result.rsplit(" ", 1)[-1])

    async def load_security_analysis(self, analysis_id: str):
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                "SELECT owner_id, response FROM security_analyses WHERE id=$1", UUID(analysis_id)
            )
            if row is None:
                return None
            events = await connection.fetch(
                "SELECT payload FROM security_analysis_events WHERE analysis_id=$1 ORDER BY sequence",
                UUID(analysis_id),
            )
        return (
            row["owner_id"],
            SecurityScopeResponseV4.model_validate(_json_value(row["response"])),
            [SecurityAnalysisEventV4.model_validate(_json_value(item["payload"])) for item in events],
        )

    async def list_security_analyses(self, owner_id: str) -> list[SecurityScopeResponseV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT response FROM security_analyses WHERE owner_id=$1 ORDER BY created_at DESC",
                owner_id,
            )
        return [SecurityScopeResponseV4.model_validate(_json_value(row["response"])) for row in rows]

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
        decision: ReportReviewDecision,
        note: str,
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
            updated = current.model_copy(
                update={
                    "status": ReportStatus.PROCESSED,
                    "decision": decision,
                    "reviewer_id": reviewer_id,
                    "review_note": note,
                    "reviewed_at": occurred_at,
                }
            )
            audit = SecurityAdminAuditEventV4(
                resource_type=SecurityAuditResourceV4.REPORT,
                resource_id=report_id,
                action=f"report_{decision.value}",
                actor_id=reviewer_id,
                note=note,
                occurred_at=occurred_at,
            )
            await connection.execute(
                "UPDATE security_analysis_reports_v4 SET status=$2,record=$3::jsonb WHERE id=$1",
                report_id,
                updated.status.value,
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
                   id,resource_type,resource_id,action,actor_id,note,evidence_refs,occurred_at
               ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)""",
            audit.audit_id,
            audit.resource_type.value,
            audit.resource_id,
            audit.action,
            audit.actor_id,
            audit.note,
            json.dumps(audit.evidence_refs),
            audit.occurred_at,
        )

    async def list_security_admin_audit(self) -> list[SecurityAdminAuditEventV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            feedback = await connection.fetch(
                """SELECT id,resource_type,resource_id,action,actor_id,note,evidence_refs,occurred_at
                   FROM security_feedback_audit_v4"""
            )
            trust = await connection.fetch(
                """SELECT id,resource_type,resource_id,action,reviewer_id AS actor_id,
                          NULL::text AS note,'[]'::jsonb AS evidence_refs,occurred_at
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

    async def claim_security_tool_execution(self, analysis_id: str, step_id: str, target: str, provider: str) -> bool:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT status, attempt_count FROM security_tool_executions
                   WHERE analysis_id=$1 AND step_id=$2 AND target_ref=$3 AND provider=$4 FOR UPDATE""",
                UUID(analysis_id),
                step_id,
                target,
                provider,
            )
            if row is None:
                await connection.execute(
                    """INSERT INTO security_tool_executions(
                           analysis_id,step_id,target_ref,provider,status,attempt_count,updated_at
                       ) VALUES($1,$2,$3,$4,'running',1,$5)""",
                    UUID(analysis_id),
                    step_id,
                    target,
                    provider,
                    now,
                )
                return True
            if row["status"] != "failed":
                return False
            await connection.execute(
                """UPDATE security_tool_executions SET status='running', attempt_count=$5, updated_at=$6
                   WHERE analysis_id=$1 AND step_id=$2 AND target_ref=$3 AND provider=$4""",
                UUID(analysis_id),
                step_id,
                target,
                provider,
                row["attempt_count"] + 1,
                now,
            )
            return True

    async def finish_security_tool_execution(
        self, analysis_id: str, step_id: str, target: str, provider: str, status: str
    ) -> None:
        if status not in {"completed", "failed", "skipped"}:
            raise ValueError("tool execution status must be terminal")
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            updated = await connection.execute(
                """UPDATE security_tool_executions SET status=$5, updated_at=$6
                   WHERE analysis_id=$1 AND step_id=$2 AND target_ref=$3 AND provider=$4""",
                UUID(analysis_id),
                step_id,
                target,
                provider,
                status,
                datetime.now(UTC),
            )
        if updated != "UPDATE 1":
            raise LookupError("security tool execution was not claimed")

    async def load_analysis(self, analysis_id: str):
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT owner_id, pgp_sym_decrypt(input_ciphertext, $2) AS request_json,
                          response
                   FROM analyses WHERE id = $1""",
                UUID(analysis_id),
                self._encryption_key,
            )
            if row is None:
                return None
            events = await connection.fetch(
                "SELECT payload FROM analysis_events WHERE analysis_id = $1 ORDER BY sequence",
                UUID(analysis_id),
            )
        return (
            row["owner_id"],
            _analysis_request_from_json(row["request_json"]),
            AnalysisResponse.model_validate(_json_value(row["response"])),
            [AnalysisEvent.model_validate(_json_value(item["payload"])) for item in events],
        )

    async def list_analysis_responses(self, *, owner_id=None, case_status=None):
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            if owner_id is not None and case_status is not None:
                rows = await connection.fetch(
                    """SELECT response FROM analyses
                       WHERE owner_id=$1 AND case_status=$2 ORDER BY created_at DESC""",
                    owner_id,
                    case_status,
                )
            elif owner_id is not None:
                rows = await connection.fetch(
                    "SELECT response FROM analyses WHERE owner_id=$1 ORDER BY created_at DESC",
                    owner_id,
                )
            elif case_status is not None:
                rows = await connection.fetch(
                    "SELECT response FROM analyses WHERE case_status=$1 ORDER BY created_at DESC",
                    case_status,
                )
            else:
                rows = await connection.fetch("SELECT response FROM analyses ORDER BY created_at DESC")
        return [AnalysisResponse.model_validate(_json_value(row["response"])) for row in rows]

    async def append_analysis_event(self, event: AnalysisEvent) -> None:
        await self._write_state_event(None, event)

    async def update_analysis(self, response: AnalysisResponse, event: AnalysisEvent) -> None:
        await self._write_state_event(response, event)

    async def complete_analysis(
        self, response: AnalysisResponse, event: AnalysisEvent, errors: list[ToolError]
    ) -> None:
        del errors
        await self._write_state_event(response, event)

    async def _write_state_event(self, response: AnalysisResponse | None, event: AnalysisEvent) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            parent = await connection.fetchrow("SELECT id FROM analyses WHERE id = $1 FOR UPDATE", event.analysis_id)
            if parent is None:
                raise LookupError("analysis is not persisted")
            sequence = await connection.fetchval(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM analysis_events WHERE analysis_id = $1",
                event.analysis_id,
            )
            if response is not None:
                await connection.execute(
                    """UPDATE analyses SET status=$2, case_status=$3, response=$4::jsonb,
                              completed_at=$5, updated_at=$6, scoring_version=$7,
                              version=version+1 WHERE id=$1""",
                    response.analysis_id,
                    response.status.value,
                    response.case_status.value if response.case_status else None,
                    response.model_dump_json(),
                    response.completed_at,
                    event.occurred_at,
                    response.scoring_version,
                )
                await connection.execute("DELETE FROM investigation_steps WHERE analysis_id=$1", response.analysis_id)
                for step in response.investigation_plan:
                    await connection.execute(
                        """INSERT INTO investigation_steps(
                               analysis_id,step_id,tool,target_ref,reason_code,dependency_ids,
                               status,attempt_count,created_at,updated_at
                           ) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$9)""",
                        response.analysis_id,
                        step.step_id,
                        step.tool.value,
                        _safe_url_or_text(step.target),
                        step.reason_code,
                        json.dumps(step.depends_on),
                        step.status.value,
                        int(step.status.value != "pending"),
                        event.occurred_at,
                    )
                await connection.execute("DELETE FROM evidence WHERE analysis_id=$1", response.analysis_id)
                for evidence in response.evidence or []:
                    safe_url = _safe_url_or_text(evidence.url) if evidence.url else None
                    content_hash = hashlib.sha256(
                        json.dumps(
                            [evidence.type.value, evidence.source, safe_url, evidence.finding],
                            ensure_ascii=False,
                        ).encode()
                    ).hexdigest()
                    await connection.execute(
                        """INSERT INTO evidence(
                               id,analysis_id,type,source,source_version,title,safe_url,
                               finding,observed_at,created_at,content_hash
                           ) VALUES($1,$2,$3,$4,'v1',$5,$6,$7,$8,$9,$10)""",
                        uuid4(),
                        response.analysis_id,
                        evidence.type.value,
                        evidence.source,
                        evidence.title,
                        safe_url,
                        evidence.finding,
                        evidence.observed_at,
                        event.occurred_at,
                        content_hash,
                    )
            await connection.execute(
                """INSERT INTO analysis_events(
                       event_id, analysis_id, sequence, event_type, payload, occurred_at
                   ) VALUES ($1,$2,$3,$4,$5::jsonb,$6)""",
                uuid4(),
                event.analysis_id,
                sequence,
                (
                    "provisional_warning"
                    if event.is_provisional
                    else "step_transition"
                    if event.step_id
                    else "analysis_status"
                ),
                event.model_dump_json(),
                event.occurred_at,
            )
            active_job = self._active_job.get()
            if response is not None and response.status.value in {"completed", "failed"} and active_job:
                job_id, worker_id = active_job
                updated = await connection.execute(
                    """UPDATE analysis_jobs SET status='completed', lease_expires_at=NULL,
                              worker_id=NULL, updated_at=$3
                       WHERE id=$1 AND worker_id=$2 AND status='running'""",
                    job_id,
                    worker_id,
                    event.occurred_at,
                )
                if updated != "UPDATE 1":
                    raise LostJobLeaseError("job lease ownership was lost before terminal commit")
            await connection.execute(
                """INSERT INTO outbox(
                       id, aggregate_type, aggregate_id, event_type, payload,
                       idempotency_key, created_at
                   ) VALUES ($1,'analysis',$2,'analysis.progressed',$3::jsonb,$4,$5)
                   ON CONFLICT (idempotency_key) DO NOTHING""",
                uuid4(),
                event.analysis_id,
                event.model_dump_json(),
                f"analysis-event:{event.analysis_id}:{sequence}",
                event.occurred_at,
            )

    async def claim_job(self, worker_id: str, lease_seconds: int = 60) -> DurableJob | None:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        lease = now + timedelta(seconds=lease_seconds)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT id, analysis_id, kind, attempt, max_attempts, idempotency_key
                   FROM analysis_jobs
                   WHERE ((status IN ('queued','retry') AND available_at <= $1)
                          OR (status='running' AND lease_expires_at <= $1))
                     AND attempt < max_attempts
                   ORDER BY available_at, created_at
                   FOR UPDATE SKIP LOCKED LIMIT 1""",
                now,
            )
            if row is None:
                return None
            attempt = row["attempt"] + 1
            await connection.execute(
                """UPDATE analysis_jobs SET status='running', attempt=$2, worker_id=$3,
                          claimed_at=$4, lease_expires_at=$5, updated_at=$4 WHERE id=$1""",
                row["id"],
                attempt,
                worker_id,
                now,
                lease,
            )
        return DurableJob(
            row["id"],
            row["analysis_id"],
            row["kind"],
            attempt,
            row["max_attempts"],
            lease,
            row["idempotency_key"],
        )

    async def latest_security_admin_copilot(
        self, analysis_id: UUID, evidence_snapshot_hash: str
    ) -> SecurityAdminCopilotResponseV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT suggestion FROM security_admin_copilot_suggestions_v4
                   WHERE analysis_id=$1 AND evidence_snapshot_hash=$2
                   ORDER BY completed_at DESC LIMIT 1""",
                analysis_id,
                evidence_snapshot_hash,
            )
        return SecurityAdminCopilotResponseV4.model_validate(row["suggestion"]) if row else None

    async def save_security_admin_copilot(
        self,
        suggestion: SecurityAdminCopilotResponseV4,
        evidence_snapshot_hash: str,
        reviewer_id: str,
        requested_at: datetime,
        completed_at: datetime,
    ) -> None:
        audit = SecurityAdminAuditEventV4(
            resource_type=SecurityAuditResourceV4.COPILOT,
            resource_id=suggestion.suggestion_id,
            action="copilot_suggestion_generated",
            actor_id=reviewer_id,
            note=f"{suggestion.generation_mode.value}:{suggestion.suggestion_version}",
            occurred_at=completed_at,
            evidence_refs=suggestion.evidence_refs,
        )
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_admin_copilot_suggestions_v4(
                       id,analysis_id,reviewer_id,suggestion,usage_metadata,evidence_snapshot_hash,
                       requested_at,completed_at
                   ) VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8)""",
                suggestion.suggestion_id,
                suggestion.analysis_id,
                reviewer_id,
                suggestion.model_dump_json(),
                suggestion.usage.model_dump_json(),
                evidence_snapshot_hash,
                requested_at,
                completed_at,
            )
            await self._insert_security_feedback_audit(connection, audit)

    async def claim_security_job(self, worker_id: str, lease_seconds: int = 60) -> DurableJob | None:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        lease = now + timedelta(seconds=lease_seconds)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT id,analysis_id,attempt,max_attempts
                   FROM security_analysis_jobs_v4
                   WHERE ((status='queued' AND available_at <= $1)
                          OR (status='running' AND lease_expires_at <= $1))
                     AND attempt < max_attempts
                   ORDER BY available_at,created_at
                   FOR UPDATE SKIP LOCKED LIMIT 1""",
                now,
            )
            if row is None:
                return None
            attempt = row["attempt"] + 1
            await connection.execute(
                """UPDATE security_analysis_jobs_v4 SET status='running',attempt=$2,worker_id=$3,
                          claimed_at=$4,lease_expires_at=$5,updated_at=$4 WHERE id=$1""",
                row["id"],
                attempt,
                worker_id,
                now,
                lease,
            )
        return DurableJob(row["id"], row["analysis_id"], "security_v4", attempt, row["max_attempts"], lease)

    async def renew_security_job(self, job_id: UUID, worker_id: str, lease_seconds: int) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE security_analysis_jobs_v4
                   SET lease_expires_at=now()+($3 * interval '1 second'),updated_at=now()
                   WHERE id=$1 AND worker_id=$2 AND status='running'""",
                job_id,
                worker_id,
                lease_seconds,
            )
        return result == "UPDATE 1"

    async def retry_security_job(self, job: DurableJob, failure_code: str, worker_id: str) -> bool:
        pool = await self._get_pool()
        exhausted = job.attempt >= job.max_attempts
        delay = min(2**job.attempt, 60)
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            owned = await connection.fetchrow(
                """SELECT analysis_id FROM security_analysis_jobs_v4
                   WHERE id=$1 AND worker_id=$2 AND status='running'
                     AND lease_expires_at > now() FOR UPDATE""",
                job.id,
                worker_id,
            )
            if owned is None:
                return False
            if not exhausted:
                await connection.execute(
                    """UPDATE security_analysis_jobs_v4 SET status='queued',failure_code=$2,
                              available_at=$3+($4 * interval '1 second'),lease_expires_at=NULL,
                              worker_id=NULL,updated_at=$3 WHERE id=$1""",
                    job.id,
                    failure_code[:64],
                    now,
                    delay,
                )
                return True
            row = await connection.fetchrow(
                "SELECT response FROM security_analyses WHERE id=$1 FOR UPDATE",
                job.analysis_id,
            )
            if row is None:
                return False
            response = SecurityScopeResponseV4.model_validate(_json_value(row["response"])).model_copy(
                update={"status": "failed", "completed_at": now}
            )
            sequence = await connection.fetchval(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM security_analysis_events WHERE analysis_id=$1",
                job.analysis_id,
            )
            event = SecurityAnalysisEventV4(
                analysis_id=job.analysis_id,
                sequence=sequence,
                status="failed",
                step="failed",
                kind="final",
                message="Security analysis failed after the retry budget was exhausted.",
                occurred_at=now,
            )
            await connection.execute(
                """UPDATE security_analyses SET status='failed',response=$2::jsonb,
                          updated_at=$3,completed_at=$3 WHERE id=$1""",
                job.analysis_id,
                response.model_dump_json(),
                now,
            )
            await connection.execute(
                """INSERT INTO security_analysis_events(
                       event_id,analysis_id,sequence,event_type,payload,occurred_at
                   ) VALUES($1,$2,$3,'final',$4::jsonb,$5)""",
                event.event_id,
                job.analysis_id,
                sequence,
                event.model_dump_json(),
                now,
            )
            await connection.execute("DELETE FROM security_analysis_payloads_v4 WHERE analysis_id=$1", job.analysis_id)
            await connection.execute(
                """UPDATE security_analysis_jobs_v4 SET status='failed',failure_code=$2,
                          lease_expires_at=NULL,worker_id=NULL,updated_at=$3 WHERE id=$1""",
                job.id,
                failure_code[:64],
                now,
            )
            await connection.execute(
                """INSERT INTO security_analysis_outbox_v4(
                       id,analysis_id,event_type,payload,idempotency_key,created_at
                   ) VALUES($1,$2,'security_analysis.final',$3::jsonb,$4,$5)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                job.analysis_id,
                event.model_dump_json(),
                f"security-v4-event:{job.analysis_id}:{sequence}",
                now,
            )
        return True

    async def finish_job(self, job_id: UUID, worker_id: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """UPDATE analysis_jobs SET status='completed', lease_expires_at=NULL,
                          worker_id=NULL, updated_at=now()
                   WHERE id=$1 AND worker_id=$2 AND status='running'""",
                job_id,
                worker_id,
            )

    async def renew_job(self, job_id: UUID, worker_id: str, lease_seconds: int) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE analysis_jobs SET lease_expires_at=now()+($3 * interval '1 second'),
                          updated_at=now() WHERE id=$1 AND worker_id=$2 AND status='running'""",
                job_id,
                worker_id,
                lease_seconds,
            )
        return result == "UPDATE 1"

    async def retry_job(self, job: DurableJob, failure_code: str, worker_id: str) -> bool:
        pool = await self._get_pool()
        exhausted = job.attempt >= job.max_attempts
        delay = min(2**job.attempt, 60)
        async with pool.acquire() as connection:
            updated = await connection.execute(
                """UPDATE analysis_jobs SET status=$2, failure_code=$3,
                          available_at=now()+($4 * interval '1 second'), lease_expires_at=NULL,
                          worker_id=NULL, updated_at=now()
                   WHERE id=$1 AND worker_id=$5 AND status='running'""",
                job.id,
                "failed" if exhausted else "retry",
                failure_code[:64],
                delay,
                worker_id,
            )
        return updated == "UPDATE 1"

    async def claim_outbox(self, worker_id: str, limit: int = 100) -> list[OutboxMessage]:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            rows = await connection.fetch(
                """SELECT id,aggregate_id,event_type,payload,idempotency_key FROM outbox
                   WHERE published_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at<=now())
                   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1""",
                limit,
            )
            ids = [row["id"] for row in rows]
            if ids:
                await connection.execute(
                    """UPDATE outbox SET worker_id=$2, lease_expires_at=now()+interval '30 seconds',
                              attempt_count=attempt_count+1 WHERE id=ANY($1::uuid[])""",
                    ids,
                    worker_id,
                )
        return [
            OutboxMessage(
                row["id"],
                row["aggregate_id"],
                row["event_type"],
                _json_value(row["payload"]),
                row["idempotency_key"],
            )
            for row in rows
        ]

    async def claim_security_outbox(self, worker_id: str, limit: int = 100) -> list[OutboxMessage]:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            rows = await connection.fetch(
                """SELECT id,analysis_id,event_type,payload,idempotency_key
                   FROM security_analysis_outbox_v4
                   WHERE published_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at<=now())
                   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1""",
                limit,
            )
            ids = [row["id"] for row in rows]
            if ids:
                await connection.execute(
                    """UPDATE security_analysis_outbox_v4 SET worker_id=$2,
                              lease_expires_at=now()+interval '30 seconds'
                       WHERE id=ANY($1::uuid[])""",
                    ids,
                    worker_id,
                )
        return [
            OutboxMessage(
                row["id"],
                row["analysis_id"],
                row["event_type"],
                _json_value(row["payload"]),
                row["idempotency_key"],
            )
            for row in rows
        ]

    async def mark_security_outbox_published(self, message_id: UUID) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """UPDATE security_analysis_outbox_v4
                   SET published_at=now(),lease_expires_at=NULL,worker_id=NULL WHERE id=$1""",
                message_id,
            )

    async def mark_outbox_published(self, message_id: UUID) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                "UPDATE outbox SET published_at=now(),lease_expires_at=NULL,worker_id=NULL WHERE id=$1",
                message_id,
            )

    async def get(self, domain: str):
        normalized = _canonical_domain_or_target(domain)
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT canonical_domain,enabling_decision_id,created_at,active
                   FROM blacklist_entries WHERE canonical_domain=$1 AND active""",
                normalized,
            )
        if row is None:
            return None
        return BlacklistLookupEntry(
            domain=row["canonical_domain"],
            decision_id=str(row["enabling_decision_id"]),
            source="reviewed-action-v3",
            added_at=row["created_at"],
            active=row["active"],
        )

    async def contains(self, domain: str) -> bool:
        return await self.get(domain) is not None

    async def add_approved(self, domain: str, decision_id: str) -> None:
        del domain, decision_id
        raise RuntimeError("direct blacklist mutation is disabled; use an approved admin action")

    async def record_report(
        self,
        *,
        report_id: str,
        analysis_id: str,
        reporter_id: str,
        reason: str,
        comment: str | None,
        created_at: datetime,
        evidence_snapshot: list[Evidence],
    ) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO analysis_reports(
                       id,analysis_id,reporter_id,reason,comment,created_at
                   ) VALUES($1,$2,$3,$4,$5,$6)""",
                UUID(report_id),
                UUID(analysis_id),
                reporter_id,
                reason.strip(),
                comment,
                created_at,
            )
            await connection.execute(
                """INSERT INTO review_queue_items(
                       id,report_id,analysis_id,status,evidence_snapshot,created_at,updated_at
                   ) VALUES($1,$2,$3,$4,$5::jsonb,$6,$6)""",
                uuid4(),
                UUID(report_id),
                UUID(analysis_id),
                ReportStatus.SUBMITTED.value,
                json.dumps([item.model_dump(mode="json") for item in evidence_snapshot]),
                created_at,
            )

    async def list_reports(self, *, limit: int, offset: int) -> list[AnalysisReportRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT r.id,r.analysis_id,r.reporter_id,r.reason,r.comment,r.created_at,q.status
                   FROM analysis_reports r
                   LEFT JOIN review_queue_items q ON q.report_id=r.id
                   ORDER BY r.created_at DESC LIMIT $1 OFFSET $2""",
                limit,
                offset,
            )
        return [
            AnalysisReportRecord(
                report_id=row["id"],
                analysis_id=row["analysis_id"],
                reporter_id=row["reporter_id"],
                reason=row["reason"],
                comment=row["comment"],
                created_at=row["created_at"],
                status=ReportStatus(row["status"] or ReportStatus.SUBMITTED.value),
            )
            for row in rows
        ]

    async def list_reports_by_analysis(self, analysis_id: str) -> list[AnalysisReportResponse]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT r.id,r.analysis_id,r.created_at,q.status
                   FROM analysis_reports r
                   LEFT JOIN review_queue_items q ON q.report_id=r.id
                   WHERE r.analysis_id=$1 ORDER BY r.created_at DESC""",
                UUID(analysis_id),
            )
        return [
            AnalysisReportResponse(
                report_id=row["id"],
                analysis_id=row["analysis_id"],
                created_at=row["created_at"],
                status=ReportStatus(row["status"] or ReportStatus.SUBMITTED.value),
            )
            for row in rows
        ]

    async def list_review_queue_items(self) -> list[ReviewQueueItem]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT q.id,q.report_id,q.analysis_id,q.status,q.evidence_snapshot,
                          q.decision,q.reviewer_id,q.reviewer_note,q.reviewed_at,
                          q.created_at,q.updated_at,r.reason,r.comment,
                          pgp_sym_decrypt(a.input_ciphertext,$1)::jsonb ->> 'message' AS analysis_content
                   FROM review_queue_items q
                   JOIN analysis_reports r ON r.id=q.report_id
                   JOIN analyses a ON a.id=q.analysis_id
                   ORDER BY q.created_at ASC""",
                self._encryption_key,
            )
        return [self._review_queue_item(row) for row in rows]

    async def get_review_queue_item(self, item_id: str) -> ReviewQueueItem | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT q.id,q.report_id,q.analysis_id,q.status,q.evidence_snapshot,
                          q.decision,q.reviewer_id,q.reviewer_note,q.reviewed_at,
                          q.created_at,q.updated_at,r.reason,r.comment,
                          pgp_sym_decrypt(a.input_ciphertext,$2)::jsonb ->> 'message' AS analysis_content
                   FROM review_queue_items q
                   JOIN analysis_reports r ON r.id=q.report_id
                   JOIN analyses a ON a.id=q.analysis_id
                   WHERE q.id=$1""",
                UUID(item_id),
                self._encryption_key,
            )
        return self._review_queue_item(row) if row is not None else None

    async def start_review_queue_item(self, item_id: str, reviewer_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE review_queue_items
                   SET status=$2,reviewer_id=$3,updated_at=now()
                   WHERE id=$1 AND status=$4""",
                UUID(item_id),
                ReportStatus.REVIEWING.value,
                reviewer_id,
                ReportStatus.SUBMITTED.value,
            )
        return result == "UPDATE 1"

    async def decide_review_queue_item(
        self,
        item_id: str,
        *,
        decision: ReportReviewDecision,
        reviewer_id: str,
        note: str,
    ) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE review_queue_items
                   SET status=$2,decision=$3,reviewer_id=$4,reviewer_note=$5,
                       reviewed_at=now(),updated_at=now()
                   WHERE id=$1 AND status=$6""",
                UUID(item_id),
                ReportStatus.PROCESSED.value,
                decision.value,
                reviewer_id,
                note.strip(),
                ReportStatus.REVIEWING.value,
            )
        return result == "UPDATE 1"

    async def create_appeal(
        self,
        analysis_id: UUID,
        owner_id: str,
        request: AppealCreateRequestV3,
        evidence: list[Evidence],
    ) -> AppealReceiptV3:
        del evidence
        pool = await self._get_pool()
        appeal_id, now = uuid4(), datetime.now(UTC)
        try:
            async with pool.acquire() as connection:
                await connection.execute(
                    """INSERT INTO appeals(
                           id,analysis_id,owner_id,reason,comment,status,created_at,updated_at
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$7)""",
                    appeal_id,
                    analysis_id,
                    owner_id,
                    request.reason.strip(),
                    request.comment,
                    AppealStatus.SUBMITTED.value,
                    now,
                )
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "23505":
                raise _platform_conflict("An active appeal already exists for this analysis.") from exc
            raise
        return AppealReceiptV3(appeal_id=appeal_id, analysis_id=analysis_id, created_at=now)

    async def get_appeal(self, appeal_id: UUID) -> tuple[str, AppealResponseV3] | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow("SELECT * FROM appeals WHERE id=$1", appeal_id)
        return (row["owner_id"], self._appeal_response(row)) if row else None

    async def list_appeals_for_analysis(self, analysis_id: UUID, owner_id: str) -> list[AppealResponseV3]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT * FROM appeals
                   WHERE analysis_id=$1 AND owner_id=$2
                   ORDER BY created_at DESC""",
                analysis_id,
                owner_id,
            )
        return [self._appeal_response(row) for row in rows]

    async def list_appeals(
        self, appeal_status: AppealStatus | None, limit: int, offset: int
    ) -> tuple[list[AppealAdminRecordV3], int]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            if appeal_status is None:
                rows = await connection.fetch(
                    "SELECT * FROM appeals ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset
                )
                total = await connection.fetchval("SELECT count(*) FROM appeals")
            else:
                rows = await connection.fetch(
                    "SELECT * FROM appeals WHERE status=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                    appeal_status.value,
                    limit,
                    offset,
                )
                total = await connection.fetchval("SELECT count(*) FROM appeals WHERE status=$1", appeal_status.value)
        return [self._appeal_admin_response(row) for row in rows], int(total)

    async def decide_appeal(
        self,
        appeal_id: UUID,
        request: AppealDecisionRequestV3,
        reviewer_id: str,
    ) -> AppealDecisionResponseV3 | None:
        pool = await self._get_pool()
        now, decision_id = datetime.now(UTC), uuid4()
        async with pool.acquire() as connection, connection.transaction():
            appeal = await connection.fetchrow("SELECT * FROM appeals WHERE id=$1 FOR UPDATE", appeal_id)
            if appeal is None:
                return None
            if appeal["status"] == AppealStatus.RESOLVED.value:
                raise _platform_conflict("The appeal has already been resolved.")
            snapshot_rows = await connection.fetch(
                """SELECT type,source,title,safe_url,finding,observed_at
                   FROM evidence WHERE analysis_id=$1 ORDER BY created_at""",
                appeal["analysis_id"],
            )
            evidence_snapshot = [
                {
                    "type": row["type"],
                    "source": row["source"],
                    "title": row["title"],
                    "url": row["safe_url"],
                    "finding": row["finding"],
                    "observed_at": row["observed_at"].isoformat(),
                }
                for row in snapshot_rows
            ]
            predecessor = await connection.fetchval(
                "SELECT id FROM review_decisions WHERE appeal_id=$1 ORDER BY decided_at DESC LIMIT 1", appeal_id
            )
            await connection.execute(
                """INSERT INTO review_decisions(
                       id,analysis_id,appeal_id,reviewer_id,decision,outcome,evidence_snapshot,
                       note,decided_at,predecessor_decision_id
                   ) VALUES($1,$2,$3,$4,'resolved',$5,$6::jsonb,$7,$8,$9)""",
                decision_id,
                appeal["analysis_id"],
                appeal_id,
                reviewer_id,
                request.outcome.value,
                json.dumps(evidence_snapshot),
                request.note.strip(),
                now,
                predecessor,
            )
            await connection.execute(
                """UPDATE appeals SET status='resolved',outcome=$2,resolution_note=$3,
                          resolved_at=$4,updated_at=$4,version=version+1 WHERE id=$1""",
                appeal_id,
                request.outcome.value,
                request.note.strip(),
                now,
            )
            if request.outcome is AppealOutcome.OVERTURN:
                await connection.execute(
                    """UPDATE blacklist_entries b SET active=false,disabling_decision_id=$2,
                              updated_at=$3,version=b.version+1
                       FROM review_decisions enabling
                       WHERE b.enabling_decision_id=enabling.id AND enabling.analysis_id=$1 AND b.active""",
                    appeal["analysis_id"],
                    decision_id,
                    now,
                )
            await connection.execute(
                """INSERT INTO user_notifications(
                       id,owner_id,resource_type,resource_id,event_type,payload,created_at,idempotency_key
                   ) VALUES($1,$2,'appeal',$3,'appeal.resolved',$4::jsonb,$5,$6)
                   ON CONFLICT(idempotency_key) DO NOTHING""",
                uuid4(),
                appeal["owner_id"],
                appeal_id,
                json.dumps({"outcome": request.outcome.value}),
                now,
                f"appeal:{appeal_id}:resolved:{decision_id}",
            )
        return AppealDecisionResponseV3(
            appeal_id=appeal_id, decision_id=decision_id, outcome=request.outcome, decided_at=now
        )

    @staticmethod
    def _appeal_response(row) -> AppealResponseV3:
        return AppealResponseV3(
            appeal_id=row["id"],
            analysis_id=row["analysis_id"],
            status=AppealStatus(row["status"]),
            reason=row["reason"],
            comment=row["comment"],
            outcome=AppealOutcome(row["outcome"]) if row["outcome"] else None,
            resolution_note=row["resolution_note"],
            created_at=row["created_at"],
            resolved_at=row["resolved_at"],
        )

    @classmethod
    def _appeal_admin_response(cls, row) -> AppealAdminRecordV3:
        response = cls._appeal_response(row)
        return AppealAdminRecordV3(owner_id=row["owner_id"], **response.model_dump(exclude={"contract_version"}))

    async def propose_admin_action(
        self,
        *,
        analysis_id: UUID | None,
        security_analysis_id: UUID | None = None,
        campaign_id: UUID | None,
        action: ReviewedAction,
        target: str | None,
        evidence: list[Evidence],
    ) -> AdminActionRecordV3:
        action_id, now = uuid4(), datetime.now(UTC)
        canonical = _canonical_domain_or_target(target) if target else None
        record = AdminActionRecordV3(
            action_id=action_id,
            analysis_id=analysis_id,
            security_analysis_id=security_analysis_id,
            campaign_id=campaign_id,
            action=action,
            target=canonical,
            status=AdminActionStatus.PENDING_REVIEW,
            evidence_snapshot=evidence,
            proposed_at=now,
        )
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            existing = await connection.fetchrow(
                """SELECT * FROM admin_actions
                   WHERE security_analysis_id IS NOT DISTINCT FROM $1
                     AND analysis_id IS NOT DISTINCT FROM $2
                     AND campaign_id IS NOT DISTINCT FROM $3
                     AND action=$4 AND canonical_target IS NOT DISTINCT FROM $5
                   ORDER BY proposed_at DESC LIMIT 1""",
                security_analysis_id,
                analysis_id,
                campaign_id,
                action.value,
                canonical,
            )
            if existing is not None:
                return self._admin_action(existing)
            inserted = await connection.fetchrow(
                """INSERT INTO admin_actions(
                       id,analysis_id,security_analysis_id,campaign_id,action,canonical_target,status,
                       evidence_snapshot,proposed_at
                   ) VALUES($1,$2,$3,$4,$5,$6,'pending_review',$7::jsonb,$8)
                   ON CONFLICT(security_analysis_id,action,canonical_target)
                     WHERE security_analysis_id IS NOT NULL DO NOTHING
                   RETURNING *""",
                action_id,
                analysis_id,
                security_analysis_id,
                campaign_id,
                action.value,
                canonical,
                json.dumps([item.model_dump(mode="json") for item in evidence]),
                now,
            )
            if inserted is None and security_analysis_id is not None:
                concurrent = await connection.fetchrow(
                    """SELECT * FROM admin_actions
                       WHERE security_analysis_id=$1 AND action=$2 AND canonical_target=$3""",
                    security_analysis_id,
                    action.value,
                    canonical,
                )
                if concurrent is not None:
                    return self._admin_action(concurrent)
        return record

    async def list_admin_actions(
        self, action_status: AdminActionStatus | None, limit: int, offset: int
    ) -> tuple[list[AdminActionRecordV3], int]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            if action_status is None:
                rows = await connection.fetch(
                    "SELECT * FROM admin_actions ORDER BY proposed_at DESC LIMIT $1 OFFSET $2", limit, offset
                )
                total = await connection.fetchval("SELECT count(*) FROM admin_actions")
            else:
                rows = await connection.fetch(
                    "SELECT * FROM admin_actions WHERE status=$1 ORDER BY proposed_at DESC LIMIT $2 OFFSET $3",
                    action_status.value,
                    limit,
                    offset,
                )
                total = await connection.fetchval(
                    "SELECT count(*) FROM admin_actions WHERE status=$1", action_status.value
                )
        return [self._admin_action(row) for row in rows], int(total)

    async def get_admin_action(self, action_id: UUID) -> AdminActionRecordV3 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow("SELECT * FROM admin_actions WHERE id=$1", action_id)
        return self._admin_action(row) if row else None

    async def list_admin_action_audit(self, action_id: UUID) -> list[AdminActionAuditRecordV3]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT d.id,d.action_id,d.reviewer_id,d.decision,d.action,d.evidence_snapshot,
                          d.note,d.decided_at,d.execution_status,d.execution_error
                   FROM review_decisions d
                   WHERE d.action_id=$1 ORDER BY d.decided_at""",
                action_id,
            )
        return [
            AdminActionAuditRecordV3(
                decision_id=row["id"],
                action_id=row["action_id"],
                reviewer_id=row["reviewer_id"],
                decision=ReviewDecision(row["decision"]),
                action=ReviewedAction(row["action"]),
                execution_status=AdminActionStatus(row["execution_status"]),
                evidence_snapshot=[Evidence.model_validate(item) for item in _json_value(row["evidence_snapshot"])],
                note=row["note"],
                decided_at=row["decided_at"],
                execution_error=row["execution_error"],
            )
            for row in rows
        ]

    async def decide_admin_action(
        self,
        action_id: UUID,
        decision: ReviewDecision,
        note: str,
        reviewer_id: str,
    ) -> AdminActionDecisionResponseV3 | None:
        pool = await self._get_pool()
        now, decision_id = datetime.now(UTC), uuid4()
        async with pool.acquire() as connection, connection.transaction():
            action = await connection.fetchrow("SELECT * FROM admin_actions WHERE id=$1 FOR UPDATE", action_id)
            if action is None:
                return None
            if action["status"] != AdminActionStatus.PENDING_REVIEW.value:
                raise _platform_conflict("The admin action has already been reviewed.")
            approved = decision is ReviewDecision.APPROVED
            new_status = AdminActionStatus.APPROVED if approved else AdminActionStatus.REJECTED
            executed_at = None
            execution_error = None
            await connection.execute(
                """INSERT INTO review_decisions(
                       id,analysis_id,action_id,reviewer_id,decision,action,evidence_snapshot,note,
                       decided_at,execution_status
                   ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)""",
                decision_id,
                action["analysis_id"],
                action_id,
                reviewer_id,
                decision.value,
                action["action"],
                json.dumps(_json_value(action["evidence_snapshot"])),
                note.strip(),
                now,
                new_status.value,
            )
            await connection.execute(
                """UPDATE admin_actions SET status=$2,reviewer_id=$3,review_note=$4,
                          reviewed_at=$5,approved_decision_id=$6,version=version+1 WHERE id=$1""",
                action_id,
                new_status.value,
                reviewer_id,
                note.strip(),
                now,
                decision_id if approved else None,
            )
            if approved and action["action"] == ReviewedAction.ADD_TO_BLACKLIST.value:
                await connection.execute(
                    """INSERT INTO blacklist_entries(
                           id,canonical_domain,active,enabling_decision_id,created_at,updated_at
                       ) VALUES($1,$2,true,$3,$4,$4)
                       ON CONFLICT(canonical_domain) DO UPDATE SET
                         active=true,enabling_decision_id=EXCLUDED.enabling_decision_id,
                         disabling_decision_id=NULL,updated_at=EXCLUDED.updated_at,
                         version=blacklist_entries.version+1""",
                    uuid4(),
                    action["canonical_target"],
                    decision_id,
                    now,
                )
                new_status = AdminActionStatus.EXECUTED
                executed_at = now
            elif approved and action["action"] == ReviewedAction.DISABLE_BLACKLIST.value:
                result = await connection.execute(
                    """UPDATE blacklist_entries SET active=false,disabling_decision_id=$2,
                              updated_at=$3,version=version+1
                       WHERE canonical_domain=$1 AND active""",
                    action["canonical_target"],
                    decision_id,
                    now,
                )
                executed_at = now
                if result.endswith(" 0"):
                    new_status = AdminActionStatus.FAILED
                    execution_error = "BLACKLIST_TARGET_NOT_ACTIVE"
                else:
                    new_status = AdminActionStatus.EXECUTED
            elif approved:
                new_status = AdminActionStatus.FAILED
                executed_at = now
                execution_error = "ACTION_SINK_NOT_CONFIGURED"
            if approved:
                await connection.execute(
                    """UPDATE admin_actions SET status=$2,executed_at=$3,execution_error=$4,
                              version=version+1 WHERE id=$1""",
                    action_id,
                    new_status.value,
                    executed_at,
                    execution_error,
                )
            await connection.execute(
                """UPDATE review_decisions SET execution_status=$2,execution_error=$3 WHERE id=$1""",
                decision_id,
                new_status.value,
                execution_error,
            )
        return AdminActionDecisionResponseV3(
            action_id=action_id,
            decision_id=decision_id,
            action=ReviewedAction(action["action"]),
            status=new_status,
            reviewed_at=now,
            executed_at=executed_at,
            execution_error=execution_error,
        )

    @staticmethod
    def _admin_action(row) -> AdminActionRecordV3:
        return AdminActionRecordV3(
            action_id=row["id"],
            analysis_id=row["analysis_id"],
            security_analysis_id=row["security_analysis_id"],
            campaign_id=row["campaign_id"],
            action=ReviewedAction(row["action"]),
            target=row["canonical_target"],
            status=AdminActionStatus(row["status"]),
            evidence_snapshot=[Evidence.model_validate(item) for item in _json_value(row["evidence_snapshot"])],
            proposed_at=row["proposed_at"],
            reviewer_id=row["reviewer_id"],
            review_note=row["review_note"],
            reviewed_at=row["reviewed_at"],
            executed_at=row["executed_at"],
            execution_error=row["execution_error"],
        )

    async def register_source(self, entry: SourceRegistryEntry) -> None:
        pool = await self._get_pool()
        try:
            async with pool.acquire() as connection:
                await connection.execute(
                    """INSERT INTO fact_check_sources(
                           id,publisher,normalized_pattern,tier,source_type,active,explicit_deny,
                           trusted_claim_review,allowed_operations,policy_version,effective_from,effective_to,
                           default_freshness_seconds,reviewer_id,reviewed_at,created_at
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15,$15)""",
                    entry.source_id,
                    entry.publisher,
                    entry.normalized_pattern,
                    entry.tier.value,
                    entry.source_type,
                    entry.active,
                    entry.explicit_deny,
                    entry.trusted_claim_review,
                    json.dumps(sorted(entry.allowed_operations)),
                    entry.policy_version,
                    entry.effective_from,
                    entry.effective_to,
                    entry.default_freshness_seconds,
                    entry.reviewer_id,
                    entry.reviewed_at,
                )
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "23505":
                raise _platform_conflict("This source policy version already exists.") from exc
            raise

    async def load_source_policies(self, at: datetime) -> list[SourceRegistryEntry]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT * FROM fact_check_sources
                   WHERE active AND effective_from <= $1 AND (effective_to IS NULL OR effective_to > $1)""",
                at,
            )
        return [
            SourceRegistryEntry(
                source_id=row["id"],
                publisher=row["publisher"],
                normalized_pattern=row["normalized_pattern"],
                tier=SourceTier(row["tier"]),
                source_type=row["source_type"],
                active=row["active"],
                explicit_deny=row["explicit_deny"],
                trusted_claim_review=row["trusted_claim_review"],
                allowed_operations=set(_json_value(row["allowed_operations"])),
                policy_version=row["policy_version"],
                effective_from=row["effective_from"],
                effective_to=row["effective_to"],
                default_freshness_seconds=row["default_freshness_seconds"],
                reviewer_id=row["reviewer_id"],
                reviewed_at=row["reviewed_at"],
            )
            for row in rows
        ]

    async def observe_source_discovery(
        self,
        *,
        url: str,
        publisher: str,
        event: str,
        claim_hash: str | None,
        agrees_with_curated: bool | None,
        allow_auto_promotion: bool = True,
    ) -> None:
        from src.agents.fact_check import registrable_domain  # noqa: PLC0415

        domain = registrable_domain(url)
        if not domain:
            return
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow("SELECT * FROM source_discoveries WHERE domain=$1 FOR UPDATE", domain)
            urls = list(dict.fromkeys([*(_json_value(row["representative_urls"]) if row else []), url]))[-5:]
            claims = list(_json_value(row["claim_hashes"]) if row else [])
            if claim_hash and claim_hash not in claims:
                claims.append(claim_hash)
            claims = claims[-1000:]
            search_delta = int(event == "search")
            extract_delta = int(event == "extract")
            comparison_delta = int(event == "comparison" and agrees_with_curated is not None)
            agreement_delta = int(event == "comparison" and agrees_with_curated is True)
            conflict_delta = int(event == "comparison" and agrees_with_curated is False)
            await connection.execute(
                """INSERT INTO source_discoveries(
                       domain,publisher,first_seen_at,last_seen_at,search_count,extract_success_count,
                       claim_hashes,curated_comparison_count,curated_agreement_count,curated_conflict_count,
                       representative_urls,status
                   ) VALUES($1,$2,$3,$3,$4,$5,$6::jsonb,$7,$8,$9,$10::jsonb,'observing')
                   ON CONFLICT(domain) DO UPDATE SET
                     publisher=EXCLUDED.publisher,last_seen_at=EXCLUDED.last_seen_at,
                     search_count=source_discoveries.search_count+EXCLUDED.search_count,
                     extract_success_count=source_discoveries.extract_success_count+EXCLUDED.extract_success_count,
                     claim_hashes=EXCLUDED.claim_hashes,
                     curated_comparison_count=source_discoveries.curated_comparison_count+EXCLUDED.curated_comparison_count,
                     curated_agreement_count=source_discoveries.curated_agreement_count+EXCLUDED.curated_agreement_count,
                     curated_conflict_count=source_discoveries.curated_conflict_count+EXCLUDED.curated_conflict_count,
                     representative_urls=EXCLUDED.representative_urls""",
                domain,
                publisher,
                now,
                search_delta,
                extract_delta,
                json.dumps(claims),
                comparison_delta,
                agreement_delta,
                conflict_delta,
                json.dumps(urls),
            )
            await connection.execute(
                """INSERT INTO source_discovery_observations(
                       id,domain,event,claim_hash,agrees_with_curated,observed_at
                   ) VALUES($1,$2,$3,$4,$5,$6)""",
                uuid4(),
                domain,
                event,
                claim_hash,
                agrees_with_curated,
                now,
            )
            current = await connection.fetchrow("SELECT * FROM source_discoveries WHERE domain=$1", domain)
            comparisons = current["curated_comparison_count"]
            agreement_rate = current["curated_agreement_count"] / comparisons if comparisons else 0.0
            conflict_rate = current["curated_conflict_count"] / comparisons if comparisons else 0.0
            eligible = (
                now - current["first_seen_at"] >= timedelta(days=30)
                and current["extract_success_count"] >= 20
                and len(_json_value(current["claim_hashes"])) >= 10
                and comparisons >= 10
                and agreement_rate >= 0.9
                and conflict_rate <= 0.05
            )
            if allow_auto_promotion and eligible and current["status"] == "observing":
                await connection.execute(
                    """INSERT INTO fact_check_sources(
                           id,publisher,normalized_pattern,tier,source_type,active,explicit_deny,
                           trusted_claim_review,allowed_operations,policy_version,effective_from,
                           default_freshness_seconds,reviewer_id,reviewed_at,created_at
                       VALUES($1,$2,$3,'B','auto_reviewed_web',true,false,false,$4::jsonb,$5,$6,21600,
                              'system-auto-promotion',$6,$6)
                       ON CONFLICT(normalized_pattern,policy_version) DO NOTHING""",
                    uuid4(),
                    publisher,
                    f"*.{domain}",
                    json.dumps(["search", "read", "compare"]),
                    f"auto-tier-b-{now.date().isoformat()}",
                    now,
                )
                await connection.execute("UPDATE source_discoveries SET status='promoted' WHERE domain=$1", domain)
            rolling = await connection.fetchrow(
                """SELECT count(*) FILTER (WHERE event='comparison') AS comparisons,
                          count(*) FILTER (WHERE event='comparison' AND agrees_with_curated=false) AS conflicts
                   FROM source_discovery_observations
                   WHERE domain=$1 AND observed_at >= $2""",
                domain,
                now - timedelta(days=30),
            )
            rolling_comparisons = int(rolling["comparisons"] or 0)
            rolling_conflict_rate = int(rolling["conflicts"] or 0) / rolling_comparisons if rolling_comparisons else 0.0
            if current["status"] == "promoted" and rolling_comparisons >= 10 and rolling_conflict_rate > 0.1:
                await connection.execute(
                    """UPDATE fact_check_sources SET active=false,effective_to=$2
                       WHERE normalized_pattern=$1 AND source_type='auto_reviewed_web' AND active""",
                    f"*.{domain}",
                    now,
                )
                await connection.execute("UPDATE source_discoveries SET status='demoted' WHERE domain=$1", domain)

    async def list_source_discoveries(self) -> list[SourceDiscoveryRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT * FROM source_discoveries ORDER BY last_seen_at DESC")
        output = []
        for row in rows:
            comparisons = row["curated_comparison_count"]
            eligible = (
                (
                    datetime.now(UTC) - row["first_seen_at"] >= timedelta(days=30)
                    and row["extract_success_count"] >= 20
                    and len(_json_value(row["claim_hashes"])) >= 10
                    and comparisons >= 10
                    and row["curated_agreement_count"] / comparisons >= 0.9
                    and row["curated_conflict_count"] / comparisons <= 0.05
                )
                if comparisons
                else False
            )
            output.append(
                SourceDiscoveryRecord(
                    domain=row["domain"],
                    publisher=row["publisher"],
                    first_seen_at=row["first_seen_at"],
                    last_seen_at=row["last_seen_at"],
                    search_count=row["search_count"],
                    extract_success_count=row["extract_success_count"],
                    independent_claim_count=len(_json_value(row["claim_hashes"])),
                    curated_comparison_count=comparisons,
                    curated_agreement_count=row["curated_agreement_count"],
                    curated_conflict_count=row["curated_conflict_count"],
                    representative_urls=list(_json_value(row["representative_urls"])),
                    status=row["status"],
                    eligible_for_auto_promotion=eligible,
                )
            )
        return output

    async def set_source_discovery_status(
        self, domain: str, status: str, *, decision: str, note: str, reviewer_id: str
    ) -> None:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            result = await connection.execute("UPDATE source_discoveries SET status=$2 WHERE domain=$1", domain, status)
            if result == "UPDATE 0":
                return
            await connection.execute(
                """INSERT INTO source_discovery_decisions(id,domain,decision,note,reviewer_id,decided_at)
                   VALUES($1,$2,$3,$4,$5,$6)""",
                uuid4(),
                domain,
                decision,
                note,
                reviewer_id,
                now,
            )
            if status in {"demoted", "denied"}:
                await connection.execute(
                    """UPDATE fact_check_sources SET active=false,effective_to=$2
                       WHERE normalized_pattern=$1 AND active AND NOT explicit_deny""",
                    f"*.{domain}",
                    now,
                )

    async def cache_fact_check_result(self, result: FactCheckResultWrite) -> UUID:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            existing = await connection.fetchval(
                """SELECT id FROM fact_check_results
                   WHERE analysis_id=$1 AND claim_hash=$2 AND comparator_version=$3
                     AND source_policy_version=$4""",
                result.analysis_id,
                result.claim_hash,
                result.comparator_version,
                result.source_policy_version,
            )
            if existing:
                return existing
            await connection.execute(
                """INSERT INTO fact_check_results(
                       id,analysis_id,claim_hash,claim_ciphertext,language,is_temporal,claim_date_start,claim_date_end,
                       stance,evidence_refs,contradiction_refs,limitations,comparator_model,
                       comparator_version,source_policy_version,fresh_until,embedding_status,created_at,updated_at
                   ) VALUES($1,$2,$3,CASE WHEN $4::text IS NULL THEN NULL ELSE pgp_sym_encrypt($4,$5) END,
                            $6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15,$16,$17,$18,$19,$19)""",
                result.result_id,
                result.analysis_id,
                result.claim_hash,
                result.normalized_claim,
                self._encryption_key,
                result.language,
                result.is_temporal,
                result.claim_date_start,
                result.claim_date_end,
                result.stance,
                json.dumps(result.evidence_refs),
                json.dumps(result.contradiction_refs),
                json.dumps(result.limitations),
                result.comparator_model,
                result.comparator_version,
                result.source_policy_version,
                result.fresh_until,
                result.embedding_status,
                result.created_at,
            )
            snapshot_ids: dict[str, UUID] = {}
            for evidence in result.evidence:
                snapshot_id = uuid4()
                row = await connection.fetchrow(
                    """INSERT INTO fact_check_evidence_snapshots(
                           id,result_id,evidence_ref,source,source_version,source_tier,policy_version,
                           canonical_url,cleaned_content,published_at,source_updated_at,effective_from,effective_to,
                           retrieved_at,temporal_compatible,proxy_penalty,content_hash,validation_status,promotion_status
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'runtime')
                       ON CONFLICT(canonical_url,content_hash,source_version) DO UPDATE
                         SET retrieved_at=GREATEST(fact_check_evidence_snapshots.retrieved_at,EXCLUDED.retrieved_at)
                       RETURNING id""",
                    snapshot_id,
                    result.result_id,
                    evidence.evidence_ref,
                    evidence.source,
                    evidence.source_version,
                    evidence.source_tier.value,
                    evidence.policy_version,
                    evidence.canonical_url,
                    evidence.cleaned_content,
                    evidence.published_at,
                    evidence.source_updated_at,
                    evidence.effective_from,
                    evidence.effective_to,
                    evidence.retrieved_at,
                    evidence.temporal_compatible,
                    evidence.proxy_penalty,
                    evidence.content_hash,
                    evidence.validation_status,
                )
                snapshot_ids[evidence.evidence_ref] = row["id"]
            for chunk in result.chunks:
                snapshot_id = snapshot_ids.get(chunk.evidence_ref)
                if snapshot_id is None:
                    continue
                await connection.execute(
                    """INSERT INTO fact_check_chunks(
                           id,evidence_snapshot_id,chunk_index,cleaned_text,content_hash,source,source_version,
                           source_tier,published_at,effective_from,effective_to,retrieved_at,splitter_version
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                       ON CONFLICT(evidence_snapshot_id,chunk_index,splitter_version) DO NOTHING""",
                    chunk.chunk_ref,
                    snapshot_id,
                    chunk.index,
                    chunk.text,
                    chunk.content_hash,
                    chunk.source,
                    chunk.source_version,
                    chunk.source_tier.value,
                    chunk.published_at,
                    chunk.effective_from,
                    chunk.effective_to,
                    chunk.retrieved_at,
                    chunk.splitter_version,
                )
            if result.embedding_status == "pending":
                now = datetime.now(UTC)
                await connection.execute(
                    """INSERT INTO analysis_jobs(
                           id,analysis_id,kind,status,max_attempts,available_at,idempotency_key,created_at,updated_at
                       ) VALUES($1,$2,'reembed_fact_check_result','queued',3,$3,$4,$3,$3)
                       ON CONFLICT(idempotency_key) DO NOTHING""",
                    uuid4(),
                    result.analysis_id,
                    now,
                    f"fact-result:{result.result_id}:embed:{result.embedding_model}:{result.embedding_version}",
                )
        return result.result_id

    async def cache_corpus_record(self, record: FactCheckCorpusRecordWrite) -> UUID:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            existing = await connection.fetchval(
                """SELECT id FROM fact_check_records
                   WHERE source_id=$1 AND content_hash=$2 AND record_version=$3""",
                record.source_id,
                record.content_hash,
                record.record_version,
            )
            if existing:
                return existing
            await connection.execute(
                """INSERT INTO fact_check_records(
                       id,source_id,source_url,publisher,normalized_claim,stance,language,
                       claim_date_start,claim_date_end,published_at,source_updated_at,
                       effective_from,effective_to,retrieved_at,ingested_at,fresh_until,
                       temporal_proxy,temporal_penalty,content_hash,record_version,
                       ingestion_provenance,policy_version,promotion_status
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                            $17,$18,$19,$20,$21,$22,$23)""",
                record.record_id,
                record.source_id,
                _safe_url_or_text(record.source_url),
                record.publisher,
                record.normalized_claim,
                record.stance,
                record.language,
                record.claim_date_start,
                record.claim_date_end,
                record.published_at,
                record.source_updated_at,
                record.effective_from,
                record.effective_to,
                record.retrieved_at,
                datetime.now(UTC),
                record.fresh_until,
                record.temporal_proxy,
                record.temporal_penalty,
                record.content_hash,
                record.record_version,
                record.ingestion_provenance,
                record.policy_version,
                record.promotion_status,
            )
        return record.record_id

    async def promote_corpus_record(self, record_id: UUID, reviewer_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT r.id,r.promotion_status,s.tier,s.explicit_deny
                   FROM fact_check_records r JOIN fact_check_sources s ON s.id=r.source_id
                   WHERE r.id=$1 FOR UPDATE OF r""",
                record_id,
            )
            if row is None or row["explicit_deny"] or row["tier"] not in {SourceTier.A.value, SourceTier.B.value}:
                return False
            if row["promotion_status"] == "trusted":
                return True
            await connection.execute(
                """UPDATE fact_check_records SET promotion_status='trusted',promoted_by=$2,promoted_at=now()
                   WHERE id=$1""",
                record_id,
                reviewer_id,
            )
        return True

    async def search_fact_check_corpus(
        self,
        query: str,
        *,
        language: str,
        claim_date_start: datetime | None = None,
        claim_date_end: datetime | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """WITH eligible AS (
                     SELECT r.*,s.tier AS source_tier FROM fact_check_records r
                     JOIN fact_check_sources s ON s.id=r.source_id
                     WHERE r.promotion_status='trusted' AND r.language=$2
                       AND s.active AND NOT s.explicit_deny
                       AND (r.fresh_until IS NULL OR r.fresh_until > now())
                       AND ($3::timestamptz IS NULL OR r.published_at <= coalesce($4,$3))
                       AND ($4::timestamptz IS NULL OR coalesce(r.effective_to,r.source_updated_at) >= $3)
                   )
                   SELECT r.*,
                          ts_rank_cd(search_vector,websearch_to_tsquery('simple',$1)) AS lexical_score
                   FROM eligible r
                   WHERE search_vector @@ websearch_to_tsquery('simple',$1)
                   ORDER BY lexical_score DESC,r.published_at DESC LIMIT $5""",
                query,
                language,
                claim_date_start,
                claim_date_end,
                min(limit, 20),
            )
        return [dict(row) for row in rows]

    async def get_reembedding_claim(self, job: DurableJob) -> tuple[UUID, str] | None:
        parts = job.idempotency_key.split(":")
        if len(parts) < 3 or parts[0] != "fact-result":
            return None
        try:
            result_id = UUID(parts[1])
        except ValueError:
            return None
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT id,pgp_sym_decrypt(claim_ciphertext,$2) AS normalized_claim
                   FROM fact_check_results WHERE id=$1 AND embedding_status='pending'""",
                result_id,
                self._encryption_key,
            )
        if row is None or not row["normalized_claim"]:
            return None
        return row["id"], row["normalized_claim"]

    async def complete_reembedding(
        self,
        result_id: UUID,
        *,
        vector: list[float],
        model: str,
        model_version: str,
        embedding_version: str,
        embedded_at: datetime,
    ) -> None:
        if len(vector) != 1536:
            raise ValueError("fact-check embeddings must contain 1536 dimensions")
        pool = await self._get_pool()
        vector_literal = "[" + ",".join(str(value) for value in vector) + "]"
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO fact_check_result_embeddings(
                       result_id,embedding_version,model,model_version,dimensions,embedding,embedded_at
                   ) VALUES($1,$2,$3,$4,1536,$5::double precision[],$6)
                   ON CONFLICT(result_id,embedding_version) DO NOTHING""",
                result_id,
                embedding_version,
                model,
                model_version,
                vector_literal,
                embedded_at,
            )
            await connection.execute(
                """UPDATE fact_check_results SET embedding_status='complete',updated_at=$2
                   WHERE id=$1 AND embedding_status='pending'""",
                result_id,
                embedded_at,
            )

    async def promote_evidence(self, result_id: UUID, evidence_ref: str, reviewer_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT e.id,e.source_tier,e.validation_status,e.promotion_status
                   FROM fact_check_evidence_snapshots e
                   WHERE e.result_id=$1 AND e.evidence_ref=$2 FOR UPDATE""",
                result_id,
                evidence_ref,
            )
            if (
                row is None
                or row["source_tier"] not in {SourceTier.A.value, SourceTier.B.value}
                or row["validation_status"] != "validated"
            ):
                return False
            if row["promotion_status"] == "trusted":
                return True
            await connection.execute(
                """UPDATE fact_check_evidence_snapshots
                   SET promotion_status='trusted',promoted_by=$2,promoted_at=now() WHERE id=$1""",
                row["id"],
                reviewer_id,
            )
        return True

    async def record_usage(self, entry: UsageLedgerEntry) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """INSERT INTO tool_usage(
                       id,analysis_id,step_id,provider,model,provider_version,operation,units,
                       input_tokens,output_tokens,estimated_cost,latency_ms,cache_status,outcome,
                       http_class,observed_at,quota_used
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                   ON CONFLICT(id) DO NOTHING""",
                entry.usage_id,
                entry.analysis_id,
                entry.step_id,
                entry.provider,
                entry.model,
                entry.provider_version,
                entry.operation,
                entry.units,
                entry.input_tokens,
                entry.output_tokens,
                entry.estimated_cost_usd,
                entry.latency_ms,
                entry.cache_status,
                entry.outcome,
                entry.http_class,
                entry.observed_at,
                entry.quota_used,
            )

    async def record_campaign(self, campaign: CampaignWrite) -> CampaignDetailV3:
        if len({item[0] for item in campaign.members}) < 3:
            raise ValueError("campaign requires at least three distinct analyses")
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO campaign_clusters(
                       id,hypothesis,window_started_at,window_ended_at,similarity_threshold,
                       minimum_analyses,clustering_version,reviewer_status,created_at,updated_at
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,'pending_review',$8,$8)
                   ON CONFLICT(id) DO NOTHING""",
                campaign.campaign_id,
                campaign.hypothesis,
                campaign.window_started_at,
                campaign.window_ended_at,
                campaign.similarity_threshold,
                campaign.minimum_analyses,
                campaign.clustering_version,
                now,
            )
            for analysis_id, match_kind, similarity, refs in campaign.members:
                await connection.execute(
                    """INSERT INTO campaign_members(
                           campaign_id,analysis_id,match_kind,similarity,evidence_refs
                       ) VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT DO NOTHING""",
                    campaign.campaign_id,
                    analysis_id,
                    match_kind,
                    similarity,
                    json.dumps(refs),
                )
            signals = dict(campaign.aggregate_signals)
            signals.update({f"domain:{value}": 1 for value in campaign.registrable_domains})
            signals.update({f"redirect:{value}": 1 for value in campaign.redirect_targets})
            for signal, count in signals.items():
                await connection.execute(
                    """INSERT INTO campaign_signals(campaign_id,signal,signal_count) VALUES($1,$2,$3)
                       ON CONFLICT(campaign_id,signal) DO UPDATE
                       SET signal_count=GREATEST(campaign_signals.signal_count,EXCLUDED.signal_count)""",
                    campaign.campaign_id,
                    signal,
                    count,
                )
        detail = await self.get_campaign(campaign.campaign_id)
        if detail is None:
            raise RuntimeError("campaign persistence failed")
        return detail

    async def add_campaign_observation(self, observation: Any) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO campaign_observations(
                       analysis_id,observed_at,registrable_domains,redirect_targets,evidence_refs
                   ) VALUES($1,$2,$3::jsonb,$4::jsonb,$5::jsonb) ON CONFLICT(analysis_id) DO NOTHING""",
                UUID(observation.analysis_id),
                observation.observed_at,
                json.dumps(observation.registrable_domains),
                json.dumps(observation.redirect_targets),
                json.dumps(observation.evidence_refs),
            )
            for feature in observation.claim_features:
                if len(feature.vector) != 1536:
                    continue
                await connection.execute(
                    """INSERT INTO campaign_claim_features(analysis_id,feature_ref,embedding)
                       VALUES($1,$2,$3::double precision[]) ON CONFLICT DO NOTHING""",
                    UUID(observation.analysis_id),
                    feature.feature_ref,
                    feature.vector,
                )

    async def recent_campaign_observations(self, since: datetime):
        from src.agents.campaign import CampaignObservation, ClaimFeature

        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT analysis_id,observed_at,registrable_domains,redirect_targets,evidence_refs
                   FROM campaign_observations WHERE observed_at >= $1 ORDER BY observed_at""",
                since,
            )
            features = await connection.fetch(
                """SELECT f.analysis_id,f.feature_ref,f.embedding
                   FROM campaign_claim_features f JOIN campaign_observations o ON o.analysis_id=f.analysis_id
                   WHERE o.observed_at >= $1""",
                since,
            )
        by_analysis: dict[UUID, list[ClaimFeature]] = {}
        for row in features:
            values = tuple(float(value) for value in row["embedding"])
            by_analysis.setdefault(row["analysis_id"], []).append(ClaimFeature(row["feature_ref"], values))
        return [
            CampaignObservation(
                analysis_id=str(row["analysis_id"]),
                observed_at=row["observed_at"],
                registrable_domains=tuple(_json_value(row["registrable_domains"])),
                redirect_targets=tuple(_json_value(row["redirect_targets"])),
                claim_features=tuple(by_analysis.get(row["analysis_id"], ())),
                evidence_refs=tuple(_json_value(row["evidence_refs"])),
            )
            for row in rows
        ]

    async def list_campaigns(
        self, reviewer_status: CampaignReviewerStatus | None, limit: int, offset: int
    ) -> tuple[list[CampaignSummaryV3], int]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            where, args = (
                ("", []) if reviewer_status is None else ("WHERE c.reviewer_status=$1", [reviewer_status.value])
            )
            limit_pos, offset_pos = len(args) + 1, len(args) + 2
            rows = await connection.fetch(
                f"""SELECT c.*,count(DISTINCT m.analysis_id) AS analysis_count
                    FROM campaign_clusters c LEFT JOIN campaign_members m ON m.campaign_id=c.id
                    {where} GROUP BY c.id ORDER BY c.created_at DESC
                    LIMIT ${limit_pos} OFFSET ${offset_pos}""",
                *args,
                limit,
                offset,
            )
            total = await connection.fetchval(f"SELECT count(*) FROM campaign_clusters c {where}", *args)
            signals = await self._campaign_signals(connection, [row["id"] for row in rows])
        return [self._campaign_summary(row, signals[row["id"]]) for row in rows], int(total)

    async def get_campaign(self, campaign_id: UUID) -> CampaignDetailV3 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT c.*,count(DISTINCT m.analysis_id) AS analysis_count
                   FROM campaign_clusters c LEFT JOIN campaign_members m ON m.campaign_id=c.id
                   WHERE c.id=$1 GROUP BY c.id""",
                campaign_id,
            )
            if row is None:
                return None
            signals = (await self._campaign_signals(connection, [campaign_id]))[campaign_id]
            members = await connection.fetch(
                "SELECT evidence_refs FROM campaign_members WHERE campaign_id=$1", campaign_id
            )
        domains = [signal.removeprefix("domain:") for signal, _ in signals if signal.startswith("domain:")]
        redirects = [signal.removeprefix("redirect:") for signal, _ in signals if signal.startswith("redirect:")]
        public_signals = [
            (signal, count) for signal, count in signals if not signal.startswith(("domain:", "redirect:"))
        ]
        evidence_refs = list(dict.fromkeys(ref for member in members for ref in _json_value(member["evidence_refs"])))
        return CampaignDetailV3(
            **self._campaign_summary(row, public_signals).model_dump(),
            evidence_refs=evidence_refs,
            registrable_domains=domains,
            redirect_targets=redirects,
            reviewer_id=row["reviewer_id"],
            review_note=row["review_note"],
            reviewed_at=row["reviewed_at"],
        )

    async def review_campaign(
        self, campaign_id: UUID, status: CampaignReviewerStatus, note: str, reviewer_id: str
    ) -> CampaignDetailV3 | None:
        if status is CampaignReviewerStatus.PENDING_REVIEW:
            raise ValueError("campaign review must be confirmed or rejected")
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection:
            updated = await connection.execute(
                """UPDATE campaign_clusters SET reviewer_status=$2,reviewer_id=$3,review_note=$4,
                          reviewed_at=$5,updated_at=$5,version=version+1
                   WHERE id=$1 AND reviewer_status='pending_review'""",
                campaign_id,
                status.value,
                reviewer_id,
                note.strip(),
                now,
            )
        if updated != "UPDATE 1":
            existing = await self.get_campaign(campaign_id)
            if existing is None:
                return None
            raise PlatformError(
                status_code=409,
                code=ErrorCode.INTERNAL_ERROR,
                message="Campaign was already reviewed.",
                retryable=False,
            )
        return await self.get_campaign(campaign_id)

    @staticmethod
    async def _campaign_signals(connection, campaign_ids: list[UUID]) -> dict[UUID, list[tuple[str, int]]]:
        result: dict[UUID, list[tuple[str, int]]] = {item: [] for item in campaign_ids}
        if not campaign_ids:
            return result
        rows = await connection.fetch(
            "SELECT campaign_id,signal,signal_count FROM campaign_signals WHERE campaign_id=ANY($1::uuid[])",
            campaign_ids,
        )
        for row in rows:
            result[row["campaign_id"]].append((row["signal"], row["signal_count"]))
        return result

    @staticmethod
    def _campaign_summary(row, signals: list[tuple[str, int]]) -> CampaignSummaryV3:
        return CampaignSummaryV3(
            campaign_id=row["id"],
            hypothesis=row["hypothesis"],
            window_started_at=row["window_started_at"],
            window_ended_at=row["window_ended_at"],
            analysis_count=row["analysis_count"],
            aggregate_signals=[
                CampaignAggregateSignalV3(signal=signal, count=count)
                for signal, count in signals
                if not signal.startswith(("domain:", "redirect:"))
            ],
            reviewer_status=CampaignReviewerStatus(row["reviewer_status"]),
            clustering_version=row["clustering_version"],
        )

    async def expire_minimized_content(self, now: datetime) -> int:
        """Cryptographically replace retained user input while preserving immutable audit rows."""
        pool = await self._get_pool()
        tombstone = json.dumps({"message": "[deleted]", "consent_to_scan_urls": False})
        async with pool.acquire() as connection:
            result = await connection.execute(
                """UPDATE analyses SET
                     input_ciphertext=pgp_sym_encrypt($1,$2),
                     input_hash=$3,
                     content_deleted_at=$4,
                     version=version+1
                   WHERE content_deleted_at IS NULL AND content_expires_at <= $4""",
                tombstone,
                self._encryption_key,
                hashlib.sha256(tombstone.encode()).hexdigest(),
                now,
            )
        return int(result.removeprefix("UPDATE "))

    async def expire_security_job_payloads(self, now: datetime) -> int:
        """Purge abandoned encrypted v4 input no later than its 24-hour TTL."""
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            rows = await connection.fetch(
                """DELETE FROM security_analysis_payloads_v4
                   WHERE expires_at <= $1 RETURNING analysis_id""",
                now,
            )
            if rows:
                analysis_ids = [row["analysis_id"] for row in rows]
                await connection.execute(
                    """UPDATE security_analysis_jobs_v4 SET status='failed',failure_code='PAYLOAD_EXPIRED',
                              lease_expires_at=NULL,worker_id=NULL,updated_at=$2
                       WHERE analysis_id=ANY($1::uuid[]) AND status IN ('queued','running')""",
                    analysis_ids,
                    now,
                )
                for analysis_id in analysis_ids:
                    stored = await connection.fetchrow(
                        "SELECT response FROM security_analyses WHERE id=$1 FOR UPDATE",
                        analysis_id,
                    )
                    if stored is None:
                        continue
                    response = SecurityScopeResponseV4.model_validate(_json_value(stored["response"])).model_copy(
                        update={"status": "failed", "completed_at": now}
                    )
                    sequence = await connection.fetchval(
                        "SELECT COALESCE(MAX(sequence),0)+1 FROM security_analysis_events WHERE analysis_id=$1",
                        analysis_id,
                    )
                    event = SecurityAnalysisEventV4(
                        analysis_id=analysis_id,
                        sequence=sequence,
                        status="failed",
                        step="payload_expired",
                        kind="final",
                        message="Encrypted Security v4 payload expired before processing completed.",
                        occurred_at=now,
                    )
                    await connection.execute(
                        """UPDATE security_analyses SET status='failed',response=$2::jsonb,
                                  updated_at=$3,completed_at=$3 WHERE id=$1""",
                        analysis_id,
                        response.model_dump_json(),
                        now,
                    )
                    await connection.execute(
                        """INSERT INTO security_analysis_events(
                               event_id,analysis_id,sequence,event_type,payload,occurred_at
                           ) VALUES($1,$2,$3,'final',$4::jsonb,$5)""",
                        event.event_id,
                        analysis_id,
                        sequence,
                        event.model_dump_json(),
                        now,
                    )
                    await connection.execute(
                        """INSERT INTO security_analysis_outbox_v4(
                               id,analysis_id,event_type,payload,idempotency_key,created_at
                           ) VALUES($1,$2,'security_analysis.final',$3::jsonb,$4,$5)
                           ON CONFLICT(idempotency_key) DO NOTHING""",
                        uuid4(),
                        analysis_id,
                        event.model_dump_json(),
                        f"security-v4-event:{analysis_id}:{sequence}",
                        now,
                    )
        return len(rows)

    async def operations_metrics(self, started_at: datetime, ended_at: datetime) -> OperationsMetricsResponseV3:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            latency_rows = await connection.fetch(
                """SELECT operation,count(*) AS calls,
                          percentile_cont(0.5) WITHIN GROUP(ORDER BY latency_ms) AS p50,
                          percentile_cont(0.95) WITHIN GROUP(ORDER BY latency_ms) AS p95,
                          percentile_cont(0.99) WITHIN GROUP(ORDER BY latency_ms) AS p99
                   FROM tool_usage WHERE observed_at >= $1 AND observed_at < $2 GROUP BY operation""",
                started_at,
                ended_at,
            )
            cache_rows = await connection.fetch(
                """SELECT provider,count(*) FILTER(WHERE cache_status='hit') AS hits,
                          count(*) FILTER(WHERE cache_status='miss') AS misses
                   FROM tool_usage WHERE observed_at >= $1 AND observed_at < $2 GROUP BY provider""",
                started_at,
                ended_at,
            )
            usage_rows = await connection.fetch(
                """SELECT provider,model,count(*) AS calls,
                          coalesce(sum(coalesce(input_tokens,0)+coalesce(output_tokens,0)),0) AS tokens,
                          coalesce(sum(estimated_cost),0) AS cost,max(quota_used) AS quota_used,
                          count(*) FILTER(WHERE outcome='rate_limited' OR http_class='429') AS rate_limited,
                          count(*) FILTER(WHERE outcome='timeout') AS timed_out
                   FROM tool_usage WHERE observed_at >= $1 AND observed_at < $2 GROUP BY provider,model""",
                started_at,
                ended_at,
            )
            risk_rows = await connection.fetch(
                """SELECT response->>'risk_level' AS risk_level,count(*) AS count
                   FROM analyses WHERE created_at >= $1 AND created_at < $2
                     AND response->>'risk_level' IS NOT NULL GROUP BY response->>'risk_level'""",
                started_at,
                ended_at,
            )
            reports = await connection.fetchval(
                "SELECT count(*) FROM analysis_reports WHERE created_at >= $1 AND created_at < $2",
                started_at,
                ended_at,
            )
            appeal_rows = await connection.fetchrow(
                """SELECT count(*) AS total,
                          count(*) FILTER(WHERE outcome='uphold') AS upheld,
                          count(*) FILTER(WHERE outcome='overturn') AS overturned,
                          count(*) FILTER(WHERE outcome='inconclusive') AS inconclusive
                   FROM appeals WHERE created_at >= $1 AND created_at < $2""",
                started_at,
                ended_at,
            )
        risk_counts = {row["risk_level"]: row["count"] for row in risk_rows}
        total_appeals = appeal_rows["total"]
        return OperationsMetricsResponseV3(
            window=MetricsWindowV3(started_at=started_at, ended_at=ended_at),
            generated_at=datetime.now(UTC),
            latency=[
                LatencyMetricV3(
                    operation=row["operation"],
                    count=row["calls"],
                    p50_ms=row["p50"],
                    p95_ms=row["p95"],
                    p99_ms=row["p99"],
                )
                for row in latency_rows
            ],
            cache=[
                CacheMetricV3(
                    provider=row["provider"],
                    hits=row["hits"],
                    misses=row["misses"],
                    hit_rate=row["hits"] / (row["hits"] + row["misses"]) if row["hits"] + row["misses"] else None,
                )
                for row in cache_rows
            ],
            usage=[
                UsageMetricV3(
                    provider=row["provider"],
                    model=row["model"],
                    calls=row["calls"],
                    tokens=row["tokens"],
                    estimated_cost_usd=float(row["cost"]),
                    quota_used=float(row["quota_used"]) if row["quota_used"] is not None else None,
                    rate_limited=row["rate_limited"],
                    timed_out=row["timed_out"],
                )
                for row in usage_rows
            ],
            risk_distribution=[
                RiskDistributionMetricV3(risk_level=level, count=risk_counts.get(level.value, 0)) for level in RiskLevel
            ],
            feedback=FeedbackMetricV3(
                reports=reports,
                appeals=total_appeals,
                appeals_upheld=appeal_rows["upheld"],
                appeals_overturned=appeal_rows["overturned"],
                appeals_inconclusive=appeal_rows["inconclusive"],
                false_positive_rate=appeal_rows["overturned"] / total_appeals if total_appeals else None,
            ),
        )

    @staticmethod
    def _review_queue_item(row) -> ReviewQueueItem:
        snapshot = _json_value(row["evidence_snapshot"])
        return ReviewQueueItem(
            item_id=row["id"],
            report_id=row["report_id"],
            analysis_id=row["analysis_id"],
            status=ReportStatus(row["status"]),
            reason=row["reason"],
            comment=row["comment"],
            analysis_content=row["analysis_content"],
            evidence_snapshot=[Evidence.model_validate(item) for item in snapshot],
            decision=ReportReviewDecision(row["decision"]) if row["decision"] else None,
            reviewer_id=row["reviewer_id"],
            reviewer_note=row["reviewer_note"],
            reviewed_at=row["reviewed_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def close(self) -> None:
        if self._owns_pool and self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def healthcheck(self) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            return bool(await connection.fetchval("SELECT 1"))


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _analysis_request_from_json(value: str) -> AnalysisCreateRequest:
    payload = json.loads(value)
    return AnalysisCreateRequestV3.model_validate(payload)


class LostJobLeaseError(RuntimeError):
    pass


def _safe_url_or_text(value: str) -> str:
    """Remove credentials, query strings, and fragments before persistence."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value[:500]
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return value[:500]
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit((parsed.scheme, f"{parsed.hostname}{port}", parsed.path, "", ""))[:2000]


def _canonical_domain_or_target(value: str) -> str:
    target = value.strip().lower()
    try:
        parsed = urlsplit(target if "://" in target else f"https://{target}")
    except ValueError:
        return target[:500]
    if parsed.hostname is None:
        raise ValueError("admin action target must contain a hostname")
    hostname = normalize_hostname(parsed.hostname)
    if DEFAULT_PUBLIC_SUFFIX_LIST.registrable_domain(hostname) is None:
        raise ValueError("admin action target must be a registrable domain")
    return hostname


def _platform_conflict(message: str) -> PlatformError:
    return PlatformError(
        status_code=409,
        code=ErrorCode.INTERNAL_ERROR,
        message=message,
        retryable=False,
    )
