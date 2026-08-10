from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.core.auth import Principal, UserRole
from src.core.errors import PlatformError
from src.models import (
    AdminActionDecisionResponseV3,
    AdminActionPageV3,
    AdminActionRecordV3,
    AdminActionStatus,
    AppealAdminRecordV3,
    AppealCreateRequestV3,
    AppealDecisionRequestV3,
    AppealDecisionResponseV3,
    AppealPageV3,
    AppealReceiptV3,
    AppealResponseV3,
    AppealStatus,
    CacheMetricV3,
    CampaignAggregateSignalV3,
    CampaignDetailV3,
    CampaignPageV3,
    CampaignReviewerStatus,
    CampaignSummaryV3,
    ErrorCode,
    Evidence,
    FeedbackMetricV3,
    LatencyMetricV3,
    MetricsWindowV3,
    OperationsMetricsResponseV3,
    ReviewDecision,
    ReviewedAction,
    RiskDistributionMetricV3,
    RiskLevel,
    UsageMetricV3,
)


class PlatformInternalModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceTier(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    UNTRUSTED = "UNTRUSTED"


class SourceRegistryEntry(PlatformInternalModel):
    source_id: UUID = Field(default_factory=uuid4)
    publisher: str
    normalized_pattern: str
    tier: SourceTier
    source_type: str
    active: bool = True
    explicit_deny: bool = False
    trusted_claim_review: bool = False
    allowed_operations: set[str]
    policy_version: str
    effective_from: datetime
    effective_to: datetime | None = None
    default_freshness_seconds: int = Field(gt=0)
    reviewer_id: str
    reviewed_at: datetime

    @field_validator("normalized_pattern")
    @classmethod
    def normalize_pattern(cls, value: str) -> str:
        pattern = value.strip().lower().rstrip(".")
        if "://" in pattern:
            parsed = urlsplit(pattern)
            pattern = (parsed.hostname or "").lower().rstrip(".")
        suffix = pattern.removeprefix("*.")
        if not suffix or "/" in suffix or "@" in suffix or "." not in suffix:
            raise ValueError("source pattern must be an exact hostname or a wildcard hostname")
        return pattern

    @model_validator(mode="after")
    def validate_policy(self) -> SourceRegistryEntry:
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("source policy effective_to must be after effective_from")
        if self.explicit_deny and self.allowed_operations:
            raise ValueError("an explicit deny cannot allow operations")
        return self


class SourcePolicyDecision(PlatformInternalModel):
    source_id: UUID | None = None
    publisher: str | None = None
    tier: SourceTier = SourceTier.UNTRUSTED
    source_type: str = "untrusted"
    allowed_operations: set[str] = Field(default_factory=set)
    policy_version: str = "unregistered"
    explicit_deny: bool = False
    trusted_claim_review: bool = False

    def allows(self, operation: str) -> bool:
        return not self.explicit_deny and operation in self.allowed_operations


class EvidenceSnapshotWrite(PlatformInternalModel):
    evidence_ref: str
    source: str
    source_version: str
    source_tier: SourceTier
    policy_version: str
    canonical_url: str
    cleaned_content: str
    published_at: datetime | None = None
    source_updated_at: datetime | None = None
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    retrieved_at: datetime
    temporal_compatible: bool
    proxy_penalty: float = Field(default=0, ge=0, le=1)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    validation_status: str = "unreviewed"

    @field_validator("canonical_url")
    @classmethod
    def safe_public_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("evidence URL must be a credential-free public HTTP(S) URL")
        return f"{parsed.scheme}://{parsed.hostname.lower()}{parsed.path or '/'}"


class EvidenceChunkWrite(PlatformInternalModel):
    chunk_ref: str
    evidence_ref: str
    index: int = Field(ge=0)
    text: str
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: str
    source_version: str
    source_tier: SourceTier
    published_at: datetime | None = None
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    retrieved_at: datetime
    splitter_version: str


class FactCheckResultWrite(PlatformInternalModel):
    result_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    claim_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    normalized_claim: str | None = Field(default=None, exclude=True)
    language: str
    is_temporal: bool
    claim_date_start: datetime | None = None
    claim_date_end: datetime | None = None
    stance: str
    evidence_refs: list[str]
    contradiction_refs: list[str]
    limitations: list[str]
    comparator_model: str
    comparator_version: str
    source_policy_version: str
    fresh_until: datetime | None = None
    embedding_status: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evidence: list[EvidenceSnapshotWrite] = Field(default_factory=list)
    chunks: list[EvidenceChunkWrite] = Field(default_factory=list)
    embedding_model: str = "text-embedding-3-small"
    embedding_version: str = "v1"

    @model_validator(mode="after")
    def pending_embedding_requires_minimized_claim(self) -> FactCheckResultWrite:
        if self.embedding_status == "pending" and not self.normalized_claim:
            raise ValueError("pending embedding requires a minimized normalized claim")
        return self


class FactCheckCorpusRecordWrite(PlatformInternalModel):
    record_id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    source_url: str
    publisher: str
    normalized_claim: str
    stance: str
    language: str
    claim_date_start: datetime | None = None
    claim_date_end: datetime | None = None
    published_at: datetime
    source_updated_at: datetime
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    retrieved_at: datetime
    fresh_until: datetime | None = None
    temporal_proxy: bool = False
    temporal_penalty: float = Field(default=0, ge=0, le=1)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_version: str
    ingestion_provenance: str
    policy_version: str
    promotion_status: str = "pending_review"


class UsageLedgerEntry(PlatformInternalModel):
    usage_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    step_id: str | None = None
    provider: str
    model: str | None = None
    provider_version: str
    operation: str
    units: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(default=0, ge=0)
    latency_ms: int = Field(ge=0)
    cache_status: str
    outcome: str
    http_class: str | None = None
    quota_used: float | None = Field(default=None, ge=0)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CampaignWrite(PlatformInternalModel):
    campaign_id: UUID = Field(default_factory=uuid4)
    hypothesis: str
    window_started_at: datetime
    window_ended_at: datetime
    similarity_threshold: float = Field(default=0.85, ge=0, le=1)
    minimum_analyses: int = Field(default=3, ge=3)
    clustering_version: str
    members: list[tuple[UUID, str, float | None, list[str]]]
    aggregate_signals: dict[str, int]
    evidence_refs: list[str]
    registrable_domains: list[str] = Field(default_factory=list)
    redirect_targets: list[str] = Field(default_factory=list)


class ArtifactRecord(PlatformInternalModel):
    artifact_id: UUID = Field(default_factory=uuid4)
    analysis_id: UUID
    owner_id: str
    storage_key: str
    media_type: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    deleted_at: datetime | None = None


class ArtifactAccess(PlatformInternalModel):
    artifact_id: UUID
    access_path: str
    expires_at: datetime


class Wave2Repository(Protocol):
    async def create_appeal(
        self, analysis_id: UUID, owner_id: str, request: AppealCreateRequestV3, evidence: list[Evidence]
    ) -> AppealReceiptV3: ...

    async def get_appeal(self, appeal_id: UUID) -> tuple[str, AppealResponseV3] | None: ...

    async def list_appeals(
        self, status: AppealStatus | None, limit: int, offset: int
    ) -> tuple[list[AppealAdminRecordV3], int]: ...

    async def decide_appeal(
        self, appeal_id: UUID, request: AppealDecisionRequestV3, reviewer_id: str
    ) -> AppealDecisionResponseV3 | None: ...

    async def list_admin_actions(
        self, status: AdminActionStatus | None, limit: int, offset: int
    ) -> tuple[list[AdminActionRecordV3], int]: ...

    async def get_admin_action(self, action_id: UUID) -> AdminActionRecordV3 | None: ...

    async def decide_admin_action(
        self, action_id: UUID, decision: ReviewDecision, note: str, reviewer_id: str
    ) -> AdminActionDecisionResponseV3 | None: ...

    async def list_campaigns(
        self, status: CampaignReviewerStatus | None, limit: int, offset: int
    ) -> tuple[list[CampaignSummaryV3], int]: ...

    async def get_campaign(self, campaign_id: UUID) -> CampaignDetailV3 | None: ...

    async def operations_metrics(self, started_at: datetime, ended_at: datetime) -> OperationsMetricsResponseV3: ...


@dataclass(slots=True)
class _MemoryAppeal:
    owner_id: str
    response: AppealResponseV3
    evidence: list[Evidence]


def default_source_policies() -> list[SourceRegistryEntry]:
    reviewed_at = datetime(2026, 1, 1, tzinfo=UTC)
    return [
        SourceRegistryEntry(
            source_id=UUID("00000000-0000-4000-8000-000000000005"),
            publisher="Vietnam government",
            normalized_pattern="*.gov.vn",
            tier=SourceTier.A,
            source_type="government",
            allowed_operations={"search", "read", "compare", "promote"},
            policy_version="source-policy-v1",
            effective_from=reviewed_at,
            default_freshness_seconds=21600,
            reviewer_id="system-bootstrap",
            reviewed_at=reviewed_at,
        )
    ]


@dataclass(slots=True)
class MemoryWave2Repository:
    """Process-local adapter for offline tests; production always selects PostgreSQL."""

    appeals: dict[UUID, _MemoryAppeal] = field(default_factory=dict)
    actions: dict[UUID, AdminActionRecordV3] = field(default_factory=dict)
    campaigns: dict[UUID, CampaignDetailV3] = field(default_factory=dict)
    sources: list[SourceRegistryEntry] = field(default_factory=default_source_policies)
    fact_results: dict[UUID, FactCheckResultWrite] = field(default_factory=dict)
    corpus_records: dict[UUID, FactCheckCorpusRecordWrite] = field(default_factory=dict)
    usage: list[UsageLedgerEntry] = field(default_factory=list)
    artifacts: dict[UUID, ArtifactRecord] = field(default_factory=dict)
    notifications: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def create_appeal(
        self, analysis_id: UUID, owner_id: str, request: AppealCreateRequestV3, evidence: list[Evidence]
    ) -> AppealReceiptV3:
        async with self._lock:
            if any(
                item.owner_id == owner_id
                and item.response.analysis_id == analysis_id
                and item.response.status is not AppealStatus.RESOLVED
                for item in self.appeals.values()
            ):
                raise _conflict("An active appeal already exists for this analysis.")
            now, appeal_id = datetime.now(UTC), uuid4()
            response = AppealResponseV3(
                appeal_id=appeal_id,
                analysis_id=analysis_id,
                status=AppealStatus.SUBMITTED,
                reason=request.reason,
                comment=request.comment,
                created_at=now,
            )
            self.appeals[appeal_id] = _MemoryAppeal(owner_id, response, list(evidence))
            return AppealReceiptV3(
                appeal_id=appeal_id, analysis_id=analysis_id, status=AppealStatus.SUBMITTED, created_at=now
            )

    async def get_appeal(self, appeal_id: UUID) -> tuple[str, AppealResponseV3] | None:
        item = self.appeals.get(appeal_id)
        return (item.owner_id, item.response.model_copy(deep=True)) if item else None

    async def list_appeals(
        self, status: AppealStatus | None, limit: int, offset: int
    ) -> tuple[list[AppealAdminRecordV3], int]:
        rows = [item for item in self.appeals.values() if status is None or item.response.status is status]
        rows.sort(key=lambda item: item.response.created_at, reverse=True)
        return (
            [
                AppealAdminRecordV3(owner_id=item.owner_id, **item.response.model_dump(exclude={"contract_version"}))
                for item in rows[offset : offset + limit]
            ],
            len(rows),
        )

    async def decide_appeal(
        self, appeal_id: UUID, request: AppealDecisionRequestV3, reviewer_id: str
    ) -> AppealDecisionResponseV3 | None:
        async with self._lock:
            item = self.appeals.get(appeal_id)
            if item is None:
                return None
            if item.response.status is AppealStatus.RESOLVED:
                raise _conflict("The appeal has already been resolved.")
            now, decision_id = datetime.now(UTC), uuid4()
            item.response = item.response.model_copy(
                update={
                    "status": AppealStatus.RESOLVED,
                    "outcome": request.outcome,
                    "resolution_note": request.note,
                    "resolved_at": now,
                }
            )
            self.audit.append(
                {
                    "decision_id": decision_id,
                    "appeal_id": appeal_id,
                    "reviewer_id": reviewer_id,
                    "outcome": request.outcome.value,
                    "evidence_snapshot": [e.model_dump(mode="json") for e in item.evidence],
                    "decided_at": now,
                }
            )
            self.notifications.append(
                {
                    "owner_id": item.owner_id,
                    "resource_id": appeal_id,
                    "event_type": "appeal.resolved",
                    "outcome": request.outcome.value,
                }
            )
            return AppealDecisionResponseV3(
                appeal_id=appeal_id, decision_id=decision_id, outcome=request.outcome, decided_at=now
            )

    async def propose_admin_action(
        self,
        *,
        analysis_id: UUID | None,
        campaign_id: UUID | None,
        action: ReviewedAction,
        target: str | None,
        evidence: list[Evidence],
    ) -> AdminActionRecordV3:
        record = AdminActionRecordV3(
            action_id=uuid4(),
            analysis_id=analysis_id,
            campaign_id=campaign_id,
            action=action,
            target=_canonical_target(target) if target else None,
            status=AdminActionStatus.PENDING_REVIEW,
            evidence_snapshot=evidence,
            proposed_at=datetime.now(UTC),
        )
        async with self._lock:
            self.actions[record.action_id] = record
        return record.model_copy(deep=True)

    async def list_admin_actions(
        self, status: AdminActionStatus | None, limit: int, offset: int
    ) -> tuple[list[AdminActionRecordV3], int]:
        rows = [item for item in self.actions.values() if status is None or item.status is status]
        rows.sort(key=lambda item: item.proposed_at, reverse=True)
        return [item.model_copy(deep=True) for item in rows[offset : offset + limit]], len(rows)

    async def get_admin_action(self, action_id: UUID) -> AdminActionRecordV3 | None:
        item = self.actions.get(action_id)
        return item.model_copy(deep=True) if item else None

    async def decide_admin_action(
        self, action_id: UUID, decision: ReviewDecision, note: str, reviewer_id: str
    ) -> AdminActionDecisionResponseV3 | None:
        async with self._lock:
            item = self.actions.get(action_id)
            if item is None:
                return None
            if item.status is not AdminActionStatus.PENDING_REVIEW:
                raise _conflict("The admin action has already been reviewed.")
            now, decision_id = datetime.now(UTC), uuid4()
            status = (
                AdminActionStatus.APPROVED if decision is ReviewDecision.APPROVED else AdminActionStatus.REJECTED
            )
            reviewed = item.model_copy(
                update={
                    "status": status,
                    "reviewer_id": reviewer_id,
                    "review_note": note,
                    "reviewed_at": now,
                }
            )
            self.actions[action_id] = reviewed
            self.audit.append(
                {
                    "decision_id": decision_id,
                    "action_id": action_id,
                    "reviewer_id": reviewer_id,
                    "decision": decision.value,
                    "evidence_snapshot": [e.model_dump(mode="json") for e in item.evidence_snapshot],
                    "decided_at": now,
                }
            )
            return AdminActionDecisionResponseV3(
                action_id=action_id,
                decision_id=decision_id,
                action=item.action,
                status=status,
                reviewed_at=now,
            )

    async def record_campaign(self, campaign: CampaignWrite) -> CampaignDetailV3:
        detail = CampaignDetailV3(
            campaign_id=campaign.campaign_id,
            hypothesis=campaign.hypothesis,
            window_started_at=campaign.window_started_at,
            window_ended_at=campaign.window_ended_at,
            analysis_count=len({item[0] for item in campaign.members}),
            aggregate_signals=[
                CampaignAggregateSignalV3(signal=key, count=value)
                for key, value in sorted(campaign.aggregate_signals.items())
            ],
            reviewer_status=CampaignReviewerStatus.PENDING_REVIEW,
            clustering_version=campaign.clustering_version,
            evidence_refs=campaign.evidence_refs,
            registrable_domains=campaign.registrable_domains,
            redirect_targets=campaign.redirect_targets,
        )
        async with self._lock:
            self.campaigns[detail.campaign_id] = detail
        return detail.model_copy(deep=True)

    async def list_campaigns(
        self, status: CampaignReviewerStatus | None, limit: int, offset: int
    ) -> tuple[list[CampaignSummaryV3], int]:
        rows = [item for item in self.campaigns.values() if status is None or item.reviewer_status is status]
        rows.sort(key=lambda item: item.window_ended_at, reverse=True)
        summaries = [
            CampaignSummaryV3.model_validate(
                item.model_dump(
                    exclude={
                        "contract_version",
                        "evidence_refs",
                        "registrable_domains",
                        "redirect_targets",
                        "reviewer_id",
                        "review_note",
                        "reviewed_at",
                    }
                )
            )
            for item in rows[offset : offset + limit]
        ]
        return summaries, len(rows)

    async def get_campaign(self, campaign_id: UUID) -> CampaignDetailV3 | None:
        item = self.campaigns.get(campaign_id)
        return item.model_copy(deep=True) if item else None

    async def register_source(self, entry: SourceRegistryEntry) -> None:
        async with self._lock:
            if any(
                item.normalized_pattern == entry.normalized_pattern and item.policy_version == entry.policy_version
                for item in self.sources
            ):
                raise _conflict("This source policy version already exists.")
            self.sources.append(entry)

    async def load_source_policies(self, at: datetime) -> list[SourceRegistryEntry]:
        return [
            item.model_copy(deep=True)
            for item in self.sources
            if item.active and item.effective_from <= at and (item.effective_to is None or item.effective_to > at)
        ]

    async def cache_fact_check_result(self, result: FactCheckResultWrite) -> UUID:
        async with self._lock:
            for existing in self.fact_results.values():
                if (
                    existing.claim_hash == result.claim_hash
                    and existing.comparator_version == result.comparator_version
                    and existing.source_policy_version == result.source_policy_version
                ):
                    return existing.result_id
            self.fact_results[result.result_id] = result.model_copy(deep=True)
        return result.result_id

    async def cache_corpus_record(self, record: FactCheckCorpusRecordWrite) -> UUID:
        async with self._lock:
            for existing in self.corpus_records.values():
                if (
                    existing.source_id == record.source_id
                    and existing.content_hash == record.content_hash
                    and existing.record_version == record.record_version
                ):
                    return existing.record_id
            self.corpus_records[record.record_id] = record.model_copy(deep=True)
        return record.record_id

    async def promote_corpus_record(self, record_id: UUID, reviewer_id: str) -> bool:
        async with self._lock:
            record = self.corpus_records.get(record_id)
            if record is None:
                return False
            source = next((item for item in self.sources if item.source_id == record.source_id), None)
            if source is None or source.explicit_deny or source.tier not in {SourceTier.A, SourceTier.B}:
                return False
            self.corpus_records[record_id] = record.model_copy(update={"promotion_status": "trusted"})
            self.audit.append(
                {
                    "record_id": record_id,
                    "reviewer_id": reviewer_id,
                    "event_type": "corpus.promoted",
                    "created_at": datetime.now(UTC),
                }
            )
            return True

    async def promote_evidence(self, result_id: UUID, evidence_ref: str, reviewer_id: str) -> bool:
        async with self._lock:
            result = self.fact_results.get(result_id)
            if result is None:
                return False
            evidence = next((item for item in result.evidence if item.evidence_ref == evidence_ref), None)
            if evidence is None or evidence.validation_status != "validated" or evidence.source_tier not in {
                SourceTier.A,
                SourceTier.B,
            }:
                return False
            self.audit.append(
                {
                    "result_id": result_id,
                    "evidence_ref": evidence_ref,
                    "reviewer_id": reviewer_id,
                    "event_type": "evidence.promoted",
                    "created_at": datetime.now(UTC),
                }
            )
            return True

    async def record_usage(self, entry: UsageLedgerEntry) -> None:
        async with self._lock:
            self.usage.append(entry)

    async def register_artifact(self, artifact: ArtifactRecord) -> None:
        async with self._lock:
            if any(item.storage_key == artifact.storage_key for item in self.artifacts.values()):
                raise _conflict("The artifact storage key already exists.")
            self.artifacts[artifact.artifact_id] = artifact

    async def get_artifact(self, artifact_id: UUID) -> ArtifactRecord | None:
        item = self.artifacts.get(artifact_id)
        return item.model_copy(deep=True) if item else None

    async def expire_artifacts(self, now: datetime) -> list[str]:
        keys = []
        async with self._lock:
            for key, item in list(self.artifacts.items()):
                if item.deleted_at is None and item.expires_at <= now:
                    keys.append(item.storage_key)
                    self.artifacts[key] = item.model_copy(update={"deleted_at": now})
        return keys

    async def operations_metrics(self, started_at: datetime, ended_at: datetime) -> OperationsMetricsResponseV3:
        usage = [item for item in self.usage if started_at <= item.observed_at < ended_at]
        return _aggregate_metrics(started_at, ended_at, usage, self.appeals.values())


class VersionedSourceRegistry:
    def __init__(self, policies: list[SourceRegistryEntry]) -> None:
        self._policies = policies

    def replace(self, policies: list[SourceRegistryEntry]) -> None:
        self._policies = list(policies)

    def classify(self, url: str, at: datetime) -> SourcePolicyDecision:
        hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
        matches = [
            policy
            for policy in self._policies
            if policy.active
            and policy.effective_from <= at
            and (policy.effective_to is None or policy.effective_to > at)
            and _hostname_matches(hostname, policy.normalized_pattern)
        ]
        if not matches:
            return SourcePolicyDecision()
        matches.sort(
            key=lambda item: (
                item.explicit_deny,
                not item.normalized_pattern.startswith("*."),
                len(item.normalized_pattern),
                item.reviewed_at,
            ),
            reverse=True,
        )
        selected = matches[0]
        if selected.explicit_deny:
            return SourcePolicyDecision(
                source_id=selected.source_id,
                publisher=selected.publisher,
                policy_version=selected.policy_version,
                explicit_deny=True,
            )
        return SourcePolicyDecision(
            source_id=selected.source_id,
            publisher=selected.publisher,
            tier=selected.tier,
            source_type=selected.source_type,
            allowed_operations=selected.allowed_operations,
            policy_version=selected.policy_version,
            trusted_claim_review=selected.trusted_claim_review,
        )


class ArtifactSigner:
    def __init__(self, secret: str, ttl_seconds: int = 300) -> None:
        if len(secret) < 16:
            raise ValueError("artifact signing secret must contain at least 16 characters")
        self._secret = secret.encode()
        self._ttl_seconds = ttl_seconds

    def issue(self, artifact_id: UUID, owner_id: str, now: datetime | None = None) -> ArtifactAccess:
        issued_at = now or datetime.now(UTC)
        expires_at = issued_at + timedelta(seconds=self._ttl_seconds)
        payload = base64.urlsafe_b64encode(
            json.dumps(
                {"artifact_id": str(artifact_id), "owner_id": owner_id, "exp": int(expires_at.timestamp())},
                separators=(",", ":"),
            ).encode()
        ).decode().rstrip("=")
        signature = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()
        token = f"{payload}.{signature}"
        return ArtifactAccess(
            artifact_id=artifact_id,
            access_path=f"/api/v3/artifacts/{artifact_id}?token={token}",
            expires_at=expires_at,
        )

    def verify(self, token: str, artifact_id: UUID, owner_id: str, now: datetime | None = None) -> bool:
        try:
            payload, signature = token.rsplit(".", 1)
            expected = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()
            decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode())
            return (
                decoded["artifact_id"] == str(artifact_id)
                and decoded["owner_id"] == owner_id
                and hmac.compare_digest(signature, expected)
                and int(decoded["exp"]) >= int((now or datetime.now(UTC)).timestamp())
            )
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
            return False


class Wave2PlatformService:
    def __init__(
        self,
        repository: Wave2Repository,
        artifact_signer: ArtifactSigner,
        active_source_registry: VersionedSourceRegistry | None = None,
    ) -> None:
        self.repository = repository
        self.artifact_signer = artifact_signer
        self._active_source_registry = active_source_registry

    async def create_appeal(
        self,
        analysis_id: UUID,
        owner_id: str,
        request: AppealCreateRequestV3,
        evidence: list[Evidence],
    ) -> AppealReceiptV3:
        return await self.repository.create_appeal(analysis_id, owner_id, request, evidence)

    async def get_appeal(self, appeal_id: UUID, principal: Principal) -> AppealResponseV3:
        stored = await self.repository.get_appeal(appeal_id)
        if stored is None:
            raise _not_found("Appeal was not found.")
        owner_id, response = stored
        if owner_id != principal.user_id and principal.role is not UserRole.SECURITY_ADMIN:
            raise _forbidden()
        return response

    async def list_appeals(
        self, status: AppealStatus | None, limit: int, offset: int
    ) -> AppealPageV3:
        items, total = await self.repository.list_appeals(status, limit, offset)
        return AppealPageV3(items=items, total=total, limit=limit, offset=offset)

    async def decide_appeal(
        self, appeal_id: UUID, request: AppealDecisionRequestV3, reviewer_id: str
    ) -> AppealDecisionResponseV3:
        response = await self.repository.decide_appeal(appeal_id, request, reviewer_id)
        if response is None:
            raise _not_found("Appeal was not found.")
        return response

    async def list_admin_actions(
        self, status: AdminActionStatus | None, limit: int, offset: int
    ) -> AdminActionPageV3:
        items, total = await self.repository.list_admin_actions(status, limit, offset)
        return AdminActionPageV3(items=items, total=total, limit=limit, offset=offset)

    async def get_admin_action(self, action_id: UUID) -> AdminActionRecordV3:
        result = await self.repository.get_admin_action(action_id)
        if result is None:
            raise _not_found("Admin action was not found.")
        return result

    async def decide_admin_action(
        self, action_id: UUID, decision: ReviewDecision, note: str, reviewer_id: str
    ) -> AdminActionDecisionResponseV3:
        result = await self.repository.decide_admin_action(action_id, decision, note, reviewer_id)
        if result is None:
            raise _not_found("Admin action was not found.")
        return result

    async def list_campaigns(
        self, status: CampaignReviewerStatus | None, limit: int, offset: int
    ) -> CampaignPageV3:
        items, total = await self.repository.list_campaigns(status, limit, offset)
        return CampaignPageV3(items=items, total=total, limit=limit, offset=offset)

    async def get_campaign(self, campaign_id: UUID) -> CampaignDetailV3:
        result = await self.repository.get_campaign(campaign_id)
        if result is None:
            raise _not_found("Campaign was not found.")
        return result

    async def operations_metrics(self, started_at: datetime, ended_at: datetime) -> OperationsMetricsResponseV3:
        if ended_at <= started_at:
            raise PlatformError(
                status_code=422,
                code=ErrorCode.VALIDATION_ERROR,
                message="Metrics 'to' must be after 'from'.",
                retryable=False,
            )
        return await self.repository.operations_metrics(started_at, ended_at)

    async def source_registry(self, at: datetime | None = None) -> VersionedSourceRegistry:
        policies = await self.repository.load_source_policies(at or datetime.now(UTC))  # type: ignore[attr-defined]
        if self._active_source_registry is not None:
            self._active_source_registry.replace(policies)
            return self._active_source_registry
        return VersionedSourceRegistry(policies)

    async def register_source(self, entry: SourceRegistryEntry) -> None:
        await self.repository.register_source(entry)  # type: ignore[attr-defined]
        if self._active_source_registry is not None:
            policies = await self.repository.load_source_policies(datetime.now(UTC))  # type: ignore[attr-defined]
            self._active_source_registry.replace(policies)

    async def issue_artifact_access(self, artifact_id: UUID, principal: Principal) -> ArtifactAccess:
        artifact = await self.repository.get_artifact(artifact_id)  # type: ignore[attr-defined]
        if artifact is None or artifact.deleted_at is not None or artifact.expires_at <= datetime.now(UTC):
            raise _not_found("Artifact was not found.")
        if artifact.owner_id != principal.user_id and principal.role is not UserRole.SECURITY_ADMIN:
            raise _forbidden()
        return self.artifact_signer.issue(artifact.artifact_id, artifact.owner_id)


def _hostname_matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname == suffix or hostname.endswith(f".{suffix}")
    return hostname == pattern


def _canonical_target(target: str) -> str:
    value = target.strip().lower()
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    hostname = (parsed.hostname or "").rstrip(".")
    return hostname or value[:500]


def _aggregate_metrics(
    started_at: datetime,
    ended_at: datetime,
    usage: list[UsageLedgerEntry],
    appeals: Any,
) -> OperationsMetricsResponseV3:
    operations: dict[str, list[int]] = defaultdict(list)
    cache_counts: dict[str, Counter[str]] = defaultdict(Counter)
    provider_rows: dict[tuple[str, str | None], list[UsageLedgerEntry]] = defaultdict(list)
    for item in usage:
        operations[item.operation].append(item.latency_ms)
        cache_counts[item.provider][item.cache_status] += 1
        provider_rows[(item.provider, item.model)].append(item)
    appeal_rows = [item.response for item in appeals if started_at <= item.response.created_at < ended_at]
    outcomes = Counter(item.outcome.value for item in appeal_rows if item.outcome is not None)
    overturned = outcomes["overturn"]
    return OperationsMetricsResponseV3(
        window=MetricsWindowV3(started_at=started_at, ended_at=ended_at),
        generated_at=datetime.now(UTC),
        latency=[
            LatencyMetricV3(
                operation=operation,
                count=len(values),
                p50_ms=_percentile(values, 0.50),
                p95_ms=_percentile(values, 0.95),
                p99_ms=_percentile(values, 0.99),
            )
            for operation, values in sorted(operations.items())
        ],
        cache=[
            CacheMetricV3(
                provider=provider,
                hits=counts["hit"],
                misses=counts["miss"],
                hit_rate=(counts["hit"] / (counts["hit"] + counts["miss"]))
                if counts["hit"] + counts["miss"]
                else None,
            )
            for provider, counts in sorted(cache_counts.items())
        ],
        usage=[
            UsageMetricV3(
                provider=provider,
                model=model,
                calls=len(rows),
                tokens=sum(row.input_tokens + row.output_tokens for row in rows),
                estimated_cost_usd=sum(row.estimated_cost_usd for row in rows),
                quota_used=max((row.quota_used for row in rows if row.quota_used is not None), default=None),
                rate_limited=sum(row.outcome == "rate_limited" or row.http_class == "429" for row in rows),
                timed_out=sum(row.outcome == "timeout" for row in rows),
            )
            for (provider, model), rows in sorted(provider_rows.items(), key=lambda item: str(item[0]))
        ],
        risk_distribution=[RiskDistributionMetricV3(risk_level=level, count=0) for level in RiskLevel],
        feedback=FeedbackMetricV3(
            reports=0,
            appeals=len(appeal_rows),
            appeals_upheld=outcomes["uphold"],
            appeals_overturned=overturned,
            appeals_inconclusive=outcomes["inconclusive"],
            false_positive_rate=overturned / len(appeal_rows) if appeal_rows else None,
        ),
    )


def _percentile(values: list[int], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(round((len(ordered) - 1) * quantile), len(ordered) - 1)
    return float(ordered[index])


def _not_found(message: str) -> PlatformError:
    return PlatformError(status_code=404, code=ErrorCode.NOT_FOUND, message=message, retryable=False)


def _forbidden() -> PlatformError:
    return PlatformError(
        status_code=403,
        code=ErrorCode.FORBIDDEN,
        message="You do not have access to this resource.",
        retryable=False,
    )


def _conflict(message: str) -> PlatformError:
    return PlatformError(status_code=409, code=ErrorCode.INTERNAL_ERROR, message=message, retryable=False)


__all__ = [
    "ArtifactAccess",
    "ArtifactRecord",
    "ArtifactSigner",
    "CampaignWrite",
    "EvidenceChunkWrite",
    "EvidenceSnapshotWrite",
    "FactCheckResultWrite",
    "FactCheckCorpusRecordWrite",
    "MemoryWave2Repository",
    "SourcePolicyDecision",
    "SourceRegistryEntry",
    "SourceTier",
    "UsageLedgerEntry",
    "VersionedSourceRegistry",
    "Wave2PlatformService",
    "default_source_policies",
]
