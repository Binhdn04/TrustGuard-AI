from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.agents.tools.domains import DEFAULT_PUBLIC_SUFFIX_LIST, normalize_hostname
from src.core.auth import Principal, UserRole
from src.core.errors import PlatformError
from src.models import (
    AdminActionAuditRecordV3,
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
    SecurityEvidenceTypeV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
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


class SourceDiscoveryRecord(PlatformInternalModel):
    domain: str
    publisher: str
    first_seen_at: datetime
    last_seen_at: datetime
    search_count: int = 0
    extract_success_count: int = 0
    independent_claim_count: int = 0
    curated_comparison_count: int = 0
    curated_agreement_count: int = 0
    curated_conflict_count: int = 0
    representative_urls: list[str] = Field(default_factory=list, max_length=5)
    status: str = "observing"
    eligible_for_auto_promotion: bool = False


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


class Wave2Repository(Protocol):
    async def propose_admin_action(
        self,
        *,
        analysis_id: UUID | None,
        security_analysis_id: UUID | None,
        campaign_id: UUID | None,
        action: ReviewedAction,
        target: str | None,
        evidence: list[Evidence],
    ) -> AdminActionRecordV3: ...

    async def create_appeal(
        self, analysis_id: UUID, owner_id: str, request: AppealCreateRequestV3, evidence: list[Evidence]
    ) -> AppealReceiptV3: ...

    async def get_appeal(self, appeal_id: UUID) -> tuple[str, AppealResponseV3] | None: ...

    async def list_appeals_for_analysis(self, analysis_id: UUID, owner_id: str) -> list[AppealResponseV3]: ...

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

    async def list_admin_action_audit(self, action_id: UUID) -> list[AdminActionAuditRecordV3]: ...

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
    policies = [
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
        ),
        SourceRegistryEntry(
            source_id=UUID("00000000-0000-4000-8000-000000000006"),
            publisher="Vietnam government",
            normalized_pattern="*.chinhphu.vn",
            tier=SourceTier.A,
            source_type="government",
            allowed_operations={"search", "read", "compare", "promote"},
            policy_version="source-policy-v1",
            effective_from=reviewed_at,
            default_freshness_seconds=21600,
            reviewer_id="system-bootstrap",
            reviewed_at=reviewed_at,
        ),
    ]
    for publisher, pattern in (
        ("VTV", "*.vtv.vn"),
        ("VOV", "*.vov.vn"),
        ("Nhan Dan", "*.nhandan.vn"),
        ("VietnamPlus", "*.vietnamplus.vn"),
        ("VnExpress", "*.vnexpress.net"),
        ("Tuoi Tre", "*.tuoitre.vn"),
        ("Thanh Nien", "*.thanhnien.vn"),
    ):
        policies.append(
            SourceRegistryEntry(
                publisher=publisher,
                normalized_pattern=pattern,
                tier=SourceTier.B,
                source_type="reviewed_news",
                allowed_operations={"search", "read", "compare"},
                policy_version="source-policy-v2",
                effective_from=reviewed_at,
                default_freshness_seconds=21600,
                reviewer_id="system-bootstrap",
                reviewed_at=reviewed_at,
            )
        )
    for publisher, pattern, source_type in (
        ("FIFA", "*.fifa.com", "sports_governing_body"),
        ("UEFA", "*.uefa.com", "sports_governing_body"),
        ("Olympics", "*.olympics.com", "sports_governing_body"),
        ("World Health Organization", "*.who.int", "international_organization"),
        ("United Nations", "*.un.org", "international_organization"),
        ("World Bank", "*.worldbank.org", "international_organization"),
        ("International Monetary Fund", "*.imf.org", "international_organization"),
        ("OECD", "*.oecd.org", "international_organization"),
        ("European Union", "*.europa.eu", "international_organization"),
        ("CDC", "*.cdc.gov", "government_health"),
        ("NIH", "*.nih.gov", "government_health"),
        ("FDA", "*.fda.gov", "government_health"),
    ):
        policies.append(
            SourceRegistryEntry(
                publisher=publisher,
                normalized_pattern=pattern,
                tier=SourceTier.A,
                source_type=source_type,
                allowed_operations={"search", "read", "compare", "promote"},
                policy_version="source-policy-international-v1",
                effective_from=reviewed_at,
                default_freshness_seconds=21600,
                reviewer_id="system-bootstrap",
                reviewed_at=reviewed_at,
            )
        )
    for publisher, pattern in (
        ("FactCheck.org", "*.factcheck.org"),
        ("PolitiFact", "*.politifact.com"),
        ("Snopes", "*.snopes.com"),
        ("Full Fact", "*.fullfact.org"),
        ("AFP Fact Check", "*.factcheck.afp.com"),
        ("Reuters Fact Check", "*.reuters.com"),
        ("AP Fact Check", "*.apnews.com"),
    ):
        policies.append(
            SourceRegistryEntry(
                publisher=publisher,
                normalized_pattern=pattern,
                tier=SourceTier.B,
                source_type="claim_review",
                trusted_claim_review=True,
                allowed_operations={"search", "read", "compare"},
                policy_version="source-policy-claim-review-v1",
                effective_from=reviewed_at,
                default_freshness_seconds=21600,
                reviewer_id="system-bootstrap",
                reviewed_at=reviewed_at,
            )
        )
    vietnam_tier_a = (
        ("National Legal Document Database", "vbpl.vn"),
        ("Ministry of Justice", "moj.gov.vn"),
        ("National Assembly of Vietnam", "quochoi.vn"),
        ("National Statistics Office", "nso.gov.vn"),
        ("Ministry of Finance", "mof.gov.vn"),
        ("State Bank of Vietnam", "sbv.gov.vn"),
        ("General Department of Taxation", "gdt.gov.vn"),
        ("Vietnam Customs", "customs.gov.vn"),
        ("State Securities Commission", "ssc.gov.vn"),
        ("Ho Chi Minh Stock Exchange", "hsx.vn"),
        ("Hanoi Stock Exchange", "hnx.vn"),
        ("Ministry of Health", "moh.gov.vn"),
        ("Drug Administration of Vietnam", "dav.gov.vn"),
        ("Vietnam Food Administration", "vfa.gov.vn"),
        ("Ministry of Education and Training", "moet.gov.vn"),
        ("Ministry of Science and Technology", "mst.gov.vn"),
        ("Vietnam Academy of Science and Technology", "vast.gov.vn"),
        ("Ministry of Agriculture and Environment", "mae.gov.vn"),
        ("Center for Environmental Monitoring", "cem.gov.vn"),
        ("Nature and Biodiversity Conservation Agency", "nbca.gov.vn"),
        ("Plant Production and Protection Department", "ppd.gov.vn"),
        ("Ministry of Construction", "moc.gov.vn"),
        ("Ministry of Industry and Trade", "moit.gov.vn"),
        ("Ministry of Public Security", "mps.gov.vn"),
        ("Ministry of National Defence", "mod.gov.vn"),
        ("Ministry of Foreign Affairs", "mofa.gov.vn"),
        ("Vietnam Social Security", "baohiemxahoi.gov.vn"),
        ("National Center for Hydro-Meteorological Forecasting", "nchmf.gov.vn"),
        ("Vietnam Disaster Management Authority", "phongchongthientai.mard.gov.vn"),
        ("Hanoi Portal", "hanoi.gov.vn"),
        ("Ho Chi Minh City Portal", "hochiminhcity.gov.vn"),
        ("Da Nang Portal", "danang.gov.vn"),
        ("Authority of Information Security", "ais.gov.vn"),
        ("Directorate for Roads of Vietnam", "drvn.gov.vn"),
        ("Vietnam National Authority of Tourism", "vietnamtourism.gov.vn"),
        ("Vietnam Administration of Forestry", "lamnghiep.gov.vn"),
    )
    vietnam_tier_b = (
        ("Vietnam Electricity", "evn.com.vn", "official_enterprise"),
        ("Bao Tin Tuc", "baotintuc.vn", "reviewed_news"),
        ("VietnamNet", "vietnamnet.vn", "reviewed_news"),
        ("Lao Dong", "laodong.vn", "reviewed_news"),
        ("Dan Tri", "dantri.com.vn", "reviewed_news"),
        ("Tien Phong", "tienphong.vn", "reviewed_news"),
        ("Quan doi Nhan dan", "qdnd.vn", "reviewed_news"),
        ("Cong an Nhan dan", "cand.com.vn", "reviewed_news"),
        ("VnEconomy", "vneconomy.vn", "reviewed_news"),
        ("Vietnam Investment Review", "vir.com.vn", "reviewed_news"),
        ("CafeF", "cafef.vn", "reviewed_news"),
        ("Thoi bao Tai chinh Viet Nam", "thoibaotaichinhvietnam.vn", "reviewed_news"),
        ("Bao Dau tu", "baodautu.vn", "reviewed_news"),
        ("Suc khoe va Doi song", "suckhoedoisong.vn", "reviewed_news"),
        ("Giao duc va Thoi dai", "giaoducthoidai.vn", "reviewed_news"),
        ("Khoa hoc va Phat trien", "khoahocphattrien.vn", "reviewed_news"),
        ("Bao Cong Thuong", "congthuong.vn", "reviewed_news"),
        ("Bao Nong nghiep va Moi truong", "nongnghiepmoitruong.vn", "reviewed_news"),
        ("Bao Xay dung", "baoxaydung.vn", "reviewed_news"),
        ("Ha Noi Moi", "hanoimoi.vn", "reviewed_news"),
        ("Sai Gon Giai Phong", "sggp.org.vn", "reviewed_news"),
        ("Thu Vien Phap Luat", "thuvienphapluat.vn", "legal_reference"),
        ("Phap Luat TP.HCM", "plo.vn", "reviewed_news"),
        ("Bao Cong ly", "congly.vn", "reviewed_news"),
        ("Dan Viet", "danviet.vn", "reviewed_news"),
        ("Tap chi Bao hiem Xa hoi", "tapchibaohiemxahoi.gov.vn", "specialized_news"),
        ("Bach Mai Hospital", "bachmai.gov.vn", "healthcare_provider"),
        ("Cho Ray Hospital", "choray.vn", "healthcare_provider"),
        ("Military Central Hospital 108", "benhvien108.vn", "healthcare_provider"),
        ("Vinmec", "vinmec.com", "healthcare_provider"),
        ("Vietnam National University Hanoi", "vnu.edu.vn", "academic_institution"),
        ("Vietnam National University HCMC", "vnuhcm.edu.vn", "academic_institution"),
        ("Hanoi University of Science and Technology", "hust.edu.vn", "academic_institution"),
        ("National Economics University", "neu.edu.vn", "academic_institution"),
        ("Can Tho University", "ctu.edu.vn", "academic_institution"),
        ("Giao duc Viet Nam", "giaoduc.net.vn", "reviewed_news"),
        ("Viettel", "viettel.com.vn", "official_enterprise"),
        ("VNPT", "vnpt.com.vn", "official_enterprise"),
        ("FPT", "fpt.com.vn", "official_enterprise"),
        ("ICT Vietnam", "ictvietnam.vn", "specialized_news"),
        ("Tinh Te", "tinhte.vn", "specialized_news"),
        ("Vietcombank", "vietcombank.com.vn", "financial_institution"),
        ("BIDV", "bidv.com.vn", "financial_institution"),
        ("VietinBank", "vietinbank.vn", "financial_institution"),
        ("Agribank", "agribank.com.vn", "financial_institution"),
        ("Bao Ngan hang", "baonganhang.vn", "specialized_news"),
        ("Brands Vietnam", "brandsvietnam.com", "specialized_news"),
        ("Vietnam Airlines", "vietnamairlines.com", "official_enterprise"),
        ("Vietnam Railways", "vnr.com.vn", "official_enterprise"),
        ("Airports Corporation of Vietnam", "vietnamairport.vn", "official_enterprise"),
        ("The thao va Van hoa", "thethaovanhoa.vn", "reviewed_news"),
        ("Bao Van Hoa", "baovanhoa.vn", "reviewed_news"),
        ("WebTheThao", "webthethao.vn", "specialized_news"),
        ("Batdongsan.com.vn", "batdongsan.com.vn", "specialized_portal"),
        ("Reatimes", "reatimes.vn", "specialized_news"),
    )
    existing_patterns = {item.normalized_pattern for item in policies}
    for publisher, domain in vietnam_tier_a:
        pattern = f"*.{domain}"
        if pattern in existing_patterns:
            continue
        existing_patterns.add(pattern)
        policies.append(
            SourceRegistryEntry(
                publisher=publisher,
                normalized_pattern=pattern,
                tier=SourceTier.A,
                source_type="government_or_official",
                allowed_operations={"search", "read", "compare", "promote"},
                policy_version="source-policy-vietnam-expanded-v1",
                effective_from=reviewed_at,
                default_freshness_seconds=21600,
                reviewer_id="system-bootstrap",
                reviewed_at=reviewed_at,
            )
        )
    for publisher, domain, source_type in vietnam_tier_b:
        if (
            source_type
            in {
                "academic_institution",
                "financial_institution",
                "healthcare_provider",
                "official_enterprise",
            }
            and domain not in existing_patterns
        ):
            existing_patterns.add(domain)
            policies.append(
                SourceRegistryEntry(
                    publisher=publisher,
                    normalized_pattern=domain,
                    tier=SourceTier.B,
                    source_type=source_type,
                    allowed_operations={"search", "read", "compare"},
                    policy_version="source-policy-vietnam-identity-v1",
                    effective_from=reviewed_at,
                    default_freshness_seconds=21600,
                    reviewer_id="system-bootstrap",
                    reviewed_at=reviewed_at,
                )
            )
        pattern = f"*.{domain}"
        if pattern in existing_patterns:
            continue
        existing_patterns.add(pattern)
        policies.append(
            SourceRegistryEntry(
                publisher=publisher,
                normalized_pattern=pattern,
                tier=SourceTier.B,
                source_type=source_type,
                allowed_operations={"search", "read", "compare"},
                policy_version="source-policy-vietnam-expanded-v1",
                effective_from=reviewed_at,
                default_freshness_seconds=21600,
                reviewer_id="system-bootstrap",
                reviewed_at=reviewed_at,
            )
        )
    return policies


def effective_source_policies(configured: list[SourceRegistryEntry]) -> list[SourceRegistryEntry]:
    """Merge built-ins with persisted policies, allowing persisted patterns to override defaults."""
    by_pattern = {item.normalized_pattern: item for item in default_source_policies()}
    by_pattern.update({item.normalized_pattern: item for item in configured})
    return list(by_pattern.values())


@dataclass(slots=True)
class MemoryWave2Repository:
    """Process-local adapter for offline tests; production always selects PostgreSQL."""

    appeals: dict[UUID, _MemoryAppeal] = field(default_factory=dict)
    actions: dict[UUID, AdminActionRecordV3] = field(default_factory=dict)
    campaigns: dict[UUID, CampaignDetailV3] = field(default_factory=dict)
    sources: list[SourceRegistryEntry] = field(default_factory=default_source_policies)
    source_discoveries: dict[str, SourceDiscoveryRecord] = field(default_factory=dict)
    fact_results: dict[UUID, FactCheckResultWrite] = field(default_factory=dict)
    corpus_records: dict[UUID, FactCheckCorpusRecordWrite] = field(default_factory=dict)
    usage: list[UsageLedgerEntry] = field(default_factory=list)
    notifications: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    action_sink: Any | None = None
    executed_blacklist: set[str] = field(default_factory=set)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def _hydrate_actions(self) -> None:
        load = getattr(self.action_sink, "list_security_admin_actions", None)
        if load is None:
            return
        for item in await load():
            self.actions.setdefault(item.action_id, item)

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

    async def list_appeals_for_analysis(self, analysis_id: UUID, owner_id: str) -> list[AppealResponseV3]:
        rows = [
            item.response.model_copy(deep=True)
            for item in self.appeals.values()
            if item.owner_id == owner_id and item.response.analysis_id == analysis_id
        ]
        return sorted(rows, key=lambda item: item.created_at, reverse=True)

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
        security_analysis_id: UUID | None = None,
        campaign_id: UUID | None,
        action: ReviewedAction,
        target: str | None,
        evidence: list[Evidence],
    ) -> AdminActionRecordV3:
        await self._hydrate_actions()
        canonical = _canonical_action_target(action, target) if target else None
        async with self._lock:
            existing = next(
                (
                    item
                    for item in self.actions.values()
                    if item.analysis_id == analysis_id
                    and item.security_analysis_id == security_analysis_id
                    and item.campaign_id == campaign_id
                    and item.action is action
                    and item.target == canonical
                    and item.status is AdminActionStatus.PENDING_REVIEW
                ),
                None,
            )
            if existing is not None:
                return existing.model_copy(deep=True)
        record = AdminActionRecordV3(
            action_id=uuid4(),
            analysis_id=analysis_id,
            security_analysis_id=security_analysis_id,
            campaign_id=campaign_id,
            action=action,
            target=canonical,
            status=AdminActionStatus.PENDING_REVIEW,
            evidence_snapshot=evidence,
            proposed_at=datetime.now(UTC),
        )
        async with self._lock:
            self.actions[record.action_id] = record
        save = getattr(self.action_sink, "save_security_admin_action", None)
        if save is not None:
            await save(record)
        return record.model_copy(deep=True)

    async def list_admin_actions(
        self, status: AdminActionStatus | None, limit: int, offset: int
    ) -> tuple[list[AdminActionRecordV3], int]:
        await self._hydrate_actions()
        rows = [item for item in self.actions.values() if status is None or item.status is status]
        rows.sort(key=lambda item: item.proposed_at, reverse=True)
        return [item.model_copy(deep=True) for item in rows[offset : offset + limit]], len(rows)

    async def get_admin_action(self, action_id: UUID) -> AdminActionRecordV3 | None:
        await self._hydrate_actions()
        item = self.actions.get(action_id)
        return item.model_copy(deep=True) if item else None

    async def list_admin_action_audit(self, action_id: UUID) -> list[AdminActionAuditRecordV3]:
        load = getattr(self.action_sink, "list_security_admin_action_audit", None)
        if load is not None:
            persisted = await load(action_id)
            if persisted:
                return persisted
        rows = [item for item in self.audit if item.get("action_id") == action_id]
        return [AdminActionAuditRecordV3.model_validate(item) for item in rows]

    async def decide_admin_action(
        self, action_id: UUID, decision: ReviewDecision, note: str, reviewer_id: str
    ) -> AdminActionDecisionResponseV3 | None:
        await self._hydrate_actions()
        async with self._lock:
            item = self.actions.get(action_id)
            if item is None:
                return None
            if item.status is not AdminActionStatus.PENDING_REVIEW:
                raise _conflict("The admin action has already been reviewed.")
            now, decision_id = datetime.now(UTC), uuid4()
            status = AdminActionStatus.REJECTED
            executed_at = None
            execution_error = None
            if decision is ReviewDecision.APPROVED:
                executed_at = now
                try:
                    if item.action in {
                        ReviewedAction.ADD_TO_BLACKLIST,
                        ReviewedAction.DISABLE_BLACKLIST,
                    }:
                        if self.action_sink is not None:
                            linked_analysis_id = item.security_analysis_id or item.analysis_id
                            await self.action_sink.apply_decision(
                                decision_id=str(decision_id),
                                analysis_id=str(linked_analysis_id) if linked_analysis_id else None,
                                reviewer_id=reviewer_id,
                                decision=decision.value,
                                action=item.action.value,
                                note=note,
                                domains=[item.target],
                            )
                        elif item.action is ReviewedAction.ADD_TO_BLACKLIST:
                            self.executed_blacklist.add(item.target)
                        else:
                            self.executed_blacklist.discard(item.target)
                        status = AdminActionStatus.EXECUTED
                    else:
                        status = AdminActionStatus.FAILED
                        execution_error = "ACTION_SINK_NOT_CONFIGURED"
                except Exception:
                    status = AdminActionStatus.FAILED
                    execution_error = "ACTION_EXECUTION_FAILED"
            reviewed = item.model_copy(
                update={
                    "status": status,
                    "reviewer_id": reviewer_id,
                    "review_note": note,
                    "reviewed_at": now,
                    "executed_at": executed_at,
                    "execution_error": execution_error,
                }
            )
            self.actions[action_id] = reviewed
            self.audit.append(
                {
                    "decision_id": decision_id,
                    "action_id": action_id,
                    "reviewer_id": reviewer_id,
                    "decision": decision.value,
                    "action": item.action.value,
                    "execution_status": status.value,
                    "execution_error": execution_error,
                    "evidence_snapshot": [e.model_dump(mode="json") for e in item.evidence_snapshot],
                    "decided_at": now,
                    "note": note,
                }
            )
            action_audit = AdminActionAuditRecordV3.model_validate(self.audit[-1])
        save_action = getattr(self.action_sink, "save_security_admin_action", None)
        if save_action is not None:
            await save_action(reviewed)
        save_audit = getattr(self.action_sink, "save_security_admin_action_audit", None)
        if save_audit is not None:
            await save_audit(action_audit)
        return AdminActionDecisionResponseV3(
            action_id=action_id,
            decision_id=decision_id,
            action=item.action,
            status=status,
            reviewed_at=now,
            executed_at=executed_at,
            execution_error=execution_error,
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

    async def review_campaign(
        self, campaign_id: UUID, status: CampaignReviewerStatus, note: str, reviewer_id: str
    ) -> CampaignDetailV3 | None:
        async with self._lock:
            item = self.campaigns.get(campaign_id)
            if item is None:
                return None
            if item.reviewer_status is not CampaignReviewerStatus.PENDING_REVIEW:
                raise _conflict("Campaign was already reviewed.")
            updated = item.model_copy(
                update={
                    "reviewer_status": status,
                    "reviewer_id": reviewer_id,
                    "review_note": note,
                    "reviewed_at": datetime.now(UTC),
                }
            )
            self.campaigns[campaign_id] = updated
            return updated.model_copy(deep=True)

    async def register_source(self, entry: SourceRegistryEntry) -> None:
        async with self._lock:
            if any(
                item.normalized_pattern == entry.normalized_pattern and item.policy_version == entry.policy_version
                for item in self.sources
            ):
                raise _conflict("This source policy version already exists.")
            self.sources.append(entry)

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
        del allow_auto_promotion
        from src.agents.fact_check import registrable_domain  # noqa: PLC0415

        domain = registrable_domain(url)
        if not domain:
            return
        now = datetime.now(UTC)
        current = self.source_discoveries.get(domain)
        if current is None:
            current = SourceDiscoveryRecord(
                domain=domain,
                publisher=publisher,
                first_seen_at=now,
                last_seen_at=now,
                representative_urls=[url],
            )
        updates: dict[str, Any] = {"last_seen_at": now, "publisher": publisher}
        if event == "search":
            updates["search_count"] = current.search_count + 1
        elif event == "extract":
            updates["extract_success_count"] = current.extract_success_count + 1
            updates["independent_claim_count"] = current.independent_claim_count + int(bool(claim_hash))
        elif event == "comparison" and agrees_with_curated is not None:
            updates["curated_comparison_count"] = current.curated_comparison_count + 1
            field_name = "curated_agreement_count" if agrees_with_curated else "curated_conflict_count"
            updates[field_name] = getattr(current, field_name) + 1
        urls = list(dict.fromkeys([*current.representative_urls, url]))[-5:]
        updates["representative_urls"] = urls
        self.source_discoveries[domain] = current.model_copy(update=updates)

    async def list_source_discoveries(self) -> list[SourceDiscoveryRecord]:
        return sorted(self.source_discoveries.values(), key=lambda item: item.last_seen_at, reverse=True)

    async def set_source_discovery_status(
        self, domain: str, status: str, *, decision: str, note: str, reviewer_id: str
    ) -> None:
        current = self.source_discoveries.get(domain)
        if current is not None:
            self.source_discoveries[domain] = current.model_copy(update={"status": status})
        if status == "demoted":
            self.sources = [
                item.model_copy(update={"active": False, "effective_to": datetime.now(UTC)})
                if item.normalized_pattern == f"*.{domain}" and item.active and not item.explicit_deny
                else item
                for item in self.sources
            ]
        self.audit.append(
            {
                "event_type": "source_discovery.decision",
                "domain": domain,
                "decision": decision,
                "note": note,
                "reviewer_id": reviewer_id,
                "decided_at": datetime.now(UTC),
            }
        )

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
            if (
                evidence is None
                or evidence.validation_status != "validated"
                or evidence.source_tier
                not in {
                    SourceTier.A,
                    SourceTier.B,
                }
            ):
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

    async def operations_metrics(self, started_at: datetime, ended_at: datetime) -> OperationsMetricsResponseV3:
        usage = [item for item in self.usage if started_at <= item.observed_at < ended_at]
        return _aggregate_metrics(started_at, ended_at, usage, self.appeals.values())


class VersionedSourceRegistry:
    def __init__(self, policies: list[SourceRegistryEntry]) -> None:
        self._policies = policies
        self._discovery_store: Any | None = None
        self._discovery_enabled = True
        self._auto_promotion_enabled = True

    def bind_discovery_store(self, store: Any, *, enabled: bool = True, auto_promotion_enabled: bool = True) -> None:
        self._discovery_store = store
        self._discovery_enabled = enabled
        self._auto_promotion_enabled = auto_promotion_enabled

    def replace(self, policies: list[SourceRegistryEntry]) -> None:
        self._policies = list(policies)

    def allowed_domains(self, operation: str = "search", *, tiers: set[SourceTier] | None = None) -> tuple[str, ...]:
        now = datetime.now(UTC)
        return tuple(
            sorted(
                {
                    item.normalized_pattern.removeprefix("*.")
                    for item in self._policies
                    if item.active
                    and not item.explicit_deny
                    and operation in item.allowed_operations
                    and (tiers is None or item.tier in tiers)
                    and item.effective_from <= now
                    and (item.effective_to is None or item.effective_to > now)
                }
            )
        )

    def official_domains(self, operation: str = "search") -> tuple[str, ...]:
        return self.allowed_domains(operation, tiers={SourceTier.A})

    def denied_domains(self) -> tuple[str, ...]:
        now = datetime.now(UTC)
        return tuple(
            sorted(
                item.normalized_pattern.removeprefix("*.")
                for item in self._policies
                if item.active
                and item.explicit_deny
                and item.effective_from <= now
                and (item.effective_to is None or item.effective_to > now)
            )
        )

    def matching_entries(self, url: str, at: datetime) -> tuple[SourceRegistryEntry, ...]:
        """Return reviewed matches so identity policy can distinguish exact from wildcard entries."""
        hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
        matches = [
            policy
            for policy in self._policies
            if policy.active
            and policy.effective_from <= at
            and (policy.effective_to is None or policy.effective_to > at)
            and _hostname_matches(hostname, policy.normalized_pattern)
        ]
        return tuple(
            sorted(
                matches,
                key=lambda item: (
                    item.explicit_deny,
                    not item.normalized_pattern.startswith("*."),
                    len(item.normalized_pattern),
                    item.reviewed_at,
                ),
                reverse=True,
            )
        )

    async def observe_discovery(
        self,
        *,
        url: str,
        publisher: str,
        event: str,
        claim_hash: str | None = None,
        agrees_with_curated: bool | None = None,
    ) -> None:
        if (
            not self._discovery_enabled
            or self._discovery_store is None
            or not hasattr(self._discovery_store, "observe_source_discovery")
        ):
            return
        decision = self.classify(url, datetime.now(UTC))
        if decision.explicit_deny or decision.tier in {SourceTier.A, SourceTier.B}:
            return
        await self._discovery_store.observe_source_discovery(
            url=url,
            publisher=publisher,
            event=event,
            claim_hash=claim_hash,
            agrees_with_curated=agrees_with_curated,
            allow_auto_promotion=self._auto_promotion_enabled,
        )

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


class Wave2PlatformService:
    def __init__(
        self,
        repository: Wave2Repository,
        active_source_registry: VersionedSourceRegistry | None = None,
    ) -> None:
        self.repository = repository
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

    async def list_user_appeals(self, analysis_id: UUID, principal: Principal) -> list[AppealResponseV3]:
        return await self.repository.list_appeals_for_analysis(analysis_id, principal.user_id)

    async def list_appeals(self, status: AppealStatus | None, limit: int, offset: int) -> AppealPageV3:
        items, total = await self.repository.list_appeals(status, limit, offset)
        return AppealPageV3(items=items, total=total, limit=limit, offset=offset)

    async def decide_appeal(
        self, appeal_id: UUID, request: AppealDecisionRequestV3, reviewer_id: str
    ) -> AppealDecisionResponseV3:
        response = await self.repository.decide_appeal(appeal_id, request, reviewer_id)
        if response is None:
            raise _not_found("Appeal was not found.")
        return response

    async def list_admin_actions(self, status: AdminActionStatus | None, limit: int, offset: int) -> AdminActionPageV3:
        items, total = await self.repository.list_admin_actions(status, limit, offset)
        return AdminActionPageV3(items=items, total=total, limit=limit, offset=offset)

    async def propose_security_admin_actions(self, response: SecurityScopeResponseV4) -> list[AdminActionRecordV3]:
        """Produce idempotent HITL proposals from completed v4 risk evidence."""
        if response.risk not in {SecurityRiskV4.HIGH_RISK, SecurityRiskV4.MALICIOUS}:
            return []
        context = response.security_context
        if context is None or not context.urls:
            return []
        referenced = set(response.explanation_evidence_refs)
        candidates = [item for item in response.evidence if not referenced or item.evidence_ref in referenced]
        proposals: list[AdminActionRecordV3] = []
        for raw_url in context.urls:
            try:
                target = _canonical_action_target(ReviewedAction.ADD_TO_BLACKLIST, raw_url)
            except ValueError:
                continue
            if any(
                item.type is SecurityEvidenceTypeV4.BLACKLIST
                and item.signal == "approved_blacklist_hit"
                and _evidence_matches_domain(item.target, target)
                for item in response.evidence
            ):
                continue
            evidence = [
                _security_action_evidence(item, target)
                for item in candidates
                if item.target in {None, "message"} or _evidence_matches_domain(item.target, target)
            ]
            evidence = [item for item in evidence if item is not None]
            if not evidence:
                continue
            proposals.append(
                await self.repository.propose_admin_action(
                    analysis_id=None,
                    security_analysis_id=response.analysis_id,
                    campaign_id=None,
                    action=ReviewedAction.ADD_TO_BLACKLIST,
                    target=target,
                    evidence=evidence,
                )
            )
        return proposals

    async def get_admin_action(self, action_id: UUID) -> AdminActionRecordV3:
        result = await self.repository.get_admin_action(action_id)
        if result is None:
            raise _not_found("Admin action was not found.")
        return result

    async def list_admin_action_audit(self, action_id: UUID) -> list[AdminActionAuditRecordV3]:
        if await self.repository.get_admin_action(action_id) is None:
            raise _not_found("Admin action was not found.")
        return await self.repository.list_admin_action_audit(action_id)

    async def decide_admin_action(
        self, action_id: UUID, decision: ReviewDecision, note: str, reviewer_id: str
    ) -> AdminActionDecisionResponseV3:
        result = await self.repository.decide_admin_action(action_id, decision, note, reviewer_id)
        if result is None:
            raise _not_found("Admin action was not found.")
        return result

    async def list_campaigns(self, status: CampaignReviewerStatus | None, limit: int, offset: int) -> CampaignPageV3:
        items, total = await self.repository.list_campaigns(status, limit, offset)
        return CampaignPageV3(items=items, total=total, limit=limit, offset=offset)

    async def get_campaign(self, campaign_id: UUID) -> CampaignDetailV3:
        result = await self.repository.get_campaign(campaign_id)
        if result is None:
            raise _not_found("Campaign was not found.")
        return result

    async def review_campaign(
        self, campaign_id: UUID, status: CampaignReviewerStatus, note: str, reviewer_id: str
    ) -> CampaignDetailV3:
        result = await self.repository.review_campaign(campaign_id, status, note, reviewer_id)  # type: ignore[attr-defined]
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
        policies = effective_source_policies(policies)
        if self._active_source_registry is not None:
            self._active_source_registry.replace(policies)
            return self._active_source_registry
        return VersionedSourceRegistry(policies)

    async def register_source(self, entry: SourceRegistryEntry) -> None:
        await self.repository.register_source(entry)  # type: ignore[attr-defined]
        if self._active_source_registry is not None:
            policies = await self.repository.load_source_policies(datetime.now(UTC))  # type: ignore[attr-defined]
            self._active_source_registry.replace(effective_source_policies(policies))

    async def list_source_discoveries(self) -> list[SourceDiscoveryRecord]:
        if not hasattr(self.repository, "list_source_discoveries"):
            return []
        return await self.repository.list_source_discoveries()

    async def decide_source_discovery(
        self, domain: str, decision: str, note: str, reviewer_id: str
    ) -> SourceDiscoveryRecord:
        from src.agents.fact_check import registrable_domain  # noqa: PLC0415

        domain = registrable_domain(f"https://{domain}")
        rows = {item.domain: item for item in await self.list_source_discoveries()}
        discovery = rows.get(domain)
        if discovery is None:
            raise _not_found("Source discovery was not found.")
        now = datetime.now(UTC)
        if decision in {"promote", "deny"}:
            entry = SourceRegistryEntry(
                publisher=discovery.publisher,
                normalized_pattern=f"*.{domain}",
                tier=SourceTier.B if decision == "promote" else SourceTier.UNTRUSTED,
                source_type="admin_reviewed_web" if decision == "promote" else "denied_discovery",
                explicit_deny=decision == "deny",
                allowed_operations={"search", "read", "compare"} if decision == "promote" else set(),
                policy_version=f"admin-discovery-{decision}-{now.strftime('%Y%m%d%H%M%S%f')}",
                effective_from=now,
                default_freshness_seconds=21600,
                reviewer_id=reviewer_id,
                reviewed_at=now,
            )
            await self.register_source(entry)
        if not hasattr(self.repository, "set_source_discovery_status"):
            raise _conflict("Discovery decisions are not supported by this repository.")
        status_value = {"promote": "promoted", "deny": "denied", "demote": "demoted"}[decision]
        await self.repository.set_source_discovery_status(
            domain, status_value, decision=decision, note=note, reviewer_id=reviewer_id
        )
        if self._active_source_registry is not None:
            policies = await self.repository.load_source_policies(now)
            self._active_source_registry.replace(effective_source_policies(policies))
        updated = {item.domain: item for item in await self.list_source_discoveries()}.get(domain)
        return updated or discovery.model_copy(update={"status": status_value})

    async def list_sources(self, at: datetime | None = None) -> list[SourceRegistryEntry]:
        policies = await self.repository.load_source_policies(at or datetime.now(UTC))  # type: ignore[attr-defined]
        return effective_source_policies(policies)


def _hostname_matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname == suffix or hostname.endswith(f".{suffix}")
    return hostname == pattern


def _canonical_action_target(action: ReviewedAction, target: str) -> str:
    if action is ReviewedAction.NONE:
        raise ValueError("none action cannot have a target")
    value = target.strip()
    try:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
    except ValueError as exc:
        raise ValueError("admin action target is invalid") from exc
    if parsed.hostname is None:
        raise ValueError("admin action target must contain a hostname")
    hostname = normalize_hostname(parsed.hostname)
    if DEFAULT_PUBLIC_SUFFIX_LIST.registrable_domain(hostname) is None:
        raise ValueError("admin action target must be a registrable domain")
    return hostname


def _evidence_matches_domain(value: str | None, domain: str) -> bool:
    if value is None:
        return False
    try:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
    except ValueError:
        return False
    return (parsed.hostname or "").casefold().rstrip(".") == domain


def _security_action_evidence(item, domain: str) -> Evidence | None:
    type_map = {
        SecurityEvidenceTypeV4.BLACKLIST: "BLACKLIST",
        SecurityEvidenceTypeV4.REDIRECT: "REDIRECT",
        SecurityEvidenceTypeV4.RDAP: "DOMAIN_REGISTRATION",
        SecurityEvidenceTypeV4.LOCAL_URL_RULE: "URL_RULE",
    }
    from src.models import EvidenceType  # noqa: PLC0415

    evidence_type = EvidenceType[type_map.get(item.type, "DOMAIN_REPUTATION")]
    return Evidence(
        type=evidence_type,
        source=item.source,
        title=item.signal,
        url=f"https://{domain}/",
        finding=item.description,
        observed_at=item.observed_at,
        policy_version=item.provenance_ref,
    )


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
                hit_rate=(counts["hit"] / (counts["hit"] + counts["miss"])) if counts["hit"] + counts["miss"] else None,
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
    "CampaignWrite",
    "EvidenceChunkWrite",
    "EvidenceSnapshotWrite",
    "FactCheckResultWrite",
    "FactCheckCorpusRecordWrite",
    "MemoryWave2Repository",
    "SourceDiscoveryRecord",
    "SourcePolicyDecision",
    "SourceRegistryEntry",
    "SourceTier",
    "UsageLedgerEntry",
    "VersionedSourceRegistry",
    "Wave2PlatformService",
    "default_source_policies",
    "effective_source_policies",
]
