from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Generic, Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.models import ClaimStance, Verdict


class ToolContractModel(BaseModel):
    """Strict provider-neutral model; provider response bodies are never fields."""

    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="after")
    @classmethod
    def reject_empty_strings_and_non_utc_times(cls, value: Any) -> Any:
        def validate(item: Any) -> None:
            if isinstance(item, str) and not item.strip():
                raise ValueError("empty strings are not valid tool contract values")
            if isinstance(item, datetime) and (item.tzinfo is None or item.utcoffset() != timedelta(0)):
                raise ValueError("timestamps must use UTC")
            if isinstance(item, list):
                for nested in item:
                    validate(nested)
            if isinstance(item, dict):
                for nested in item.values():
                    validate(nested)

        validate(value)
        return value


class ToolName(StrEnum):
    URL_REPUTATION = "url_reputation"
    REDIRECT_RESOLVER = "redirect_resolver"
    RDAP = "rdap"
    FACT_CHECK_CORPUS = "fact_check_corpus"
    DOMAIN_FAMILIARITY = "domain_familiarity"


class ToolResultStatus(StrEnum):
    SUCCESS = "success"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    FAILED = "failed"


class ToolErrorCode(StrEnum):
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    INVALID_TARGET = "INVALID_TARGET"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    REDIRECT_LOOP = "REDIRECT_LOOP"
    DOWNLOAD_BLOCKED = "DOWNLOAD_BLOCKED"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    UNSUPPORTED = "UNSUPPORTED"


class CacheStatus(StrEnum):
    HIT = "hit"
    MISS = "miss"
    BYPASS = "bypass"


class NormalizedToolError(ToolContractModel):
    tool: ToolName
    code: ToolErrorCode
    message: str
    retryable: bool
    provider: str | None = None
    http_status_code: int | None = Field(default=None, ge=100, le=599)
    retry_after_ms: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_retry_after(self) -> Self:
        if self.retry_after_ms is not None and self.code is not ToolErrorCode.RATE_LIMITED:
            raise ValueError("retry_after_ms is only valid for rate limiting")
        return self


class CacheMetadata(ToolContractModel):
    status: CacheStatus
    cache_key_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    stored_at: datetime | None = None
    expires_at: datetime | None = None
    bypass_reason: str | None = None

    @model_validator(mode="after")
    def validate_cache_state(self) -> Self:
        if self.status is CacheStatus.HIT:
            if None in (self.cache_key_hash, self.stored_at, self.expires_at):
                raise ValueError("cache hit requires key hash, stored_at and expires_at")
            if self.expires_at <= self.stored_at:  # type: ignore[operator]
                raise ValueError("cache expiry must be after storage time")
        elif self.stored_at is not None or self.expires_at is not None:
            raise ValueError("only a cache hit can contain cache timestamps")
        if self.status is CacheStatus.BYPASS and self.bypass_reason is None:
            raise ValueError("cache bypass requires a reason")
        if self.status is not CacheStatus.BYPASS and self.bypass_reason is not None:
            raise ValueError("bypass_reason is only valid for cache bypass")
        return self


class UsageMetadata(ToolContractModel):
    usage_ref: str
    provider: str
    provider_version: str
    operation: str
    attempts: int = Field(ge=0)
    network_calls: int = Field(ge=0)
    latency_ms: float = Field(ge=0)
    request_units: float = Field(default=0, ge=0)
    response_units: float = Field(default=0, ge=0)
    tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(default=0, ge=0)
    observed_at: datetime


ResultT = TypeVar("ResultT")


class NormalizedToolResult(ToolContractModel, Generic[ResultT]):
    status: ToolResultStatus
    result: ResultT | None = None
    error: NormalizedToolError | None = None
    cache: CacheMetadata
    usage: UsageMetadata

    @model_validator(mode="after")
    def exactly_one_outcome(self) -> Self:
        if self.status in {ToolResultStatus.SUCCESS, ToolResultStatus.INCONCLUSIVE}:
            if self.result is None or self.error is not None:
                raise ValueError("successful or inconclusive outcome requires only a normalized result")
        elif self.result is not None or self.error is None:
            raise ValueError("blocked or failed outcome requires only a normalized error")
        if self.cache.status is CacheStatus.HIT and self.usage.network_calls != 0:
            raise ValueError("cache hit cannot record a network call")
        return self


class UrlReputationFinding(ToolContractModel):
    provider: str
    provider_version: str
    normalized_url: str
    matched: bool
    verdict: Verdict
    signals: list[str] = Field(default_factory=list)
    observed_at: datetime

    @model_validator(mode="after")
    def no_hit_is_inconclusive(self) -> Self:
        if not self.matched and self.verdict is not Verdict.INCONCLUSIVE:
            raise ValueError("provider no-hit must be inconclusive")
        return self


class UrlReputationCascadeResult(ToolContractModel):
    normalized_url: str
    findings: list[UrlReputationFinding] = Field(min_length=1)
    verdict: Verdict
    provider_conflict: bool
    policy_version: str


class DomainFamiliarityResult(ToolContractModel):
    registrable_domain: str
    matched: bool
    popularity_rank: int | None = Field(default=None, ge=1)
    popularity_bucket: int | None = Field(default=None, ge=1)
    dataset_window_end: datetime | None = None
    observed_at: datetime

    @model_validator(mode="after")
    def validate_ranking(self) -> Self:
        if self.matched != (self.popularity_rank is not None or self.popularity_bucket is not None):
            raise ValueError("matched ranking requires rank or bucket and no-hit cannot contain either")
        return self


class DnsResolutionResult(ToolContractModel):
    normalized_url: str
    domain: str
    address_count: int = Field(ge=1)
    ipv4_count: int = Field(ge=0)
    ipv6_count: int = Field(ge=0)
    observed_at: datetime

    @model_validator(mode="after")
    def validate_address_counts(self) -> Self:
        if self.ipv4_count + self.ipv6_count != self.address_count:
            raise ValueError("DNS address family counts must equal address_count")
        return self


class DnsResolutionError(ToolContractModel):
    tool: Literal["dns"] = "dns"
    code: ToolErrorCode
    message: str
    retryable: bool
    provider: str | None = None


class DnsResolutionEnvelope(ToolContractModel):
    status: ToolResultStatus
    result: DnsResolutionResult | None = None
    error: DnsResolutionError | None = None
    cache: CacheMetadata
    usage: UsageMetadata

    @model_validator(mode="after")
    def exactly_one_outcome(self) -> Self:
        if self.status in {ToolResultStatus.SUCCESS, ToolResultStatus.INCONCLUSIVE}:
            if self.result is None or self.error is not None:
                raise ValueError("successful or inconclusive DNS outcome requires only a normalized result")
        elif self.result is not None or self.error is None:
            raise ValueError("blocked or failed DNS outcome requires only a normalized error")
        if self.cache.status is CacheStatus.HIT and self.usage.network_calls != 0:
            raise ValueError("DNS cache hit cannot record a network call")
        return self


class RedirectResolutionStatus(StrEnum):
    NO_REDIRECT = "no_redirect"
    RESOLVED = "resolved"


class RedirectResolutionResult(ToolContractModel):
    normalized_url: str
    final_url: str
    redirect_chain: list[str] = Field(min_length=1)
    status: RedirectResolutionStatus
    signals: list[str] = Field(default_factory=list)
    observed_at: datetime

    @model_validator(mode="after")
    def validate_chain(self) -> Self:
        if self.redirect_chain[0] != self.normalized_url or self.redirect_chain[-1] != self.final_url:
            raise ValueError("redirect chain endpoints must match normalized_url and final_url")
        if self.status is RedirectResolutionStatus.NO_REDIRECT and len(self.redirect_chain) != 1:
            raise ValueError("no_redirect result must contain exactly one URL")
        if self.status is RedirectResolutionStatus.RESOLVED and len(self.redirect_chain) < 2:
            raise ValueError("resolved redirect requires at least two URLs")
        return self


class FactCheckCorpusRecord(ToolContractModel):
    record_id: str
    record_version: str
    publisher: str
    source_url: str
    claim: str
    stance: ClaimStance
    language: str = Field(min_length=2, max_length=35)
    published_at: datetime
    updated_at: datetime
    embedding_model: str
    embedding_version: str
    ingestion_source: str

    @model_validator(mode="after")
    def validate_dates(self) -> Self:
        if self.updated_at < self.published_at:
            raise ValueError("fact-check update cannot precede publication")
        return self


class FactCheckCorpusMatch(ToolContractModel):
    record: FactCheckCorpusRecord
    similarity: float = Field(ge=0, le=1)


class FactCheckSearchResult(ToolContractModel):
    matches: list[FactCheckCorpusMatch]
    corpus_version: str


class EmbeddingVector(ToolContractModel):
    claim_index: int = Field(ge=0)
    vector: list[float]


class EmbeddingBatch(ToolContractModel):
    vectors: list[EmbeddingVector] = Field(min_length=1, max_length=5)
    model: str
    model_version: str
    dimensions: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_vectors(self) -> Self:
        if [item.claim_index for item in self.vectors] != list(range(len(self.vectors))):
            raise ValueError("embedding vectors must preserve input order")
        if any(len(item.vector) != self.dimensions for item in self.vectors):
            raise ValueError("embedding dimensions do not match vector length")
        return self


class GoogleClaimReviewMatch(ToolContractModel):
    claim_text: str
    review_ref: str
    review_url: str
    reviewer: str
    publisher: str
    title: str
    textual_rating: str | None = None
    stance: ClaimStance = ClaimStance.UNRATED
    source_tier: str = "untrusted"
    trusted_claim_review: bool = False
    policy_version: str = "unregistered"
    published_at: datetime | None = None
    observed_at: datetime


class CorpusCandidate(ToolContractModel):
    evidence_ref: str
    record: FactCheckCorpusRecord
    fts_rank: int | None = Field(default=None, ge=1)
    vector_rank: int | None = Field(default=None, ge=1)
    rrf_score: float = Field(ge=0)
    source_tier: str = "untrusted"
    temporal_status: str = "compatible"


class WebCandidate(ToolContractModel):
    evidence_ref: str
    canonical_url: str
    title: str
    snippet: str
    publisher: str
    source_tier: str = "untrusted"
    published_at: datetime | None = None
    source_version: str
    search_score: float = Field(default=0.0, ge=0, le=1)
    policy_version: str = "unregistered"


class ExtractedWebEvidence(ToolContractModel):
    evidence_ref: str
    canonical_url: str
    title: str
    text: str
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    publisher: str
    source_tier: str
    source_version: str
    search_score: float = Field(default=0.0, ge=0, le=1)
    published_at: datetime | None = None
    observed_at: datetime
    policy_version: str = "unregistered"


class TavilyExtractBatch(ToolContractModel):
    evidence: list[ExtractedWebEvidence]
    failed_urls: list[str] = Field(default_factory=list)
