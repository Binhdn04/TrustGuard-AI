from __future__ import annotations

import asyncio
import inspect
import re
import unicodedata
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.models import ClaimEvidence, ClaimStance, ToolError


class SourceTier(StrEnum):
    A = "a"
    B = "b"
    C = "c"
    UNTRUSTED = "untrusted"


class EmbeddingStatus(StrEnum):
    COMPLETE = "complete"
    PENDING = "pending"
    NOT_CONFIGURED = "not_configured"


class ExtractedClaim(BaseModel):
    """Private, canonical claim representation used by the Wave 2 pipeline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(pattern=r"^claim:[a-f0-9]{64}$")
    normalized_text: str = Field(min_length=1, max_length=1000)
    language: str = Field(default="vi", min_length=2, max_length=35)
    is_temporal: bool = False
    claim_date_start: date | None = None
    claim_date_end: date | None = None

    @model_validator(mode="after")
    def validate_dates(self) -> ExtractedClaim:
        if self.claim_date_start and self.claim_date_end and self.claim_date_end < self.claim_date_start:
            raise ValueError("claim date range is reversed")
        if (self.claim_date_start or self.claim_date_end) and not self.is_temporal:
            raise ValueError("dated claims must be temporal")
        return self

    @classmethod
    def from_text(
        cls,
        text: str,
        *,
        language: str = "vi",
        claim_date_start: date | None = None,
        claim_date_end: date | None = None,
        is_temporal: bool | None = None,
    ) -> ExtractedClaim:
        normalized = canonicalize_claim(text)
        digest = sha256(f"{language}\0{normalized}".encode()).hexdigest()
        temporal = bool(claim_date_start or claim_date_end) if is_temporal is None else is_temporal
        return cls(
            claim_id=f"claim:{digest}",
            normalized_text=normalized,
            language=language,
            is_temporal=temporal,
            claim_date_start=claim_date_start,
            claim_date_end=claim_date_end,
        )


_EMAIL = re.compile(r"(?<!\w)[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?!\w)")
_PHONE = re.compile(r"(?<!\d)(?:\+?84|0)[\s.-]?(?:\d[\s.-]?){8,10}(?!\d)")
_SECRET = re.compile(
    r"\b(?:otp|pin|mã\s+(?:xác\s+nhận|otp))\s*+(?:[:=-]\s*+)?[A-Z0-9-]{4,12}\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>]+", re.IGNORECASE)


def _safe_url(match: re.Match[str]) -> str:
    try:
        parts = urlsplit(match.group(0).rstrip(".,);]"))
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
        return urlunsplit((parts.scheme.lower(), host.lower() + port, parts.path or "/", "", ""))
    except (ValueError, UnicodeError):
        return "[URL]"


def canonicalize_claim(text: str) -> str:
    """Normalize claim text and remove common secrets before external calls."""
    value = unicodedata.normalize("NFKC", text)
    value = _URL.sub(_safe_url, value)
    value = _EMAIL.sub("[EMAIL]", value)
    value = _PHONE.sub("[PHONE]", value)
    value = _SECRET.sub("[SECRET]", value)
    value = " ".join(value.split()).strip()
    if not value:
        raise ValueError("claim must not be empty after canonicalization")
    return value[:1000]


@dataclass(frozen=True, slots=True)
class EvidenceCandidate:
    evidence_ref: str
    source_url: str
    publisher: str
    source_tier: SourceTier
    stance: ClaimStance = ClaimStance.UNRATED
    title: str = "Fact-check evidence"
    finding: str = "Evidence matched the extracted claim."
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    published_at: datetime | None = None
    effective_from: date | None = None
    effective_to: date | None = None
    trusted_claim_review: bool = False
    reviewer: str | None = None
    publication_date_is_proxy: bool = False


@dataclass(frozen=True, slots=True)
class EvidenceSufficiency:
    sufficient: bool
    matched_rule: str | None
    eligible_refs: tuple[str, ...]
    missing_requirements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FactCheckPipelineResult:
    claim_findings: tuple[ClaimEvidence, ...]
    limitations: tuple[str, ...]
    errors: tuple[ToolError, ...]
    tool_usage_refs: tuple[str, ...]
    embedding_status: EmbeddingStatus
    usage_records: tuple[Any, ...]
    claim_feature_vectors: tuple[tuple[str, tuple[float, ...]], ...] = ()


@dataclass(frozen=True, slots=True)
class CapturedUsage:
    provider: str
    provider_version: str
    operation: str
    network_calls: int
    tokens: int
    estimated_cost_usd: float
    latency_ms: float
    observed_at: datetime
    cache_status: str
    outcome: str


class EmbeddingProvider(Protocol):
    async def embed_batch(self, claims: Sequence[str]) -> Any: ...


class GoogleClaimSearch(Protocol):
    async def search(self, claim: ExtractedClaim) -> Any: ...


class HybridCorpusRetriever(Protocol):
    async def search(self, claim: ExtractedClaim, *, vector: Sequence[float] | None = None) -> Any: ...


class TavilySearch(Protocol):
    async def search(self, claim: ExtractedClaim, *, max_results: int = 10) -> Any: ...


class JinaReader(Protocol):
    async def read(self, candidate: Any) -> Any: ...


class Chunker(Protocol):
    def split(self, evidence: Sequence[Any]) -> Sequence[Any]: ...


class Reranker(Protocol):
    def rank(self, claim: ExtractedClaim, candidates: Sequence[Any], *, top_k: int = 5) -> Sequence[Any]: ...


class EvidenceComparator(Protocol):
    async def compare(self, claim: ExtractedClaim, evidence: Sequence[Any]) -> Any: ...


class SourceRegistry(Protocol):
    def classify(self, canonical_url: str, at: datetime) -> Any: ...


def _get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _unwrap(envelope: Any) -> tuple[Any, str | None, ToolError | None]:
    """Accept normalized envelopes while keeping test/local adapters lightweight."""
    usage = _get(envelope, "usage")
    usage_ref = _get(usage, "usage_ref")
    status = _enum_value(_get(envelope, "status"))
    if status in {"blocked", "failed"}:
        error = _get(envelope, "error")
        code = _enum_value(_get(error, "code", "PROVIDER_ERROR"))
        return (
            None,
            usage_ref,
            ToolError(
                tool=str(_enum_value(_get(error, "tool", "fact_check"))),
                code=str(code),
                message=str(_get(error, "message", "Fact-check provider failed")),
                retryable=bool(_get(error, "retryable", False)),
            ),
        )
    result = _get(envelope, "result", envelope)
    return result, usage_ref, None


def _source_tier(value: Any) -> SourceTier:
    raw = str(_enum_value(value) or "untrusted").lower().replace("tier_", "").replace("tier ", "")
    try:
        return SourceTier(raw)
    except ValueError:
        return SourceTier.UNTRUSTED


def _as_candidate(item: Any, *, default_ref_prefix: str) -> EvidenceCandidate:
    record = _get(item, "record", item)
    source_url = str(_get(record, "source_url", _get(item, "url", _get(item, "canonical_url", ""))))
    publisher = str(_get(record, "publisher", _get(item, "publisher", _get(item, "reviewer", "unknown"))))
    record_id = str(_get(record, "record_id", _get(item, "review_ref", "")))
    evidence_ref = str(_get(item, "evidence_ref", "")) or (
        f"{default_ref_prefix}:sha256:" + sha256(f"{source_url}\0{publisher}\0{record_id}".encode()).hexdigest()
    )
    stance_raw = _enum_value(_get(record, "stance", _get(item, "stance", ClaimStance.UNRATED)))
    try:
        stance = ClaimStance(stance_raw)
    except ValueError:
        stance = ClaimStance.UNRATED
    observed_at = _get(record, "updated_at", _get(item, "observed_at", datetime.now(UTC)))
    if not isinstance(observed_at, datetime):
        observed_at = datetime.now(UTC)
    return EvidenceCandidate(
        evidence_ref=evidence_ref,
        source_url=source_url,
        publisher=publisher,
        source_tier=_source_tier(_get(item, "source_tier", _get(record, "source_tier"))),
        stance=stance,
        title=str(_get(item, "title", f"Fact-check by {publisher}")),
        finding=str(
            _get(record, "claim", _get(item, "finding", _get(item, "text", "Evidence matched the extracted claim.")))
        ),
        observed_at=observed_at,
        published_at=_get(record, "published_at", _get(item, "published_at")),
        effective_from=_get(item, "effective_from"),
        effective_to=_get(item, "effective_to"),
        trusted_claim_review=bool(_get(item, "trusted_claim_review", _get(item, "is_trusted_claim_review", False))),
        reviewer=_get(item, "reviewer"),
        publication_date_is_proxy=bool(_get(item, "publication_date_is_proxy", False)),
    )


def _temporal_compatible(claim: ExtractedClaim, item: EvidenceCandidate) -> bool:
    if not claim.is_temporal:
        return True

    if item.effective_from is not None or item.effective_to is not None:
        evidence_start = item.effective_from
        evidence_end = item.effective_to
    else:
        # Publication time is a point-in-time proxy when no effective interval exists.
        evidence_start = evidence_end = item.published_at.date() if item.published_at else None
    if evidence_start is None and evidence_end is None:
        return False

    claim_start = claim.claim_date_start
    claim_end = claim.claim_date_end
    if claim_start is None and claim_end is None:
        return True
    if claim_end is not None and evidence_start is not None and evidence_start > claim_end:
        return False
    if claim_start is not None and evidence_end is not None and evidence_end < claim_start:
        return False
    return True


def evaluate_evidence_sufficiency(claim: ExtractedClaim, evidence: Sequence[EvidenceCandidate]) -> EvidenceSufficiency:
    eligible = [
        item for item in evidence if item.source_tier is not SourceTier.UNTRUSTED and _temporal_compatible(claim, item)
    ]
    tier_a = [item for item in eligible if item.source_tier is SourceTier.A]
    if tier_a:
        return EvidenceSufficiency(True, "one_tier_a", tuple(item.evidence_ref for item in tier_a), ())
    trusted_reviews = [item for item in eligible if item.source_tier is SourceTier.B and item.trusted_claim_review]
    if trusted_reviews:
        return EvidenceSufficiency(
            True,
            "one_trusted_claim_review_tier_b",
            tuple(item.evidence_ref for item in trusted_reviews),
            (),
        )
    tier_b = [item for item in eligible if item.source_tier is SourceTier.B]
    publishers = {item.publisher.casefold() for item in tier_b}
    if len(publishers) >= 2:
        return EvidenceSufficiency(True, "two_independent_tier_b", tuple(item.evidence_ref for item in tier_b), ())
    return EvidenceSufficiency(
        False,
        None,
        tuple(item.evidence_ref for item in eligible),
        ("Cần một nguồn Tier A, một ClaimReview Tier B tin cậy, hoặc hai publisher Tier B độc lập.",),
    )


async def _call_corpus(provider: HybridCorpusRetriever, claim: ExtractedClaim, vector: Sequence[float] | None):
    try:
        return await provider.search(claim, vector=vector)
    except TypeError:
        return await provider.search(claim)  # type: ignore[call-arg]


def _items(result: Any) -> list[Any]:
    if result is None:
        return []
    if isinstance(result, Sequence) and not isinstance(result, (str, bytes)):
        return list(result)
    for key in ("matches", "candidates", "items", "vectors"):
        nested = _get(result, key)
        if nested is not None:
            return list(nested)
    return []


class FactCheckOrchestrator:
    """Wave 2 orchestration; providers gather evidence, while Risk Engine owns decisions."""

    def __init__(
        self,
        *,
        embedding_provider: EmbeddingProvider | None = None,
        google_claim_search: GoogleClaimSearch | None = None,
        corpus_retriever: HybridCorpusRetriever | None = None,
        tavily_search: TavilySearch | None = None,
        jina_reader: JinaReader | None = None,
        chunker: Chunker | None = None,
        reranker: Reranker | None = None,
        comparator: EvidenceComparator | None = None,
        source_registry: SourceRegistry | None = None,
        max_claim_concurrency: int = 3,
    ) -> None:
        if not 1 <= max_claim_concurrency <= 3:
            raise ValueError("claim concurrency must be between one and three")
        self.embedding_provider = embedding_provider
        self.google_claim_search = google_claim_search
        self.corpus_retriever = corpus_retriever
        self.tavily_search = tavily_search
        self.jina_reader = jina_reader
        self.chunker = chunker
        self.reranker = reranker
        self.comparator = comparator
        self.source_registry = source_registry
        self.max_claim_concurrency = max_claim_concurrency
        self._usage_records: ContextVar[list[Any] | None] = ContextVar("fact_check_usage", default=None)

    def _unwrap(self, envelope: Any):
        usage = _get(envelope, "usage")
        if usage is not None and hasattr(usage, "usage_ref"):
            records = self._usage_records.get()
            if records is not None:
                cache = _get(envelope, "cache")
                status = _get(envelope, "status", "success")
                records.append(
                    CapturedUsage(
                        provider=usage.provider,
                        provider_version=usage.provider_version,
                        operation=usage.operation,
                        network_calls=usage.network_calls,
                        tokens=usage.tokens,
                        estimated_cost_usd=usage.estimated_cost_usd,
                        latency_ms=usage.latency_ms,
                        observed_at=usage.observed_at,
                        cache_status=str(_get(cache, "status", "miss")),
                        outcome=str(getattr(status, "value", status)),
                    )
                )
        return _unwrap(envelope)

    async def verify(self, claims: Sequence[ExtractedClaim]) -> FactCheckPipelineResult:
        selected = tuple(claims[:5])
        if not selected:
            return FactCheckPipelineResult((), (), (), (), EmbeddingStatus.NOT_CONFIGURED, ())
        usage_records: list[Any] = []
        self._usage_records.set(usage_records)
        vectors: list[Sequence[float] | None] = [None] * len(selected)
        usage_refs: list[str] = []
        errors: list[ToolError] = []
        limitations: list[str] = []
        embedding_status = EmbeddingStatus.NOT_CONFIGURED
        if self.embedding_provider is not None:
            try:
                envelope = await self.embedding_provider.embed_batch([item.normalized_text for item in selected])
                result, usage_ref, error = self._unwrap(envelope)
                if usage_ref:
                    usage_refs.append(usage_ref)
                if error:
                    errors.append(error)
                    embedding_status = EmbeddingStatus.PENDING
                    limitations.append("Embedding chưa sẵn sàng; tiếp tục bằng Google/FTS và web có điều kiện.")
                else:
                    batch = _items(result)
                    if len(batch) != len(selected):
                        raise ValueError("embedding batch size does not match claim count")
                    vectors = [tuple(_get(item, "vector", item)) for item in batch]
                    embedding_status = EmbeddingStatus.COMPLETE
            except Exception as exc:
                embedding_status = EmbeddingStatus.PENDING
                errors.append(ToolError(tool="embedding", code="PROVIDER_ERROR", message=str(exc), retryable=True))
                limitations.append("Embedding chưa sẵn sàng; tiếp tục bằng Google/FTS và web có điều kiện.")

        semaphore = asyncio.Semaphore(self.max_claim_concurrency)

        async def bounded(index: int, claim: ExtractedClaim):
            async with semaphore:
                return await self._verify_one(claim, vectors[index])

        outputs = await asyncio.gather(*(bounded(index, claim) for index, claim in enumerate(selected)))
        findings: list[ClaimEvidence] = []
        for claim_findings, claim_limitations, claim_errors, claim_usage in outputs:
            findings.extend(claim_findings)
            limitations.extend(claim_limitations)
            errors.extend(claim_errors)
            usage_refs.extend(claim_usage)
        return FactCheckPipelineResult(
            tuple(findings),
            tuple(dict.fromkeys(limitations)),
            tuple(errors),
            tuple(dict.fromkeys(usage_refs)),
            embedding_status,
            tuple(usage_records),
            tuple(
                (
                    "claim-feature:sha256:" + sha256(item.normalized_text.encode()).hexdigest(),
                    tuple(vector),
                )
                for item, vector in zip(selected, vectors, strict=True)
                if vector is not None
            ),
        )

    async def _verify_one(self, claim: ExtractedClaim, vector: Sequence[float] | None):
        limitations: list[str] = []
        errors: list[ToolError] = []
        usage_refs: list[str] = []
        initial_calls = []
        labels = []
        if self.google_claim_search is not None:
            initial_calls.append(self.google_claim_search.search(claim))
            labels.append("google_claim_search")
        if self.corpus_retriever is not None:
            initial_calls.append(_call_corpus(self.corpus_retriever, claim, vector))
            labels.append("hybrid_corpus")
        evidence: list[EvidenceCandidate] = []
        if initial_calls:
            results = await asyncio.gather(*initial_calls, return_exceptions=True)
            for label, envelope in zip(labels, results, strict=True):
                if isinstance(envelope, BaseException):
                    errors.append(ToolError(tool=label, code="PROVIDER_ERROR", message=str(envelope), retryable=True))
                    limitations.append(f"{label} không trả được evidence.")
                    continue
                result, usage_ref, error = self._unwrap(envelope)
                if usage_ref:
                    usage_refs.append(usage_ref)
                if error:
                    errors.append(error)
                    limitations.append(f"{label} không trả được evidence.")
                    continue
                evidence.extend(_as_candidate(item, default_ref_prefix=label) for item in _items(result))

        temporal_missing = any(
            item.source_tier is not SourceTier.UNTRUSTED and not _temporal_compatible(claim, item) for item in evidence
        )
        if temporal_missing:
            limitations.append("Evidence không tương thích thời gian hoặc không có ngày đã bị loại.")
        if any(item.publication_date_is_proxy for item in evidence):
            limitations.append("Một số evidence chỉ có ngày xuất bản proxy và được hạ độ tin cậy.")
        gate = evaluate_evidence_sufficiency(claim, evidence)
        comparison_input: list[Any] = [
            item
            for item in evidence
            if item.source_tier is not SourceTier.UNTRUSTED and _temporal_compatible(claim, item)
        ]
        if not gate.sufficient:
            web_items = await self._conditional_web(claim, limitations, errors, usage_refs)
            combined = [*evidence, *(_as_candidate(item, default_ref_prefix="web") for item in web_items)]
            gate = evaluate_evidence_sufficiency(claim, combined)
            if gate.sufficient:
                comparison_input = [
                    item
                    for item in combined
                    if item.source_tier is not SourceTier.UNTRUSTED and _temporal_compatible(claim, item)
                ]
            else:
                comparison_input = []
                limitations.extend(gate.missing_requirements)

        findings = await self._compare_or_project(claim, comparison_input, limitations, errors, usage_refs)
        if not findings:
            limitations.append("Không có đủ evidence nhất quán để kết luận claim.")
        return findings, limitations, errors, usage_refs

    async def _conditional_web(self, claim, limitations, errors, usage_refs):
        if self.tavily_search is None:
            return []
        try:
            envelope = await self.tavily_search.search(claim, max_results=10)
            result, usage_ref, error = self._unwrap(envelope)
            if usage_ref:
                usage_refs.append(usage_ref)
            if error:
                errors.append(error)
                limitations.append("Tavily không hoàn tất; không tạo citation thay thế.")
                return []
            candidates = _items(result)[:10]
        except Exception as exc:
            errors.append(ToolError(tool="tavily", code="PROVIDER_ERROR", message=str(exc), retryable=True))
            limitations.append("Tavily không hoàn tất; không tạo citation thay thế.")
            return []

        approved: list[Any] = []
        seen_urls: set[str] = set()
        for candidate in candidates:
            url = str(_get(candidate, "canonical_url", _get(candidate, "url", "")))
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            decision = self.source_registry.classify(url, datetime.now(UTC)) if self.source_registry else candidate
            if _source_tier(_get(decision, "source_tier", _get(decision, "tier"))) is SourceTier.UNTRUSTED:
                continue
            if bool(_get(decision, "explicit_deny", False)):
                continue
            approved.append(candidate)
            if len(approved) == 5:
                break
        if self.jina_reader is None or not approved:
            return []
        fetched: list[Any] = []
        results = await asyncio.gather(*(self.jina_reader.read(item) for item in approved), return_exceptions=True)
        for envelope in results:
            if isinstance(envelope, BaseException):
                limitations.append("Jina Reader không đọc được một nguồn; nguồn đó bị bỏ qua.")
                continue
            result, usage_ref, error = self._unwrap(envelope)
            if usage_ref:
                usage_refs.append(usage_ref)
            if error:
                errors.append(error)
                limitations.append("Jina Reader không đọc được một nguồn; nguồn đó bị bỏ qua.")
            elif result is not None:
                fetched.append(result)
        if not fetched or self.chunker is None or self.reranker is None:
            return []
        try:
            chunks = list(self.chunker.split(fetched))
            ranked = self.reranker.rank(claim, chunks, top_k=5)
            if inspect.isawaitable(ranked):
                ranked = await ranked
            return list(ranked)[:5]
        except Exception as exc:
            errors.append(ToolError(tool="reranker", code="PROVIDER_ERROR", message=str(exc), retryable=False))
            limitations.append("FlashRank không hoàn tất; không tạo citation hoặc safe verdict giả.")
            return []

    async def _compare_or_project(self, claim, candidates, limitations, errors, usage_refs):
        eligible = [item for item in candidates if _source_tier(_get(item, "source_tier")) is not SourceTier.UNTRUSTED]
        if self.comparator is not None and eligible:
            try:
                submitted = eligible[:5]
                envelope = await self.comparator.compare(claim, submitted)
                result, usage_ref, error = self._unwrap(envelope)
                if usage_ref:
                    usage_refs.append(usage_ref)
                if error:
                    errors.append(error)
                    limitations.append("Comparator không hoàn tất; kết quả claim là inconclusive.")
                    return []
                allowed_refs = {str(_get(item, "evidence_ref", _get(item, "chunk_ref", ""))) for item in submitted}
                cited_refs = [str(ref) for ref in _get(result, "evidence_refs", ())]
                if not cited_refs or any(ref not in allowed_refs for ref in cited_refs):
                    limitations.append("Comparator trả citation không hợp lệ; kết quả bị loại.")
                    return []
                stance_value = _enum_value(_get(result, "stance", "inconclusive"))
                if stance_value == "inconclusive":
                    limitations.extend(str(item) for item in _get(result, "limitations", ()))
                    return []
                stance = ClaimStance(stance_value)
                by_ref = {str(_get(item, "evidence_ref", _get(item, "chunk_ref", ""))): item for item in submitted}
                return [self._to_claim_evidence(by_ref[ref], stance) for ref in cited_refs]
            except Exception as exc:
                errors.append(ToolError(tool="comparator", code="PROVIDER_ERROR", message=str(exc), retryable=True))
                limitations.append("Comparator không hoàn tất; kết quả claim là inconclusive.")
                return []

        projected = [item for item in eligible if _get(item, "stance", ClaimStance.UNRATED) is not ClaimStance.UNRATED]
        stances = {ClaimStance(_enum_value(_get(item, "stance"))) for item in projected}
        if ClaimStance.SUPPORTS in stances and ClaimStance.REFUTES in stances:
            limitations.append("Các nguồn fact-check đáng tin cậy đang mâu thuẫn; kết quả claim chưa kết luận.")
            return []
        return [self._to_claim_evidence(item, ClaimStance(_enum_value(_get(item, "stance")))) for item in projected]

    @staticmethod
    def _to_claim_evidence(item: Any, stance: ClaimStance) -> ClaimEvidence:
        return ClaimEvidence(
            source=str(_get(item, "publisher", _get(item, "source", "Fact-check source"))),
            title=str(_get(item, "title", "Fact-check evidence")),
            url=_get(item, "source_url", _get(item, "safe_url", _get(item, "url"))),
            finding=str(_get(item, "finding", "Evidence matched the extracted claim.")),
            relevance=max(0.0, min(1.0, float(_get(item, "rerank_score", _get(item, "similarity", 1.0))))),
            stance=stance,
            observed_at=_get(item, "observed_at", datetime.now(UTC)),
        )


__all__ = [
    "EmbeddingStatus",
    "EvidenceCandidate",
    "EvidenceSufficiency",
    "ExtractedClaim",
    "FactCheckOrchestrator",
    "FactCheckPipelineResult",
    "SourceTier",
    "canonicalize_claim",
    "evaluate_evidence_sufficiency",
]
