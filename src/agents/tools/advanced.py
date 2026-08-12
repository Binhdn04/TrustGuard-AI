from __future__ import annotations

import html
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from hashlib import sha256
from time import perf_counter
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from src.agents.fact_check import ExtractedClaim

from .models import (
    CacheMetadata,
    CacheStatus,
    EmbeddingBatch,
    EmbeddingVector,
    EvidenceChunk,
    FetchedEvidence,
    GoogleClaimReviewMatch,
    NormalizedToolError,
    NormalizedToolResult,
    RerankedCandidate,
    ScreenshotResult,
    ToolErrorCode,
    ToolName,
    ToolResultStatus,
    UsageMetadata,
    WebCandidate,
)
from .network import SsrfGuard
from .providers import map_google_fact_check_rating


def _now() -> datetime:
    return datetime.now(UTC)


def _usage(
    provider: str,
    version: str,
    operation: str,
    started: float,
    *,
    calls: int = 1,
    request_units: float = 1,
    response_units: float = 0,
    tokens: int = 0,
) -> UsageMetadata:
    observed = _now()
    seed = f"{provider}\0{operation}\0{observed.isoformat()}\0{started}"
    return UsageMetadata(
        usage_ref=f"usage:{sha256(seed.encode()).hexdigest()}",
        provider=provider,
        provider_version=version,
        operation=operation,
        attempts=1,
        network_calls=calls,
        latency_ms=(perf_counter() - started) * 1000,
        request_units=request_units,
        response_units=response_units,
        tokens=tokens,
        observed_at=observed,
    )


def _miss() -> CacheMetadata:
    return CacheMetadata(status=CacheStatus.MISS)


def _failure(
    tool: ToolName,
    provider: str,
    version: str,
    operation: str,
    started: float,
    code: ToolErrorCode,
    message: str,
    *,
    retryable: bool,
    retry_after_ms: int | None = None,
):
    return NormalizedToolResult(
        status=ToolResultStatus.FAILED,
        error=NormalizedToolError(
            tool=tool, code=code, message=message, retryable=retryable, provider=provider, retry_after_ms=retry_after_ms
        ),
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="transient_failure"),
        usage=_usage(provider, version, operation, started),
    )


class OpenAIEmbeddingProvider:
    """One bounded OpenAI embeddings request; never falls back to a local model."""

    provider = "openai"
    provider_version = "v1"
    model = "text-embedding-3-small"
    dimensions = 1536

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        endpoint: str = "https://api.openai.com/v1/embeddings",
        timeout: float = 10,
    ) -> None:
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self.api_key, self.endpoint = api_key, endpoint

    async def embed_batch(self, claims: Sequence[str]) -> NormalizedToolResult[EmbeddingBatch]:
        if not 1 <= len(claims) <= 5:
            raise ValueError("embedding batch must contain between one and five claims")
        started = perf_counter()
        try:
            response = await self._client.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "input": list(claims), "dimensions": self.dimensions},
            )
            if response.status_code == 429:
                retry = response.headers.get("retry-after")
                retry_ms = int(float(retry) * 1000) if retry else None
                return _failure(
                    ToolName.FACT_CHECK_CORPUS,
                    self.provider,
                    self.provider_version,
                    "embed_batch",
                    started,
                    ToolErrorCode.RATE_LIMITED,
                    "Embedding provider rate limited the request",
                    retryable=True,
                    retry_after_ms=retry_ms,
                )
            response.raise_for_status()
            payload = response.json()
            ordered = sorted(payload.get("data", []), key=lambda item: item.get("index", -1))
            vectors = [EmbeddingVector(claim_index=i, vector=item["embedding"]) for i, item in enumerate(ordered)]
            batch = EmbeddingBatch(
                vectors=vectors,
                model=payload.get("model", self.model),
                model_version=payload.get("model", self.model),
                dimensions=self.dimensions,
            )
            usage = payload.get("usage", {})
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS,
                result=batch,
                cache=_miss(),
                usage=_usage(
                    self.provider,
                    self.provider_version,
                    "embed_batch",
                    started,
                    response_units=len(vectors),
                    tokens=int(usage.get("total_tokens", 0)),
                ),
            )
        except (httpx.TimeoutException, httpx.HTTPError, ValueError, KeyError) as exc:
            code = (
                ToolErrorCode.PROVIDER_TIMEOUT
                if isinstance(exc, httpx.TimeoutException)
                else ToolErrorCode.PROVIDER_ERROR
            )
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "embed_batch",
                started,
                code,
                "Embedding provider failed",
                retryable=True,
            )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class GoogleClaimSearchAdapter:
    endpoint = "https://factchecktools.googleapis.com/v1alpha1/claims:search"
    provider = "google-fact-check-tools"
    provider_version = "v1alpha1"

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10,
        classify_source: Callable[[str, datetime], Any] | None = None,
    ) -> None:
        self.api_key, self._classify = api_key, classify_source
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def search(self, claim: ExtractedClaim) -> NormalizedToolResult[list[GoogleClaimReviewMatch]]:
        started = perf_counter()
        try:
            response = await self._client.get(
                self.endpoint,
                params={
                    "key": self.api_key,
                    "query": claim.normalized_text,
                    "languageCode": claim.language,
                    "pageSize": 10,
                },
            )
            if response.status_code == 429:
                return _failure(
                    ToolName.FACT_CHECK_CORPUS,
                    self.provider,
                    self.provider_version,
                    "claims.search",
                    started,
                    ToolErrorCode.RATE_LIMITED,
                    "Claim Search rate limited the request",
                    retryable=True,
                )
            response.raise_for_status()
            payload = response.json()
            results = []
            for indexed in payload.get("claims", []):
                for review in indexed.get("claimReview", []):
                    publisher = review.get("publisher") or {}
                    url = review.get("url")
                    name = publisher.get("name")
                    if not url or not name:
                        continue
                    observed = _now()
                    decision = self._classify(url, observed) if self._classify else None
                    tier = str(getattr(decision, "tier", "untrusted")).lower().replace("sourcetier.", "")
                    trusted = bool(getattr(decision, "trusted_claim_review", False))
                    date_raw = review.get("reviewDate")
                    try:
                        published = datetime.fromisoformat(date_raw.replace("Z", "+00:00")) if date_raw else None
                        if published is not None and published.tzinfo is None:
                            published = published.replace(tzinfo=UTC)
                    except (ValueError, AttributeError):
                        published = None
                    results.append(
                        GoogleClaimReviewMatch(
                            claim_text=str(indexed.get("text") or claim.normalized_text),
                            review_ref="claimreview:sha256:" + sha256(f"{url}\0{name}".encode()).hexdigest(),
                            review_url=url,
                            reviewer=name,
                            publisher=name,
                            title=str(review.get("title") or indexed.get("text") or "ClaimReview"),
                            textual_rating=review.get("textualRating") or None,
                            stance=map_google_fact_check_rating(review.get("textualRating")),
                            source_tier=tier,
                            trusted_claim_review=trusted,
                            published_at=published,
                            observed_at=observed,
                        )
                    )
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if results else ToolResultStatus.INCONCLUSIVE,
                result=results,
                cache=_miss(),
                usage=_usage(
                    self.provider, self.provider_version, "claims.search", started, response_units=len(results)
                ),
            )
        except (httpx.TimeoutException, httpx.HTTPError, ValueError):
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "claims.search",
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "Google Claim Search failed",
                retryable=True,
            )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def reciprocal_rank_fusion(
    fts: Sequence[Any], vector: Sequence[Any], *, k: int = 60
) -> list[tuple[Any, int | None, int | None, float]]:
    if k <= 0:
        raise ValueError("RRF k must be positive")
    merged: dict[tuple[str, str], list[Any]] = {}
    for kind, rows in (("fts", fts[:20]), ("vector", vector[:20])):
        for rank, row in enumerate(rows, 1):
            key = (str(row["record_id"]), str(row["record_version"]))
            entry = merged.setdefault(key, [row, None, None, 0.0])
            entry[1 if kind == "fts" else 2] = rank
            entry[3] += 1 / (k + rank)
    return [tuple(v) for v in sorted(merged.values(), key=lambda x: (-x[3], str(x[0]["record_id"])))]


def canonicalize_evidence_url(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").encode("idna").decode().lower()
    port = f":{parts.port}" if parts.port and parts.port not in {80, 443} else ""
    return urlunsplit((parts.scheme.lower(), host + port, parts.path or "/", parts.query, ""))


class EvidenceChunker:
    def __init__(self, *, chunk_size: int = 1200, overlap: int = 150) -> None:
        if not 0 <= overlap < chunk_size:
            raise ValueError("overlap must be smaller than chunk size")
        self.chunk_size, self.overlap = chunk_size, overlap

    def split(self, evidence: Sequence[FetchedEvidence]) -> list[EvidenceChunk]:
        output = []
        for item in evidence:
            text = "\n".join(
                part.strip() for part in re.split(r"\n\s*\n|(?<=[.!?])\s+", item.cleaned_content) if part.strip()
            )
            start = 0
            index = 0
            while start < len(text):
                end = min(len(text), start + self.chunk_size)
                if end < len(text):
                    boundary = max(text.rfind("\n", start, end), text.rfind(" ", start, end))
                    if boundary > start + self.chunk_size // 2:
                        end = boundary
                body = text[start:end].strip()
                if body:
                    ref_seed = "\0".join((item.evidence_ref, str(index), body))
                    ref = f"chunk:sha256:{sha256(ref_seed.encode()).hexdigest()}"
                    output.append(
                        EvidenceChunk(
                            chunk_ref=ref,
                            evidence_ref=item.evidence_ref,
                            index=index,
                            text=body,
                            canonical_url=item.canonical_url,
                            content_sha256=item.content_sha256,
                            source_tier=item.source_tier,
                            source_version=item.source_version,
                            published_at=item.published_at,
                        )
                    )
                    index += 1
                if end >= len(text):
                    break
                start = max(start + 1, end - self.overlap)
        return output


class FlashRankReranker:
    model_name = "ms-marco-MultiBERT-L-12"

    def __init__(self, ranker: Any, *, max_length: int = 512) -> None:
        if ranker is None:
            raise ValueError("a preloaded FlashRank ranker is required")
        self.ranker, self.max_length = ranker, max_length

    def rank(
        self, claim: ExtractedClaim, candidates: Sequence[EvidenceChunk], *, top_k: int = 5
    ) -> list[RerankedCandidate]:
        passages = [{"id": c.chunk_ref, "text": c.text, "meta": c} for c in candidates]
        # FlashRank 0.2.x configures max_length on Ranker construction; rerank
        # accepts a RerankRequest-like object as its only argument. Keep this
        # provider boundary structural so importing this module remains safe
        # when the optional live dependency is not installed.
        request = SimpleNamespace(query=claim.normalized_text, passages=passages)
        ranked = self.ranker.rerank(request)
        by_ref = {c.chunk_ref: c for c in candidates}
        output = []
        for position, row in enumerate(ranked[: min(top_k, 5)], 1):
            item = by_ref[str(row.get("id"))]
            output.append(
                RerankedCandidate(
                    chunk_ref=item.chunk_ref,
                    evidence_ref=item.evidence_ref,
                    rank=position,
                    rerank_score=float(row.get("score", 0)),
                    text=item.text,
                    canonical_url=item.canonical_url,
                    title="Web evidence",
                    publisher=urlsplit(item.canonical_url).hostname or "unknown",
                    source_tier=item.source_tier,
                    source_version=item.source_version,
                    published_at=item.published_at,
                )
            )
        return output


def clean_reader_content(value: str) -> str:
    value = re.sub(r"<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>", " ", value, flags=re.I | re.S)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", value)).split())


class TavilySearchAdapter:
    endpoint = "https://api.tavily.com/search"
    provider = "tavily"
    provider_version = "v1"

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10,
        allowed_domains: Callable[[ExtractedClaim], Sequence[str]] | None = None,
        classify_source: Callable[[str, datetime], Any] | None = None,
    ) -> None:
        self.api_key, self._domains, self._classify = api_key, allowed_domains, classify_source
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def search(self, claim: ExtractedClaim, *, max_results: int = 10) -> NormalizedToolResult[list[WebCandidate]]:
        started = perf_counter()
        maximum = min(max(1, max_results), 10)
        body: dict[str, Any] = {
            "api_key": self.api_key,
            "query": claim.normalized_text,
            "max_results": maximum,
            "include_answer": False,
            "include_raw_content": False,
        }
        domains = list(self._domains(claim)) if self._domains else []
        if domains:
            body["include_domains"] = domains
        if claim.claim_date_start:
            body["start_date"] = claim.claim_date_start.isoformat()
        if claim.claim_date_end:
            body["end_date"] = claim.claim_date_end.isoformat()
        try:
            response = await self._client.post(self.endpoint, json=body)
            response.raise_for_status()
            output, seen = [], set()
            for row in response.json().get("results", [])[:maximum]:
                url = canonicalize_evidence_url(str(row.get("url", "")))
                if not url or url in seen:
                    continue
                seen.add(url)
                host = urlsplit(url).hostname or "unknown"
                decision = self._classify(url, _now()) if self._classify else None
                tier = getattr(getattr(decision, "tier", None), "value", None) or "untrusted"
                publisher = getattr(decision, "publisher", None) or host
                output.append(
                    WebCandidate(
                        evidence_ref="web:sha256:" + sha256(url.encode()).hexdigest(),
                        canonical_url=url,
                        title=str(row.get("title") or host),
                        snippet=str(row.get("content") or "No snippet"),
                        publisher=publisher,
                        source_tier=str(tier),
                        source_version=self.provider_version,
                    )
                )
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if output else ToolResultStatus.INCONCLUSIVE,
                result=output,
                cache=_miss(),
                usage=_usage(self.provider, self.provider_version, "search", started, response_units=len(output)),
            )
        except (httpx.HTTPError, ValueError):
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "search",
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "Tavily search failed",
                retryable=True,
            )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class JinaReaderAdapter:
    provider = "jina-reader"
    provider_version = "v1"

    def __init__(
        self,
        api_key: str = "",
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        timeout: float = 10,
    ) -> None:
        self.api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._guard = guard or SsrfGuard()

    async def read(self, candidate: WebCandidate) -> NormalizedToolResult[FetchedEvidence]:
        started = perf_counter()
        try:
            # Validate the original source immediately before delegating the fetch.
            await self._guard.validate(candidate.canonical_url)
            headers = {"Accept": "text/plain"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            response = await self._client.get("https://r.jina.ai/" + candidate.canonical_url, headers=headers)
            response.raise_for_status()
            cleaned = clean_reader_content(response.text)
            digest = sha256(cleaned.encode()).hexdigest()
            result = FetchedEvidence(
                evidence_ref=candidate.evidence_ref,
                canonical_url=candidate.canonical_url,
                title=candidate.title,
                cleaned_content=cleaned,
                content_sha256=digest,
                publisher=candidate.publisher,
                source_tier=candidate.source_tier,
                source_version=candidate.source_version,
                published_at=candidate.published_at,
                observed_at=_now(),
            )
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS,
                result=result,
                cache=_miss(),
                usage=_usage(
                    self.provider, self.provider_version, "read", started, response_units=len(cleaned.encode())
                ),
            )
        except (httpx.HTTPError, ValueError, RuntimeError):
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "read",
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "Jina Reader failed",
                retryable=True,
            )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class PlaywrightScreenshotRenderer:
    """Isolated screenshot boundary. The browser launcher must be preinstalled in the image."""

    provider = "playwright-chromium"
    provider_version = "v1"

    def __init__(
        self,
        capture: Callable[..., Any],
        artifact_store: Callable[[bytes], Any],
        *,
        guard: SsrfGuard | None = None,
        timeout_seconds: float = 8,
    ) -> None:
        self._capture, self._store = capture, artifact_store
        self._guard, self.timeout_seconds = guard or SsrfGuard(), timeout_seconds

    async def render(self, normalized_url: str) -> NormalizedToolResult[ScreenshotResult]:
        """Capture callable must use a fresh context with downloads and persistence disabled."""
        import asyncio

        started = perf_counter()
        try:
            await self._guard.validate(normalized_url)
            captured = await asyncio.wait_for(
                self._capture(
                    normalized_url,
                    fresh_context=True,
                    accept_downloads=False,
                    storage_state=None,
                    revalidate=self._guard.validate,
                ),
                self.timeout_seconds,
            )
            final_url = canonicalize_evidence_url(str(captured["final_url"]))
            await self._guard.validate(final_url)
            if captured.get("download_attempted"):
                return _failure(
                    ToolName.SCREENSHOT_RENDERER,
                    self.provider,
                    self.provider_version,
                    "render",
                    started,
                    ToolErrorCode.DOWNLOAD_BLOCKED,
                    "The page attempted a download",
                    retryable=False,
                )
            artifact_ref = await self._store(bytes(captured["image"]))
            visible = " ".join(str(captured.get("visible_text", "")).split())
            result = ScreenshotResult(
                artifact_ref=str(artifact_ref),
                final_url=final_url,
                visible_text_sha256=sha256(visible.encode()).hexdigest(),
                signals=list(captured.get("signals", [])),
                observed_at=_now(),
            )
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS,
                result=result,
                cache=_miss(),
                usage=_usage(self.provider, self.provider_version, "render", started),
            )
        except TimeoutError:
            return _failure(
                ToolName.SCREENSHOT_RENDERER,
                self.provider,
                self.provider_version,
                "render",
                started,
                ToolErrorCode.PROVIDER_TIMEOUT,
                "Screenshot renderer timed out",
                retryable=True,
            )
        except Exception as exc:
            code = ToolErrorCode.SSRF_BLOCKED if getattr(exc, "error", None) else ToolErrorCode.PROVIDER_ERROR
            status = ToolResultStatus.BLOCKED if code is ToolErrorCode.SSRF_BLOCKED else ToolResultStatus.FAILED
            result = _failure(
                ToolName.SCREENSHOT_RENDERER,
                self.provider,
                self.provider_version,
                "render",
                started,
                code,
                "Screenshot rendering was blocked"
                if status is ToolResultStatus.BLOCKED
                else "Screenshot renderer failed",
                retryable=False,
            )
            return result.model_copy(update={"status": status})
