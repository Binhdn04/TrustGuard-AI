from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from hashlib import sha256
from time import perf_counter
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from src.agents.fact_check import ExtractedClaim

from .models import (
    CacheMetadata,
    CacheStatus,
    EmbeddingBatch,
    EmbeddingVector,
    ExtractedWebEvidence,
    GoogleClaimReviewMatch,
    NormalizedToolError,
    NormalizedToolResult,
    ScreenshotResult,
    TavilyExtractBatch,
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
    http_status_code: int | None = None,
    calls: int = 1,
):
    return NormalizedToolResult(
        status=ToolResultStatus.FAILED,
        error=NormalizedToolError(
            tool=tool,
            code=code,
            message=message,
            retryable=retryable,
            provider=provider,
            retry_after_ms=retry_after_ms,
            http_status_code=http_status_code,
        ),
        cache=CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="transient_failure"),
        usage=_usage(provider, version, operation, started, calls=calls),
    )


def _provider_failure_details(
    failures: Sequence[BaseException], provider_label: str
) -> tuple[ToolErrorCode, str, bool, int | None, int | None]:
    statuses = [item.response.status_code for item in failures if isinstance(item, httpx.HTTPStatusError)]
    timeouts = [item for item in failures if isinstance(item, httpx.TimeoutException)]
    unique_statuses = sorted(set(statuses))
    status_code = unique_statuses[0] if len(unique_statuses) == 1 else None

    if statuses and len(statuses) == len(failures) and all(status == 429 for status in statuses):
        retry_values: list[int] = []
        for item in failures:
            if not isinstance(item, httpx.HTTPStatusError):
                continue
            retry = item.response.headers.get("retry-after")
            try:
                if retry is not None:
                    retry_values.append(int(float(retry) * 1000))
            except ValueError:
                continue
        return (
            ToolErrorCode.RATE_LIMITED,
            f"{provider_label} rate limited the request (HTTP 429)",
            True,
            min(retry_values) if retry_values else None,
            429,
        )

    details: list[str] = []
    if timeouts:
        details.append(f"{len(timeouts)} timeout(s)")
    if unique_statuses:
        details.append("HTTP " + ", ".join(str(status) for status in unique_statuses))
    suffix = f" ({'; '.join(details)})" if details else ""
    if timeouts and not statuses:
        return ToolErrorCode.PROVIDER_TIMEOUT, f"{provider_label} timed out{suffix}", True, None, None
    retryable = bool(timeouts) or any(status == 429 or status >= 500 for status in statuses)
    return ToolErrorCode.PROVIDER_ERROR, f"{provider_label} failed{suffix}", retryable, None, status_code


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
        variants = claim.query_variants

        async def fetch(query):
            response = await self._client.get(
                self.endpoint,
                params={"key": self.api_key, "query": query.text, "languageCode": query.language, "pageSize": 10},
            )
            response.raise_for_status()
            return response.json()

        responses = await asyncio.gather(*(fetch(query) for query in variants), return_exceptions=True)
        payloads = [item for item in responses if not isinstance(item, BaseException)]
        if not payloads:
            code, message, retryable, retry_after_ms, http_status_code = _provider_failure_details(
                [item for item in responses if isinstance(item, BaseException)], "Google Claim Search"
            )
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "claims.search",
                started,
                code,
                message,
                retryable=retryable,
                retry_after_ms=retry_after_ms,
                http_status_code=http_status_code,
                calls=len(variants),
            )

        try:
            results = []
            seen_urls: set[str] = set()
            for payload in payloads:
                if not isinstance(payload, dict):
                    continue
                for indexed in payload.get("claims", []):
                    for review in indexed.get("claimReview", []):
                        publisher = review.get("publisher") or {}
                        url = review.get("url")
                        name = publisher.get("name")
                        if not url or not name or url in seen_urls:
                            continue
                        seen_urls.add(url)
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
                                policy_version=str(getattr(decision, "policy_version", "unregistered")),
                                published_at=published,
                                observed_at=observed,
                            )
                        )
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if results else ToolResultStatus.INCONCLUSIVE,
                result=results,
                cache=_miss(),
                usage=_usage(
                    self.provider,
                    self.provider_version,
                    "claims.search",
                    started,
                    calls=len(variants),
                    response_units=len(results),
                ),
            )
        except (TypeError, ValueError):
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "claims.search",
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "Google Claim Search returned an invalid response payload",
                retryable=False,
                calls=len(variants),
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
        excluded_domains: Callable[[ExtractedClaim], Sequence[str]] | None = None,
        official_domains: Callable[[ExtractedClaim], Sequence[str]] | None = None,
        classify_source: Callable[[str, datetime], Any] | None = None,
        discovery_observer: Callable[..., Any] | None = None,
    ) -> None:
        self.api_key = api_key
        self._excluded_domains = excluded_domains
        self._official_domains = official_domains
        self._classify = classify_source
        self._observe_discovery = discovery_observer
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def search(self, claim: ExtractedClaim, *, max_results: int = 10) -> NormalizedToolResult[list[WebCandidate]]:
        started = perf_counter()
        maximum = min(max(1, max_results), 10)
        variants = claim.query_variants
        excluded_domains = list(self._excluded_domains(claim))[:150] if self._excluded_domains else []
        official_domains = list(self._official_domains(claim)) if self._official_domains else []

        async def fetch(query):
            body: dict[str, Any] = {
                "query": query.text,
                "max_results": maximum,
                "include_answer": False,
                "include_raw_content": False,
            }
            query_folded = query.text.casefold()
            official_query = bool(
                official_domains and any(marker in query_folded for marker in ("official", "chính thức"))
            )
            body["search_depth"] = "advanced" if official_query else "basic"
            if official_query:
                body["include_domains"] = official_domains
            elif excluded_domains:
                body["exclude_domains"] = excluded_domains
            # Claim dates describe when the asserted event/policy applies,
            # not when corroborating articles were published. A future policy
            # can be documented by an article published before its start date.
            response = await self._client.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=body,
            )
            response.raise_for_status()
            return response.json()

        responses = await asyncio.gather(*(fetch(query) for query in variants), return_exceptions=True)
        payloads = [item for item in responses if not isinstance(item, BaseException)]
        if not payloads:
            code, message, retryable, retry_after_ms, http_status_code = _provider_failure_details(
                [item for item in responses if isinstance(item, BaseException)], "Tavily search"
            )
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "search",
                started,
                code,
                message,
                retryable=retryable,
                retry_after_ms=retry_after_ms,
                http_status_code=http_status_code,
                calls=len(variants),
            )

        try:
            output, seen = [], set()
            row_groups = [payload.get("results", []) for payload in payloads if isinstance(payload, dict)]
            maximum_group_size = max((len(rows) for rows in row_groups), default=0)
            for index in range(maximum_group_size):
                for rows in row_groups:
                    if index >= len(rows):
                        continue
                    row = rows[index]
                    raw_url = str(row.get("url") or "").strip()
                    if not raw_url:
                        continue
                    url = canonicalize_evidence_url(raw_url)
                    if url in seen:
                        continue
                    seen.add(url)
                    host = urlsplit(url).hostname or "unknown"
                    decision = self._classify(url, _now()) if self._classify else None
                    denied = bool(getattr(decision, "explicit_deny", False))
                    if denied:
                        continue
                    tier = getattr(getattr(decision, "tier", None), "value", None) or "c"
                    if str(tier).casefold() == "untrusted":
                        tier = "c"
                    publisher = getattr(decision, "publisher", None) or host
                    raw_policy_version = getattr(decision, "policy_version", None)
                    policy_version = (
                        "discovery-v1"
                        if str(tier).casefold() == "c" and raw_policy_version in {None, "unregistered"}
                        else raw_policy_version or "unregistered"
                    )
                    output.append(
                        WebCandidate(
                            evidence_ref="web:sha256:" + sha256(url.encode()).hexdigest(),
                            canonical_url=url,
                            title=str(row.get("title") or host),
                            snippet=str(row.get("content") or "No snippet"),
                            publisher=publisher,
                            source_tier=str(tier),
                            source_version=self.provider_version,
                            search_score=max(0.0, min(1.0, float(row.get("score", 0.0)))),
                            policy_version=policy_version,
                        )
                    )
                    if str(tier).casefold() == "c" and self._observe_discovery is not None:
                        observed = self._observe_discovery(
                            url=url,
                            publisher=publisher,
                            event="search",
                            claim_hash=sha256(claim.normalized_text.encode()).hexdigest(),
                        )
                        if hasattr(observed, "__await__"):
                            await observed
            unique_publishers: list[WebCandidate] = []
            repeated_publishers: list[WebCandidate] = []
            seen_publishers: set[str] = set()
            for candidate in output:
                publisher = candidate.publisher.casefold()
                if publisher in seen_publishers:
                    repeated_publishers.append(candidate)
                    continue
                seen_publishers.add(publisher)
                unique_publishers.append(candidate)
            output = (unique_publishers + repeated_publishers)[:maximum]
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if output else ToolResultStatus.INCONCLUSIVE,
                result=output,
                cache=_miss(),
                usage=_usage(
                    self.provider,
                    self.provider_version,
                    "search",
                    started,
                    calls=len(variants),
                    response_units=len(output),
                ),
            )
        except (TypeError, ValueError):
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "search",
                started,
                ToolErrorCode.PROVIDER_ERROR,
                "Tavily search returned an invalid response payload",
                retryable=False,
                calls=len(variants),
            )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class TavilyExtractAdapter:
    endpoint = "https://api.tavily.com/extract"
    provider = "tavily"
    provider_version = "v1"

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        timeout: float = 10,
        discovery_observer: Callable[..., Any] | None = None,
    ) -> None:
        if not api_key.strip():
            raise ValueError("Tavily API key is required")
        self.api_key = api_key
        self._timeout = max(1.0, min(float(timeout), 60.0))
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._guard = guard or SsrfGuard()
        self._observe_discovery = discovery_observer

    async def extract(
        self,
        claim: ExtractedClaim,
        candidates: Sequence[WebCandidate],
    ) -> NormalizedToolResult[TavilyExtractBatch]:
        started = perf_counter()
        selected = list(candidates[:5])
        try:
            if not selected:
                return NormalizedToolResult(
                    status=ToolResultStatus.INCONCLUSIVE,
                    result=TavilyExtractBatch(evidence=[], failed_urls=[]),
                    cache=_miss(),
                    usage=_usage(self.provider, self.provider_version, "extract", started, calls=0),
                )
            validated: list[WebCandidate] = []
            blocked_urls: list[str] = []
            for candidate in selected:
                try:
                    await self._guard.validate(candidate.canonical_url)
                    validated.append(candidate)
                except (ValueError, RuntimeError):
                    blocked_urls.append(candidate.canonical_url)
            if not validated:
                return NormalizedToolResult(
                    status=ToolResultStatus.INCONCLUSIVE,
                    result=TavilyExtractBatch(evidence=[], failed_urls=blocked_urls),
                    cache=_miss(),
                    usage=_usage(self.provider, self.provider_version, "extract", started, calls=0),
                )
            response = await self._client.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "urls": [item.canonical_url for item in validated],
                    "query": claim.normalized_text,
                    "chunks_per_source": 3,
                    "extract_depth": "basic",
                    "format": "markdown",
                    "include_images": False,
                    "timeout": self._timeout,
                    "include_usage": True,
                },
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Tavily Extract response must be an object")
            by_url = {item.canonical_url: item for item in validated}
            evidence: list[ExtractedWebEvidence] = []
            returned_urls: set[str] = set()
            for row in payload.get("results", []):
                if not isinstance(row, dict):
                    continue
                url = canonicalize_evidence_url(str(row.get("url") or ""))
                candidate = by_url.get(url)
                raw_content = str(row.get("raw_content") or "").strip()
                if candidate is None or not raw_content:
                    continue
                returned_urls.add(url)
                text = "\n\n".join((candidate.title, candidate.snippet, raw_content))
                evidence.append(
                    ExtractedWebEvidence(
                        evidence_ref=candidate.evidence_ref,
                        canonical_url=url,
                        title=candidate.title,
                        text=text,
                        content_sha256=sha256(text.encode()).hexdigest(),
                        publisher=candidate.publisher,
                        source_tier=candidate.source_tier,
                        source_version=f"{candidate.source_version}+extract-{self.provider_version}",
                        search_score=candidate.search_score,
                        published_at=candidate.published_at,
                        observed_at=_now(),
                        policy_version=candidate.policy_version,
                    )
                )
                if str(candidate.source_tier).casefold() == "c" and self._observe_discovery is not None:
                    observed = self._observe_discovery(
                        url=url,
                        publisher=candidate.publisher,
                        event="extract",
                        claim_hash=sha256(claim.normalized_text.encode()).hexdigest(),
                    )
                    if hasattr(observed, "__await__"):
                        await observed
            failed_urls = [*blocked_urls]
            for row in payload.get("failed_results", []):
                if not isinstance(row, dict):
                    continue
                raw_url = str(row.get("url") or "")
                if raw_url:
                    failed_urls.append(canonicalize_evidence_url(raw_url))
            failed_urls.extend(url for url in by_url if url not in returned_urls and url not in failed_urls)
            batch = TavilyExtractBatch(evidence=evidence, failed_urls=list(dict.fromkeys(failed_urls)))
            return NormalizedToolResult(
                status=ToolResultStatus.SUCCESS if evidence else ToolResultStatus.INCONCLUSIVE,
                result=batch,
                cache=_miss(),
                usage=_usage(
                    self.provider,
                    self.provider_version,
                    "extract",
                    started,
                    response_units=sum(len(item.text.encode()) for item in evidence),
                ),
            )
        except (httpx.TimeoutException, httpx.HTTPError, TypeError, ValueError, KeyError) as exc:
            code, message, retryable, retry_after_ms, http_status_code = _provider_failure_details(
                [exc], "Tavily Extract"
            )
            return _failure(
                ToolName.FACT_CHECK_CORPUS,
                self.provider,
                self.provider_version,
                "extract",
                started,
                code,
                message,
                retryable=retryable,
                retry_after_ms=retry_after_ms,
                http_status_code=http_status_code,
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
