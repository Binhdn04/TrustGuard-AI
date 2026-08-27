from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from time import perf_counter
from typing import Any, Protocol, Self
from urllib.parse import urlsplit

import httpx
from pydantic import Field, model_validator

from src.agents.nodes.rules import normalize_url
from src.agents.tools.errors import ToolCallError, UnsafeUrlError
from src.agents.tools.models import ToolContractModel
from src.agents.tools.network import BROWSER_NAVIGATION_HEADERS, GuardedHttpClient, SsrfGuard, SsrfPolicy
from src.security_ai.runtime import BudgetExceededError, TurnExecutionContext

_MAX_PROVIDER_RESPONSE_BYTES = 1_000_000
_MAX_HTML_BYTES = 1_000_000
_MAX_REDIRECTS = 5
_MAX_QUERY_LENGTH = 300
_MAX_SEARCH_RESULTS = 10
_MAX_EXTRACT_URLS = 5
_MAX_EXTRACT_CONTENT_CHARS = 200_000
_HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_UNSAFE_QUERY_RE = re.compile(
    r"(?i)(?:https?://|www\.|[\w.+-]+@[\w.-]+\.[a-z]{2,}|"
    r"\b(?:otp|password|passcode|token|secret|api[_-]?key)\s*[:=])"
)


class VerificationTransportStatus(StrEnum):
    SUCCESS = "success"
    NO_HIT = "no_hit"
    LIMITED = "limited"
    BLOCKED = "blocked"


class VerificationTransportLimitation(StrEnum):
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    INVALID_QUERY = "invalid_query"
    INVALID_TARGET = "invalid_target"
    SSRF_BLOCKED = "ssrf_blocked"
    NETWORK_BUDGET_EXHAUSTED = "network_budget_exhausted"
    TURN_DEADLINE_EXCEEDED = "turn_deadline_exceeded"
    PROVIDER_TIMEOUT = "provider_timeout"
    RATE_LIMITED = "rate_limited"
    PROVIDER_ERROR = "provider_error"
    PROVIDER_REDIRECT_REJECTED = "provider_redirect_rejected"
    RESPONSE_TOO_LARGE = "response_too_large"
    REDIRECT_LIMIT_EXCEEDED = "redirect_limit_exceeded"
    REDIRECT_LOOP = "redirect_loop"
    UNSUPPORTED_CONTENT_TYPE = "unsupported_content_type"


class VerificationTransportUsage(ToolContractModel):
    provider: str
    operation: str
    adapter_attempts: int = Field(ge=0)
    network_units: int = Field(ge=0)
    latency_ms: float = Field(ge=0)
    response_bytes: int = Field(default=0, ge=0)


class WebSearchHit(ToolContractModel):
    title: str = Field(max_length=500)
    url: str = Field(max_length=2048)
    snippet: str = Field(max_length=2000)
    score: float = Field(default=0, ge=0, le=1)


class WebSearchEnvelope(ToolContractModel):
    status: VerificationTransportStatus
    results: list[WebSearchHit] = Field(default_factory=list, max_length=_MAX_SEARCH_RESULTS)
    limitation: VerificationTransportLimitation | None = None
    usage: VerificationTransportUsage
    tool_calls_used: int = Field(default=1, ge=0)

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.tool_calls_used != self.usage.adapter_attempts:
            raise ValueError("tool call count must equal adapter attempts")
        if self.status is VerificationTransportStatus.SUCCESS and not self.results:
            raise ValueError("successful search requires results")
        if self.status is VerificationTransportStatus.NO_HIT and self.results:
            raise ValueError("no-hit search cannot contain results")
        if self.status in {VerificationTransportStatus.LIMITED, VerificationTransportStatus.BLOCKED}:
            if self.results or self.limitation is None:
                raise ValueError("limited search requires only a normalized limitation")
        elif self.limitation is not None:
            raise ValueError("successful/no-hit search cannot contain a limitation")
        return self


class ExtractedWebDocument(ToolContractModel):
    url: str = Field(max_length=2048)
    title: str | None = Field(default=None, max_length=500)
    content: str = Field(max_length=_MAX_EXTRACT_CONTENT_CHARS, exclude=True)


class WebExtractEnvelope(ToolContractModel):
    status: VerificationTransportStatus
    documents: list[ExtractedWebDocument] = Field(default_factory=list, max_length=_MAX_EXTRACT_URLS)
    failed_urls: list[str] = Field(default_factory=list, max_length=_MAX_EXTRACT_URLS)
    limitation: VerificationTransportLimitation | None = None
    usage: VerificationTransportUsage
    tool_calls_used: int = Field(default=1, ge=0)

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.tool_calls_used != self.usage.adapter_attempts:
            raise ValueError("tool call count must equal adapter attempts")
        if self.status is VerificationTransportStatus.SUCCESS and not self.documents:
            raise ValueError("successful extract requires documents")
        if self.status is VerificationTransportStatus.NO_HIT and self.documents:
            raise ValueError("no-hit extract cannot contain documents")
        if self.status in {VerificationTransportStatus.LIMITED, VerificationTransportStatus.BLOCKED}:
            if self.documents or self.limitation is None:
                raise ValueError("limited extract requires only a normalized limitation")
        elif self.limitation is not None:
            raise ValueError("successful/no-hit extract cannot contain a limitation")
        return self


class FetchedHtml(ToolContractModel):
    final_url: str = Field(max_length=2048)
    redirect_chain: list[str] = Field(min_length=1, max_length=_MAX_REDIRECTS + 1)
    media_type: str
    body: bytes = Field(max_length=_MAX_HTML_BYTES, exclude=True, repr=False)


class HtmlFetchEnvelope(ToolContractModel):
    status: VerificationTransportStatus
    document: FetchedHtml | None = None
    limitation: VerificationTransportLimitation | None = None
    usage: VerificationTransportUsage
    tool_calls_used: int = Field(default=1, ge=0)

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.tool_calls_used != self.usage.adapter_attempts:
            raise ValueError("tool call count must equal adapter attempts")
        if self.status is VerificationTransportStatus.SUCCESS:
            if self.document is None or self.limitation is not None:
                raise ValueError("successful fetch requires only a document")
        elif self.document is not None or self.limitation is None:
            raise ValueError("non-success fetch requires only a normalized limitation")
        return self


class WebSearchProvider(Protocol):
    async def search_one(
        self,
        query: str,
        *,
        execution_context: TurnExecutionContext,
        max_results: int = 5,
        include_domains: Sequence[str] = (),
    ) -> WebSearchEnvelope: ...


class WebExtractProvider(Protocol):
    async def extract(
        self,
        urls: Sequence[str],
        *,
        query: str,
        execution_context: TurnExecutionContext,
    ) -> WebExtractEnvelope: ...


class _TransportError(RuntimeError):
    def __init__(
        self,
        limitation: VerificationTransportLimitation,
        *,
        blocked: bool = False,
    ) -> None:
        super().__init__(limitation.value)
        self.limitation = limitation
        self.blocked = blocked


def _usage(
    provider: str,
    operation: str,
    started: float,
    execution_context: TurnExecutionContext,
    starting_network_units: int,
    *,
    response_bytes: int = 0,
) -> VerificationTransportUsage:
    return VerificationTransportUsage(
        provider=provider,
        operation=operation,
        adapter_attempts=1,
        network_units=execution_context.network_units - starting_network_units,
        latency_ms=round((perf_counter() - started) * 1000, 3),
        response_bytes=response_bytes,
    )


def _validate_query(query: str) -> str:
    bounded = " ".join(query.split())
    if not bounded or len(bounded) > _MAX_QUERY_LENGTH or _UNSAFE_QUERY_RE.search(bounded):
        raise _TransportError(VerificationTransportLimitation.INVALID_QUERY, blocked=True)
    return bounded


def _limitation_status(failure: _TransportError) -> VerificationTransportStatus:
    return VerificationTransportStatus.BLOCKED if failure.blocked else VerificationTransportStatus.LIMITED


class _BoundedProviderClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        timeout: float,
        max_response_bytes: int = _MAX_PROVIDER_RESPONSE_BYTES,
    ) -> None:
        self._client = client
        self._timeout = max(0.1, min(float(timeout), 60.0))
        self._max_response_bytes = min(max_response_bytes, _MAX_PROVIDER_RESPONSE_BYTES)

    async def post_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        body: dict[str, Any],
        execution_context: TurnExecutionContext,
    ) -> tuple[dict[str, Any], int]:
        remaining = execution_context.remaining_seconds
        if remaining <= 0:
            raise _TransportError(VerificationTransportLimitation.TURN_DEADLINE_EXCEEDED)
        request = self._client.build_request("POST", url, headers=headers, json=body)
        try:
            execution_context.reserve_network_units()
        except BudgetExceededError as exc:
            raise _TransportError(VerificationTransportLimitation.NETWORK_BUDGET_EXHAUSTED) from exc

        response: httpx.Response | None = None
        try:
            response = await asyncio.wait_for(
                self._client.send(request, stream=True, follow_redirects=False),
                timeout=min(self._timeout, remaining),
            )
            if response.is_redirect:
                raise _TransportError(VerificationTransportLimitation.PROVIDER_REDIRECT_REJECTED)
            if response.status_code == 429:
                raise _TransportError(VerificationTransportLimitation.RATE_LIMITED)
            if response.status_code >= 400:
                raise _TransportError(VerificationTransportLimitation.PROVIDER_ERROR)
            advertised = response.headers.get("content-length")
            if advertised is not None:
                try:
                    if int(advertised) > self._max_response_bytes:
                        raise _TransportError(VerificationTransportLimitation.RESPONSE_TOO_LARGE)
                except ValueError as exc:
                    raise _TransportError(VerificationTransportLimitation.PROVIDER_ERROR) from exc
            payload_bytes = bytearray()
            async for chunk in response.aiter_bytes():
                if len(payload_bytes) + len(chunk) > self._max_response_bytes:
                    raise _TransportError(VerificationTransportLimitation.RESPONSE_TOO_LARGE)
                payload_bytes.extend(chunk)
        except TimeoutError as exc:
            raise _TransportError(VerificationTransportLimitation.PROVIDER_TIMEOUT) from exc
        except httpx.TimeoutException as exc:
            raise _TransportError(VerificationTransportLimitation.PROVIDER_TIMEOUT) from exc
        except httpx.HTTPError as exc:
            raise _TransportError(VerificationTransportLimitation.PROVIDER_ERROR) from exc
        finally:
            if response is not None:
                await response.aclose()

        try:
            payload = json.loads(payload_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _TransportError(VerificationTransportLimitation.PROVIDER_ERROR) from exc
        if not isinstance(payload, dict):
            raise _TransportError(VerificationTransportLimitation.PROVIDER_ERROR)
        return payload, len(payload_bytes)


class TavilyWebSearchProvider:
    endpoint = "https://api.tavily.com/search"
    provider = "tavily"

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10,
    ) -> None:
        if not api_key.strip():
            raise ValueError("Tavily API key is required")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._transport = _BoundedProviderClient(self._client, timeout=timeout)

    async def search_one(
        self,
        query: str,
        *,
        execution_context: TurnExecutionContext,
        max_results: int = 5,
        include_domains: Sequence[str] = (),
    ) -> WebSearchEnvelope:
        started = perf_counter()
        starting_units = execution_context.network_units
        try:
            safe_query = _validate_query(query)
            maximum = min(max(1, max_results), _MAX_SEARCH_RESULTS)
            domains = list(dict.fromkeys(domain.casefold() for domain in include_domains if domain.strip()))[:10]
            body = {
                "query": safe_query,
                "max_results": maximum,
                "search_depth": "basic",
                "include_answer": False,
                "include_raw_content": False,
                "include_images": False,
            }
            if domains:
                body["include_domains"] = domains
            payload, response_bytes = await self._transport.post_json(
                self.endpoint,
                headers={"Authorization": f"Bearer {self._api_key}"},
                body=body,
                execution_context=execution_context,
            )
            results: list[WebSearchHit] = []
            seen: set[str] = set()
            for row in payload.get("results", []):
                if not isinstance(row, dict):
                    continue
                raw_url = str(row.get("url") or "").strip()
                parsed = urlsplit(raw_url)
                if parsed.username or parsed.password:
                    continue
                normalized = normalize_url(raw_url)
                if normalized is None or normalized in seen:
                    continue
                seen.add(normalized)
                results.append(
                    WebSearchHit(
                        title=str(row.get("title") or parsed.hostname or "Untitled")[:500],
                        url=normalized,
                        snippet=str(row.get("content") or "No snippet")[:2000],
                        score=max(0.0, min(1.0, float(row.get("score") or 0))),
                    )
                )
                if len(results) == maximum:
                    break
            status = VerificationTransportStatus.SUCCESS if results else VerificationTransportStatus.NO_HIT
            return WebSearchEnvelope(
                status=status,
                results=results,
                usage=_usage(
                    self.provider,
                    "search_one",
                    started,
                    execution_context,
                    starting_units,
                    response_bytes=response_bytes,
                ),
            )
        except (TypeError, ValueError):
            failure = _TransportError(VerificationTransportLimitation.PROVIDER_ERROR)
            return self._failure(failure, started, execution_context, starting_units)
        except _TransportError as failure:
            return self._failure(failure, started, execution_context, starting_units)

    def _failure(
        self,
        failure: _TransportError,
        started: float,
        execution_context: TurnExecutionContext,
        starting_units: int,
    ) -> WebSearchEnvelope:
        return WebSearchEnvelope(
            status=_limitation_status(failure),
            limitation=failure.limitation,
            usage=_usage(self.provider, "search_one", started, execution_context, starting_units),
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class TavilyWebExtractProvider:
    endpoint = "https://api.tavily.com/extract"
    provider = "tavily"

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        timeout: float = 10,
    ) -> None:
        if not api_key.strip():
            raise ValueError("Tavily API key is required")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._guard = guard or SsrfGuard()
        self._transport = _BoundedProviderClient(self._client, timeout=timeout)

    async def extract(
        self,
        urls: Sequence[str],
        *,
        query: str,
        execution_context: TurnExecutionContext,
    ) -> WebExtractEnvelope:
        started = perf_counter()
        starting_units = execution_context.network_units
        failed_urls: list[str] = []
        try:
            safe_query = _validate_query(query)
            selected = list(dict.fromkeys(urls))[:_MAX_EXTRACT_URLS]
            if not selected:
                return WebExtractEnvelope(
                    status=VerificationTransportStatus.NO_HIT,
                    usage=_usage(self.provider, "extract", started, execution_context, starting_units),
                )
            validated: list[str] = []
            for raw_url in selected:
                try:
                    parsed = urlsplit(raw_url)
                    if parsed.username or parsed.password:
                        raise UnsafeUrlError("URLs containing credentials are not allowed")
                    target = await self._guard.validate(raw_url)
                    validated.append(target.url)
                except (ToolCallError, ValueError):
                    failed_urls.append(raw_url)
            if not validated:
                raise _TransportError(VerificationTransportLimitation.SSRF_BLOCKED, blocked=True)

            payload, response_bytes = await self._transport.post_json(
                self.endpoint,
                headers={"Authorization": f"Bearer {self._api_key}"},
                body={
                    "urls": validated,
                    "query": safe_query,
                    "chunks_per_source": 3,
                    "extract_depth": "basic",
                    "format": "markdown",
                    "include_images": False,
                },
                execution_context=execution_context,
            )
            allowed = {normalize_url(item) for item in validated}
            documents: list[ExtractedWebDocument] = []
            returned: set[str] = set()
            for row in payload.get("results", []):
                if not isinstance(row, dict):
                    continue
                url = normalize_url(str(row.get("url") or ""))
                content = str(row.get("raw_content") or "").strip()
                if url is None or url not in allowed or not content:
                    continue
                returned.add(url)
                documents.append(
                    ExtractedWebDocument(
                        url=url,
                        title=(str(row.get("title"))[:500] if row.get("title") else None),
                        content=content[:_MAX_EXTRACT_CONTENT_CHARS],
                    )
                )
            failed_urls.extend(item for item in validated if normalize_url(item) not in returned)
            status = VerificationTransportStatus.SUCCESS if documents else VerificationTransportStatus.NO_HIT
            return WebExtractEnvelope(
                status=status,
                documents=documents,
                failed_urls=list(dict.fromkeys(failed_urls)),
                usage=_usage(
                    self.provider,
                    "extract",
                    started,
                    execution_context,
                    starting_units,
                    response_bytes=response_bytes,
                ),
            )
        except _TransportError as failure:
            return WebExtractEnvelope(
                status=_limitation_status(failure),
                failed_urls=list(dict.fromkeys(failed_urls)),
                limitation=failure.limitation,
                usage=_usage(self.provider, "extract", started, execution_context, starting_units),
            )
        except (TypeError, ValueError):
            return WebExtractEnvelope(
                status=VerificationTransportStatus.LIMITED,
                failed_urls=list(dict.fromkeys(failed_urls)),
                limitation=VerificationTransportLimitation.PROVIDER_ERROR,
                usage=_usage(self.provider, "extract", started, execution_context, starting_units),
            )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class GuardedHtmlFetcher:
    provider = "guarded-html"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        timeout: float = 10,
    ) -> None:
        selected_guard = guard or SsrfGuard(
            policy=SsrfPolicy(max_redirects=_MAX_REDIRECTS, max_response_bytes=_MAX_HTML_BYTES)
        )
        if selected_guard.policy.max_redirects > _MAX_REDIRECTS:
            raise ValueError("HTML fetch redirect policy exceeds the maximum")
        if selected_guard.policy.max_response_bytes > _MAX_HTML_BYTES:
            raise ValueError("HTML fetch byte policy exceeds the maximum")
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._http = GuardedHttpClient(self._client, selected_guard)
        self._timeout = max(0.1, min(float(timeout), 60.0))

    async def fetch(
        self,
        url: str,
        *,
        execution_context: TurnExecutionContext,
    ) -> HtmlFetchEnvelope:
        started = perf_counter()
        starting_units = execution_context.network_units
        try:
            remaining = execution_context.remaining_seconds
            if remaining <= 0:
                raise _TransportError(VerificationTransportLimitation.TURN_DEADLINE_EXCEEDED)
            response, chain = await asyncio.wait_for(
                self._http.get(
                    url,
                    before_request=execution_context.reserve_network_units,
                    headers=BROWSER_NAVIGATION_HEADERS,
                ),
                timeout=min(self._timeout, remaining),
            )
            if response.status_code == 429:
                raise _TransportError(VerificationTransportLimitation.RATE_LIMITED)
            if response.status_code >= 400:
                raise _TransportError(VerificationTransportLimitation.PROVIDER_ERROR)
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
            if media_type not in _HTML_MEDIA_TYPES:
                raise _TransportError(
                    VerificationTransportLimitation.UNSUPPORTED_CONTENT_TYPE,
                    blocked=True,
                )
            return HtmlFetchEnvelope(
                status=VerificationTransportStatus.SUCCESS,
                document=FetchedHtml(
                    final_url=chain[-1],
                    redirect_chain=chain,
                    media_type=media_type,
                    body=response.content,
                ),
                usage=_usage(
                    self.provider,
                    "fetch",
                    started,
                    execution_context,
                    starting_units,
                    response_bytes=len(response.content),
                ),
            )
        except TimeoutError:
            failure = _TransportError(VerificationTransportLimitation.PROVIDER_TIMEOUT)
        except BudgetExceededError:
            failure = _TransportError(VerificationTransportLimitation.NETWORK_BUDGET_EXHAUSTED)
        except UnsafeUrlError:
            failure = _TransportError(VerificationTransportLimitation.SSRF_BLOCKED, blocked=True)
        except ToolCallError as exc:
            code = getattr(exc.error, "code", "")
            limitation = {
                "SSRF_BLOCKED": VerificationTransportLimitation.SSRF_BLOCKED,
                "REDIRECT_LOOP": VerificationTransportLimitation.REDIRECT_LOOP,
                "TOO_MANY_REDIRECTS": VerificationTransportLimitation.REDIRECT_LIMIT_EXCEEDED,
                "RESPONSE_TOO_LARGE": VerificationTransportLimitation.RESPONSE_TOO_LARGE,
            }.get(code, VerificationTransportLimitation.PROVIDER_ERROR)
            failure = _TransportError(
                limitation,
                blocked=limitation is VerificationTransportLimitation.SSRF_BLOCKED,
            )
        except _TransportError as caught:
            failure = caught
        except httpx.TimeoutException:
            failure = _TransportError(VerificationTransportLimitation.PROVIDER_TIMEOUT)
        except httpx.HTTPError:
            failure = _TransportError(VerificationTransportLimitation.PROVIDER_ERROR)
        return HtmlFetchEnvelope(
            status=_limitation_status(failure),
            limitation=failure.limitation,
            usage=_usage(self.provider, "fetch", started, execution_context, starting_units),
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


@dataclass(frozen=True, slots=True)
class OfficialVerificationProviderBundle:
    search: WebSearchProvider | None
    extract: WebExtractProvider | None
    limitations: tuple[VerificationTransportLimitation, ...] = ()
    local_registry_available: bool = True


def build_official_verification_providers(
    settings: Any,
    *,
    search_client: httpx.AsyncClient | None = None,
    extract_client: httpx.AsyncClient | None = None,
    guard: SsrfGuard | None = None,
) -> OfficialVerificationProviderBundle:
    api_key = str(getattr(settings, "tavily_api_key", "") or "")
    if not api_key.strip():
        return OfficialVerificationProviderBundle(
            search=None,
            extract=None,
            limitations=(VerificationTransportLimitation.PROVIDER_UNAVAILABLE,),
        )
    timeout = float(getattr(settings, "provider_timeout_seconds", 10))
    return OfficialVerificationProviderBundle(
        search=TavilyWebSearchProvider(api_key, client=search_client, timeout=timeout),
        extract=TavilyWebExtractProvider(
            api_key,
            client=extract_client,
            guard=guard,
            timeout=timeout,
        ),
    )


__all__ = [
    "ExtractedWebDocument",
    "FetchedHtml",
    "GuardedHtmlFetcher",
    "HtmlFetchEnvelope",
    "OfficialVerificationProviderBundle",
    "TavilyWebExtractProvider",
    "TavilyWebSearchProvider",
    "VerificationTransportLimitation",
    "VerificationTransportStatus",
    "VerificationTransportUsage",
    "WebExtractEnvelope",
    "WebExtractProvider",
    "WebSearchEnvelope",
    "WebSearchHit",
    "WebSearchProvider",
    "build_official_verification_providers",
]
