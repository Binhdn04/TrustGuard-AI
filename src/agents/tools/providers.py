from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from src.agents.tools.errors import ToolCallError
from src.agents.tools.network import SsrfGuard
from src.models import ClaimEvidence, UrlScanResult, Verdict


class GoogleSafeBrowsingScanner:
    """Google Safe Browsing v4 adapter; raw provider data never leaves this class."""

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        guard: SsrfGuard | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not api_key.strip():
            raise ValueError("Google Safe Browsing API key is required")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._guard = guard or SsrfGuard()

    async def scan(self, normalized_url: str) -> UrlScanResult:
        await self._guard.validate(normalized_url)
        payload = {
            "client": {"clientId": "p-068", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": normalized_url}],
            },
        }
        try:
            response = await self._client.post(self.endpoint, params={"key": self._api_key}, json=payload)
            response.raise_for_status()
            data: Any = response.json()
            if not isinstance(data, dict):
                raise ValueError("provider response must be an object")
        except httpx.TimeoutException as exc:
            raise ToolCallError("url_scanner", "PROVIDER_TIMEOUT", "URL reputation provider timed out", retryable=True) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ToolCallError("url_scanner", "PROVIDER_ERROR", "URL reputation provider failed", retryable=True) from exc
        matches = data.get("matches") or []
        signals = sorted({str(match.get("threatType", "unknown")).casefold() for match in matches})
        # A no-hit response is absence of evidence, never affirmative safety evidence.
        verdict = Verdict.MALICIOUS if matches else Verdict.INCONCLUSIVE
        return UrlScanResult(
            provider="google-safe-browsing-v4",
            normalized_url=normalized_url,
            verdict=verdict,
            redirect_chain=[],
            signals=signals or ["no_known_threat_match"],
            observed_at=datetime.now(UTC),
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> GoogleSafeBrowsingScanner:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()


class GoogleFactCheckRetriever:
    """Google Fact Check Tools API adapter with normalized ClaimEvidence output."""

    endpoint = "https://factchecktools.googleapis.com/v1alpha1/claims:search"

    def __init__(self, api_key: str, *, client: httpx.AsyncClient | None = None, timeout: float = 10.0) -> None:
        if not api_key.strip():
            raise ValueError("Google Fact Check API key is required")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def search(self, claim: str, limit: int = 5) -> list[ClaimEvidence]:
        if not claim.strip():
            raise ValueError("claim is required")
        limit = max(1, min(limit, 20))
        try:
            response = await self._client.get(
                self.endpoint,
                params={"key": self._api_key, "query": claim, "pageSize": limit, "languageCode": "vi"},
            )
            response.raise_for_status()
            payload: Any = response.json()
            if not isinstance(payload, dict):
                raise ValueError("provider response must be an object")
        except httpx.TimeoutException as exc:
            raise ToolCallError("claim_retriever", "PROVIDER_TIMEOUT", "Fact-check provider timed out", retryable=True) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ToolCallError("claim_retriever", "PROVIDER_ERROR", "Fact-check provider failed", retryable=True) from exc
        results: list[ClaimEvidence] = []
        for item in payload.get("claims", []):
            for review in item.get("claimReview", []):
                publisher = review.get("publisher") or {}
                title = str(review.get("title") or item.get("text") or "Fact-check result")
                rating = str(review.get("textualRating") or "Fact-check source discusses this claim")
                reviewed_at = review.get("reviewDate")
                try:
                    observed_at = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00")) if reviewed_at else datetime.now(UTC)
                    if observed_at.tzinfo is None:
                        observed_at = observed_at.replace(tzinfo=UTC)
                except (AttributeError, ValueError):
                    observed_at = datetime.now(UTC)
                results.append(ClaimEvidence(
                    source=str(publisher.get("name") or "Google Fact Check Tools"),
                    title=title,
                    url=review.get("url") or None,
                    finding=rating,
                    relevance=1.0,
                    observed_at=observed_at.astimezone(UTC),
                ))
                if len(results) >= limit:
                    return results
        return results

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> GoogleFactCheckRetriever:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()
