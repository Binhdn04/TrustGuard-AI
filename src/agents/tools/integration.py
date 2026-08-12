from __future__ import annotations

from typing import Any

from src.agents.tools.advanced import (
    GoogleClaimSearchAdapter,
    OpenAIEmbeddingProvider,
    TavilyExtractAdapter,
    TavilySearchAdapter,
)
from src.agents.tools.providers import GoogleFactCheckRetriever, GoogleSafeBrowsingScanner
from src.agents.tools.rdap import RdapDomainIntelligence
from src.agents.tools.redirect import GuardedRedirectResolver
from src.agents.tools.reputation import (
    GoogleWebRiskProvider,
    ProductionUrlReputationCascade,
    VirusTotalUrlProvider,
)


def build_domain_intelligence_adapter(settings: Any) -> RdapDomainIntelligence:
    """Build a lazy RDAP adapter; its HTTP client is created only on an allowed lookup."""
    return RdapDomainIntelligence(timeout=min(settings.provider_timeout_seconds, 5.0))


def build_provider_adapters(settings: Any, source_registry: Any | None = None) -> dict[str, object]:
    """Create only explicitly configured real adapters; empty config stays offline."""

    adapters: dict[str, object] = {}
    timeout = settings.provider_timeout_seconds
    web_risk_key = getattr(settings, "google_web_risk_api_key", "")
    virus_total_key = getattr(settings, "virustotal_api_key", "")
    if web_risk_key:
        primary = GoogleWebRiskProvider(web_risk_key, timeout=timeout)
        secondary = VirusTotalUrlProvider(virus_total_key, timeout=timeout) if virus_total_key else None
        adapters["url_reputation"] = ProductionUrlReputationCascade(
            primary,
            secondary,
            allow_secondary=getattr(settings, "reputation_secondary_enabled", True),
            max_network_calls=getattr(settings, "reputation_max_network_calls", 4),
        )
    # Keep the v2 graph operational while it migrates to the normalized v3
    # cascade.  Web Risk remains the production v3 primary.
    if settings.google_safe_browsing_api_key:
        adapters["url_scanner"] = GoogleSafeBrowsingScanner(settings.google_safe_browsing_api_key, timeout=timeout)
    if settings.google_fact_check_api_key:
        adapters["claim_retriever"] = GoogleFactCheckRetriever(settings.google_fact_check_api_key, timeout=timeout)
        adapters["google_claim_search"] = GoogleClaimSearchAdapter(
            settings.google_fact_check_api_key,
            timeout=timeout,
            classify_source=source_registry.classify if source_registry else None,
        )
    if getattr(settings, "openai_api_key", ""):
        adapters["embedding_provider"] = OpenAIEmbeddingProvider(settings.openai_api_key, timeout=timeout)
    if getattr(settings, "tavily_api_key", ""):
        adapters["tavily_search"] = TavilySearchAdapter(
            settings.tavily_api_key,
            timeout=timeout,
            excluded_domains=(lambda _claim: source_registry.denied_domains()) if source_registry else None,
            official_domains=(lambda _claim: source_registry.official_domains("search")) if source_registry else None,
            classify_source=source_registry.classify if source_registry else None,
            discovery_observer=source_registry.observe_discovery if source_registry else None,
        )
        adapters["tavily_extract"] = TavilyExtractAdapter(
            settings.tavily_api_key,
            timeout=timeout,
            discovery_observer=source_registry.observe_discovery if source_registry else None,
        )
    # These constructors perform no I/O. Consent is checked in the executor
    # before either lazy RDAP lookup or redirect resolution is called.
    adapters["domain_intelligence"] = build_domain_intelligence_adapter(settings)
    adapters["redirect_resolver"] = GuardedRedirectResolver(timeout=min(timeout, 5.0))
    return adapters
