from __future__ import annotations

from typing import Any

from src.agents.tools.providers import GoogleFactCheckRetriever, GoogleSafeBrowsingScanner
from src.agents.tools.rdap import RdapDomainIntelligence
from src.agents.tools.rdap_v3 import NormalizedRdapProvider
from src.agents.tools.redirects import GuardedRedirectResolver
from src.agents.tools.reputation import GoogleWebRiskProvider, UrlReputationService, VirusTotalUrlProvider


def build_domain_intelligence_adapter(settings: Any) -> RdapDomainIntelligence:
    """Build a lazy RDAP adapter; its HTTP client is created only on an allowed lookup."""
    return RdapDomainIntelligence(timeout=min(settings.provider_timeout_seconds, 5.0))


def build_provider_adapters(settings: Any) -> dict[str, object]:
    """Create only explicitly configured real adapters; empty config stays offline."""

    adapters: dict[str, object] = {}
    timeout = settings.provider_timeout_seconds
    if settings.google_safe_browsing_api_key:
        adapters["url_scanner"] = GoogleSafeBrowsingScanner(settings.google_safe_browsing_api_key, timeout=timeout)
    if settings.google_fact_check_api_key:
        adapters["claim_retriever"] = GoogleFactCheckRetriever(settings.google_fact_check_api_key, timeout=timeout)
    return adapters


def build_v3_tools_data_adapters(settings: Any) -> dict[str, object]:
    """Build Wave 1 adapters against the frozen v3 tool protocols."""
    timeout = settings.provider_timeout_seconds
    adapters: dict[str, object] = {
        "rdap": NormalizedRdapProvider(timeout=min(timeout, 5.0)),
        "redirect_resolver": GuardedRedirectResolver(timeout=min(timeout, 5.0)),
    }
    web_risk_key = getattr(settings, "google_web_risk_api_key", "")
    virus_total_key = getattr(settings, "virustotal_api_key", "")
    if web_risk_key:
        primary = GoogleWebRiskProvider(web_risk_key, timeout=timeout)
        secondary = VirusTotalUrlProvider(virus_total_key, timeout=timeout) if virus_total_key else None
        adapters["url_reputation"] = UrlReputationService(
            primary,
            secondary,
            max_attempts=getattr(settings, "reputation_max_attempts", 2),
            failure_threshold=getattr(settings, "reputation_circuit_failure_threshold", 3),
            secondary_call_budget=getattr(settings, "reputation_secondary_call_budget", 1),
        )
    return adapters
