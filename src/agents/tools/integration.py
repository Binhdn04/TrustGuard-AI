from __future__ import annotations

from typing import Any

from src.agents.tools.providers import GoogleFactCheckRetriever, GoogleSafeBrowsingScanner
from src.agents.tools.rdap import RdapDomainIntelligence


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
