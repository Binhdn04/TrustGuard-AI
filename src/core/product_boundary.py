from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

LEGACY_API_PREFIXES = ("/api/v2", "/api/v3")
SECURITY_TRIAGE_API_PREFIX = "/api/v4"
SECURITY_TRIAGE_CONTRACT_VERSION = "v4"

ProductProfile = Literal["legacy_analysis", "security_triage_vnext"]
CompatibilityUsage = Literal["legacy_read", "legacy_write", "security_read", "security_write"]

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True, slots=True)
class ProductRouteMetadata:
    api_contract: str
    product_profile: ProductProfile
    compatibility_usage: CompatibilityUsage


def _matches_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(f"{prefix}/")


def product_route_metadata(path: str, method: str) -> ProductRouteMetadata | None:
    """Classify versioned product traffic without inspecting query strings or bodies."""
    is_read = method.upper() in _READ_METHODS
    for prefix in LEGACY_API_PREFIXES:
        if _matches_prefix(path, prefix):
            return ProductRouteMetadata(
                api_contract=prefix.rsplit("/", 1)[-1],
                product_profile="legacy_analysis",
                compatibility_usage="legacy_read" if is_read else "legacy_write",
            )
    if _matches_prefix(path, SECURITY_TRIAGE_API_PREFIX):
        return ProductRouteMetadata(
            api_contract=SECURITY_TRIAGE_CONTRACT_VERSION,
            product_profile="security_triage_vnext",
            compatibility_usage="security_read" if is_read else "security_write",
        )
    return None


__all__ = [
    "LEGACY_API_PREFIXES",
    "SECURITY_TRIAGE_API_PREFIX",
    "SECURITY_TRIAGE_CONTRACT_VERSION",
    "ProductRouteMetadata",
    "product_route_metadata",
]
