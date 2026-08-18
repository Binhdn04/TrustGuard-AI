from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SECURITY_TRIAGE_API_PREFIX = "/api/v4"
SECURITY_TRIAGE_CONTRACT_VERSION = "v4"

ProductProfile = Literal["security_triage_vnext"]

@dataclass(frozen=True, slots=True)
class ProductRouteMetadata:
    api_contract: str
    product_profile: ProductProfile


def _matches_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(f"{prefix}/")


def product_route_metadata(path: str, method: str) -> ProductRouteMetadata | None:
    """Classify versioned product traffic without inspecting query strings or bodies."""
    del method
    if _matches_prefix(path, SECURITY_TRIAGE_API_PREFIX):
        return ProductRouteMetadata(
            api_contract=SECURITY_TRIAGE_CONTRACT_VERSION,
            product_profile="security_triage_vnext",
        )
    return None


__all__ = [
    "SECURITY_TRIAGE_API_PREFIX",
    "SECURITY_TRIAGE_CONTRACT_VERSION",
    "ProductRouteMetadata",
    "product_route_metadata",
]
