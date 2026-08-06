from __future__ import annotations

from src.models import ClaimStance

# Provider ratings are normalized by exact value. Keeping this table explicit
# prevents arbitrary review prose from becoming a deterministic scoring signal.
_RATING_STANCE_V1 = {
    "false": ClaimStance.REFUTES,
    "true": ClaimStance.SUPPORTS,
    "mixed": ClaimStance.MIXED,
}


def normalize_claim_rating(rating: str) -> ClaimStance:
    return _RATING_STANCE_V1.get(rating.strip().casefold(), ClaimStance.UNRATED)


__all__ = ["normalize_claim_rating"]
