from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from time import perf_counter
from typing import Protocol

from src.models import SecurityScopeResponseV4, SecurityTriageCreateRequestV4
from src.security_ai.runtime import TurnExecutionContext
from src.services.official_verification_coordinator import (
    OfficialLinkVerificationCoordinator,
    OfficialVerificationCoordinatorOutcome,
    apply_official_verification_outcome,
)


class OfficialVerificationMode(StrEnum):
    OFF = "off"
    SHADOW = "shadow"
    VISIBLE = "visible"
    ENFORCED = "enforced"


@dataclass(frozen=True, slots=True)
class OfficialVerificationTelemetryEvent:
    """Strictly redacted aggregate event; raw inputs are impossible to store."""

    analysis_id: str
    stage: str
    provider: str
    operation: str
    counts: dict[str, int]
    latency_ms: int
    cost_usd: float
    status: str
    strength: str
    target_hash: str
    error_code: str | None = None


class OfficialVerificationTelemetrySink(Protocol):
    def record(self, event: OfficialVerificationTelemetryEvent) -> None: ...


class StructuredOfficialVerificationTelemetry:
    def __init__(self) -> None:
        self._logger = logging.getLogger("trustguard.official_verification")

    def record(self, event: OfficialVerificationTelemetryEvent) -> None:
        self._logger.info(
            "official_verification_stage",
            extra={"official_verification": asdict(event)},
        )


def _target_hash(scope: SecurityScopeResponseV4) -> str:
    context = scope.security_context
    values: list[str] = []
    if context is not None:
        values.extend(context.urls)
        if context.claimed_entity:
            values.append(context.claimed_entity)
    canonical = "\0".join(sorted(value.casefold().strip() for value in values if value.strip()))
    if not canonical:
        canonical = str(scope.analysis_id)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _limitation_error_code(limitations: Sequence[str]) -> str | None:
    error_markers = (
        "provider_timeout",
        "provider_error",
        "provider_unavailable",
        "rate_limited",
        "budget_exceeded",
        "deadline_exceeded",
        "ssrf_blocked",
        "response_too_large",
        "unsupported_content_type",
    )
    for limitation in limitations:
        if any(marker in limitation for marker in error_markers):
            return limitation.upper()[:100]
    return None


class OfficialVerificationRolloutStage:
    """Apply one rollout mode without allowing shadow data into responses."""

    def __init__(
        self,
        coordinator: OfficialLinkVerificationCoordinator,
        *,
        mode: OfficialVerificationMode | str,
        telemetry: OfficialVerificationTelemetrySink | None = None,
        closers: Sequence[object] = (),
    ) -> None:
        self.mode = OfficialVerificationMode(mode)
        if self.mode is OfficialVerificationMode.OFF:
            raise ValueError("off mode must omit the official verification stage")
        self._coordinator = coordinator
        self._telemetry = telemetry or StructuredOfficialVerificationTelemetry()
        self._closers = tuple(closers)

    @property
    def risk_v3_enforced(self) -> bool:
        return self.mode is OfficialVerificationMode.ENFORCED

    async def run(
        self,
        request: SecurityTriageCreateRequestV4,
        scope: SecurityScopeResponseV4,
        *,
        execution_context: TurnExecutionContext,
    ) -> SecurityScopeResponseV4:
        started = perf_counter()
        starting_network_units = execution_context.network_units
        starting_cost_usd = execution_context.estimated_cost_usd
        try:
            outcome = await self._coordinator.coordinate(
                request,
                scope,
                execution_context=execution_context,
            )
        except Exception:
            self._record(
                scope,
                OfficialVerificationCoordinatorOutcome(),
                started,
                status="error",
                error_code="COORDINATOR_ERROR",
                network_units=max(0, execution_context.network_units - starting_network_units),
                cost_usd=max(0.0, execution_context.estimated_cost_usd - starting_cost_usd),
            )
            if self.mode is OfficialVerificationMode.SHADOW:
                return scope
            limitations = list(dict.fromkeys([*scope.limitations, "official_verification_error"]))
            return scope.model_copy(update={"limitations": limitations})

        report = outcome.report
        self._record(
            scope,
            outcome,
            started,
            status="completed" if report is not None else "not_applicable",
            error_code=_limitation_error_code(outcome.limitations),
            network_units=max(0, execution_context.network_units - starting_network_units),
            cost_usd=max(0.0, execution_context.estimated_cost_usd - starting_cost_usd),
        )
        if self.mode is OfficialVerificationMode.SHADOW or report is None:
            return scope
        return apply_official_verification_outcome(scope, outcome)

    def _record(
        self,
        scope: SecurityScopeResponseV4,
        outcome: OfficialVerificationCoordinatorOutcome,
        started: float,
        *,
        status: str,
        error_code: str | None = None,
        network_units: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        report = outcome.report
        self._telemetry.record(
            OfficialVerificationTelemetryEvent(
                analysis_id=str(scope.analysis_id),
                stage="official_link_verification",
                provider="mixed" if outcome.adapter_attempts else "local_registry",
                operation="coordinate",
                counts={
                    "adapter_attempts": outcome.adapter_attempts,
                    "network_units": network_units,
                    "search_attempts": outcome.search_attempts,
                    "candidates": outcome.candidate_count,
                    "official_fetches": outcome.official_fetches,
                    "outbound_resolutions": outcome.outbound_resolutions,
                    "identity_candidates": outcome.identity_candidate_count,
                    "identity_verified": outcome.identity_verified_count,
                    "identity_conflicting": outcome.identity_conflicting_count,
                    "identity_cache_hits": outcome.identity_cache_hits,
                    "identity_official_controlled": sum(
                        item.relationship.value == "official_controlled"
                        for item in (report.identity_associations if report is not None else [])
                    ),
                    "identity_parent_organization": sum(
                        item.relationship.value == "parent_organization"
                        for item in (report.identity_associations if report is not None else [])
                    ),
                    "identity_endorsed_service": sum(
                        item.relationship.value == "endorsed_third_party_service"
                        for item in (report.identity_associations if report is not None else [])
                    ),
                },
                latency_ms=max(0, round((perf_counter() - started) * 1000)),
                cost_usd=round(cost_usd, 8),
                status=status,
                strength=report.overall_status.value if report is not None else "none",
                target_hash=_target_hash(scope),
                error_code=error_code,
            )
        )

    async def aclose(self) -> None:
        seen: set[int] = set()
        for closer in self._closers:
            if id(closer) in seen:
                continue
            seen.add(id(closer))
            close = getattr(closer, "aclose", None)
            if close is not None:
                await close()


__all__ = [
    "OfficialVerificationMode",
    "OfficialVerificationRolloutStage",
    "OfficialVerificationTelemetryEvent",
    "OfficialVerificationTelemetrySink",
    "StructuredOfficialVerificationTelemetry",
]
