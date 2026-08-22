from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlsplit

from src.agents.tools.domains import canonicalize_registrable_domain
from src.models import (
    InvestigationStepV4,
    SecurityCampaignReviewerStatusV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityInvestigationStepStatusV4,
    SecurityInvestigationToolV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryRecordV4,
    SecurityScopeResponseV4,
    SecurityToolErrorV4,
)
from src.services.security_memory import SecurityMemoryService


@dataclass(frozen=True, slots=True)
class _NamedSignals:
    domains: frozenset[str]
    redirects: frozenset[str]
    brand: str | None
    scenario: str
    action: str | None
    patterns: frozenset[str]
    threat: str

    @property
    def values(self) -> frozenset[str]:
        values = {f"domain:{item}" for item in self.domains}
        values.update(f"redirect:{item}" for item in self.redirects)
        values.add(f"scenario:{self.scenario}")
        values.update(f"pattern:{item}" for item in self.patterns)
        values.add(f"threat:{self.threat}")
        if self.brand:
            values.add(f"brand:{self.brand}")
        if self.action:
            values.add(f"action:{self.action}")
        return frozenset(values)


def _normalized_domain(value: str) -> str | None:
    try:
        return canonicalize_registrable_domain(value)
    except ValueError:
        return None


def _signals(scope: SecurityScopeResponseV4) -> _NamedSignals | None:
    context = scope.security_context
    if context is None:
        return None
    domains = {item for value in context.urls if (item := _normalized_domain(value)) is not None}
    redirects: set[str] = set()
    for evidence in scope.evidence:
        if evidence.type is not SecurityEvidenceTypeV4.REDIRECT:
            continue
        candidates = [evidence.target, evidence.description.rsplit(" -> ", 1)[-1].strip()]
        for candidate in candidates:
            if not candidate:
                continue
            parsed = urlsplit(candidate)
            normalized = _normalized_domain(parsed.hostname or candidate)
            if normalized:
                redirects.add(normalized)
    patterns = {
        name
        for name, present in (
            ("credential_request", context.credential_request),
            ("otp_request", context.otp_request),
            ("payment_request", context.payment_request),
            ("personal_information_request", context.personal_information_request),
            ("urgency", context.urgency),
        )
        if present
    }
    brand = " ".join(context.claimed_entity.casefold().split()) if context.claimed_entity else None
    return _NamedSignals(
        domains=frozenset(domains),
        redirects=frozenset(redirects),
        brand=brand,
        scenario=context.scenario.value,
        action=context.requested_action.value if context.requested_action else None,
        patterns=frozenset(patterns),
        threat=context.potential_threat.value,
    )


def _eligible_match(matches: set[str]) -> bool:
    identity = {item for item in matches if item.startswith(("domain:", "redirect:"))}
    semantic = {item for item in matches if not item.startswith(("domain:", "redirect:"))}
    has_brand = any(item.startswith("brand:") for item in semantic)
    # Exact infrastructure is sufficient. Generic scenario/threat matches need
    # multiple independent named signals so one broad record cannot poison
    # unrelated analyses.
    return bool(identity) or (has_brand and len(semantic) >= 2) or len(semantic) >= 3


def _memory_signal_set(record: SecurityMemoryRecordV4) -> set[str]:
    values = {f"domain:{item}" for item in record.canonical_domains}
    values.update(f"redirect:{item}" for item in record.redirect_targets)
    values.add(f"scenario:{record.scenario.value}")
    values.update(f"pattern:{item}" for item in record.security_patterns)
    values.add(f"threat:{record.threat_type.value}")
    if record.claimed_brand:
        values.add(f"brand:{record.claimed_brand}")
    if record.requested_action:
        values.add(f"action:{record.requested_action.value}")
    return values


def _public_match_summary(matches: set[str]) -> str:
    labels = sorted({item.split(":", 1)[0].replace("pattern", "action pattern") for item in matches})
    return ", ".join(labels)


def _public_target(matches: set[str]) -> str | None:
    identities = sorted(item.split(":", 1)[1] for item in matches if item.startswith(("domain:", "redirect:")))
    return identities[0] if len(identities) == 1 else None


def _signal_labels(matches: set[str]) -> list[str]:
    return sorted({item.split(":", 1)[0] for item in matches})


def _evidence_ref(analysis_id, provenance: str, matches: set[str]) -> str:
    material = f"{analysis_id}\0{provenance}\0{'|'.join(sorted(matches))}"
    return "evidence:" + sha256(material.encode()).hexdigest()[:16]


class SecurityMemoryLookupTool:
    """Local, reviewer-gated lookup over privacy-minimized named signals."""

    def __init__(self, memory: SecurityMemoryService, *, enabled: bool, max_results: int = 5) -> None:
        self._memory = memory
        self.enabled = enabled
        self._max_results = max_results

    async def enrich(self, scope: SecurityScopeResponseV4, *, owner_id: str) -> SecurityScopeResponseV4:
        if not self.enabled:
            return scope
        signals = _signals(scope)
        if signals is None:
            return scope
        step_key = sha256(f"{scope.analysis_id}\0security_memory_lookup".encode()).hexdigest()[:12]
        step = InvestigationStepV4(
            step_id=f"step-{step_key}",
            tool=SecurityInvestigationToolV4.SECURITY_MEMORY_LOOKUP,
            target="reviewed-security-memory",
            reason_code="reviewed_memory_enabled",
            status=SecurityInvestigationStepStatusV4.PENDING,
        )
        try:
            memories, campaigns = await self._memory.reviewed_candidates(owner_id, scope.analysis_id)
        except Exception:
            failed = step.model_copy(
                update={"status": SecurityInvestigationStepStatusV4.FAILED, "status_reason": "lookup_failed"}
            )
            error = SecurityToolErrorV4(
                tool=SecurityInvestigationToolV4.SECURITY_MEMORY_LOOKUP,
                target=step.target,
                code="MEMORY_LOOKUP_FAILED",
                message="Reviewed Security Memory lookup was unavailable.",
                retryable=True,
                provider="local_security_memory",
            )
            return scope.model_copy(
                update={
                    "next_step": "RISK_ASSESSMENT",
                    "investigation_status": SecurityInvestigationStatusV4.PARTIAL,
                    "investigation_plan": [*scope.investigation_plan, failed],
                    "errors": [*scope.errors, error],
                    "limitations": list(
                        dict.fromkeys([*scope.limitations, "Không thể truy hồi Security Memory đã review."])
                    ),
                }
            )

        evidence: list[SecurityEvidenceV4] = []
        allowed = {
            SecurityMemoryAdminVerdictV4.MALICIOUS,
            SecurityMemoryAdminVerdictV4.SAFE,
            SecurityMemoryAdminVerdictV4.FALSE_POSITIVE,
        }
        for candidate in sorted(memories, key=lambda item: item.reviewed_at, reverse=True):
            record = candidate.record
            if record.admin_verdict not in allowed or record.analysis_id == scope.analysis_id:
                continue
            matches = set(signals.values) & _memory_signal_set(record)
            if not _eligible_match(matches):
                continue
            provenance = f"security-memory:{record.memory_id}"
            evidence.append(
                SecurityEvidenceV4(
                    evidence_ref=_evidence_ref(scope.analysis_id, provenance, matches),
                    type=SecurityEvidenceTypeV4.REVIEWED_SECURITY_MEMORY,
                    source="security_memory_lookup",
                    signal="+".join(
                        [
                            f"reviewed_memory_{record.admin_verdict.value}",
                            *_signal_labels(matches),
                        ]
                    ),
                    target=_public_target(matches),
                    description=(
                        f"Mẫu Security Memory đã review trùng {_public_match_summary(matches)}; "
                        f"verdict={record.admin_verdict.value}; reviewed_at={candidate.reviewed_at.isoformat()}."
                    ),
                    observed_at=candidate.reviewed_at,
                    confidence=0.95 if any(item.startswith(("domain:", "redirect:")) for item in matches) else 0.85,
                    provenance_ref=provenance,
                )
            )
            if len(evidence) >= self._max_results:
                break

        if len(evidence) < self._max_results:
            for candidate in sorted(
                campaigns,
                key=lambda item: item.record.reviewed_at or item.record.window_ended_at,
                reverse=True,
            ):
                record = candidate.record
                if (
                    record.reviewer_status is not SecurityCampaignReviewerStatusV4.CONFIRMED
                    or scope.analysis_id in record.analysis_ids
                    or record.reviewed_at is None
                ):
                    continue
                matches = set(signals.values) & set(record.aggregate_signals)
                if not _eligible_match(matches):
                    continue
                provenance = f"security-campaign:{record.campaign_id}"
                evidence.append(
                    SecurityEvidenceV4(
                        evidence_ref=_evidence_ref(scope.analysis_id, provenance, matches),
                        type=SecurityEvidenceTypeV4.REVIEWED_SECURITY_MEMORY,
                        source="security_memory_lookup",
                        signal="+".join(["reviewed_campaign_confirmed", *_signal_labels(matches)]),
                        target=_public_target(matches),
                        description=(
                            f"Campaign đã được reviewer xác nhận trùng {_public_match_summary(matches)}; "
                            f"verdict=confirmed; reviewed_at={record.reviewed_at.isoformat()}."
                        ),
                        observed_at=record.reviewed_at,
                        confidence=0.95 if any(item.startswith(("domain:", "redirect:")) for item in matches) else 0.85,
                        provenance_ref=provenance,
                    )
                )
                if len(evidence) >= self._max_results:
                    break

        completed = step.model_copy(
            update={"status": SecurityInvestigationStepStatusV4.COMPLETED, "status_reason": "tool_completed"}
        )
        status = scope.investigation_status
        if status is SecurityInvestigationStatusV4.NOT_STARTED:
            status = SecurityInvestigationStatusV4.COMPLETED
        return scope.model_copy(
            update={
                "next_step": "RISK_ASSESSMENT",
                "investigation_status": status,
                "investigation_plan": [*scope.investigation_plan, completed],
                "evidence": list({item.evidence_ref: item for item in [*scope.evidence, *evidence]}.values()),
            }
        )


__all__ = ["SecurityMemoryLookupTool"]
