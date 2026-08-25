from __future__ import annotations

import math
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from src.agents.contracts import CampaignDetectionOutput, CampaignFeatures, CampaignHypothesis
from src.agents.fact_check import canonicalize_claim
from src.agents.tools.domains import canonicalize_registrable_domain, canonicalize_url
from src.models.security_v4 import (
    SecurityCampaignRecordV4,
    SecurityEvidenceTypeV4,
    SecurityMemoryAdminVerdictV4,
    SecurityMemoryRecordV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
)


@dataclass(frozen=True, slots=True)
class CampaignConfig:
    """Versioned clustering policy. A policy change must use a new version."""

    window: timedelta = timedelta(hours=24)
    cosine_threshold: float = 0.85
    minimum_analyses: int = 3
    feature_version: str = "campaign-features-v1"
    clustering_version: str = "campaign-clustering-v1"

    def __post_init__(self) -> None:
        if self.window <= timedelta(0):
            raise ValueError("campaign window must be positive")
        if not 0 <= self.cosine_threshold <= 1:
            raise ValueError("cosine threshold must be between 0 and 1")
        if self.minimum_analyses < 3:
            raise ValueError("campaign minimum must be at least three analyses")
        if not self.feature_version.strip() or not self.clustering_version.strip():
            raise ValueError("campaign versions must not be empty")


@dataclass(frozen=True, slots=True)
class ClaimFeature:
    """Opaque claim vector; raw claim text is deliberately not retained."""

    feature_ref: str
    vector: tuple[float, ...]

    def __post_init__(self) -> None:
        if not self.feature_ref.strip() or not self.vector:
            raise ValueError("claim feature requires a reference and vector")
        if any(not math.isfinite(value) for value in self.vector):
            raise ValueError("claim feature vector must contain finite values")
        if math.sqrt(sum(value * value for value in self.vector)) == 0:
            raise ValueError("claim feature vector must not be zero")


class ClaimFeatureEncoder(Protocol):
    version: str

    async def encode(self, claims: Sequence[str]) -> Sequence[ClaimFeature]: ...


@dataclass(frozen=True, slots=True)
class CampaignObservation:
    analysis_id: str
    observed_at: datetime
    registrable_domains: tuple[str, ...] = ()
    redirect_targets: tuple[str, ...] = ()
    claim_features: tuple[ClaimFeature, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.analysis_id.strip():
            raise ValueError("analysis_id must not be empty")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() != timedelta(0):
            raise ValueError("observed_at must use UTC")


class CampaignObservationStore(Protocol):
    async def add(self, observation: CampaignObservation) -> None: ...

    async def recent(self, since: datetime) -> Sequence[CampaignObservation]: ...


@dataclass(slots=True)
class InMemoryCampaignObservationStore:
    """Deterministic dev/test store; production persistence can implement the protocol."""

    _items: dict[str, CampaignObservation] = field(default_factory=dict)

    async def add(self, observation: CampaignObservation) -> None:
        self._items.setdefault(observation.analysis_id, observation)

    async def recent(self, since: datetime) -> Sequence[CampaignObservation]:
        return tuple(item for item in self._items.values() if item.observed_at >= since)


class RepositoryCampaignObservationStore:
    def __init__(self, repository: Any) -> None:
        self._repository = repository

    async def add(self, observation: CampaignObservation) -> None:
        await self._repository.add_campaign_observation(observation)

    async def recent(self, since: datetime) -> Sequence[CampaignObservation]:
        return await self._repository.recent_campaign_observations(since)

    async def record_hypotheses(
        self,
        hypotheses: Sequence[CampaignHypothesis],
        members: Sequence[CampaignObservation],
        config: CampaignConfig,
    ) -> None:
        from src.services.platform_wave2 import CampaignWrite

        domains = sorted({value for item in members for value in item.registrable_domains})
        redirects = sorted({value for item in members for value in item.redirect_targets})
        for hypothesis in hypotheses:
            await self._repository.record_campaign(
                CampaignWrite(
                    campaign_id=hypothesis.hypothesis_id,
                    hypothesis=f"Potential coordinated campaign across {hypothesis.analysis_count} analyses",
                    window_started_at=hypothesis.window_started_at,
                    window_ended_at=hypothesis.window_ended_at,
                    similarity_threshold=config.cosine_threshold,
                    minimum_analyses=config.minimum_analyses,
                    clustering_version=config.clustering_version,
                    members=[
                        (UUID(item.analysis_id), "shared_signal", None, list(item.evidence_refs)) for item in members
                    ],
                    aggregate_signals={
                        **{f"domain:{value}": 1 for value in domains},
                        **{f"redirect:{value}": 1 for value in redirects},
                    },
                    evidence_refs=hypothesis.evidence_refs,
                    registrable_domains=domains,
                    redirect_targets=redirects,
                )
            )


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        return -1.0
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    return numerator / (left_norm * right_norm)


def _matches(left: CampaignObservation, right: CampaignObservation, threshold: float) -> bool:
    if set(left.registrable_domains) & set(right.registrable_domains):
        return True
    if set(left.redirect_targets) & set(right.redirect_targets):
        return True
    return any(_cosine(a.vector, b.vector) >= threshold for a in left.claim_features for b in right.claim_features)


def _component(seed: CampaignObservation, observations: Sequence[CampaignObservation], threshold: float):
    by_id = {item.analysis_id: item for item in observations}
    selected = {seed.analysis_id}
    pending = deque([seed])
    while pending:
        current = pending.popleft()
        for candidate in observations:
            if candidate.analysis_id not in selected and _matches(current, candidate, threshold):
                selected.add(candidate.analysis_id)
                pending.append(candidate)
    return [by_id[item_id] for item_id in sorted(selected)]


def cluster_observations(
    observations: Sequence[CampaignObservation],
    *,
    config: CampaignConfig = CampaignConfig(),
) -> list[CampaignHypothesis]:
    """Cluster privacy-minimized observations into admin-only hypotheses."""
    remaining = {item.analysis_id: item for item in observations}
    hypotheses: list[CampaignHypothesis] = []
    while remaining:
        seed = remaining[min(remaining)]
        members = _component(seed, tuple(remaining.values()), config.cosine_threshold)
        for member in members:
            remaining.pop(member.analysis_id, None)
        if len(members) < config.minimum_analyses:
            continue
        member_ids = sorted(item.analysis_id for item in members)
        cluster_key = f"{config.clustering_version}\0" + "\0".join(member_ids)
        evidence_refs = sorted({ref for item in members for ref in item.evidence_refs})
        if not evidence_refs:
            evidence_refs = ["campaign:sha256:" + sha256(cluster_key.encode()).hexdigest()]
        hypotheses.append(
            CampaignHypothesis(
                hypothesis_id=uuid5(NAMESPACE_URL, cluster_key),
                evidence_refs=evidence_refs,
                analysis_count=len(members),
                window_started_at=min(item.observed_at for item in members),
                window_ended_at=max(item.observed_at for item in members),
                clustering_version=config.clustering_version,
            )
        )
    return sorted(hypotheses, key=lambda item: str(item.hypothesis_id))


def _registrable_domains(state: Mapping[str, Any]) -> tuple[str, ...]:
    values: set[str] = set()
    for target in state.get("normalized_urls", ()):
        try:
            values.add(canonicalize_registrable_domain(str(target)))
        except ValueError:
            continue
    return tuple(sorted(values))


def _redirect_targets(state: Mapping[str, Any]) -> tuple[str, ...]:
    values: set[str] = set()
    for finding in state.get("url_findings", ()):
        chain = getattr(finding, "redirect_chain", ())
        if len(chain) < 2:
            continue
        try:
            values.add(canonicalize_url(chain[-1]).partition("?")[0])
        except ValueError:
            continue
    for evidence in state.get("evidence", ()):
        if getattr(getattr(evidence, "type", None), "value", None) != "redirect":
            continue
        finding = str(getattr(evidence, "finding", ""))
        candidate = finding.rsplit(" -> ", 1)[-1]
        try:
            values.add(canonicalize_url(candidate).partition("?")[0])
        except ValueError:
            continue
    return tuple(sorted(values))


class ConfigurableCampaignDetector:
    """Collect features and return hypotheses only; it has no action side effects."""

    def __init__(
        self,
        store: CampaignObservationStore,
        *,
        encoder: ClaimFeatureEncoder | None = None,
        config: CampaignConfig = CampaignConfig(),
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._encoder = encoder
        self._config = config
        self._clock = clock

    async def detect(self, state: Mapping[str, Any]) -> CampaignDetectionOutput:
        observed_at = self._clock()
        claims: list[str] = []
        for value in state.get("claims", ()):
            try:
                claims.append(canonicalize_claim(str(value)))
            except ValueError:
                continue
            if len(claims) == 5:
                break
        reused_features = state.get("claim_feature_vectors", ())
        if reused_features:
            try:
                claim_features = tuple(ClaimFeature(str(ref), tuple(vector)) for ref, vector in reused_features)[:5]
            except (TypeError, ValueError):
                claim_features = ()
        elif self._encoder and claims:
            try:
                claim_features = tuple(await self._encoder.encode(claims))[:5]
            except Exception:
                claim_features = ()
        else:
            claim_features = ()
        domains = _registrable_domains(state)
        redirects = _redirect_targets(state)
        features = CampaignFeatures(
            registrable_domains=list(domains),
            redirect_targets=list(redirects),
            claim_feature_refs=[item.feature_ref for item in claim_features],
            observed_at=observed_at,
            feature_version=self._config.feature_version,
        )
        analysis_id = str(state.get("analysis_id", "")).strip()
        if not analysis_id or not (domains or redirects or claim_features):
            return {"campaign_features": features, "campaign_hypotheses": []}
        refs = tuple(
            sorted(
                {"campaign-domain:sha256:" + sha256(value.encode()).hexdigest() for value in (*domains, *redirects)}
                | {item.feature_ref for item in claim_features}
            )
        )
        observation = CampaignObservation(
            analysis_id=analysis_id,
            observed_at=observed_at,
            registrable_domains=domains,
            redirect_targets=redirects,
            claim_features=claim_features,
            evidence_refs=refs,
        )
        await self._store.add(observation)
        recent = tuple(
            item
            for item in await self._store.recent(observed_at - self._config.window)
            if item.observed_at <= observed_at
        )
        seed = next((item for item in recent if item.analysis_id == analysis_id), observation)
        members = _component(seed, recent, self._config.cosine_threshold)
        hypotheses = cluster_observations(members, config=self._config)
        persist = getattr(self._store, "record_hypotheses", None)
        if persist is not None and hypotheses:
            await persist(hypotheses, members, self._config)
        return {"campaign_features": features, "campaign_hypotheses": hypotheses}


@dataclass(frozen=True, slots=True)
class SecurityCampaignConfig:
    """Explainable v4 fingerprint policy; it never calls an embedding provider."""

    window: timedelta = timedelta(hours=24)
    minimum_analyses: int = 3
    fingerprint_version: str = "security-fingerprint-v1"
    clustering_version: str = "security-clustering-v1"

    def __post_init__(self) -> None:
        if self.window <= timedelta(0):
            raise ValueError("security campaign window must be positive")
        if self.minimum_analyses < 3:
            raise ValueError("security campaign minimum must be at least three analyses")
        if not self.fingerprint_version.strip() or not self.clustering_version.strip():
            raise ValueError("security campaign versions must not be empty")


_SENSITIVE_PATH_MARKERS = {
    "account",
    "credential",
    "login",
    "otp",
    "password",
    "pay",
    "payment",
    "secure",
    "signin",
    "verify",
    "wallet",
}
_ROUTINE_PATH_FEATURES = {"path:account", "path:login", "path:signin", "path:verify"}


def _security_url_parts(value: str) -> tuple[str, str, set[str]]:
    canonical = canonicalize_url(value)
    parsed = urlsplit(canonical)
    domain = canonicalize_registrable_domain(canonical)
    minimized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    lexical: set[str] = set()
    hostname = parsed.hostname or ""
    if "xn--" in hostname:
        lexical.add("host:punycode")
    if "-" in hostname:
        lexical.add("host:hyphenated")
    if any(character.isdigit() for character in hostname):
        lexical.add("host:contains_digit")
    path_tokens = {token.casefold() for token in parsed.path.replace("-", "/").replace("_", "/").split("/")}
    lexical.update(f"path:{token}" for token in sorted(path_tokens & _SENSITIVE_PATH_MARKERS))
    depth = len([part for part in parsed.path.split("/") if part])
    lexical.add(f"path_depth:{min(depth, 3)}")
    return domain, "url:sha256:" + sha256(minimized.encode()).hexdigest(), lexical


def _redirect_domains(response: SecurityScopeResponseV4) -> set[str]:
    values: set[str] = set()
    for evidence in response.evidence:
        if evidence.type is not SecurityEvidenceTypeV4.REDIRECT:
            continue
        candidate = evidence.description.rsplit(" -> ", 1)[-1].strip()
        try:
            values.add(canonicalize_registrable_domain(candidate))
        except ValueError:
            continue
    return values


def build_security_memory_record(
    response: SecurityScopeResponseV4,
    *,
    config: SecurityCampaignConfig = SecurityCampaignConfig(),
) -> SecurityMemoryRecordV4:
    """Build privacy-minimized intelligence from a completed v4 response."""

    context = response.security_context
    if context is None or response.risk is None or response.threat_type is None or response.policy_version is None:
        raise ValueError("completed in-scope security result is required")
    domains: set[str] = set()
    fingerprints: set[str] = set()
    lexical: set[str] = set()
    sensitive_semantics = bool(
        context.credential_request
        or context.otp_request
        or context.payment_request
        or context.personal_information_request
    )
    for value in context.urls:
        try:
            domain, fingerprint, features = _security_url_parts(value)
        except ValueError:
            continue
        domains.add(domain)
        fingerprints.add(fingerprint)
        lexical.update(features if sensitive_semantics else features - _ROUTINE_PATH_FEATURES)
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
    observed_at = response.completed_at or response.created_at
    claimed_brand = " ".join(context.claimed_entity.casefold().split()) if context.claimed_entity else None
    return SecurityMemoryRecordV4(
        memory_id=uuid5(NAMESPACE_URL, f"security-memory\0{response.analysis_id}"),
        analysis_id=response.analysis_id,
        canonical_domains=sorted(domains),
        url_fingerprints=sorted(fingerprints),
        redirect_targets=sorted(_redirect_domains(response)),
        claimed_brand=claimed_brand,
        scenario=context.scenario,
        requested_action=context.requested_action,
        security_patterns=sorted(patterns),
        lexical_features=sorted(lexical),
        threat_type=response.threat_type,
        risk=response.risk,
        risk_policy_version=response.policy_version,
        fingerprint_version=config.fingerprint_version,
        first_seen_at=observed_at,
        last_seen_at=observed_at,
        evidence_refs=list(
            dict.fromkeys(response.explanation_evidence_refs or [e.evidence_ref for e in response.evidence])
        ),
    )


def _security_signal_set(record: SecurityMemoryRecordV4) -> set[str]:
    values = {f"domain:{item}" for item in record.canonical_domains}
    values.update(f"redirect:{item}" for item in record.redirect_targets)
    values.add(f"scenario:{record.scenario.value}")
    values.update(f"pattern:{item}" for item in record.security_patterns)
    values.update(f"lexical:{item}" for item in record.lexical_features)
    if record.claimed_brand:
        values.add(f"brand:{record.claimed_brand}")
    if record.requested_action:
        values.add(f"action:{record.requested_action.value}")
    values.add(f"threat:{record.threat_type.value}")
    return values


def _security_matches(left: SecurityMemoryRecordV4, right: SecurityMemoryRecordV4) -> bool:
    if set(left.canonical_domains) & set(right.canonical_domains):
        return True
    if set(left.redirect_targets) & set(right.redirect_targets):
        return True
    if left.claimed_brand and left.claimed_brand == right.claimed_brand:
        return True
    same_scenario = left.scenario == right.scenario and left.scenario.value != "unknown"
    same_action = left.requested_action is not None and left.requested_action == right.requested_action
    shared_patterns = set(left.security_patterns) & set(right.security_patterns)
    return same_scenario and (same_action or (left.threat_type == right.threat_type and bool(shared_patterns)))


def _security_component(
    seed: SecurityMemoryRecordV4, observations: Sequence[SecurityMemoryRecordV4]
) -> list[SecurityMemoryRecordV4]:
    by_id = {item.analysis_id: item for item in observations}
    selected = {seed.analysis_id}
    pending = deque([seed])
    while pending:
        current = pending.popleft()
        for candidate in observations:
            if candidate.analysis_id not in selected and _security_matches(current, candidate):
                selected.add(candidate.analysis_id)
                pending.append(candidate)
    return [by_id[item_id] for item_id in sorted(selected, key=str)]


def cluster_security_memory(
    observations: Sequence[SecurityMemoryRecordV4],
    *,
    config: SecurityCampaignConfig = SecurityCampaignConfig(),
) -> list[SecurityCampaignRecordV4]:
    """Cluster on named security signals and keep every hypothesis reviewer-gated."""

    newest = max((item.last_seen_at for item in observations), default=None)
    cutoff = newest - config.window if newest is not None else None
    eligible = [
        item
        for item in observations
        if cutoff is not None and item.last_seen_at >= cutoff
        if item.admin_verdict not in {SecurityMemoryAdminVerdictV4.SAFE, SecurityMemoryAdminVerdictV4.FALSE_POSITIVE}
        and item.risk not in {SecurityRiskV4.SAFE, SecurityRiskV4.LOW_RISK, SecurityRiskV4.INSUFFICIENT_EVIDENCE}
    ]
    remaining = {item.analysis_id: item for item in eligible}
    campaigns: list[SecurityCampaignRecordV4] = []
    while remaining:
        seed = remaining[min(remaining, key=str)]
        members = _security_component(seed, tuple(remaining.values()))
        for member in members:
            remaining.pop(member.analysis_id, None)
        if len(members) < config.minimum_analyses:
            continue
        member_ids = sorted((item.analysis_id for item in members), key=str)
        counts: dict[str, int] = {}
        for member in members:
            for signal in _security_signal_set(member):
                counts[signal] = counts.get(signal, 0) + 1
        aggregate = {key: value for key, value in sorted(counts.items()) if value >= 2}
        explaining = [key for key, value in aggregate.items() if value == len(members)] or list(aggregate)[:5]
        cluster_key = f"{config.clustering_version}\0" + "\0".join(map(str, member_ids))
        refs = sorted({ref for item in members for ref in item.evidence_refs})
        if not refs:
            refs = ["campaign:sha256:" + sha256(cluster_key.encode()).hexdigest()]
        campaigns.append(
            SecurityCampaignRecordV4(
                campaign_id=uuid5(NAMESPACE_URL, cluster_key),
                hypothesis="Potential coordinated security campaign: " + ", ".join(explaining[:5]),
                analysis_ids=member_ids,
                window_started_at=min(item.first_seen_at for item in members),
                window_ended_at=max(item.last_seen_at for item in members),
                aggregate_signals=aggregate,
                clustering_version=config.clustering_version,
                evidence_refs=refs[:100],
                created_at=max(item.last_seen_at for item in members),
            )
        )
    return sorted(campaigns, key=lambda item: str(item.campaign_id))


__all__ = [
    "CampaignConfig",
    "CampaignObservation",
    "CampaignObservationStore",
    "ClaimFeature",
    "ClaimFeatureEncoder",
    "ConfigurableCampaignDetector",
    "InMemoryCampaignObservationStore",
    "RepositoryCampaignObservationStore",
    "cluster_observations",
    "SecurityCampaignConfig",
    "build_security_memory_record",
    "cluster_security_memory",
]
