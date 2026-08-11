from __future__ import annotations

import math
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

from src.agents.contracts import CampaignDetectionOutput, CampaignFeatures, CampaignHypothesis
from src.agents.fact_check import canonicalize_claim
from src.agents.tools.domains import canonicalize_registrable_domain, canonicalize_url


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
]
