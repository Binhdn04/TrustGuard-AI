"""Bounded, evidence-led retrieval planning for official-link discovery.

The planner has no trust authority.  It records candidate material and chooses
the next *missing evidence edge*; deterministic verification consumes the
material separately.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlsplit


class EvidenceEdge(StrEnum):
    ENTITY_OFFICIAL_IDENTITY = "entity_official_identity"
    ENTITY_CAMPAIGN = "entity_campaign"
    CAMPAIGN_EXACT_RESOURCE = "campaign_exact_resource"
    OFFICIAL_SOURCE_SOCIAL_PUBLICATION = "official_source_social_publication"
    SOCIAL_PUBLICATION_EXACT_RESOURCE = "social_publication_exact_resource"


class RetrievalDirection(StrEnum):
    CLAIM_CENTRIC = "claim_centric"
    RESOURCE_CENTRIC = "resource_centric"
    SOURCE_CENTRIC = "source_centric"


@dataclass(frozen=True)
class EvidenceFrontier:
    edge: EvidenceEdge
    direction: RetrievalDirection
    queries: tuple[str, ...] = ()
    candidate_urls: tuple[str, ...] = ()


@dataclass
class EvidenceGraph:
    entity: str
    campaign: str = ""
    resource_url: str = ""
    candidate_sources: set[str] = field(default_factory=set)
    fetched_sources: set[str] = field(default_factory=set)
    resource_links: set[str] = field(default_factory=set)
    social_publications: set[str] = field(default_factory=set)


class EvidenceRetrievalPlanner:
    """Choose non-equivalent, bounded retrieval frontiers from observed facts."""

    max_queries_per_frontier = 2
    max_providers_per_frontier = 2
    max_consecutive_no_evidence = 2

    def __init__(
        self,
        *,
        entity: str,
        campaign: str = "",
        resource_url: str = "",
        normalized_entity: str = "",
        normalized_topic: str = "",
    ) -> None:
        self.graph = EvidenceGraph(
            entity=" ".join(entity.split()), campaign=" ".join(campaign.split()), resource_url=resource_url
        )
        self._normalized_entity = " ".join(normalized_entity.split())
        self._normalized_topic = " ".join(normalized_topic.split())
        self._completed: set[tuple[EvidenceEdge, RetrievalDirection]] = set()
        self._semantic_work: set[str] = set()
        self._consecutive_no_evidence = 0

    @property
    def stop_reason(self) -> str | None:
        if self._consecutive_no_evidence >= self.max_consecutive_no_evidence:
            return "consecutive_retrievals_no_new_evidence"
        return None

    def observe_candidates(self, urls: list[str] | tuple[str, ...]) -> bool:
        before = len(self.graph.candidate_sources)
        self.graph.candidate_sources.update(urls)
        return self._record_progress(len(self.graph.candidate_sources) > before)

    def observe_source(
        self,
        url: str,
        *,
        resource_links: list[str] | tuple[str, ...] = (),
        social_urls: list[str] | tuple[str, ...] = (),
    ) -> bool:
        before = (len(self.graph.fetched_sources), len(self.graph.resource_links), len(self.graph.social_publications))
        self.graph.fetched_sources.add(url)
        self.graph.resource_links.update(resource_links)
        self.graph.social_publications.update(social_urls)
        return self._record_progress(
            before
            != (len(self.graph.fetched_sources), len(self.graph.resource_links), len(self.graph.social_publications))
        )

    def next_frontier(self) -> EvidenceFrontier | None:
        if self.stop_reason is not None:
            return None
        # Search hits are candidate evidence.  Extract them before searching
        # again; this is the key guard against a query-paraphrase loop.
        unfetched = sorted(self.graph.candidate_sources - self.graph.fetched_sources)
        if unfetched:
            return self._frontier(
                EvidenceEdge.ENTITY_CAMPAIGN, RetrievalDirection.SOURCE_CENTRIC, candidates=unfetched[:2]
            )
        if not self.graph.candidate_sources:
            identity = self._frontier(
                EvidenceEdge.ENTITY_OFFICIAL_IDENTITY,
                RetrievalDirection.CLAIM_CENTRIC,
                queries=self._claim_queries(),
            )
            if identity is not None:
                return identity
            if self.graph.resource_url and not self.graph.resource_links:
                return self._frontier(
                    EvidenceEdge.CAMPAIGN_EXACT_RESOURCE,
                    RetrievalDirection.RESOURCE_CENTRIC,
                    queries=self._resource_queries(),
                )
        if self.graph.social_publications and not self.graph.resource_links:
            return self._frontier(
                EvidenceEdge.SOCIAL_PUBLICATION_EXACT_RESOURCE,
                RetrievalDirection.RESOURCE_CENTRIC,
                queries=self._resource_queries(),
            )
        return None

    def complete_frontier(self, frontier: EvidenceFrontier, *, new_evidence: bool) -> None:
        self._completed.add((frontier.edge, frontier.direction))
        self._record_progress(new_evidence)

    def _frontier(
        self,
        edge: EvidenceEdge,
        direction: RetrievalDirection,
        *,
        queries: tuple[str, ...] = (),
        candidates: tuple[str, ...] = (),
    ) -> EvidenceFrontier | None:
        key = (edge, direction)
        if key in self._completed:
            return None
        filtered = tuple(query for query in queries if self._remember_work(direction, query))[
            : self.max_queries_per_frontier
        ]
        if direction is not RetrievalDirection.SOURCE_CENTRIC and not filtered:
            return None
        return EvidenceFrontier(edge=edge, direction=direction, queries=filtered, candidate_urls=tuple(candidates))

    def _claim_queries(self) -> tuple[str, ...]:
        values = [
            " ".join(
                value
                for value in (self.graph.entity, f'"{self.graph.campaign}"' if self.graph.campaign else "")
                if value
            )
        ]
        normalized = (
            " ".join(
                value
                for value in (self._normalized_entity or self.graph.entity, self._normalized_topic, "official")
                if value
            )
            if self._normalized_entity or self._normalized_topic
            else self.graph.entity
        )
        if normalized:
            values.append(normalized)
        return tuple(value for value in values if value)

    def _resource_queries(self) -> tuple[str, ...]:
        parsed = urlsplit(self.graph.resource_url)
        identifier = parsed.path.rstrip("/").split("/")[-1]
        values = [self.graph.resource_url]
        if parsed.hostname and identifier:
            values.append(f"{parsed.hostname} {identifier}")
        return tuple(value for value in values if len(value) <= 300)

    def _remember_work(self, direction: RetrievalDirection, value: str) -> bool:
        # URL punctuation and case do not make a search materially different.
        normalized = "".join(value.casefold().split()).rstrip("/")
        fingerprint = hashlib.sha256(f"{direction.value}:{normalized}".encode()).hexdigest()
        if fingerprint in self._semantic_work:
            return False
        self._semantic_work.add(fingerprint)
        return True

    def _record_progress(self, new_evidence: bool) -> bool:
        self._consecutive_no_evidence = 0 if new_evidence else self._consecutive_no_evidence + 1
        return new_evidence
