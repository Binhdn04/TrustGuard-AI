from __future__ import annotations

import re
from dataclasses import dataclass

from src.agents.nodes.extraction import extract_urls
from src.agents.security_scope import requested_action_source_span
from src.models import RequestedActionV4
from src.services.security_entity_mentions import EntityMentionCandidate, extract_recovery_phrases

_CLAUSE_RE = re.compile(r"[^.!?;\n]+(?:[.!?;]|$)", re.UNICODE)
_PHRASE_RE = re.compile(r"[^\s,;:.!?]+(?:\s+[^\s,;:.!?]+){0,7}", re.UNICODE)
_MAX_CANDIDATES = 50


@dataclass(frozen=True, slots=True)
class SemanticSpanCandidate:
    span_id: str
    start: int
    end: int
    kind: str
    specificity: int

    def as_prompt_data(self, message: str) -> dict[str, object]:
        return {
            "id": self.span_id,
            "text": message[self.start : self.end],
            "kind": self.kind,
        }


def _trimmed(message: str, start: int, end: int) -> tuple[int, int] | None:
    while start < end and message[start].isspace():
        start += 1
    while end > start and message[end - 1].isspace():
        end -= 1
    return (start, end) if end > start else None


def generate_semantic_span_candidates(
    message: str,
    entity_candidates: list[EntityMentionCandidate] | None = None,
) -> list[SemanticSpanCandidate]:
    """Create bounded, backend-owned spans for semantic grounding.

    IDs are stable for a message because ranges are sorted before numbering.
    Specific literal phrases outrank clauses, and the full-message candidate is
    retained as the final fail-soft grounding option.
    """
    ranges: dict[tuple[int, int], tuple[str, int]] = {}

    def add(start: int, end: int, kind: str, specificity: int) -> None:
        bounded = _trimmed(message, max(0, start), min(len(message), end))
        if bounded is None:
            return
        previous = ranges.get(bounded)
        if previous is None or specificity > previous[1]:
            ranges[bounded] = (kind, specificity)

    cursor = 0
    for url in extract_urls(message):
        start = message.find(url, cursor)
        if start < 0:
            start = message.find(url)
        if start >= 0:
            add(start, start + len(url), "url", 4)
            cursor = start + len(url)

    supplied_entities = entity_candidates or []
    for item in supplied_entities:
        add(item.start, item.end, "entity", 4)
    for item in extract_recovery_phrases(message, supplied_entities):
        add(item.start, item.end, "phrase", 3)
    for action in RequestedActionV4:
        if (action_span := requested_action_source_span(message, action)) is not None:
            add(*action_span, "action_phrase", 4)

    clauses: list[tuple[int, int]] = []
    for match in _CLAUSE_RE.finditer(message):
        bounded = _trimmed(message, match.start(), match.end())
        if bounded is not None:
            clauses.append(bounded)
            add(*bounded, "clause", 2)

    # Useful short phrases give the model more precise anchors inside long
    # clauses without attempting semantic classification in the backend.
    for clause_start, clause_end in clauses:
        clause = message[clause_start:clause_end]
        for match in _PHRASE_RE.finditer(clause):
            if 2 <= len(match.group(0).split()) <= 8:
                add(clause_start + match.start(), clause_start + match.end(), "phrase", 3)

    full = _trimmed(message, 0, len(message))
    ordered = sorted(
        ranges.items(),
        key=lambda item: (-item[1][1], item[0][0], item[0][1] - item[0][0], item[1][0]),
    )[: _MAX_CANDIDATES - (1 if full is not None else 0)]
    candidates = [
        SemanticSpanCandidate(
            span_id=f"span_{index}",
            start=bounds[0],
            end=bounds[1],
            kind=metadata[0],
            specificity=metadata[1],
        )
        for index, (bounds, metadata) in enumerate(ordered)
    ]
    if full is not None:
        candidates.append(
            SemanticSpanCandidate(
                span_id=f"span_{len(candidates)}",
                start=full[0],
                end=full[1],
                kind="full_message",
                specificity=1,
            )
        )
    return candidates


__all__ = ["SemanticSpanCandidate", "generate_semantic_span_candidates"]
