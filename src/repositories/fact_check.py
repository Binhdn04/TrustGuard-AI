from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.models import ClaimEvidence

_WORD = re.compile(r"[^\W_]+", re.UNICODE)


def _tokens(value: str) -> set[str]:
    return {token.casefold() for token in _WORD.findall(value) if len(token) > 1}


class JsonFactCheckRepository:
    """Small provenance-bearing offline corpus suitable for deterministic CI."""

    def __init__(self, records: list[ClaimEvidence]) -> None:
        self._records = [record.model_copy(deep=True) for record in records]

    @classmethod
    def from_file(cls, path: str | Path) -> JsonFactCheckRepository:
        with Path(path).open(encoding="utf-8") as stream:
            payload: Any = json.load(stream)
        if not isinstance(payload, list):
            raise ValueError("fact-check corpus must be a JSON array")
        now = datetime.now(UTC)
        records: list[ClaimEvidence] = []
        for item in payload:
            if not isinstance(item, dict):
                raise ValueError("fact-check records must be objects")
            normalized = dict(item)
            normalized.setdefault("observed_at", now)
            normalized.setdefault("relevance", 1.0)
            records.append(ClaimEvidence.model_validate(normalized))
        return cls(records)

    async def search(self, claim: str, limit: int = 5) -> list[ClaimEvidence]:
        query = _tokens(claim)
        if not query or limit <= 0:
            return []
        ranked: list[tuple[float, ClaimEvidence]] = []
        for record in self._records:
            document = _tokens(f"{record.title} {record.finding}")
            overlap = len(query & document)
            if not overlap:
                continue
            score = overlap / len(query | document)
            ranked.append((score, record))
        ranked.sort(key=lambda pair: (-pair[0], pair[1].title.casefold()))
        return [record.model_copy(update={"relevance": min(1.0, score * 4)}) for score, record in ranked[:limit]]
