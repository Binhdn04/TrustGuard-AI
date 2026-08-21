from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from src.models import BrandRecordV4, EntityUrlClaimV4, EntityUrlRelationshipV4

_TOKEN_RE = re.compile(r"[^\W_]+(?:[.&'’-][^\W_]+)*", re.UNICODE)
_ORG_PREFIXES = (
    ("truong", "dai", "hoc"),
    ("benh", "vien"),
    ("dai", "hoc"),
    ("ngan", "hang"),
    ("cong", "ty"),
    ("tap", "doan"),
    ("cong", "an"),
    ("ubnd",),
    ("bo",),
    ("so",),
    ("cuc",),
    ("truong",),
    ("hospital",),
    ("university",),
    ("bank",),
    ("company",),
)
_GENERIC_ORGANIZATIONS = {" ".join(item) for item in _ORG_PREFIXES}
_PHRASE_CUES = {
    "ben",
    "don vi",
    "nha mang",
    "nhan vien",
    "phia",
    "team",
}
_BOUNDARY_WORDS = {
    "bao",
    "cho",
    "cua",
    "day",
    "de",
    "den",
    "de nghi",
    "gioi",
    "gui",
    "hay",
    "la",
    "o",
    "qua",
    "sang",
    "tai",
    "tren",
    "tuyen",
    "vao",
    "web",
    "website",
    "xem",
    "yeu",
}
_BOUNDARY_SEQUENCES = {
    ("canh", "bao"),
    ("gioi", "thieu"),
    ("lien", "he"),
    ("moi", "tham"),
    ("phoi", "hop"),
    ("thong", "bao"),
    ("to", "chuc"),
    ("trien", "khai"),
    ("tuyen", "dung"),
    ("yeu", "cau"),
}
_CLAIMED_SITE_RE = re.compile(
    r"\b(?:trang\s+)?web(?:site)?\s+(?:chính\s+thức\s+)?của\b"
    r"|\b(?:trang\s+)?web(?:site)?\s+chính\s+thức\b"
    r"|\bcổng\s+thông\s+tin\s+(?:chính\s+thức\s+)?của\b",
    re.IGNORECASE,
)


def _fold(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char)).replace("đ", "d")


def _is_boundary(folded_tokens: list[str], index: int) -> bool:
    return folded_tokens[index] in _BOUNDARY_WORDS or any(
        tuple(folded_tokens[index : index + len(sequence)]) == sequence for sequence in _BOUNDARY_SEQUENCES
    )


@dataclass(frozen=True, slots=True)
class EntityMentionCandidate:
    mention_id: str
    text: str
    start: int
    end: int
    source: str = "local_organization_rule"
    canonical: str | None = None

    def as_prompt_data(self) -> dict[str, object]:
        return {
            "id": self.mention_id,
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "source": self.source,
            **({"canonical": self.canonical} if self.canonical else {}),
        }


@dataclass(frozen=True, slots=True)
class OrganizationGazetteerEntry:
    canonical: str
    aliases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OrganizationGazetteer:
    entries: tuple[OrganizationGazetteerEntry, ...] = ()

    @classmethod
    def from_brands(cls, brands: list[BrandRecordV4]) -> OrganizationGazetteer:
        entries = []
        for brand in brands:
            aliases = tuple(dict.fromkeys(value.strip() for value in (brand.name, *brand.aliases) if value.strip()))
            entries.append(OrganizationGazetteerEntry(canonical=brand.name, aliases=aliases))
        return cls(tuple(entries))

    def find(self, message: str) -> list[EntityMentionCandidate]:
        matches: list[tuple[int, int, str]] = []
        for entry in self.entries:
            for alias in sorted(entry.aliases, key=len, reverse=True):
                pattern = re.compile(rf"(?<!\w){re.escape(alias)}(?!\w)", re.IGNORECASE)
                matches.extend((match.start(), match.end(), entry.canonical) for match in pattern.finditer(message))
        # Prefer the longest reviewed alias when registry aliases overlap.
        selected: list[tuple[int, int, str]] = []
        for candidate in sorted(matches, key=lambda item: (item[0], -(item[1] - item[0]), item[2])):
            if any(start <= candidate[0] and candidate[1] <= end for start, end, _ in selected):
                continue
            selected.append(candidate)
        return [
            EntityMentionCandidate(
                mention_id=f"entity_{index}",
                text=message[start:end],
                start=start,
                end=end,
                source="reviewed_brand_gazetteer",
                canonical=canonical,
            )
            for index, (start, end, canonical) in enumerate(selected[:10])
        ]


def extract_entity_mentions(
    message: str,
    literal_entities: tuple[str, ...] = (),
    gazetteer: OrganizationGazetteer | None = None,
) -> list[EntityMentionCandidate]:
    """Extract bounded organization mentions and compute offsets locally.

    This intentionally favors precision over recall. Semantic AI may classify
    relations between these candidates, but it never creates their offsets.
    """
    gazetteer_mentions = gazetteer.find(message) if gazetteer is not None else []
    tokens = list(_TOKEN_RE.finditer(message))
    folded = [_fold(item.group(0)) for item in tokens]
    spans: list[tuple[int, int]] = []
    for index, _token in enumerate(tokens):
        prefix = next(
            (item for item in _ORG_PREFIXES if tuple(folded[index : index + len(item)]) == item),
            None,
        )
        if prefix is None:
            continue
        end_index = index + len(prefix)
        while end_index < len(tokens) and end_index - index < 8:
            separator = message[tokens[end_index - 1].end() : tokens[end_index].start()]
            if any(char in separator for char in ".!?;,:\n"):
                break
            if _is_boundary(folded, end_index) or tokens[end_index].group(0).casefold().startswith(("http", "www")):
                break
            end_index += 1
        spans.append((tokens[index].start(), tokens[end_index - 1].end()))

    # Prefer the outermost organization phrase when prefixes are nested, e.g.
    # "Bệnh viện Đại học Y" rather than a second "Đại học Y" candidate.
    outermost = [
        span
        for span in spans
        if not any(other != span and other[0] <= span[0] and span[1] <= other[1] for other in spans)
    ]
    unique = sorted(set(outermost), key=lambda item: (item[0], item[1]))
    folded_message = message.casefold()
    for entity in literal_entities:
        start = folded_message.find(entity.casefold())
        if start >= 0:
            unique.append((start, start + len(entity)))
    unique = sorted(set(unique), key=lambda item: (item[0], item[1]))
    if gazetteer_mentions or any(_fold(message[start:end]) not in _GENERIC_ORGANIZATIONS for start, end in unique):
        unique = [(start, end) for start, end in unique if _fold(message[start:end]) not in _GENERIC_ORGANIZATIONS]
    rule_mentions = [
        EntityMentionCandidate(
            mention_id="",
            text=message[start:end],
            start=start,
            end=end,
        )
        for start, end in unique
    ]
    # Reviewed aliases take precedence over overlapping broad prefix rules.
    merged = list(gazetteer_mentions)
    merged.extend(
        item
        for item in rule_mentions
        if not any(
            item.start <= known.start < item.end or known.start <= item.start < known.end
            for known in gazetteer_mentions
        )
    )
    merged.sort(key=lambda item: (item.start, item.end))
    return [
        EntityMentionCandidate(
            mention_id=f"entity_{index}",
            text=item.text,
            start=item.start,
            end=item.end,
            source=item.source,
            canonical=item.canonical,
        )
        for index, item in enumerate(merged[:10])
    ]


def extract_recovery_phrases(
    message: str,
    organization_mentions: list[EntityMentionCandidate],
) -> list[EntityMentionCandidate]:
    """Create bounded phrase IDs only when organization extraction has no hit."""
    if organization_mentions:
        return []
    tokens = list(_TOKEN_RE.finditer(message))
    folded = [_fold(item.group(0)) for item in tokens]
    candidates: list[tuple[int, int]] = []
    for index in range(len(tokens)):
        cue_length = next(
            (
                len(cue.split())
                for cue in _PHRASE_CUES
                if tuple(folded[index : index + len(cue.split())]) == tuple(cue.split())
            ),
            0,
        )
        if not cue_length or index + cue_length >= len(tokens):
            continue
        end_index = index + cue_length + 1
        while end_index < len(tokens) and end_index - index < cue_length + 3:
            separator = message[tokens[end_index - 1].end() : tokens[end_index].start()]
            if any(char in separator for char in ".!?;,:\n") or _is_boundary(folded, end_index):
                break
            end_index += 1
        candidates.append((tokens[index].start(), tokens[end_index - 1].end()))
    return [
        EntityMentionCandidate(
            mention_id=f"phrase_{index}",
            text=message[start:end],
            start=start,
            end=end,
            source="local_phrase_recovery",
        )
        for index, (start, end) in enumerate(sorted(set(candidates))[:10])
    ]


def deterministic_entity_url_claims(
    message: str,
    mentions: list[EntityMentionCandidate],
    url_count: int,
) -> list[EntityUrlClaimV4]:
    """Return only high-precision ownership claims supported by local wording."""
    if not mentions or url_count != 1:
        return []
    marker = _CLAIMED_SITE_RE.search(message)
    if marker is None:
        return []
    preceding = [item for item in mentions if item.end <= marker.start()]
    entity = max(preceding, key=lambda item: item.end) if preceding else (mentions[0] if len(mentions) == 1 else None)
    if entity is None:
        return []
    return [
        EntityUrlClaimV4(
            entity_name=entity.text,
            url_index=0,
            relationship=EntityUrlRelationshipV4.CLAIMED_OFFICIAL_SITE,
            confidence=1.0,
        )
    ]


__all__ = [
    "EntityMentionCandidate",
    "OrganizationGazetteer",
    "OrganizationGazetteerEntry",
    "deterministic_entity_url_claims",
    "extract_entity_mentions",
    "extract_recovery_phrases",
]
