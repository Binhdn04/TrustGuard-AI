from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

from src.models import (
    BrandRecordV4,
    EntityUrlClaimV4,
    EntityUrlRelationshipV4,
    GroundedEntityMentionV4,
    GroundedEntityRoleV4,
)

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
_ATTRIBUTION_VERBS = {
    "gui",
    "yeu cau",
    "thong bao",
    "trien khai",
    "cung cap",
}
_ATTRIBUTION_REJECTED_TOKENS = {
    "anh",
    "assistant",
    "ban",
    "bo",
    "he thong",
    "ho",
    "huong dan",
    "lenh",
    "prompt",
    "nguoi gui",
    "nguoi",
    "chi",
    "system",
    "toi",
}
_ATTRIBUTION_BOUNDARY_WORDS = {"duoc", "nhan", "rang", "tin", "tu"}
_DOMAIN_RE = re.compile(r"(?<![\w.-])(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>()]*)?", re.IGNORECASE)
_TITLE_STOPWORDS = {
    "please",
    "this",
    "that",
    "the",
    "a",
    "an",
    "i",
    "we",
    "you",
    "he",
    "she",
    "they",
    "ho",
    "toi",
    "nguoi",
    "ban",
    "anh",
    "chi",
    "safe",
}
_PLATFORM_NOUNS = {"form", "forms", "drive", "docs", "sheet", "sheets", "survey", "portal", "platform"}


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
        if prefix == ("bo",):
            if tokens[index].group(0).casefold() not in {"bộ", "bo"}:
                continue
            # "cán bộ" denotes a sender/role, not a ministry publisher.
            if index > 0 and folded[index - 1] == "can":
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

    # Recover a bounded sender/actor immediately before an attribution verb.
    # This is deliberately lexical rather than a free-form NER rule: it only
    # accepts title-cased/acronym subjects, stops at clause boundaries, and
    # rejects pronouns plus common prompt-injection vocabulary.
    for verb in _ATTRIBUTION_VERBS:
        verb_tokens = tuple(verb.split())
        for index in range(len(tokens) - len(verb_tokens) + 1):
            if tuple(folded[index : index + len(verb_tokens)]) != verb_tokens or index == 0:
                continue
            start_index = index - 1
            while start_index > 0 and index - start_index < 6:
                separator = message[tokens[start_index - 1].end() : tokens[start_index].start()]
                if (
                    any(char in separator for char in ".!?;,:\n")
                    or _is_boundary(folded, start_index - 1)
                    or folded[start_index - 1] in _ATTRIBUTION_BOUNDARY_WORDS
                ):
                    break
                start_index -= 1
            candidate_tokens = folded[start_index:index]
            candidate_text = message[tokens[start_index].start() : tokens[index - 1].end()].strip()
            folded_candidate = " ".join(candidate_tokens)
            first = candidate_text[:1]
            title_or_acronym = bool(first and first.isupper()) or candidate_text.isupper()
            if (
                title_or_acronym
                and folded_candidate not in _ATTRIBUTION_REJECTED_TOKENS
                and not any(token in _ATTRIBUTION_REJECTED_TOKENS for token in candidate_tokens)
            ):
                spans.append((tokens[start_index].start(), tokens[index - 1].end()))

    # Open-world proper-name recovery.  The registry improves canonical
    # resolution below, but is deliberately not the admission gate for names
    # explicitly written by the user (for example, an unreviewed company next
    # to a known hosted form provider).
    for index, token in enumerate(tokens):
        value = token.group(0)
        if not value[:1].isupper() or _fold(value) in _TITLE_STOPWORDS:
            continue
        end_index = index + 1
        while end_index < len(tokens) and end_index - index < 5:
            separator = message[tokens[end_index - 1].end() : tokens[end_index].start()]
            next_value = tokens[end_index].group(0)
            if (
                separator.strip()
                or any(char in separator for char in ".!?;,:\n")
                or not (next_value[:1].isupper() or next_value.isupper())
                or _is_boundary(folded, end_index)
            ):
                break
            end_index += 1
        # A lone capital at sentence start is common prose. Admit a proper-name
        # sequence only when the text itself supplies an actor or service cue.
        following = " ".join(folded[end_index : end_index + 2])
        sequence = folded[index:end_index]
        if (sequence and sequence[-1] in _PLATFORM_NOUNS) or any(verb in following for verb in _ATTRIBUTION_VERBS):
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
    # A reviewed alias resolves an identity but cannot truncate a larger,
    # text-grounded mention ("Google" must not erase "Google Form").
    merged = [
        known
        for known in gazetteer_mentions
        if not any(
            item.start <= known.start and known.end <= item.end and (item.start, item.end) != (known.start, known.end)
            for item in rule_mentions
        )
    ]
    merged.extend(
        item
        for item in rule_mentions
        if not any(item.start <= known.start < item.end or known.start <= item.start < known.end for known in merged)
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


def ground_entity_roles(message: str, candidates: list[EntityMentionCandidate]) -> list[GroundedEntityMentionV4]:
    """Classify grounded mentions without making registry or trust claims.

    Roles are intentionally local and conservative.  They preserve the
    message's entities so later registry resolution and discovery can decide
    whether an identity is known, rather than whether it may exist.
    """
    mentions: list[GroundedEntityMentionV4] = []
    for candidate in candidates:
        following = _fold(message[candidate.end : candidate.end + 40])
        words = _fold(candidate.text).split()
        role = GroundedEntityRoleV4.OTHER
        if words and words[-1] in _PLATFORM_NOUNS:
            role = GroundedEntityRoleV4.PLATFORM_PROVIDER
        elif any(verb in following for verb in _ATTRIBUTION_VERBS):
            role = GroundedEntityRoleV4.CLAIMED_ORGANIZATION
        elif (
            words
            and candidate.text[:1].isupper()
            and (tuple(words[:1]) in _ORG_PREFIXES or tuple(words[:2]) in _ORG_PREFIXES)
        ):
            role = GroundedEntityRoleV4.CLAIMED_ORGANIZATION
        mentions.append(
            GroundedEntityMentionV4(
                text=candidate.text,
                start=candidate.start,
                end=candidate.end,
                role=role,
                source=candidate.source,
                registry_name=candidate.canonical,
            )
        )

    # A message often names the publisher first and a hosted service later.
    # Select that publisher only as a compatibility projection; retain every
    # other mention and its role for downstream consumers.
    if not any(item.role is GroundedEntityRoleV4.CLAIMED_ORGANIZATION for item in mentions):
        other_indices = [index for index, item in enumerate(mentions) if item.role is GroundedEntityRoleV4.OTHER]
        if len(other_indices) == 1 and mentions[other_indices[0]].text[:1].isupper():
            index = other_indices[0]
            mentions[index] = mentions[index].model_copy(update={"role": GroundedEntityRoleV4.CLAIMED_ORGANIZATION})

    occupied = {(item.start, item.end) for item in mentions}
    for match in _DOMAIN_RE.finditer(message):
        raw = match.group(0).rstrip(".,;:!?)]")
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        text = (parsed.hostname or "").casefold()
        host_start = match.start() + raw.casefold().find(text) if text else match.start()
        end = host_start + len(text)
        if not text or any(start <= match.start() < stop for start, stop in occupied):
            continue
        mentions.append(
            GroundedEntityMentionV4(
                text=text,
                start=host_start,
                end=end,
                role=GroundedEntityRoleV4.RESOURCE_INTERMEDIARY,
                source="message_url",
            )
        )
    return sorted(mentions, key=lambda item: (item.start, item.end))[:20]


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
    "ground_entity_roles",
    "extract_recovery_phrases",
]
