from __future__ import annotations

import ipaddress
from pathlib import Path

PSL_VERSION = "2026-08-06"
_DEFAULT_PSL = Path(__file__).with_name("public_suffix_list.dat")


def normalize_hostname(value: str) -> str:
    candidate = value.strip().casefold().rstrip(".")
    if not candidate or "://" in candidate or "/" in candidate or "@" in candidate:
        raise ValueError("domain must be a hostname")
    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain is not valid IDNA") from exc
    if len(normalized) > 253:
        raise ValueError("domain must not exceed 253 characters")
    labels = normalized.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("domain is invalid")
    if any(not all(character.isalnum() or character == "-" for character in label) for label in labels):
        raise ValueError("domain is invalid")
    return normalized


class PublicSuffixList:
    """Small PSL parser backed by a versioned, replaceable data file."""

    def __init__(self, path: str | Path = _DEFAULT_PSL) -> None:
        rules = {
            line.strip().casefold()
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("//")
        }
        self._exceptions = {rule[1:] for rule in rules if rule.startswith("!")}
        self._wildcards = {rule[2:] for rule in rules if rule.startswith("*.")}
        self._exact = {rule for rule in rules if not rule.startswith(("!", "*."))}

    def registrable_domain(self, value: str) -> str | None:
        candidate = value.strip().rstrip(".")
        try:
            ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError:
            pass
        else:
            return None
        domain = normalize_hostname(value)
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            return None

        labels = domain.split(".")
        exception_length = 0
        match_length = 1  # prevailing '*' rule from the PSL algorithm
        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            if candidate in self._exceptions:
                exception_length = len(labels) - index
                break
            if candidate in self._exact:
                match_length = max(match_length, len(labels) - index)
            if index + 1 < len(labels) and ".".join(labels[index + 1 :]) in self._wildcards:
                match_length = max(match_length, len(labels) - index)
        suffix_length = exception_length - 1 if exception_length else match_length
        if len(labels) <= suffix_length:
            return None
        return ".".join(labels[-(suffix_length + 1) :])


DEFAULT_PUBLIC_SUFFIX_LIST = PublicSuffixList()
