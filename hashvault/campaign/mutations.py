"""Evidence-conditioned candidate synthesis for credential corpora."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime

_LEET_MAP = {
    "a": ("a", "@", "4"),
    "b": ("b", "8"),
    "e": ("e", "3"),
    "g": ("g", "9"),
    "i": ("i", "1", "!"),
    "l": ("l", "1"),
    "o": ("o", "0"),
    "s": ("s", "5", "$"),
    "t": ("t", "7"),
    "z": ("z", "2"),
}

_COMMON_SUFFIXES = (
    "",
    "!",
    "!!",
    "!!!",
    "@",
    "#",
    "$",
    "?",
    "1",
    "01",
    "12",
    "123",
    "1234",
    "12345",
    "123456",
    "007",
    "69",
    "99",
    "2024",
    "2025",
    "2026",
    "2027",
    "2024!",
    "2025!",
    "2026!",
    "2027!",
    "!2024",
    "!2025",
    "!2026",
    "!2027",
    "@2024",
    "@2025",
    "@2026",
    "#2024",
    "#2025",
    "#2026",
    "2024@",
    "2025@",
    "2026@",
)

_COMMON_PREFIXES = ("", "!", "@", "#", "1", "123")

_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"
)


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def case_variants(value: str) -> list[str]:
    return _dedupe(
        [
            value,
            value.lower(),
            value.upper(),
            value.capitalize(),
            value.title(),
            value.swapcase(),
        ]
    )


def leet_variants(value: str, *, max_variants: int = 48) -> list[str]:
    results = [value]
    frontier = [value]
    for index, character in enumerate(value.lower()):
        replacements = _LEET_MAP.get(character)
        if not replacements or len(replacements) == 1:
            continue
        next_frontier: list[str] = []
        for base in frontier:
            for replacement in replacements[1:]:
                candidate = base[:index] + replacement + base[index + 1 :]
                if candidate not in results:
                    results.append(candidate)
                    next_frontier.append(candidate)
                if len(results) >= max_variants:
                    return results
        frontier.extend(next_frontier)
        if len(frontier) > max_variants:
            frontier = frontier[:max_variants]
    return results


def _years() -> list[str]:
    current = datetime.now().year
    start = max(1980, current - 30)
    return [str(year) for year in range(start, current + 6)]


def _suffixes() -> list[str]:
    return _dedupe([*_COMMON_SUFFIXES, *_years(), *[f"{year}!" for year in _years()]])


def _context_tokens(usernames: Iterable[str], sources: Iterable[str]) -> list[str]:
    tokens: list[str] = []
    for username in usernames:
        if not username:
            continue
        local = username.split("@", 1)[0]
        tokens.extend([username, local, local.capitalize(), local.upper()])
        tokens.extend([local.split(".", 1)[0], local.split("_", 1)[0]])
    for source in sources:
        if not source:
            continue
        for match in _DOMAIN_RE.findall(source):
            label = match.split(".", 1)[0]
            tokens.extend([label, label.capitalize(), label.upper(), match])
    return _dedupe(token for token in tokens if len(token) >= 2)


def _decorate(base: str) -> list[str]:
    variants: list[str] = []
    for prefix in _COMMON_PREFIXES:
        for suffix in _suffixes():
            variants.append(f"{prefix}{base}{suffix}")
    return variants


def generate_candidates(
    known_plaintexts: Iterable[str],
    *,
    usernames: Iterable[str] = (),
    sources: Iterable[str] = (),
    limit: int = 50_000,
) -> list[str]:
    """Build a deterministic, evidence-conditioned candidate stream."""

    known = _dedupe(value for value in known_plaintexts if value)
    context = _context_tokens(usernames, sources)
    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if not value or value in seen or len(candidates) >= limit:
            return
        seen.add(value)
        candidates.append(value)

    for value in known:
        add(value)
        for variant in case_variants(value):
            add(variant)
        for variant in leet_variants(value):
            add(variant)

    for base in _dedupe([*known, *context]):
        for variant in case_variants(base):
            for decorated in _decorate(variant):
                add(decorated)
                if len(candidates) >= limit:
                    return candidates

    for left in known:
        for right in known:
            if left == right:
                continue
            add(f"{left}{right}")
            add(f"{left}{right.capitalize()}")
            add(f"{left}{right}{datetime.now().year}")
            if len(candidates) >= limit:
                return candidates

    for token in context:
        for year in _years():
            add(f"{token}{year}")
            add(f"{token}{year}!")
            add(f"{token.capitalize()}{year}")
            add(f"{token.capitalize()}{year}!")
            if len(candidates) >= limit:
                return candidates

    return candidates
