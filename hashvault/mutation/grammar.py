"""Bounded, deterministic mutation grammar for targeted guess lists."""

from __future__ import annotations

import re
from typing import Iterable, Sequence

from hashvault.mutation.seeds import Seed


_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
_DIGITS = ("1", "12", "123", "1234", "0", "01", "007")
_SYMBOLS = ("!", "@", "#", "$", "!!", "!@#")


def case_variants(term: str) -> list[str]:
    values = [
        term,
        term.lower(),
        term.upper(),
        term.capitalize(),
        term.translate(_LEET),
    ]
    if term.islower():
        values.append(term.title())
    return _unique(values)


def year_variants(years: Iterable[int | str]) -> list[str]:
    result: list[str] = []
    for year in years:
        digits = re.sub(r"\D", "", str(year))
        if len(digits) >= 4:
            result.append(digits[-4:])
            result.append(digits[-2:])
    return _unique(result)


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        term = str(value).strip()
        if not term or term in seen:
            continue
        seen.add(term)
        result.append(term)
    return result


def generate_candidates(
    seeds: Sequence[Seed],
    *,
    limit: int = 500,
    years: Iterable[int | str] = (),
    include_years: bool = True,
    include_combinations: bool = True,
) -> list[str]:
    if limit <= 0:
        return []
    suffixes = list(_DIGITS) + list(_SYMBOLS)
    if include_years:
        suffixes.extend(year_variants(years))

    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> bool:
        term = value.strip()
        if not term or len(term) > 96 or term in seen:
            return False
        seen.add(term)
        candidates.append(term)
        return len(candidates) >= limit

    per_seed: list[list[str]] = []
    for seed in seeds:
        values: list[str] = []
        for base in case_variants(seed.term):
            values.append(base)
            values.extend(base + suffix for suffix in suffixes)
            if len(base) > 2:
                values.extend(prefix + base for prefix in ("!", "@", "#"))
        per_seed.append(values[:limit])

    depth = max((len(values) for values in per_seed), default=0)
    for index in range(depth):
        for values in per_seed:
            if index >= len(values):
                continue
            if add(values[index]):
                return candidates[:limit]

    if include_combinations and len(seeds) > 1:
        primary = [seed.term for seed in seeds[:8]]
        secondary = [seed.term for seed in seeds[:8]]
        for left in primary:
            for right in secondary:
                if left.casefold() == right.casefold():
                    continue
                for separator in ("", "_", "-", ".", "@"):
                    if add(f"{left}{separator}{right}"):
                        return candidates[:limit]
                    if include_years:
                        for year in year_variants(years):
                            if add(f"{left}{separator}{right}{year}"):
                                return candidates[:limit]

    return candidates[:limit]
