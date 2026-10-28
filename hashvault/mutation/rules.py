"""Generate conservative Hashcat rule lines from context metadata."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from hashvault.mutation.grammar import year_variants


_BASE_RULES = (
    ":",
    "c",
    "C",
    "u",
    "l",
    "t",
    "r",
    "sa@",
    "se3",
    "si1",
    "so0",
    "ss$",
    "$1",
    "$12",
    "$123",
    "$1234",
    "$!",
    "$@",
    "$#",
    "^1",
    "^!",
    "c$1",
    "c$!",
    "u$1",
    "l$1",
)


def hashcat_rule_lines(
    years: Iterable[int | str] = (),
    *,
    extra_rules: Iterable[str] = (),
) -> list[str]:
    rules = list(_BASE_RULES)
    for year in year_variants(years):
        rules.append("".join(f"${char}" for char in year))
    rules.extend(rule for rule in extra_rules if rule.strip())
    seen: set[str] = set()
    result: list[str] = []
    for rule in rules:
        line = rule.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        result.append(line)
    return result


def write_rule_file(path: str | Path, rules: Iterable[str]) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [line for line in rules if line.strip()]
    target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)
