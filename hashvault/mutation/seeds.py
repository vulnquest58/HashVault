"""Deterministic seed extraction from context, history, and local wordlists."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from hashvault.models.orm import CrackedHash
from hashvault.mutation.context import ContextProfile, unique_terms


@dataclass(frozen=True)
class Seed:
    term: str
    source: str
    weight: float = 1.0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def extract_seeds(
    context: Optional[ContextProfile] = None,
    *,
    extra_terms: Iterable[str] = (),
    history_terms: Iterable[str] = (),
    enrichment_terms: Iterable[str] = (),
) -> list[Seed]:
    seeds: list[Seed] = []

    def add(values: Iterable[str], source: str, weight: float) -> None:
        seen = {seed.term.casefold() for seed in seeds}
        for value in unique_terms(values):
            key = value.casefold()
            if key in seen or len(value) > 80:
                continue
            seen.add(key)
            seeds.append(Seed(term=value, source=source, weight=weight))

    if context is not None:
        add(context.seed_terms(), "context", 1.0)
    add(extra_terms, "manual", 1.0)
    add(enrichment_terms, "enrichment", 0.8)
    add(history_terms, "history", 0.6)
    return seeds


def history_seeds(session: Session, limit: int = 500) -> list[str]:
    if limit <= 0:
        return []
    rows = (
        session.query(CrackedHash.plaintext)
        .filter(
            CrackedHash.plaintext.isnot(None),
            func.length(CrackedHash.plaintext) > 0,
            func.length(CrackedHash.plaintext) <= 80,
        )
        .order_by(CrackedHash.cracked_at.desc())
        .limit(limit * 4)
        .all()
    )
    return unique_terms(row[0] for row in rows if row and row[0])[:limit]


def load_wordlist_seeds(paths: Iterable[str | Path], limit: int = 500) -> list[str]:
    terms: list[str] = []
    for path in paths:
        candidate = Path(path)
        if not candidate.exists() or not candidate.is_file():
            continue
        try:
            with candidate.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    term = line.rstrip("\r\n")
                    if not term or len(term) > 80:
                        continue
                    terms.append(term)
                    if len(terms) >= limit:
                        return unique_terms(terms)[:limit]
        except OSError:
            continue
    return unique_terms(terms)[:limit]
