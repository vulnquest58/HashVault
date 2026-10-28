"""Local-only enrichment sources for mutation seed generation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from hashvault.mutation.seeds import history_seeds, load_wordlist_seeds


@dataclass
class EnrichmentResult:
    terms: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def collect_local_enrichment(
    session: Optional[Session],
    *,
    use_history: bool = False,
    wordlist_paths: Iterable[str | Path] = (),
    history_limit: int = 500,
    wordlist_limit: int = 500,
) -> EnrichmentResult:
    terms: list[str] = []
    sources: list[str] = []
    warnings: list[str] = []

    if use_history:
        if session is None:
            warnings.append("History enrichment requested without a database session.")
        else:
            terms.extend(history_seeds(session, history_limit))
            sources.append("cracked-history")

    for path in wordlist_paths:
        candidate = Path(path)
        if not candidate.exists():
            warnings.append(f"Enrichment wordlist not found: {candidate}")
            continue
        terms.extend(load_wordlist_seeds([candidate], wordlist_limit))
        sources.append(str(candidate))

    seen: set[str] = set()
    unique: list[str] = []
    for term in terms:
        key = term.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(term)
    return EnrichmentResult(
        terms=unique[: max(history_limit, wordlist_limit)],
        sources=sources,
        warnings=warnings,
    )
