"""High-level mutation pipeline shared by the CLI and interactive shell."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session

from hashvault.mutation.context import ContextProfile
from hashvault.mutation.enrichment import collect_local_enrichment
from hashvault.mutation.grammar import generate_candidates
from hashvault.mutation.llm import LLMError, LLMSettings, OllamaSeeder
from hashvault.mutation.rules import hashcat_rule_lines
from hashvault.mutation.seeds import Seed, extract_seeds
from hashvault.mutation.transliteration import expand_language_terms


@dataclass
class MutationResult:
    context: dict[str, Any]
    seeds: list[Seed]
    candidates: list[str]
    rules: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "seeds": [seed.to_dict() for seed in self.seeds],
            "candidates": list(self.candidates),
            "rules": list(self.rules),
            "metadata": dict(self.metadata),
        }


def _expanded_seeds(seeds: Iterable[Seed], language: str) -> list[Seed]:
    expanded: list[Seed] = []
    seen: set[str] = set()
    for seed in seeds:
        for term in expand_language_terms([seed.term], language):
            key = term.casefold()
            if key in seen:
                continue
            seen.add(key)
            expanded.append(Seed(term=term, source=seed.source, weight=seed.weight))
    return expanded


def build_mutation(
    context: Optional[ContextProfile] = None,
    *,
    extra_terms: Iterable[str] = (),
    session: Optional[Session] = None,
    config: Any = None,
    use_history: bool = False,
    enrich_paths: Iterable[str | Path] = (),
    use_llm: bool = False,
    limit: Optional[int] = None,
    language: Optional[str] = None,
    years: Iterable[int | str] = (),
    include_years: Optional[bool] = None,
) -> MutationResult:
    profile = context or ContextProfile()
    mutation_config = getattr(config, "mutation", None)
    default_limit = int(getattr(mutation_config, "max_candidates", 500))
    candidate_limit = max(0, int(limit if limit is not None else default_limit))
    language = language or str(getattr(mutation_config, "arabic_language", "auto"))
    if include_years is None:
        include_years = bool(getattr(mutation_config, "include_years", True))

    warnings: list[str] = []
    enrichment_config = getattr(config, "enrichment", None)
    configured_paths = []
    if getattr(enrichment_config, "enabled", False):
        configured_paths = list(getattr(enrichment_config, "wordlist_paths", []) or [])
    enrichment_paths: list[str | Path] = []
    seen_paths: set[str] = set()
    for path in [*configured_paths, *enrich_paths]:
        key = str(Path(path).resolve())
        if key in seen_paths:
            continue
        seen_paths.add(key)
        enrichment_paths.append(path)
    enrichment = collect_local_enrichment(
        session,
        use_history=use_history,
        wordlist_paths=enrichment_paths,
        history_limit=int(getattr(mutation_config, "max_history_seeds", 500)),
        wordlist_limit=int(getattr(mutation_config, "max_enrichment_seeds", 500)),
    )
    warnings.extend(enrichment.warnings)

    seeds = extract_seeds(
        profile,
        extra_terms=extra_terms,
        enrichment_terms=enrichment.terms,
    )

    llm_metadata: dict[str, Any] = {"requested": bool(use_llm)}
    if use_llm:
        settings = LLMSettings.from_config(config) if config is not None else LLMSettings()
        if not settings.enabled:
            warnings.append("LLM requested but disabled in configuration.")
            llm_metadata.update({"enabled": False, "candidates": 0})
        else:
            try:
                suggestions = OllamaSeeder(settings).suggest(profile, seeds)
                seeds.extend(
                    Seed(term=term, source="llm", weight=0.7) for term in suggestions
                )
                llm_metadata.update(
                    {"enabled": True, "model": settings.model, "candidates": len(suggestions)}
                )
            except LLMError as exc:
                warnings.append(str(exc))
                llm_metadata.update({"enabled": True, "candidates": 0, "error": str(exc)})

    seeds = _expanded_seeds(seeds, language)
    year_values = list(years)
    year_values.extend(getattr(mutation_config, "years", []) or [])
    year_values.extend(profile.dates)
    candidates = generate_candidates(
        seeds,
        limit=candidate_limit,
        years=year_values,
        include_years=include_years,
    )
    rules = hashcat_rule_lines(year_values)

    metadata = {
        "language": language,
        "limit": candidate_limit,
        "include_years": include_years,
        "seed_count": len(seeds),
        "candidate_count": len(candidates),
        "enrichment_sources": enrichment.sources,
        "llm": llm_metadata,
        "warnings": warnings,
    }
    return MutationResult(
        context=profile.to_dict(),
        seeds=seeds,
        candidates=candidates,
        rules=rules,
        metadata=metadata,
    )
