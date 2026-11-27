"""Context-aware seed extraction and bounded password mutation."""

from hashvault.mutation.context import ContextProfile
from hashvault.mutation.grammar import generate_candidates
from hashvault.mutation.seeds import Seed, extract_seeds
from hashvault.mutation.service import MutationResult, build_mutation
from hashvault.mutation.transliteration import expand_language_terms, language_variants

__all__ = [
    "ContextProfile",
    "MutationResult",
    "Seed",
    "build_mutation",
    "expand_language_terms",
    "extract_seeds",
    "generate_candidates",
    "language_variants",
]
