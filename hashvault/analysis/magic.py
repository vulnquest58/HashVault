"""
"Magic" envelope detector — CyberChef's Magic feature for HashVault.

Given a blob of (possibly) encoded text, ranks every registered Operation by a
heuristic confidence score and returns the most promising decoders, optionally
filtered by category.

The recipe engine (recipe.py) consumes this ranking to peel layers recursively.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from hashvault.analysis.operations import OPERATIONS, OPERATIONS_BY_CATEGORY, Operation


@dataclass
class OperationCandidate:
    """An Operation paired with its confidence score for a given input."""
    operation: Operation
    score: float


def detect(
    text: str,
    *,
    category: Optional[str] = None,
    min_score: float = 0.05,
) -> List[OperationCandidate]:
    """
    Return all operations that plausibly apply to ``text``, sorted by
    confidence (highest first).

    Parameters
    ----------
    text:
        The text to score.
    category:
        Optional CyberChef category filter (e.g. 'Data format', 'Compression').
        When None all categories are considered.
    min_score:
        Minimum score threshold; operations scoring below this are dropped.
    """
    candidates: List[OperationCandidate] = []
    if not text:
        return candidates

    ops = OPERATIONS_BY_CATEGORY.get(category, list(OPERATIONS)) if category else OPERATIONS

    for op in ops:
        try:
            score = float(op.score(text))
        except Exception:
            score = 0.0
        if score >= min_score:
            candidates.append(OperationCandidate(operation=op, score=score))

    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates


def best_operation(text: str, *, category: Optional[str] = None) -> Optional[OperationCandidate]:
    """Return the single best-scoring operation for ``text``, or None."""
    candidates = detect(text, category=category)
    return candidates[0] if candidates else None


def describe_text(text: str) -> str:
    """
    Human-readable summary of what the Magic detector thinks the text is.
    Used for CLI output and test diagnostics.
    """
    top = detect(text)
    if not top:
        return "Unknown encoding"
    best = top[0]
    return (
        f"{best.operation.name} ({best.operation.category}) "
        f"— confidence {best.score:.0%}"
    )
