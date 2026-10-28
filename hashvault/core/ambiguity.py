"""Confidence-margin and ambiguity diagnostics for identification results."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional


@dataclass
class AmbiguityReport:
    resolved: bool
    method: str
    candidate_count: int
    top_name: Optional[str]
    top_confidence: Optional[float]
    second_name: Optional[str]
    second_confidence: Optional[float]
    margin: Optional[float]
    entropy: float
    requires_confirmation: bool
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _candidate_name(candidate: Any) -> Optional[str]:
    pattern = getattr(candidate, "pattern", None)
    return getattr(pattern, "name", None)


def _confidence(candidate: Any) -> float:
    try:
        return float(getattr(candidate, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def normalized_entropy(confidences: Iterable[float]) -> float:
    values = [max(0.0, float(value)) for value in confidences]
    total = sum(values)
    if total <= 0.0 or len(values) <= 1:
        return 0.0
    probabilities = [value / total for value in values if value > 0.0]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    maximum = math.log2(len(probabilities))
    return entropy / maximum if maximum else 0.0


def analyze_ambiguity(
    identification: Any,
    *,
    threshold: float = 0.75,
    margin_threshold: float = 0.2,
    top_k: int = 8,
) -> AmbiguityReport:
    candidates = list(getattr(identification, "candidates", []) or [])[:top_k]
    confidences = [_confidence(candidate) for candidate in candidates]
    top = candidates[0] if candidates else None
    second = candidates[1] if len(candidates) > 1 else None
    top_conf = confidences[0] if confidences else None
    second_conf = confidences[1] if len(confidences) > 1 else None
    margin = (
        max(0.0, float(top_conf) - float(second_conf))
        if top_conf is not None and second_conf is not None
        else None
    )
    resolved = bool(getattr(identification, "resolved", False))
    requires_confirmation = bool(candidates) and (
        not resolved
        or (margin is not None and margin < margin_threshold)
        or (top_conf is not None and top_conf < threshold)
    )

    recommendations: list[str] = []
    if len(candidates) > 1 and (margin or 0.0) < margin_threshold:
        recommendations.append("Provide --pattern or --hint to disambiguate.")
    if top is not None:
        recommendations.append(f"Try the top candidate with --pattern '{_candidate_name(top)}'.")
    if not resolved:
        recommendations.append("Use --auto only after reviewing candidate modes.")
    if len(candidates) >= 4 and normalized_entropy(confidences) > 0.8:
        recommendations.append("Treat ranking as low-information and prefer trial cracking.")

    return AmbiguityReport(
        resolved=resolved,
        method=str(getattr(identification, "method", "ambiguous")),
        candidate_count=len(candidates),
        top_name=_candidate_name(top) if top is not None else None,
        top_confidence=round(float(top_conf), 4) if top_conf is not None else None,
        second_name=_candidate_name(second) if second is not None else None,
        second_confidence=round(float(second_conf), 4) if second_conf is not None else None,
        margin=round(margin, 4) if margin is not None else None,
        entropy=round(normalized_entropy(confidences), 4),
        requires_confirmation=requires_confirmation,
        recommendations=recommendations,
    )


def ambiguity_payload(identification: Any, **kwargs: Any) -> dict[str, Any]:
    return analyze_ambiguity(identification, **kwargs).to_dict()
