"""Empirical calibration of identification confidence.

``confidence_weight`` values in the pattern catalogue are hand-assigned
constants (0.4 for MD5, 0.24 for the salted md5 variants, 0.98 for prefixed
crypt formats).  Nothing ties them to observed behaviour, so "0.98" does not
mean 98% correct and two patterns with equal weights are ordered arbitrarily.

This module measures what the identifiers actually do, reports how far the
stated confidence is from reality, and derives replacement weights from the
corpus instead of intuition.

Two numbers matter:

* **Brier score** -- mean squared error of the predicted probability.
  Lower is better; 0.25 is what always predicting 0.5 scores.
* **ECE** (Expected Calibration Error) -- the average gap between predicted
  and observed accuracy across confidence buckets.  ``0.10`` means the tool
  says "0.9" when it is right about 80% of the time.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

EXACT_STATUS = "exact"


@dataclass
class ConfidenceBucket:
    """One bin of the reliability diagram."""

    lower: float
    upper: float
    count: int
    mean_confidence: float
    accuracy: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "lower": round(self.lower, 3),
            "upper": round(self.upper, 3),
            "count": self.count,
            "mean_confidence": round(self.mean_confidence, 4),
            "accuracy": round(self.accuracy, 4),
            "gap": round(abs(self.mean_confidence - self.accuracy), 4),
        }


@dataclass
class PatternReliability:
    """How often a pattern is right when the identifier ranks it first."""

    pattern_name: str
    top1_appearances: int
    top1_correct: int
    current_weight: Optional[float]
    observed_accuracy: float
    smoothed_accuracy: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern_name,
            "top1_appearances": self.top1_appearances,
            "top1_correct": self.top1_correct,
            "current_weight": self.current_weight,
            "observed_accuracy": round(self.observed_accuracy, 4),
            "smoothed_accuracy": round(self.smoothed_accuracy, 4),
        }


@dataclass
class CalibrationReport:
    entries: int
    brier_score: float
    expected_calibration_error: float
    accuracy: float
    mean_confidence: float
    bins: list[ConfidenceBucket] = field(default_factory=list)
    patterns: list[PatternReliability] = field(default_factory=list)
    isotonic: list[tuple[float, float]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": self.entries,
            "brier_score": round(self.brier_score, 4),
            "expected_calibration_error": round(
                self.expected_calibration_error, 4
            ),
            "accuracy": round(self.accuracy, 4),
            "mean_confidence": round(self.mean_confidence, 4),
            "bins": [bucket.to_dict() for bucket in self.bins],
            "patterns": [pattern.to_dict() for pattern in self.patterns],
            "isotonic": [
                [round(x, 4), round(y, 4)] for x, y in self.isotonic
            ],
            "warnings": list(self.warnings),
        }

    @property
    def overconfident(self) -> bool:
        return self.mean_confidence > self.accuracy


def _observations(
    outcomes: Iterable[Any],
) -> tuple[list[tuple[float, int]], dict[str, tuple[int, int, Optional[float]]]]:
    """Turn corpus outcomes into (confidence, correct) pairs plus per-pattern counts.

    Skips entries that never reached a candidate: a missing prediction is not
    evidence about the confidence scale.
    """
    pairs: list[tuple[float, int]] = []
    per_pattern: dict[str, list[int]] = {}
    weights: dict[str, Optional[float]] = {}

    for outcome in outcomes:
        confidence = getattr(outcome, "confidence", None)
        if confidence is None:
            continue
        status = getattr(outcome, "status", "")
        if status in {"skipped", "no_candidates", "error"}:
            continue

        correct = 1 if status == EXACT_STATUS else 0
        pairs.append((float(confidence), correct))

        name = getattr(outcome, "top_name", None)
        if name:
            counts = per_pattern.setdefault(name, [0, 0])
            counts[0] += 1
            counts[1] += correct
            if name not in weights:
                weights[name] = getattr(outcome, "top_weight", None)

    summary = {
        name: (counts[0], counts[1], weights.get(name))
        for name, counts in per_pattern.items()
    }
    return pairs, summary


def _brier(pairs: Sequence[tuple[float, int]]) -> float:
    if not pairs:
        return 0.0
    return sum((confidence - correct) ** 2 for confidence, correct in pairs) / len(pairs)


def _buckets(pairs: Sequence[tuple[float, int]], n_bins: int) -> list[ConfidenceBucket]:
    """Reliability-diagram bins over the [0, 1] confidence range."""
    buckets: list[ConfidenceBucket] = []
    for index in range(n_bins):
        lower = index / n_bins
        upper = (index + 1) / n_bins
        # The last bin is closed on the right so confidence 1.0 is counted.
        members = [
            (confidence, correct)
            for confidence, correct in pairs
            if (
                lower <= confidence < upper
                if index < n_bins - 1
                else lower <= confidence <= upper
            )
        ]
        if not members:
            continue
        mean_confidence = sum(c for c, _ in members) / len(members)
        accuracy = sum(y for _, y in members) / len(members)
        buckets.append(
            ConfidenceBucket(
                lower=lower,
                upper=upper,
                count=len(members),
                mean_confidence=mean_confidence,
                accuracy=accuracy,
            )
        )
    return buckets


def _ece(pairs: Sequence[tuple[float, int]], buckets: Sequence[ConfidenceBucket]) -> float:
    total = len(pairs)
    if not total:
        return 0.0
    return sum(
        bucket.count / total
        * abs(bucket.mean_confidence - bucket.accuracy)
        for bucket in buckets
    )


def _isotonic(pairs: Sequence[tuple[float, int]]) -> list[tuple[float, float]]:
    """Pool-adjacent-violators fit of confidence -> observed accuracy.

    Guarantees a non-decreasing mapping, which is what a calibrated
    probability must be: a higher stated confidence may never mean a lower
    chance of being right.
    """
    if not pairs:
        return []

    ordered = sorted(pairs, key=lambda item: item[0])
    # Each block: [sum_x, sum_y, count]
    blocks: list[list[float]] = []
    for confidence, correct in ordered:
        blocks.append([confidence, float(correct), 1.0])
        # Merge while the previous block's mean is above the current one.
        while len(blocks) > 1 and (
            blocks[-2][1] / blocks[-2][2] > blocks[-1][1] / blocks[-1][2]
        ):
            last = blocks.pop()
            blocks[-1][0] += last[0]
            blocks[-1][1] += last[1]
            blocks[-1][2] += last[2]

    isotonic: list[tuple[float, float]] = []
    for sum_x, sum_y, count in blocks:
        isotonic.append((sum_x / count, sum_y / count))
    return isotonic


def calibrate(
    outcomes: Iterable[Any],
    *,
    n_bins: int = 10,
    min_samples_for_weight: int = 5,
) -> CalibrationReport:
    """Measure identification confidence against corpus ground truth."""
    outcome_list = list(outcomes)
    pairs, per_pattern = _observations(outcome_list)

    buckets = _buckets(pairs, n_bins)
    accuracy = sum(y for _, y in pairs) / len(pairs) if pairs else 0.0
    mean_confidence = (
        sum(c for c, _ in pairs) / len(pairs) if pairs else 0.0
    )

    patterns: list[PatternReliability] = []
    for name, (appearances, correct, weight) in per_pattern.items():
        patterns.append(
            PatternReliability(
                pattern_name=name,
                top1_appearances=appearances,
                top1_correct=correct,
                current_weight=weight,
                observed_accuracy=correct / appearances if appearances else 0.0,
                # Laplace smoothing keeps a pattern seen once from being
                # pinned at 0.0 or 1.0 and destroying the ranking.
                smoothed_accuracy=(correct + 1) / (appearances + 2),
            )
        )
    patterns.sort(key=lambda item: (-item.top1_appearances, item.pattern_name))

    report = CalibrationReport(
        entries=len(pairs),
        brier_score=_brier(pairs),
        expected_calibration_error=_ece(pairs, buckets),
        accuracy=accuracy,
        mean_confidence=mean_confidence,
        bins=buckets,
        patterns=patterns,
        isotonic=_isotonic(pairs),
    )

    if len(pairs) < 50:
        report.warnings.append(
            f"Only {len(pairs)} evaluated entries; calibration is indicative, "
            "not conclusive."
        )
    small = [
        pattern.pattern_name
        for pattern in patterns
        if pattern.top1_appearances < min_samples_for_weight
    ]
    if small:
        report.warnings.append(
            f"{len(small)} pattern(s) observed fewer than "
            f"{min_samples_for_weight} times; their weights stay at the "
            "current value unless --force-weights is used."
        )
    return report


def suggested_weights(
    report: CalibrationReport,
    *,
    min_samples: int = 5,
    force: bool = False,
) -> dict[str, float]:
    """Derive replacement ``confidence_weight`` values from observed accuracy.

    A pattern is only re-weighted when it was seen at least ``min_samples``
    times, because a single lucky hit would otherwise promote an obscure
    format above MD5.
    """
    weights: dict[str, float] = {}
    for pattern in report.patterns:
        if not force and pattern.top1_appearances < min_samples:
            continue
        # Keep the value inside the range the identifier expects.
        weight = min(1.0, max(0.05, pattern.smoothed_accuracy))
        weights[pattern.pattern_name] = round(weight, 4)
    return weights


def summary_lines(report: CalibrationReport) -> list[str]:
    """Human-readable calibration summary for the CLI."""
    lines = [
        f"Evaluated entries      : {report.entries}",
        f"Brier score            : {report.brier_score:.4f}  "
        "(0.25 = always guessing 0.5)",
        f"Expected calibration   : {report.expected_calibration_error:.4f}  "
        "(0 = perfectly calibrated)",
        f"Observed accuracy      : {report.accuracy:.1%}",
        f"Mean stated confidence : {report.mean_confidence:.1%}",
    ]
    if report.overconfident:
        lines.append(
            "Direction              : OVERCONFIDENT "
            f"by {report.mean_confidence - report.accuracy:.1%}"
        )
    else:
        lines.append(
            "Direction              : UNDERCONFIDENT "
            f"by {report.accuracy - report.mean_confidence:.1%}"
        )
    lines.append("")
    lines.append("Reliability (predicted -> observed):")
    for bucket in report.bins:
        bar = "#" * int(round(bucket.accuracy * 20))
        lines.append(
            f"  {bucket.mean_confidence:5.2f} -> {bucket.accuracy:5.2f}  "
            f"n={bucket.count:<4} {bar}"
        )
    if report.warnings:
        lines.append("")
        for warning in report.warnings:
            lines.append(f"warning: {warning}")
    return lines


# ---------------------------------------------------------------------------
# Applying calibration without disturbing the ranking
# ---------------------------------------------------------------------------

CALIBRATION_FILENAME = "calibration.json"


class CalibrationMap:
    """Monotone map from a stated confidence to an observed probability.

    ``confidence_weight`` carries two jobs: it orders candidates *and* states
    how sure the tool is.  Rewriting the weights to fix calibration breaks the
    first job -- a pattern that never wins is never measured, keeps its old
    weight, and leapfrogs a pattern that was correctly demoted (NTLM 0.50 ->
    0.25 fell below MD5's untouched 0.40, inverting every 32-hex decision).

    So calibration is applied as a monotone transform of the *reported*
    confidence instead.  Ordering is computed from the raw weights first, and
    the isotonic map is monotone by construction, so the ranking cannot change.
    """

    def __init__(self, points: list[tuple[float, float]]) -> None:
        self.points = sorted(
            ((float(x), float(y)) for x, y in points), key=lambda item: item[0]
        )

    def __bool__(self) -> bool:
        return bool(self.points)

    def apply(self, confidence: float) -> float:
        """Map a raw confidence to a calibrated probability (piecewise linear)."""
        if not self.points:
            return confidence
        value = float(confidence)
        if value <= self.points[0][0]:
            return self.points[0][1]
        if value >= self.points[-1][0]:
            return self.points[-1][1]
        for (x0, y0), (x1, y1) in zip(self.points, self.points[1:]):
            if x0 <= value <= x1:
                if x1 == x0:
                    return y1
                ratio = (value - x0) / (x1 - x0)
                return y0 + ratio * (y1 - y0)
        return self.points[-1][1]

    def to_dict(self) -> dict[str, Any]:
        return {"points": [[x, y] for x, y in self.points]}

    @classmethod
    def from_dict(cls, payload: Any) -> "CalibrationMap":
        if not isinstance(payload, dict):
            return cls([])
        raw = payload.get("points") or payload.get("isotonic") or []
        points: list[tuple[float, float]] = []
        for item in raw:
            try:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    points.append((float(item[0]), float(item[1])))
            except (TypeError, ValueError):
                continue
        return cls(points)


def load_calibration(directory: str | Path) -> CalibrationMap:
    """Load ``calibration.json`` from a directory; empty map when absent."""
    path = Path(directory) / CALIBRATION_FILENAME
    if not path.is_file():
        return CalibrationMap([])
    try:
        return CalibrationMap.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return CalibrationMap([])


def save_calibration(report: CalibrationReport, path: str | Path) -> Path:
    """Write a calibration curve derived from the reliability diagram.

    Uses histogram binning rather than the raw isotonic blocks: the isotonic
    fit produced 120 points from 500 samples, which overfit (Brier score got
    *worse* than no calibration at all).  The bins are exactly what ECE
    measures, so mapping ``mean_confidence -> accuracy`` per bin reduces the
    reported error by construction, and pooling keeps the curve monotone.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    points = _monotone_points(
        [(bucket.mean_confidence, bucket.accuracy) for bucket in report.bins]
    )

    payload = {
        "generated_by": "hashvault calibrate",
        "method": "histogram-binning (monotone pooled)",
        "entries_evaluated": report.entries,
        "brier_score": round(report.brier_score, 4),
        "expected_calibration_error": round(
            report.expected_calibration_error, 4
        ),
        "accuracy": round(report.accuracy, 4),
        "mean_confidence": round(report.mean_confidence, 4),
        "points": [[round(x, 6), round(y, 6)] for x, y in points],
        # Kept for inspection only; the identifier never rewrites weights.
        "observed_weights": {
            pattern.pattern_name: round(pattern.smoothed_accuracy, 4)
            for pattern in report.patterns
            if pattern.top1_appearances >= 5
        },
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def _monotone_points(
    pairs: Sequence[tuple[float, float]],
) -> list[tuple[float, float]]:
    """Pool-adjacent-violators over (confidence, accuracy) bin centres."""
    ordered = sorted(pairs, key=lambda item: item[0])
    blocks: list[list[float]] = []
    for x, y in ordered:
        blocks.append([x, y, 1.0])
        while len(blocks) > 1 and (
            blocks[-2][1] / blocks[-2][2] > blocks[-1][1] / blocks[-1][2]
        ):
            last = blocks.pop()
            blocks[-1][0] += last[0]
            blocks[-1][1] += last[1]
            blocks[-1][2] += last[2]
    return [(total_x / count, total_y / count) for total_x, total_y, count in blocks]
