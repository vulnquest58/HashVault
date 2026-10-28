"""Resolve an ambiguous identification by trying the top candidates.

The identifier can rank candidates but cannot separate formats that share a
shape: ``md5($pass.$salt)`` and ``md5($salt.$pass)`` produce the same regex,
and a bare 32-hex digest could be MD5, MD4, NTLM or LM.  For those inputs the
honest answer is "ambiguous" -- unless we spend a little cracking time.

This module holds the decision logic only.  It never runs a subprocess itself;
the caller supplies ``attempt`` so the selection can be unit-tested without
hashcat, John or the built-in engine.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional, Sequence

TrialAttempt = Callable[[Any, Optional[int]], bool]


@dataclass
class TrialOutcome:
    """Result of one candidate trial."""

    pattern_name: str
    hashcat_mode: Optional[int]
    tool: str
    success: bool
    elapsed_seconds: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DisambiguationResult:
    """Outcome of a trial-disambiguation round."""

    resolved: bool = False
    chosen: Optional[Any] = None
    trials: list[TrialOutcome] = field(default_factory=list)
    budget_exhausted: bool = False

    @property
    def chosen_name(self) -> Optional[str]:
        return getattr(self.chosen, "pattern", self.chosen) and getattr(
            getattr(self.chosen, "pattern", None), "name", None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolved": self.resolved,
            "chosen": self.chosen_name,
            "budget_exhausted": self.budget_exhausted,
            "trials": [trial.to_dict() for trial in self.trials],
        }


def trial_disambiguate(
    candidates: Sequence[Any],
    attempt: TrialAttempt,
    *,
    max_trials: int = 3,
    budget_seconds: Optional[float] = None,
    tool: str = "auto",
) -> DisambiguationResult:
    """Try candidates in rank order until one cracks.

    Parameters
    ----------
    candidates:
        Identifier candidates, best first.  Each needs a ``pattern`` attribute
        with ``name``/``hashcat_mode`` (``Candidate`` from ``core.identifier``).
    attempt:
        ``attempt(candidate, remaining_seconds) -> bool``.  Returning True
        means the candidate cracked the hash, which proves the format.
    max_trials:
        How many candidates may be tried.  Keep this small: every trial is a
        real cracking run.
    budget_seconds:
        Wall-clock cap across all trials.  ``None`` means the caller already
        bounded each attempt individually.
    """
    result = DisambiguationResult()
    started = time.monotonic()

    for index, candidate in enumerate(candidates):
        if index >= max_trials:
            break

        pattern = getattr(candidate, "pattern", candidate)
        remaining: Optional[int] = None
        if budget_seconds is not None:
            left = budget_seconds - (time.monotonic() - started)
            if left <= 0:
                result.budget_exhausted = True
                break
            remaining = max(1, int(left))

        trial_started = time.monotonic()
        error: Optional[str] = None
        try:
            success = bool(attempt(candidate, remaining))
        except Exception as exc:  # a broken engine must not abort the search
            success = False
            error = f"{type(exc).__name__}: {exc}"

        result.trials.append(
            TrialOutcome(
                pattern_name=getattr(pattern, "name", "?"),
                hashcat_mode=getattr(pattern, "hashcat_mode", None),
                tool=tool,
                success=success,
                elapsed_seconds=round(time.monotonic() - trial_started, 4),
                error=error,
            )
        )

        if success:
            result.resolved = True
            result.chosen = candidate
            break

    return result
