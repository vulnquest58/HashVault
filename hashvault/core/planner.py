"""Estimate whether a cracking job will finish inside an audit window.

HashVault already knows the hash work factor (``core.parameters``) and can
measure the device (``utils.system.detect_gpu``), but nothing joined them, so
"crack this" gave no idea whether it meant ten seconds or ten months.

This module answers the planning question:

    given this hash, this wordlist and these rules, how long will it take on
    this machine -- and is that acceptable for the engagement?

Rates are either **measured** (``hashcat -b``) or taken from a labelled
**reference** table.  The distinction is reported, never hidden: a reference
rate is a guess about hardware, a measured rate is evidence about *this* box.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence

from hashvault.core.parameters import ParameterReport, analyze_parameters

MEASURED = "measured"
REFERENCE = "reference"
UNKNOWN = "unknown"

# Conservative single-GPU figures (hashes/second) used only when no benchmark
# could run.  They exist to produce an order of magnitude, not a promise.
_REFERENCE_RATES: dict[str, float] = {
    "raw-md5": 50_000_000_000.0,
    "raw-sha1": 15_000_000_000.0,
    "raw-sha256": 7_000_000_000.0,
    "raw-sha512": 1_000_000_000.0,
    "ntlm": 50_000_000_000.0,
    "md5crypt": 30_000_000.0,
    "sha256crypt": 10_000_000.0,
    "sha512crypt": 2_500_000.0,
    "bcrypt": 20_000.0,
    "phpass": 4_000_000.0,
    "argon2id": 12_000.0,
    "argon2i": 12_000.0,
    "scrypt": 200_000.0,
}

# Default sizes when the caller does not supply real counts.
_DEFAULT_RULE_COUNT = 1


@dataclass
class CrackPlan:
    """Feasibility estimate for one cracking strategy."""

    format: str
    hashcat_mode: Optional[int]
    work_factor: Optional[float]
    cost_class: str
    keyspace: int
    candidates_per_second: float
    rate_source: str
    eta_seconds: Optional[float]
    budget_seconds: Optional[float]
    feasible: Optional[bool]
    recommendations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def eta_human(self) -> str:
        return format_duration(self.eta_seconds)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["eta_human"] = self.eta_human
        return data


def format_duration(seconds: Optional[float]) -> str:
    """Render a duration for humans; ``None`` means "unknown"."""
    if seconds is None:
        return "unknown"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 90:
        return f"{seconds:.1f} s"
    minutes = seconds / 60
    if minutes < 90:
        return f"{minutes:.1f} min"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f} h"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    return f"{days / 365:.1f} years"


def mask_keyspace(mask: str, *, custom_charset: Optional[int] = None) -> int:
    """Count the keyspace of a hashcat mask such as ``?l?l?d?d``.

    ``?a`` is 95 printable ASCII, ``?b`` is 256 byte values, ``?d``/``?l``/
    ``?u``/``?s`` are 10/26/26/33, and a literal character counts as one.
    """
    sizes = {
        "?d": 10,
        "?l": 26,
        "?u": 26,
        "?s": 33,
        "?a": 95,
        "?b": 256,
        "?h": 16,
        "?H": 16,
    }
    total = _DEFAULT_RULE_COUNT
    index = 0
    while index < len(mask):
        token = mask[index: index + 2]
        if token in sizes:
            total *= sizes[token]
            index += 2
            continue
        if token in ("?1", "?2", "?3", "?4") and custom_charset:
            total *= custom_charset
            index += 2
            continue
        total *= 1  # literal character
        index += 1
    return total


def estimate_rates_from_reference(fmt: str) -> tuple[float, str]:
    """Return ``(rate, source)`` for a format with no measured benchmark."""
    rate = _REFERENCE_RATES.get(fmt)
    if rate:
        return rate, REFERENCE
    return 0.0, UNKNOWN


def plan_crack(
    hash_value: str,
    *,
    wordlist_entries: Optional[int] = None,
    rule_count: int = _DEFAULT_RULE_COUNT,
    mask: Optional[str] = None,
    measured_rate: Optional[float] = None,
    budget_seconds: Optional[float] = None,
    format_hint: Optional[str] = None,
    parameters: Optional[ParameterReport] = None,
) -> CrackPlan:
    """Estimate the work needed to exhaust a candidate space.

    Exactly one of ``wordlist_entries`` or ``mask`` should be supplied; the
    keyspace is their product with ``rule_count``.
    """
    report = parameters or analyze_parameters(hash_value)
    fmt = format_hint or report.format

    if wordlist_entries is not None and mask is not None:
        warnings = ["Both a wordlist and a mask were supplied; using the mask."]
        keyspace = mask_keyspace(mask) * max(1, rule_count)
    elif mask is not None:
        warnings = []
        keyspace = mask_keyspace(mask) * max(1, rule_count)
    elif wordlist_entries is not None:
        warnings = []
        keyspace = max(1, int(wordlist_entries)) * max(1, rule_count)
    else:
        warnings = ["No wordlist size or mask supplied; keyspace unknown."]
        keyspace = 0

    if measured_rate is not None and measured_rate > 0:
        rate, source = float(measured_rate), MEASURED
    else:
        rate, source = estimate_rates_from_reference(fmt)

    eta: Optional[float] = None
    if keyspace > 0 and rate > 0:
        eta = keyspace / rate

    feasible: Optional[bool] = None
    if eta is not None and budget_seconds is not None:
        feasible = eta <= budget_seconds

    recommendations: list[str] = []
    if source == UNKNOWN:
        warnings.append(
            f"No reference rate for format {fmt!r}; run a benchmark "
            "(`hashvault plan --measure`) for a real estimate."
        )
    if feasible is False and eta is not None:
        recommendations.append(
            f"Exhausting this keyspace takes {format_duration(eta)}, longer "
            f"than the {format_duration(budget_seconds)} budget. Narrow the "
            "space: top-N wordlist, targeted mask, or context mutation."
        )
    if report.cost_class in {"high", "very_high"}:
        recommendations.append(
            f"Work factor is {report.cost_class}; prioritise guessing quality "
            "over keyspace size."
        )
    if rule_count > 1:
        recommendations.append(
            f"Rules multiply the keyspace by {rule_count}; verify that the "
            "rule set is worth the factor."
        )

    return CrackPlan(
        format=fmt,
        hashcat_mode=None,
        work_factor=report.work_factor,
        cost_class=report.cost_class,
        keyspace=keyspace,
        candidates_per_second=rate,
        rate_source=source,
        eta_seconds=eta,
        budget_seconds=budget_seconds,
        feasible=feasible,
        recommendations=recommendations,
        warnings=warnings,
    )


def count_wordlist(path: str | Path, *, limit: Optional[int] = None) -> int:
    """Count lines in a wordlist, stopping early once ``limit`` is reached."""
    count = 0
    try:
        with open(path, "rb") as handle:
            for _ in handle:
                count += 1
                if limit is not None and count >= limit:
                    break
    except OSError:
        return 0
    return count


# hashcat prints e.g. "Speed.#1.........: 1234.5 MH/s"
_HASHCAT_SPEED_RE = re.compile(
    r"Speed\.#\d+\.*:\s*([0-9.]+)\s*([kKmMgGtT]?)[Hh]/s"
)
_SPEED_UNITS = {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}


def parse_hashcat_benchmark(output: str) -> Optional[float]:
    """Extract the fastest H/s figure from ``hashcat -b`` output."""
    best: Optional[float] = None
    for match in _HASHCAT_SPEED_RE.finditer(output or ""):
        try:
            value = float(match.group(1))
        except ValueError:
            continue
        unit = (match.group(2) or "").lower()
        rate = value * _SPEED_UNITS.get(unit, 1.0)
        if rate > 0 and (best is None or rate > best):
            best = rate
    return best


def measure_rate(
    hashcat_bin: str,
    mode: int,
    *,
    timeout_seconds: float = 60.0,
) -> tuple[Optional[float], str]:
    """Run ``hashcat -b -m <mode>`` and return ``(rate, explanation)``.

    Returns ``(None, reason)`` when benchmarking is impossible, so the caller
    can fall back to a reference rate and say so instead of guessing silently.
    """
    binary = shutil.which(hashcat_bin) or hashcat_bin
    if not binary or not Path(binary).exists():
        return None, f"hashcat binary not found ({hashcat_bin})"

    try:
        proc = subprocess.run(
            [binary, "-b", "-m", str(mode), "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return None, f"benchmark timed out after {timeout_seconds:.0f}s"
    except (OSError, ValueError) as exc:
        return None, f"benchmark could not start: {exc}"

    rate = parse_hashcat_benchmark((proc.stdout or "") + (proc.stderr or ""))
    if rate is None:
        return None, "hashcat reported no speed (mode may be unsupported here)"
    return rate, f"measured with hashcat mode {mode}"


def summary_lines(plan: CrackPlan) -> list[str]:
    """Human-readable planning output for the CLI."""
    lines = [
        f"Format            : {plan.format}",
        f"Work factor       : {plan.work_factor if plan.work_factor else 'n/a'} "
        f"({plan.cost_class})",
        f"Keyspace          : {plan.keyspace:,} candidates",
        f"Rate              : {plan.candidates_per_second:,.0f} H/s "
        f"({plan.rate_source})",
        f"Estimated time    : {plan.eta_human}",
    ]
    if plan.budget_seconds is not None:
        verdict = "within budget" if plan.feasible else "EXCEEDS budget"
        lines.append(
            f"Budget            : {format_duration(plan.budget_seconds)} "
            f"-> {verdict}"
        )
    for warning in plan.warnings:
        lines.append(f"warning: {warning}")
    if plan.recommendations:
        lines.append("")
        lines.append("Recommendations:")
        for recommendation in plan.recommendations:
            lines.append(f"  - {recommendation}")
    return lines
