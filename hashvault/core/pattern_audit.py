"""Static and data-driven quality audit for the hash pattern catalogue.

The identifier ranks candidates purely by ``confidence_weight``, so a pattern
whose regex is wrong is not merely useless: it silently steals matches from a
correct pattern.  Two real defects of that class (a generated JWT regex that
required the literal ``_`` and ``-`` from the hashcat example, and a Flask
session pattern that tied with it at 0.24) produced wrong mode 29100 results
for every JWT before they were found by hand.

This module turns that manual hunt into a repeatable check.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

ERROR = "error"
WARNING = "warning"
INFO = "info"

# Patterns that legitimately accept almost any input: the identity detector and
# the extractors are not hash-shaped, so they are exempt from width checks.
_WIDE_PATTERN_EXEMPT = {"HashDetector"}

# Decoys that a well-formed hash regex must reject.  Using characters that
# cannot appear in any hash encoding (hex/base64/crypt alphabets) keeps the
# check free of false positives.
_DECOY_CHARS = "!@#$%^&*() "


@dataclass
class PatternIssue:
    """One defect found in the catalogue."""

    pattern_name: str
    hashcat_mode: Optional[int]
    code: str
    severity: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    patterns_checked: int
    issues: list[PatternIssue] = field(default_factory=list)
    examples_checked: int = 0
    suppressed: int = 0

    def counts(self) -> dict[str, int]:
        counts = {ERROR: 0, WARNING: 0, INFO: 0}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts

    @property
    def ok(self) -> bool:
        """True when nothing blocks a release (warnings are tolerated)."""
        return self.counts()[ERROR] == 0

    def by_code(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for issue in self.issues:
            counts[issue.code] += 1
        return dict(sorted(counts.items(), key=lambda item: -item[1]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "patterns_checked": self.patterns_checked,
            "examples_checked": self.examples_checked,
            "suppressed_known_issues": self.suppressed,
            "summary": self.counts(),
            "by_code": self.by_code(),
            "issues": [issue.to_dict() for issue in self.issues],
        }


def _name_key(value: str) -> str:
    """Reduce a pattern/algorithm name to comparable alphanumerics."""
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def _names_agree(pattern_name: str, meta_name: str) -> bool:
    """True when the pattern name plausibly describes the same algorithm.

    hashcat renumbers modes between releases, so an example can legitimately
    belong to a different algorithm than the pattern that now claims the
    mode.  That is upstream drift, not a regex bug, and the two need to be
    reported separately or the audit cries wolf.
    """
    left, right = _name_key(pattern_name), _name_key(meta_name)
    if not left or not right:
        return True
    return left[:8] in right or right[:8] in left


def _load_examples(patterns_file: str | Path) -> dict[int, dict[str, Any]]:
    """Read ``patterns.meta.json`` (mode -> hashcat example metadata)."""
    meta_path = Path(patterns_file).parent / "patterns.meta.json"
    if not meta_path.is_file():
        return {}
    try:
        raw = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    examples: dict[int, dict[str, Any]] = {}
    for key, value in raw.items():
        try:
            examples[int(key)] = value
        except (TypeError, ValueError):
            continue
    return examples


def _usable_example(meta: dict[str, Any]) -> Optional[str]:
    """Return the hashcat example for a mode, or None if it is not comparable.

    Hashcat ships truncated and binary examples; matching those against a
    regex says nothing about the pattern's correctness.
    """
    example = meta.get("Example.Hash")
    if not example:
        return None
    text = str(example).strip()
    if not text or "Truncated" in text or "use --mach" in text:
        return None
    if meta.get("Example.Hash.Format") not in (None, "plain"):
        return None
    return text


def _too_loose(regex: re.Pattern[str], length: Optional[int]) -> Optional[str]:
    """Return a decoy the regex wrongly accepts, if any.

    A hash regex must reject strings made only of characters that no hash
    encoding uses.  ``length`` is the pattern's declared minimum so the decoy
    cannot fail merely by being the wrong size.
    """
    sizes = {size for size in (length, 32, 40, 64) if size and size > 0}
    for size in sorted(sizes):
        for char in ("!", " ", "@"):
            decoy = char * size
            if regex.fullmatch(decoy):
                return f"matches the decoy {char * 4!r}*{size}"
    return None


def _load_allowlist(patterns_file: Optional[str | Path]) -> set[tuple[Optional[int], str]]:
    """Read documented, tolerated defects from ``audit_allowlist.json``."""
    if not patterns_file:
        return set()
    path = Path(patterns_file).parent / "audit_allowlist.json"
    if not path.is_file():
        return set()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    allowed: set[tuple[Optional[int], str]] = set()
    for item in raw.get("known_issues") or []:
        try:
            allowed.add((int(item["mode"]), str(item["code"])))
        except (KeyError, TypeError, ValueError):
            continue
    return allowed


def audit_patterns(
    patterns: Sequence[Any],
    *,
    patterns_file: Optional[str | Path] = None,
    include_info: bool = True,
    allow_known: bool = True,
) -> AuditReport:
    """Audit every pattern for regex validity, examples, and ranking ties.

    Parameters
    ----------
    patterns:
        Objects exposing ``name``, ``regex``, ``hashcat_mode``,
        ``confidence_weight`` (ORM rows or the DTO schema both work).
    patterns_file:
        Location of ``patterns.json``; the sibling ``patterns.meta.json``
        supplies the hashcat example used for the self-match check.
    allow_known:
        Honour ``audit_allowlist.json`` so documented upstream drift does not
        mask new regressions.
    """
    report = AuditReport(patterns_checked=len(patterns))
    examples = _load_examples(patterns_file) if patterns_file else {}
    allowlist = _load_allowlist(patterns_file) if allow_known else set()

    compiled: dict[str, tuple[Any, re.Pattern[str]]] = {}
    by_regex: dict[str, list[Any]] = defaultdict(list)
    by_mode: dict[int, list[tuple[Any, re.Pattern[str]]]] = defaultdict(list)

    for pattern in patterns:
        name = getattr(pattern, "name", "?")
        mode = getattr(pattern, "hashcat_mode", None)
        regex_text = getattr(pattern, "regex", "") or ""

        try:
            compiled_regex = re.compile(regex_text)
        except re.error as exc:
            report.issues.append(
                PatternIssue(
                    name,
                    mode,
                    "invalid_regex",
                    ERROR,
                    f"regex does not compile: {exc}",
                )
            )
            continue

        compiled[name] = (pattern, compiled_regex)
        by_regex[regex_text].append(pattern)
        if isinstance(mode, int):
            by_mode[mode].append((pattern, compiled_regex))

        if name in _WIDE_PATTERN_EXEMPT:
            continue

        # 1. Would the pattern swallow input that cannot be a hash?
        length = getattr(pattern, "min_length", None)
        if isinstance(length, int):
            decoy = _too_loose(compiled_regex, length)
            if decoy:
                report.issues.append(
                    PatternIssue(
                        name,
                        mode,
                        "too_loose",
                        ERROR,
                        f"regex {decoy}; it will match non-hash input",
                    )
                )

    # 2. Does *some* pattern for each hashcat mode accept that mode's example?
    #    Several modes legitimately have two patterns (the stored form and the
    #    crackable form of the same algorithm), and only one of them can match,
    #    so the check is per mode rather than per pattern.
    for mode, group in by_mode.items():
        meta = examples.get(mode)
        example = _usable_example(meta) if meta else None
        if example is None:
            continue
        report.examples_checked += 1
        if any(regex.fullmatch(example) for _, regex in group):
            continue

        meta_name = str(meta.get("Name") or "")
        pattern, _ = group[0]
        name = getattr(pattern, "name", "?")
        if _names_agree(name, meta_name):
            # Same algorithm but no pattern accepts its example: real defect.
            report.issues.append(
                PatternIssue(
                    name,
                    mode,
                    "self_mismatch",
                    ERROR,
                    "no pattern for this mode matches the hashcat example: "
                    f"{example[:60]!r}",
                )
            )
        else:
            report.issues.append(
                PatternIssue(
                    name,
                    mode,
                    "mode_drift",
                    WARNING,
                    "hashcat mode %s is called %r upstream, so the example "
                    "belongs to another algorithm: %r"
                    % (mode, meta_name[:40], example[:50]),
                )
            )

    # 3. Identical regexes: the identifier cannot separate them by shape.
    for regex_text, group in by_regex.items():
        if len(group) < 2:
            continue
        names = sorted(getattr(p, "name", "?") for p in group)
        weights = {getattr(p, "confidence_weight", None) for p in group}
        if len(weights) == 1:
            # Identical shape AND identical weight: the identifier cannot
            # order these by anything, so top-1 is effectively random.  That
            # is inherent to the formats (md5($pass.$salt) and
            # md5($salt.$pass) really are indistinguishable), so it is a
            # warning to be fixed by calibration or trial cracking -- not by
            # editing the regex.
            report.issues.append(
                PatternIssue(
                    names[0],
                    getattr(group[0], "hashcat_mode", None),
                    "ambiguous_tie",
                    WARNING,
                    f"{len(group)} patterns share an identical regex AND "
                    f"confidence {weights.pop()} -> ranking is arbitrary: "
                    + ", ".join(names),
                )
            )
        elif include_info:
            report.issues.append(
                PatternIssue(
                    names[0],
                    getattr(group[0], "hashcat_mode", None),
                    "duplicate_regex",
                    INFO,
                    f"{len(group)} patterns share an identical regex "
                    "(weights differ, so ordering is deterministic): "
                    + ", ".join(names),
                )
            )

    return _apply_allowlist(report, allowlist)


def _apply_allowlist(
    report: AuditReport,
    allowlist: set[tuple[Optional[int], str]],
) -> AuditReport:
    """Drop issues already documented in ``audit_allowlist.json``."""
    if not allowlist:
        return report
    kept: list[PatternIssue] = []
    for issue in report.issues:
        if (issue.hashcat_mode, issue.code) in allowlist:
            report.suppressed += 1
            continue
        kept.append(issue)
    report.issues = kept
    return report


def render_audit_report(report: AuditReport) -> list[str]:
    """Human-readable lines for the CLI."""
    counts = report.counts()
    lines = [
        f"Patterns checked : {report.patterns_checked}",
        f"Examples checked : {report.examples_checked}",
        f"Issues           : {counts[ERROR]} error(s), "
        f"{counts[WARNING]} warning(s), {counts[INFO]} info",
    ]
    if report.suppressed:
        lines.append(
            f"Suppressed       : {report.suppressed} documented upstream "
            "issue(s) (see audit_allowlist.json)"
        )
    if report.issues:
        lines.append("")
        for issue in report.issues:
            mode = "-" if issue.hashcat_mode is None else str(issue.hashcat_mode)
            lines.append(
                f"[{issue.severity.upper():<7}] {issue.code:<16} "
                f"mode={mode:<6} {issue.pattern_name}"
            )
            lines.append(f"          {issue.detail}")
    else:
        lines.append("")
        lines.append("No issues found.")
    return lines
