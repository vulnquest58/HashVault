# hashvault/core/identifier.py
"""
Hash identification engine with confidence scoring.
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from hashvault.core.normalizer import normalize_hash
from hashvault.core.registry import HashCategory, ResolutionMethod
from hashvault.exceptions import NoCandidateError
from hashvault.models.orm import Pattern

logger = logging.getLogger("hashvault.identifier")


@dataclass
class Candidate:
    """Candidate pattern with confidence score."""
    pattern: Pattern
    confidence: float


class SourceContext:
    """Context about where the hash came from."""
    def __init__(
        self,
        origin_file: Optional[str] = None,
        associated_format: Optional[str] = None,
        domain_prefix: bool = False,
        user_declared_hint: Optional[HashCategory] = None,
    ):
        self.origin_file = origin_file
        self.associated_format = associated_format
        self.domain_prefix = domain_prefix
        self.user_declared_hint = user_declared_hint


class IdentificationResult:
    """Result of hash identification."""
    def __init__(
        self,
        candidates: List[Candidate],
        resolved: bool = False,
        method: str = "ambiguous",
        chosen_pattern: Optional[Pattern] = None,
        confidence_score: Optional[float] = None,
    ):
        self.candidates = candidates
        self.resolved = resolved
        self.method = method
        self.chosen_pattern = chosen_pattern
        self.confidence_score = confidence_score


class Identifier:
    """Main hash identification engine."""

    def __init__(self, patterns: List[Pattern], calibration: Any = None):
        self.patterns = patterns
        # Optional monotone confidence map; applied to the *reported*
        # confidence after ranking, so it cannot reorder candidates.
        self.calibration = calibration
        self._compile_patterns()

    # Matches an exact single-token regex like '^[0-9a-fA-F]{32}$'.
    _RIGID_RE = re.compile(r"^\^\[[^\]]+\]\{(\d+)\}\$")

    def _compute_rigid_length(self, regex: str) -> Optional[int]:
        """Return the fixed length if ``regex`` is an exact rigid single-token
        pattern (no variable salt/iteration), else None.

        This lets the scorer skip non-matching hashes by length alone, which is
        the dominant cost with hundreds of patterns loaded.
        """
        m = self._RIGID_RE.match(regex)
        return int(m.group(1)) if m else None

    def _compile_patterns(self) -> None:
        """Compile regex patterns once and build fast lookup indexes."""
        self.compiled_patterns: List[Tuple[Pattern, re.Pattern[str], Optional[int]]] = []
        self._by_length: Dict[int, List[Tuple[Pattern, re.Pattern[str]]]] = {}
        self._variable: List[Tuple[Pattern, re.Pattern[str]]] = []
        self._prefix_entries: List[Tuple[Pattern, str, re.Pattern[str]]] = []

        for pattern in self.patterns:
            try:
                regex = re.compile(pattern.regex, re.IGNORECASE)
            except re.error as exc:
                # Silently skipping a broken pattern hides a data error: the
                # hash type becomes unidentifiable with no explanation.
                logger.warning(
                    "Skipping pattern %r: invalid regex (%s)", pattern.name, exc
                )
                continue

            rigid = self._compute_rigid_length(pattern.regex)
            self.compiled_patterns.append((pattern, regex, rigid))
            if rigid is None:
                self._variable.append((pattern, regex))
            else:
                self._by_length.setdefault(rigid, []).append((pattern, regex))

            prefix = (pattern.prefix_hint or "").strip()
            # A one-character prefix such as "$" is not definitive.
            if len(prefix) >= 2:
                self._prefix_entries.append((pattern, prefix, regex))

        # Longest/most-specific prefix first; regex-confirmed entries win ties.
        self._prefix_entries.sort(
            key=lambda item: (len(item[1]), item[0].confidence_weight),
            reverse=True,
        )

    def _check_definitive_prefix(
        self, normalized: str
    ) -> Optional[Tuple[Candidate, bool]]:
        """Resolve using the most specific (longest) matching prefix hint.

        Returns ``(candidate, regex_ok)``.  ``regex_ok`` reports whether the
        winning pattern's own regex also accepts the value.  A prefix match
        alone is *not* proof of format: a string that merely begins with
        ``$1$`` or ``sha256$`` must not be reported as resolved, otherwise the
        pipeline routes a non-hash into cracking with the wrong mode.  Callers
        only treat ``regex_ok=True`` as definitive and fall back to normal
        candidate ranking otherwise.
        """
        matched: List[Tuple[bool, int, float, Pattern]] = []
        for pattern, prefix, regex in self._prefix_entries:
            if normalized.startswith(prefix):
                matched.append(
                    (
                        bool(regex.fullmatch(normalized)),
                        len(prefix),
                        pattern.confidence_weight,
                        pattern,
                    )
                )

        if not matched:
            return None

        matched.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
        regex_ok, _, _, pattern = matched[0]
        return Candidate(pattern=pattern, confidence=0.98 if regex_ok else 0.85), regex_ok

    def _apply_source_context(
        self, candidates: List[Candidate], context: Optional[SourceContext]
    ) -> List[Candidate]:
        """Apply source context to adjust confidence scores."""
        if not context:
            return candidates

        for candidate in candidates:
            # Adjust confidence based on format hints
            if context.associated_format:
                fmt_str = context.associated_format.value if hasattr(context.associated_format, "value") else str(context.associated_format)
                if candidate.pattern.source_format_hints:
                    try:
                        hints = json.loads(candidate.pattern.source_format_hints)
                        if fmt_str in hints:
                            candidate.confidence = min(1.0, candidate.confidence + 0.4)
                    except Exception:
                        pass

            # User hint overrides
            if context.user_declared_hint:
                hint_str = context.user_declared_hint.value if hasattr(context.user_declared_hint, "value") else str(context.user_declared_hint)
                cat_str = candidate.pattern.category.value if hasattr(candidate.pattern.category, "value") else str(candidate.pattern.category)
                if cat_str == hint_str:
                    candidate.confidence = min(1.0, candidate.confidence + 0.3)

            # Domain prefix / username hint (e.g. Administrator:hash)
            if context.domain_prefix:
                cat_str = candidate.pattern.category.value if hasattr(candidate.pattern.category, "value") else str(candidate.pattern.category)
                if candidate.pattern.name == "NTLM":
                    candidate.confidence = min(1.0, candidate.confidence + 0.45)
                elif cat_str == HashCategory.WINDOWS.value or cat_str == "windows":
                    candidate.confidence = min(1.0, candidate.confidence + 0.1)

        return candidates

    def _get_pattern_candidates(self, normalized: str) -> List[Candidate]:
        """Get all matching candidates based on regex.

        Rigid-length patterns are grouped by their exact length, so only the
        handful of patterns that *can* match a given token are evaluated.
        """
        candidates: List[Candidate] = []
        length = len(normalized)
        pairs = list(self._variable)
        pairs.extend(self._by_length.get(length, ()))

        for pattern, regex in pairs:
            if regex.fullmatch(normalized):
                score = pattern.confidence_weight

                # Penalize generic patterns (common lengths without prefix)
                if pattern.prefix_hint is None and length in (32, 40, 64):
                    score *= 0.6

                # Bonus for matching prefix
                if pattern.prefix_hint and normalized.startswith(pattern.prefix_hint):
                    score = min(1.0, score * 1.5)

                candidates.append(Candidate(pattern=pattern, confidence=score))

        # Sort by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def _apply_calibration(self, candidates: List[Candidate]) -> List[Candidate]:
        """Map reported confidences through the calibration curve.

        Runs after the candidates are ranked, and the map is monotone, so the
        order is preserved while the number shown means what it says.
        """
        if not self.calibration:
            return candidates
        for candidate in candidates:
            candidate.confidence = self.calibration.apply(candidate.confidence)
        return candidates

    def identify(
        self,
        raw_hash: str,
        context: Optional[SourceContext] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> IdentificationResult:
        """
        Identify hash type with confidence scoring.

        Layers:
        1. Regex/length filtering
        2. Definitive prefixes
        3. Source context
        4. Confidence margin decision
        """
        # Normalize first
        normalized, username = normalize_hash(raw_hash)

        if username and not context:
            context = SourceContext(domain_prefix=True)
        elif username and context and not context.domain_prefix:
            context.domain_prefix = True

        # Layer 2: Check for definitive prefixes.  Only a regex-confirmed
        # prefix is definitive; a bare prefix match is a hint, never a result.
        prefix_match = self._check_definitive_prefix(normalized)
        weak_prefix: Optional[Candidate] = None
        if prefix_match is not None:
            candidate, regex_ok = prefix_match
            if regex_ok:
                return IdentificationResult(
                    candidates=[candidate],
                    resolved=True,
                    method=ResolutionMethod.PREFIX.value,
                    chosen_pattern=candidate.pattern,
                    confidence_score=candidate.confidence,
                )
            weak_prefix = candidate

        # Layer 1: Get regex matches
        candidates = self._get_pattern_candidates(normalized)

        # Layer 3: Apply source context
        if context:
            candidates = self._apply_source_context(candidates, context)

        # Sort again after context adjustments
        candidates.sort(key=lambda c: c.confidence, reverse=True)

        if not candidates:
            if weak_prefix is not None:
                # The prefix looked familiar but no pattern (including that
                # one) actually accepts the value.  Report the guess as an
                # unresolved candidate instead of claiming a match: a string
                # like "$6$garbage" must not be routed into cracking with the
                # sha-crypt mode.
                weak_prefix.confidence = min(weak_prefix.confidence, 0.3)
                return IdentificationResult(
                    candidates=[weak_prefix],
                    resolved=False,
                    method=ResolutionMethod.AMBIGUOUS.value,
                )
            return IdentificationResult(
                candidates=[],
                resolved=False,
                method=ResolutionMethod.AMBIGUOUS.value,
            )

        # A bare prefix hint never competes with real regex matches: it is
        # ranked below them and cannot trigger the single-match shortcut.
        if weak_prefix is not None:
            candidates = [
                candidate
                for candidate in candidates
                if candidate.pattern.name != weak_prefix.pattern.name
            ]
            if not candidates:
                weak_prefix.confidence = min(weak_prefix.confidence, 0.3)
                return IdentificationResult(
                    candidates=[weak_prefix],
                    resolved=False,
                    method=ResolutionMethod.AMBIGUOUS.value,
                )

        # Layer 4: Decision logic
        candidates = self._apply_calibration(candidates)

        if len(candidates) == 1:
            return IdentificationResult(
                candidates=candidates,
                resolved=True,
                method=ResolutionMethod.SINGLE_MATCH.value,
                chosen_pattern=candidates[0].pattern,
                confidence_score=candidates[0].confidence,
            )

        top = candidates[0]
        second = candidates[1]
        threshold = 0.75
        margin = 0.2

        if config:
            threshold = config.get("auto_select_confidence_threshold", threshold)
            margin = config.get("auto_select_margin", margin)

        if top.confidence >= threshold and (top.confidence - second.confidence) >= margin:
            return IdentificationResult(
                candidates=candidates,
                resolved=True,
                method=ResolutionMethod.CONFIDENCE_MARGIN.value,
                chosen_pattern=top.pattern,
                confidence_score=top.confidence,
            )

        return IdentificationResult(
            candidates=candidates,
            resolved=False,
            method=ResolutionMethod.AMBIGUOUS.value,
        )


_IDENTIFIER_CACHE_KEY = "hashvault_identifier_cache"


def get_identifier(db_session: Session) -> Identifier:
    """Return a cached Identifier for this SQLAlchemy session.

    Recompiling 400+ regexes for every hash used to dominate identification
    time (and the benchmark suite).  The cache lives on the session, so it is
    discarded automatically when the session/DB is recreated.
    """
    cached = db_session.info.get(_IDENTIFIER_CACHE_KEY)
    if cached is not None:
        return cached

    patterns = db_session.query(Pattern).order_by(Pattern.popularity.desc()).all()
    if not patterns:
        raise NoCandidateError("No patterns in database; cannot identify hashes.")

    # Load the calibration curve once per session, next to the catalogue.
    calibration = None
    try:
        from hashvault.core.calibration import load_calibration
        from hashvault.core.database import package_root

        calibration = load_calibration(package_root() / "data" / "patterns") or None
    except Exception:  # pragma: no cover - calibration is optional
        calibration = None

    identifier = Identifier(patterns, calibration=calibration)
    db_session.info[_IDENTIFIER_CACHE_KEY] = identifier
    return identifier


def clear_identifier_cache(db_session: Session) -> None:
    """Drop the cached identifier (call after mutating the patterns table)."""
    db_session.info.pop(_IDENTIFIER_CACHE_KEY, None)


def identify(
    raw_hash: str,
    db_session: Any,
    config: Any,
    context: Optional[SourceContext] = None,
) -> IdentificationResult:
    """Convenience function matching functional API."""
    normalized, username = normalize_hash(raw_hash)
    if username:
        if context is None:
            context = SourceContext(domain_prefix=True)
        elif not context.domain_prefix:
            context.domain_prefix = True

    identifier = get_identifier(db_session)
    cfg_dict = {
        "auto_select_confidence_threshold": getattr(config.strategy, "auto_select_confidence_threshold", 0.75),
        "auto_select_margin": getattr(config.strategy, "auto_select_margin", 0.2),
    } if hasattr(config, "strategy") else None
    res = identifier.identify(normalized, context=context, config=cfg_dict)
    if not res.candidates:
        raise NoCandidateError(f"No matching pattern candidate found for hash: {raw_hash}")
    return res
