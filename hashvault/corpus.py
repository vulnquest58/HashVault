"""Corpus loading and benchmark evaluation helpers.

The corpus couples three concerns that are easy to mix up in a benchmark:

* a stable description of an example (hash, expected mode, plaintext);
* identification accuracy, measured independently of cracking;
* cracking verification, measured only where a verified plaintext exists and
  the selected engine actually supports the format.
"""

from __future__ import annotations

import json
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from hashvault.config import Config
from hashvault.core.builtin import BuiltinCracker, builtin_supports
from hashvault.core.cracker import create_crack_session, release_session_artifacts
from hashvault.core.database import resolve_resource_path
from hashvault.core.identifier import Identifier
from hashvault.core.registry import HashCategory
from hashvault.exceptions import NoCandidateError
from hashvault.models.schemas import PatternSchema

DEFAULT_HASHCAT_CORPUS = resolve_resource_path("data/corpus/hashcat_examples.json")
DEFAULT_XDF_CORPUS = resolve_resource_path("data/corpus/0xdf_cases.json")
DEFAULT_CRYPTO_CORPUS = resolve_resource_path("data/corpus/crypto_vectors.json")
DEFAULT_CTF_CORPUS = resolve_resource_path("data/corpus/ctf_writeups.json")
DEFAULT_CTF_PUBLIC_CORPUS = resolve_resource_path("data/corpus/ctf_public.json")
DEFAULT_CORPUS_FILES = (
    DEFAULT_HASHCAT_CORPUS,
    DEFAULT_XDF_CORPUS,
    DEFAULT_CRYPTO_CORPUS,
    DEFAULT_CTF_CORPUS,
    DEFAULT_CTF_PUBLIC_CORPUS,
)

EXACT = "exact"
CANDIDATE_ONLY = "candidate_only"
MISMATCH = "mismatch"
NO_CANDIDATES = "no_candidates"
ERROR = "error"
SKIPPED = "skipped"
CRACKED = "cracked"
MISMATCHED_PLAINTEXT = "plaintext_mismatch"
FAILED = "failed"


@dataclass(frozen=True)
class CorpusEntry:
    """One corpus hash with optional ground-truth plaintext."""

    id: str
    source: str
    mode: int
    name: str
    raw_input: str
    expected_plaintext: Optional[str] = None
    category: str = ""
    username: Optional[str] = None
    domain: Optional[str] = None
    box: Optional[str] = None
    url: Optional[str] = None
    example_format: str = "plain"
    slow_hash: bool = False
    is_binary: bool = False
    truncated: bool = False
    usable_for_identification: bool = True
    usable_for_cracking: bool = True
    unusable_reason: Optional[str] = None
    reference: Optional[str] = None
    notes: Optional[str] = None
    upstream_repo: Optional[str] = None
    upstream_path: Optional[str] = None
    upstream_commit: Optional[str] = None
    upstream_url: Optional[str] = None
    license: Optional[str] = None
    verified: bool = False
    verification: Optional[str] = None

    @classmethod
    def from_dict(cls, item: dict[str, Any]) -> "CorpusEntry":
        try:
            entry_id = str(item["id"]).strip()
            mode = int(item["mode"])
            name = str(item["name"]).strip()
            raw_input = str(item["raw_input"]).strip()
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid corpus entry: {item!r}") from exc
        if not entry_id or not name or not raw_input:
            raise ValueError(f"Corpus entry has an empty required field: {item!r}")

        expected_plaintext = item.get("expected_plaintext")
        if expected_plaintext is not None:
            expected_plaintext = str(expected_plaintext)
            if expected_plaintext in {"", "N/A"}:
                expected_plaintext = None

        usable_identification = bool(item.get("usable_for_identification", True))
        usable_cracking = bool(
            item.get(
                "usable_for_cracking",
                usable_identification and bool(expected_plaintext),
            )
        )
        if not expected_plaintext:
            usable_cracking = False

        return cls(
            id=entry_id,
            source=str(item.get("source") or "unknown"),
            mode=mode,
            name=name,
            raw_input=raw_input,
            expected_plaintext=expected_plaintext,
            category=str(item.get("category") or item.get("hashcat_category") or ""),
            username=str(item["username"]) if item.get("username") else None,
            domain=str(item["domain"]) if item.get("domain") else None,
            box=str(item["box"]) if item.get("box") else None,
            url=str(item.get("url") or item.get("reference") or "") or None,
            example_format=str(item.get("example_format") or "plain"),
            slow_hash=bool(item.get("slow_hash", False)),
            is_binary=bool(item.get("is_binary", False)),
            truncated=bool(item.get("truncated", False)),
            usable_for_identification=usable_identification,
            usable_for_cracking=usable_cracking,
            unusable_reason=str(item["unusable_reason"]) if item.get("unusable_reason") else None,
            reference=str(item["reference"]) if item.get("reference") else None,
            notes=str(item["notes"]) if item.get("notes") else None,
            upstream_repo=str(item["upstream_repo"]) if item.get("upstream_repo") else None,
            upstream_path=str(item["upstream_path"]) if item.get("upstream_path") else None,
            upstream_commit=str(item["upstream_commit"]) if item.get("upstream_commit") else None,
            upstream_url=str(item["upstream_url"]) if item.get("upstream_url") else None,
            license=str(item["license"]) if item.get("license") else None,
            verified=bool(item.get("verified", False)),
            verification=str(item["verification"]) if item.get("verification") else None,
        )


def _extract_items(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("entries", "cases", "hashes", "vectors"):
            items = document.get(key)
            if isinstance(items, list):
                return items
    raise ValueError("Corpus JSON must be a list or contain an entries/cases list")


def load_corpus_file(path: str | Path) -> list[CorpusEntry]:
    corpus_path = Path(path)
    document = json.loads(corpus_path.read_text(encoding="utf-8"))
    entries = [CorpusEntry.from_dict(item) for item in _extract_items(document)]
    _validate_entries(entries)
    return entries


def load_corpora(paths: Iterable[str | Path]) -> list[CorpusEntry]:
    entries: list[CorpusEntry] = []
    for path in paths:
        entries.extend(load_corpus_file(path))
    _validate_entries(entries)
    return entries


def load_default_corpora(
    sources: Sequence[str] = ("hashcat", "0xdf", "crypto", "ctf", "ctf-public"),
) -> list[CorpusEntry]:
    paths: list[Path] = []
    for source in sources:
        if source == "hashcat":
            paths.append(DEFAULT_HASHCAT_CORPUS)
        elif source == "0xdf":
            paths.append(DEFAULT_XDF_CORPUS)
        elif source == "crypto":
            paths.append(DEFAULT_CRYPTO_CORPUS)
        elif source == "ctf":
            paths.append(DEFAULT_CTF_CORPUS)
        elif source == "ctf-public":
            paths.append(DEFAULT_CTF_PUBLIC_CORPUS)
        else:
            raise ValueError(f"Unknown corpus source: {source}")
    return load_corpora(paths)


def load_corpus_from_db(
    session,
    sources: Optional[Sequence[str]] = None,
) -> list[CorpusEntry]:
    """Load corpus entries previously seeded into the database."""
    from hashvault.models.orm import CorpusEntryRecord

    query = session.query(CorpusEntryRecord)
    if sources is not None:
        query = query.filter(CorpusEntryRecord.source.in_(tuple(sources)))
    rows = query.order_by(CorpusEntryRecord.id).all()
    entry_fields = tuple(item.name for item in fields(CorpusEntry))
    entries = [
        CorpusEntry(**{name: getattr(row, name) for name in entry_fields})
        for row in rows
    ]
    _validate_entries(entries)
    return entries


def _validate_entries(entries: Iterable[CorpusEntry]) -> None:
    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            raise ValueError(f"Duplicate corpus entry id: {entry.id}")
        seen.add(entry.id)


@dataclass
class IdentificationOutcome:
    id: str
    source: str
    expected_mode: int
    expected_name: str
    status: str
    top_mode: Optional[int] = None
    top_name: Optional[str] = None
    confidence: Optional[float] = None
    candidate_modes: list[int] = field(default_factory=list)
    candidate_names: list[str] = field(default_factory=list)
    #: Current ``confidence_weight`` of the top-ranked pattern, so calibration
    #: can compare the assigned weight against observed accuracy.
    top_weight: Optional[float] = None
    resolved: bool = False
    method: str = ""
    error: Optional[str] = None
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IdentificationReport:
    outcomes: list[IdentificationOutcome]
    elapsed_seconds: float
    total_entries: int

    @property
    def mismatches(self) -> list[IdentificationOutcome]:
        return [o for o in self.outcomes if o.status == MISMATCH]

    def summary(self) -> dict[str, Any]:
        counts = Counter(outcome.status for outcome in self.outcomes)
        evaluated = self.total_entries - counts[SKIPPED]
        exact = counts[EXACT]
        candidate_only = counts[CANDIDATE_ONLY]
        resolved = sum(
            1
            for outcome in self.outcomes
            if outcome.status != SKIPPED and outcome.resolved
        )
        avg_ms = (
            sum(outcome.elapsed_ms for outcome in self.outcomes if outcome.status != SKIPPED)
            / evaluated
            if evaluated
            else 0.0
        )
        return {
            "total_entries": self.total_entries,
            "evaluated": evaluated,
            "exact": exact,
            "candidate_only": candidate_only,
            "identified_any": exact + candidate_only,
            "mismatch": counts[MISMATCH],
            "no_candidates": counts[NO_CANDIDATES],
            "errors": counts[ERROR],
            "skipped": counts[SKIPPED],
            "resolved": resolved,
            "top1_accuracy": exact / evaluated if evaluated else 0.0,
            "candidate_coverage": (exact + candidate_only) / evaluated if evaluated else 0.0,
            "avg_ms": avg_ms,
            "elapsed_seconds": self.elapsed_seconds,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


def _identification_config(config: Optional[Config | dict[str, Any]]) -> Optional[dict[str, Any]]:
    if config is None:
        return None
    if isinstance(config, dict):
        return config
    strategy = getattr(config, "strategy", None)
    if strategy is None:
        return None
    return {
        "auto_select_confidence_threshold": getattr(
            strategy, "auto_select_confidence_threshold", 0.75
        ),
        "auto_select_margin": getattr(strategy, "auto_select_margin", 0.2),
    }


def evaluate_identification(
    entries: Iterable[CorpusEntry],
    identifier: Identifier,
    *,
    config: Optional[Config | dict[str, Any]] = None,
    include_unusable: bool = False,
) -> IdentificationReport:
    entry_list = list(entries)
    identifier_config = _identification_config(config)
    outcomes: list[IdentificationOutcome] = []
    started = time.perf_counter()

    for entry in entry_list:
        if not include_unusable and not entry.usable_for_identification:
            outcomes.append(
                IdentificationOutcome(
                    id=entry.id,
                    source=entry.source,
                    expected_mode=entry.mode,
                    expected_name=entry.name,
                    status=SKIPPED,
                    error=entry.unusable_reason or "unusable example",
                )
            )
            continue

        entry_started = time.perf_counter()
        try:
            result = identifier.identify(
                entry.raw_input,
                config=identifier_config,
            )
            candidate_modes = [
                candidate.pattern.hashcat_mode
                for candidate in result.candidates
                if candidate.pattern.hashcat_mode is not None
            ]
            candidate_names = [candidate.pattern.name for candidate in result.candidates]
            top_mode = candidate_modes[0] if candidate_modes else None
            top_name = candidate_names[0] if candidate_names else None
            confidence = (
                result.candidates[0].confidence if result.candidates else None
            )
            top_weight = (
                getattr(result.candidates[0].pattern, "confidence_weight", None)
                if result.candidates
                else None
            )

            if top_mode == entry.mode:
                status = EXACT
            elif entry.mode in candidate_modes:
                status = CANDIDATE_ONLY
            else:
                status = MISMATCH
            outcome = IdentificationOutcome(
                id=entry.id,
                source=entry.source,
                expected_mode=entry.mode,
                expected_name=entry.name,
                status=status,
                top_mode=top_mode,
                top_name=top_name,
                confidence=confidence,
                top_weight=top_weight,
                candidate_modes=candidate_modes,
                candidate_names=candidate_names,
                resolved=bool(result.resolved),
                method=str(result.method),
                elapsed_ms=(time.perf_counter() - entry_started) * 1000,
            )
        except NoCandidateError as exc:
            outcome = IdentificationOutcome(
                id=entry.id,
                source=entry.source,
                expected_mode=entry.mode,
                expected_name=entry.name,
                status=NO_CANDIDATES,
                error=str(exc),
                elapsed_ms=(time.perf_counter() - entry_started) * 1000,
            )
        except Exception as exc:  # pragma: no cover - defensive benchmark guard
            outcome = IdentificationOutcome(
                id=entry.id,
                source=entry.source,
                expected_mode=entry.mode,
                expected_name=entry.name,
                status=ERROR,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=(time.perf_counter() - entry_started) * 1000,
            )
        outcomes.append(outcome)

    return IdentificationReport(
        outcomes=outcomes,
        elapsed_seconds=time.perf_counter() - started,
        total_entries=len(entry_list),
    )


@dataclass
class CrackingOutcome:
    id: str
    source: str
    mode: int
    expected_plaintext: Optional[str]
    status: str
    actual_plaintext: Optional[str] = None
    engine: str = "builtin"
    error: Optional[str] = None
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CrackingReport:
    outcomes: list[CrackingOutcome]
    elapsed_seconds: float
    total_entries: int
    engine: str = "builtin"

    def summary(self) -> dict[str, Any]:
        counts = Counter(outcome.status for outcome in self.outcomes)
        attempted = (
            counts[CRACKED]
            + counts[MISMATCHED_PLAINTEXT]
            + counts[FAILED]
            + counts[ERROR]
        )
        return {
            "total_entries": self.total_entries,
            "attempted": attempted,
            "cracked": counts[CRACKED],
            "plaintext_mismatch": counts[MISMATCHED_PLAINTEXT],
            "failed": counts[FAILED],
            "errors": counts[ERROR],
            "skipped": counts[SKIPPED],
            "success_rate": counts[CRACKED] / attempted if attempted else 0.0,
            "elapsed_seconds": self.elapsed_seconds,
            "engine": self.engine,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


def _pattern_for_entry(entry: CorpusEntry) -> PatternSchema:
    try:
        category = HashCategory(entry.category)
    except ValueError:
        category = HashCategory.RAW_GENERIC
    return PatternSchema(
        name=entry.name,
        regex=r".*",
        hashcat_mode=entry.mode,
        category=category,
        is_slow=entry.slow_hash,
    )


def evaluate_cracking(
    entries: Iterable[CorpusEntry],
    config: Config,
    *,
    wordlist_path: Optional[str | Path] = None,
    max_candidates: Optional[int] = None,
    include_unusable: bool = False,
) -> CrackingReport:
    """Run the built-in engine against corpus entries.

    Without ``wordlist_path`` the evaluator uses a one-word wordlist containing
    the known plaintext for each entry.  This is a deterministic engine
    correctness check, not a claim about real-world cracking speed.  Pass a
    real wordlist to measure search performance.
    """
    entry_list = list(entries)
    outcomes: list[CrackingOutcome] = []
    started = time.perf_counter()
    engine = "builtin"

    with tempfile.TemporaryDirectory(prefix="hashvault-corpus-") as tmp_dir:
        runtime_config = config.model_copy(deep=True)
        runtime_config.paths.sessions_dir = str(Path(tmp_dir) / "sessions")
        shared_wordlist = Path(wordlist_path) if wordlist_path else None
        cracker = BuiltinCracker(runtime_config)

        for index, entry in enumerate(entry_list):
            if not entry.expected_plaintext:
                outcomes.append(
                    CrackingOutcome(
                        id=entry.id,
                        source=entry.source,
                        mode=entry.mode,
                        expected_plaintext=entry.expected_plaintext,
                        status=SKIPPED,
                        error="no verified plaintext",
                    )
                )
                continue

            if not include_unusable and not entry.usable_for_cracking:
                outcomes.append(
                    CrackingOutcome(
                        id=entry.id,
                        source=entry.source,
                        mode=entry.mode,
                        expected_plaintext=entry.expected_plaintext,
                        status=SKIPPED,
                        error=entry.unusable_reason or "not usable for cracking",
                    )
                )
                continue

            pattern = _pattern_for_entry(entry)
            if not builtin_supports(pattern):
                outcomes.append(
                    CrackingOutcome(
                        id=entry.id,
                        source=entry.source,
                        mode=entry.mode,
                        expected_plaintext=entry.expected_plaintext,
                        status=SKIPPED,
                        error=f"mode {entry.mode} is not supported by the built-in engine",
                    )
                )
                continue

            if shared_wordlist is None:
                wordlist = Path(tmp_dir) / f"entry-{index}.txt"
                wordlist.write_text(
                    (entry.expected_plaintext or "") + "\n",
                    encoding="utf-8",
                )
            else:
                wordlist = shared_wordlist

            entry_started = time.perf_counter()
            try:
                session = create_crack_session(runtime_config.paths.sessions_dir)
                result = cracker.crack(
                    hash_value=entry.raw_input,
                    pattern=pattern,
                    wordlist_path=wordlist,
                    session=session,
                    max_candidates=max_candidates,
                )
                release_session_artifacts(
                    session,
                    keep=getattr(
                        runtime_config.strategy, "keep_session_artifacts", False
                    ),
                )
                if result.success and result.plaintext == entry.expected_plaintext:
                    status = CRACKED
                elif result.success:
                    status = MISMATCHED_PLAINTEXT
                elif result.engine_error:
                    status = ERROR
                else:
                    status = FAILED
                outcomes.append(
                    CrackingOutcome(
                        id=entry.id,
                        source=entry.source,
                        mode=entry.mode,
                        expected_plaintext=entry.expected_plaintext,
                        status=status,
                        actual_plaintext=result.plaintext,
                        engine=engine,
                        error=result.error_message,
                        elapsed_ms=(time.perf_counter() - entry_started) * 1000,
                    )
                )
            except Exception as exc:  # pragma: no cover - defensive benchmark guard
                outcomes.append(
                    CrackingOutcome(
                        id=entry.id,
                        source=entry.source,
                        mode=entry.mode,
                        expected_plaintext=entry.expected_plaintext,
                        status=ERROR,
                        engine=engine,
                        error=f"{type(exc).__name__}: {exc}",
                        elapsed_ms=(time.perf_counter() - entry_started) * 1000,
                    )
                )

    return CrackingReport(
        outcomes=outcomes,
        elapsed_seconds=time.perf_counter() - started,
        total_entries=len(entry_list),
        engine=engine,
    )
