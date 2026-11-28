"""Layered recipe corpus loading and benchmark evaluation."""

from __future__ import annotations

import json
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from hashvault.analysis.analyzer import prepare_input
from hashvault.config import Config
from hashvault.core.builtin import BuiltinCracker, builtin_supports
from hashvault.core.cracker import create_crack_session, release_session_artifacts
from hashvault.core.database import resolve_resource_path
from hashvault.core.identifier import identify
from hashvault.exceptions import NoCandidateError

DEFAULT_LAYER_CORPUS = Path(
    resolve_resource_path("data/corpus/layer_vectors.json")
)


@dataclass(frozen=True)
class LayerVector:
    id: str
    raw_input: str
    expected_hash: str
    expected_operations: tuple[str, ...] = ()
    expected_plaintext: Optional[str] = None
    expected_mode: Optional[int] = None
    name: str = ""
    source: str = "layer-corpus"
    notes: Optional[str] = None
    keys: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, item: dict[str, Any]) -> "LayerVector":
        try:
            entry_id = str(item["id"]).strip()
            raw_input = str(item["raw_input"])
            expected_hash = str(item["expected_hash"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid layer vector: {item!r}") from exc
        operations = item.get("expected_operations") or []
        if isinstance(operations, str):
            operations = [operations]
        keys = item.get("keys") or {}
        if not isinstance(keys, dict):
            raise ValueError(f"Layer vector keys must be an object: {entry_id}")
        expected_mode = item.get("expected_mode")
        return cls(
            id=entry_id,
            raw_input=raw_input,
            expected_hash=expected_hash,
            expected_operations=tuple(str(op) for op in operations),
            expected_plaintext=(
                str(item["expected_plaintext"])
                if item.get("expected_plaintext")
                else None
            ),
            expected_mode=int(expected_mode) if expected_mode is not None else None,
            name=str(item.get("name") or entry_id),
            source=str(item.get("source") or "layer-corpus"),
            notes=str(item["notes"]) if item.get("notes") else None,
            keys={str(key): str(value) for key, value in keys.items()},
        )


def _extract_items(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("entries", "vectors", "cases"):
            values = document.get(key)
            if isinstance(values, list):
                return values
    raise ValueError("Layer corpus must be a list or contain an entries list")


def load_layer_vectors(path: str | Path = DEFAULT_LAYER_CORPUS) -> list[LayerVector]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    vectors = [LayerVector.from_dict(item) for item in _extract_items(document)]
    seen: set[str] = set()
    for vector in vectors:
        if vector.id in seen:
            raise ValueError(f"Duplicate layer vector id: {vector.id}")
        seen.add(vector.id)
    return vectors


@dataclass
class LayerOutcome:
    id: str
    chain: list[str]
    expected_operations: list[str]
    actual_hash: str
    expected_hash: str
    pattern: Optional[str] = None
    expected_mode: Optional[int] = None
    chain_ok: bool = False
    hash_ok: bool = False
    terminal: bool = False
    mode_ok: bool = False
    resolved: bool = False
    cracked: Optional[bool] = None
    status: str = "fail"
    error: Optional[str] = None
    elapsed_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.status == "pass"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LayerReport:
    outcomes: list[LayerOutcome]
    elapsed_seconds: float
    crack_requested: bool = False

    def summary(self) -> dict[str, Any]:
        counts = Counter(outcome.status for outcome in self.outcomes)
        total = len(self.outcomes)
        attempted_crack = [
            outcome for outcome in self.outcomes if outcome.cracked is not None
        ]
        return {
            "total": total,
            "passed": counts["pass"],
            "failed": counts["fail"],
            "skipped": counts["skip"],
            "chain_ok": sum(outcome.chain_ok for outcome in self.outcomes),
            "hash_ok": sum(outcome.hash_ok for outcome in self.outcomes),
            "terminal_ok": sum(outcome.terminal for outcome in self.outcomes),
            "mode_ok": sum(outcome.mode_ok for outcome in self.outcomes),
            "resolved": sum(outcome.resolved for outcome in self.outcomes),
            "crack_attempted": len(attempted_crack),
            "cracked": sum(outcome.cracked is True for outcome in attempted_crack),
            "chain_accuracy": (
                sum(outcome.chain_ok for outcome in self.outcomes) / total
                if total
                else 0.0
            ),
            "pass_rate": counts["pass"] / total if total else 0.0,
            "elapsed_seconds": self.elapsed_seconds,
            "crack_requested": self.crack_requested,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


def _evaluate_crack(
    outcome: LayerOutcome,
    vector: LayerVector,
    pattern: Any,
    config: Config,
    temp_root: Path,
    index: int,
) -> None:
    if not vector.expected_plaintext or not builtin_supports(pattern):
        outcome.cracked = None
        return
    wordlist = temp_root / f"layer-{index}.txt"
    wordlist.write_text(vector.expected_plaintext + "\n", encoding="utf-8")
    runtime = config.model_copy(deep=True)
    runtime.paths.sessions_dir = str(temp_root / "sessions")
    session = create_crack_session(runtime.paths.sessions_dir)
    result = BuiltinCracker(runtime).crack(
        hash_value=outcome.actual_hash,
        pattern=pattern,
        wordlist_path=wordlist,
        session=session,
    )
    release_session_artifacts(session)
    outcome.cracked = bool(
        result.success and result.plaintext == vector.expected_plaintext
    )
    if not outcome.cracked:
        outcome.error = result.error_message or "layer cracking mismatch"


def benchmark_layers(
    vectors: Iterable[LayerVector],
    db_session: Any,
    config: Config,
    *,
    crack: bool = False,
    max_layers: int = 12,
    beam_width: int = 8,
    max_seconds: float = 8.0,
) -> LayerReport:
    entry_list = list(vectors)
    outcomes: list[LayerOutcome] = []
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="hashvault-layers-") as temp_dir:
        temp_root = Path(temp_dir)
        for index, vector in enumerate(entry_list):
            layer_started = time.perf_counter()
            outcome = LayerOutcome(
                id=vector.id,
                chain=[],
                expected_operations=list(vector.expected_operations),
                actual_hash="",
                expected_hash=vector.expected_hash,
                expected_mode=vector.expected_mode,
            )
            try:
                handoff = prepare_input(
                    vector.raw_input,
                    max_layers=max_layers,
                    beam_width=beam_width,
                    keys=vector.keys or None,
                    max_seconds=max_seconds,
                )
                outcome.actual_hash = handoff.primary
                outcome.chain = [
                    layer.operation for layer in handoff.trace.layers
                ]
                outcome.terminal = bool(handoff.trace.terminal)
                outcome.hash_ok = outcome.actual_hash == vector.expected_hash
                outcome.chain_ok = outcome.chain == list(vector.expected_operations)

                pattern = None
                try:
                    identification = identify(
                        outcome.actual_hash, db_session, config
                    )
                    candidate = (
                        next(
                            (
                                item
                                for item in identification.candidates
                                if vector.expected_mode is not None
                                and item.pattern.hashcat_mode == vector.expected_mode
                            ),
                            None,
                        )
                        or (
                            identification.candidates[0]
                            if identification.candidates
                            else None
                        )
                    )
                    if candidate is not None:
                        pattern = candidate.pattern
                        outcome.pattern = getattr(pattern, "name", None)
                        modes = [
                            item.pattern.hashcat_mode
                            for item in identification.candidates
                            if item.pattern.hashcat_mode is not None
                        ]
                        outcome.mode_ok = (
                            vector.expected_mode is None
                            or vector.expected_mode in modes
                        )
                    outcome.resolved = bool(identification.resolved)
                except NoCandidateError:
                    outcome.mode_ok = vector.expected_mode is None
                    outcome.resolved = False

                if crack:
                    if pattern is None:
                        outcome.cracked = None
                    else:
                        _evaluate_crack(
                            outcome, vector, pattern, config, temp_root, index
                        )
                outcome.status = (
                    "pass"
                    if outcome.hash_ok
                    and outcome.chain_ok
                    and outcome.terminal
                    and outcome.mode_ok
                    and (not crack or outcome.cracked is not False)
                    else "fail"
                )
            except Exception as exc:
                outcome.status = "fail"
                outcome.error = f"{type(exc).__name__}: {exc}"
            outcome.elapsed_ms = (time.perf_counter() - layer_started) * 1000
            outcomes.append(outcome)
    return LayerReport(
        outcomes=outcomes,
        elapsed_seconds=time.perf_counter() - started,
        crack_requested=crack,
    )
