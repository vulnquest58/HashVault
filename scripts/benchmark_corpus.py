#!/usr/bin/env python3
"""Benchmark HashVault against the Hashcat and 0xdf corpora."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table

from hashvault.config import load_config
from hashvault.core.database import get_db_session, init_db, reset_db_engine
from hashvault.core.identifier import get_identifier
from hashvault.corpus import (
    CANDIDATE_ONLY,
    DEFAULT_CORPUS_FILES,
    CrackingReport,
    IdentificationReport,
    evaluate_cracking,
    evaluate_identification,
    load_corpora,
    load_corpus_from_db,
    load_default_corpora,
)

console = Console()
PATTERNS_FILE = PROJECT_ROOT / "data" / "patterns" / "patterns.json"


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _source_breakdown(report: IdentificationReport) -> Table:
    table = Table(title="Identification by source")
    table.add_column("Source", style="cyan")
    table.add_column("Entries", justify="right")
    table.add_column("Evaluated", justify="right")
    table.add_column("Exact", justify="right", style="green")
    table.add_column("In candidates", justify="right", style="yellow")
    table.add_column("Mismatch", justify="right", style="red")
    table.add_column("Skipped", justify="right", style="dim")

    sources = sorted({outcome.source for outcome in report.outcomes})
    for source in sources:
        rows = [outcome for outcome in report.outcomes if outcome.source == source]
        evaluated = [row for row in rows if row.status != "skipped"]
        exact = sum(1 for row in evaluated if row.status == "exact")
        in_candidates = sum(
            1 for row in evaluated if row.status in {"exact", CANDIDATE_ONLY}
        )
        mismatch = sum(1 for row in evaluated if row.status == "mismatch")
        table.add_row(
            source,
            str(len(rows)),
            str(len(evaluated)),
            str(exact),
            str(in_candidates),
            str(mismatch),
            str(len(rows) - len(evaluated)),
        )
    return table


def _ranking_gaps(report: IdentificationReport, limit: int) -> Table:
    table = Table(title="Ranking gaps (expected type present but not top-1)")
    table.add_column("Entry", style="cyan", no_wrap=True)
    table.add_column("Expected", style="green")
    table.add_column("Top candidate", style="yellow")
    table.add_column("Conf.", justify="right")
    table.add_column("Rank", justify="right")
    table.add_column("Resolved", justify="center")

    gaps = [
        outcome
        for outcome in report.outcomes
        if outcome.status == CANDIDATE_ONLY
    ]
    gaps.sort(
        key=lambda outcome: (
            outcome.expected_mode not in outcome.candidate_modes,
            outcome.id,
        )
    )
    for outcome in gaps[:limit]:
        try:
            rank = outcome.candidate_modes.index(outcome.expected_mode) + 1
        except ValueError:
            rank = 0
        table.add_row(
            outcome.id,
            f"{outcome.expected_mode} {outcome.expected_name}",
            f"{outcome.top_mode} {outcome.top_name}",
            f"{outcome.confidence:.2f}" if outcome.confidence is not None else "-",
            str(rank),
            "yes" if outcome.resolved else "no",
        )
    return table


def _mismatch_table(report: IdentificationReport, limit: int) -> Table:
    table = Table(title=f"Identification mismatches (first {limit})")
    table.add_column("Entry", style="cyan", no_wrap=True)
    table.add_column("Expected", style="green")
    table.add_column("Top candidate", style="yellow")
    table.add_column("Conf.", justify="right")
    table.add_column("Candidates", justify="right")
    for outcome in report.mismatches[:limit]:
        table.add_row(
            outcome.id,
            f"{outcome.expected_mode} {outcome.expected_name}",
            f"{outcome.top_mode} {outcome.top_name}",
            f"{outcome.confidence:.2f}" if outcome.confidence is not None else "-",
            str(len(outcome.candidate_modes)),
        )
    return table


def _crack_failures(report: CrackingReport, limit: int) -> Table:
    table = Table(title=f"Cracking failures (first {limit})")
    table.add_column("Entry", style="cyan", no_wrap=True)
    table.add_column("Mode", justify="right")
    table.add_column("Status", style="red")
    table.add_column("Error", style="dim")
    failures = [
        outcome
        for outcome in report.outcomes
        if outcome.status in {"failed", "error", "plaintext_mismatch"}
    ]
    for outcome in failures[:limit]:
        table.add_row(
            outcome.id,
            str(outcome.mode),
            outcome.status,
            (outcome.error or "")[:120],
        )
    return table


def _write_json(path: str | Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        choices=("all", "hashcat", "0xdf", "crypto"),
        default="all",
        help="Which built-in corpus to load.",
    )
    parser.add_argument(
        "--from-db",
        action="store_true",
        help="Seed/load corpus entries from the SQLite database instead of JSON files.",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        action="append",
        default=[],
        help="Additional corpus JSON file (repeatable).",
    )
    parser.add_argument("--limit", type=int, default=None, help="Evaluate at most N entries.")
    parser.add_argument(
        "--include-unusable",
        action="store_true",
        help="Attempt identification for truncated/binary examples too.",
    )
    parser.add_argument("--crack", action="store_true", help="Also run the built-in cracker.")
    parser.add_argument(
        "--wordlist",
        type=Path,
        default=None,
        help="Optional real wordlist for cracking (default: per-entry known plaintext).",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=None,
        help="Cap candidates per cracking attempt.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Write the full report as JSON.",
    )
    parser.add_argument(
        "--show-gaps",
        type=int,
        default=10,
        help="Number of ranking-gap rows to print.",
    )
    parser.add_argument(
        "--show-mismatches",
        type=int,
        default=10,
        help="Number of mismatch rows to print.",
    )
    parser.add_argument(
        "--show-failures",
        type=int,
        default=10,
        help="Number of cracking-failure rows to print.",
    )
    args = parser.parse_args()

    config = load_config()
    temp_db_dir: Optional[str] = None
    if args.from_db:
        init_db(
            config.paths.database,
            seed_patterns_path=str(PATTERNS_FILE),
            seed_corpus_paths=DEFAULT_CORPUS_FILES,
        )
        with get_db_session() as session:
            entries = load_corpus_from_db(
                session,
                None if args.source == "all" else (args.source,),
            )
        loaded_from = "database"
    else:
        # Use a clean catalogue so stale rows in a developer DB cannot change
        # benchmark results. DB-backed runs are available via --from-db.
        temp_db_dir = tempfile.mkdtemp(prefix="hashvault-benchmark-")
        init_db(
            str(Path(temp_db_dir) / "benchmark.sqlite3"),
            seed_patterns_path=str(PATTERNS_FILE),
        )
        if args.source == "all":
            entries = load_default_corpora()
        else:
            entries = load_default_corpora((args.source,))
        loaded_from = args.source
    if args.corpus:
        entries.extend(load_corpora(args.corpus))
    if args.limit is not None:
        entries = entries[: max(0, args.limit)]

    with get_db_session() as session:
        identifier = get_identifier(session)
        identification = evaluate_identification(
            entries,
            identifier,
            config=config,
            include_unusable=args.include_unusable,
        )
        # Every identification candidate is needed for JSON reporting; keep the
        # DB session open only long enough to build the identifier.
        session.expunge_all()

    identification_summary = identification.summary()
    console.print("\n[bold cyan]=== HashVault Corpus Benchmark ===[/bold cyan]")
    console.print(
        f"Loaded [bold]{len(entries)}[/bold] entries from "
        f"[bold]{loaded_from}[/bold]"
        + (f" plus {len(args.corpus)} extra file(s)" if args.corpus else "")
    )

    summary_table = Table(title="Identification summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", justify="right")
    rows = (
        ("Total entries", identification_summary["total_entries"]),
        ("Evaluated", identification_summary["evaluated"]),
        ("Skipped unusable", identification_summary["skipped"]),
        (
            "Exact top-1",
            f"{identification_summary['exact']} "
            f"({_percent(identification_summary['top1_accuracy'])})",
        ),
        (
            "Expected in candidates",
            f"{identification_summary['identified_any']} "
            f"({_percent(identification_summary['candidate_coverage'])})",
        ),
        ("Resolved", identification_summary["resolved"]),
        ("Mismatches", identification_summary["mismatch"]),
        ("No candidates", identification_summary["no_candidates"]),
        ("Errors", identification_summary["errors"]),
        (
            "Elapsed",
            f"{identification_summary['elapsed_seconds']:.3f}s "
            f"({identification_summary['avg_ms']:.3f} ms/hash)",
        ),
    )
    for metric, value in rows:
        summary_table.add_row(metric, str(value))
    console.print(summary_table)
    console.print(_source_breakdown(identification))

    if identification.mismatches and args.show_mismatches:
        console.print(_mismatch_table(identification, args.show_mismatches))
    if args.show_gaps and any(
        outcome.status == CANDIDATE_ONLY for outcome in identification.outcomes
    ):
        console.print(_ranking_gaps(identification, args.show_gaps))

    payload: dict[str, Any] = {"identification": identification.to_dict()}

    if args.crack:
        cracking = evaluate_cracking(
            entries,
            config,
            wordlist_path=args.wordlist,
            max_candidates=args.max_candidates,
            include_unusable=args.include_unusable,
        )
        payload["cracking"] = cracking.to_dict()
        cracking_summary = cracking.summary()
        crack_table = Table(title="Cracking summary (built-in engine)")
        crack_table.add_column("Metric", style="cyan")
        crack_table.add_column("Value", justify="right")
        crack_rows = (
            ("Attempted", cracking_summary["attempted"]),
            (
                "Cracked",
                f"{cracking_summary['cracked']} "
                f"({_percent(cracking_summary['success_rate'])})",
            ),
            ("Failed", cracking_summary["failed"]),
            ("Plaintext mismatch", cracking_summary["plaintext_mismatch"]),
            ("Errors", cracking_summary["errors"]),
            ("Skipped unsupported", cracking_summary["skipped"]),
            ("Elapsed", f"{cracking_summary['elapsed_seconds']:.3f}s"),
        )
        for metric, value in crack_rows:
            crack_table.add_row(metric, str(value))
        console.print(crack_table)
        if args.show_failures and any(
            outcome.status in {"failed", "error", "plaintext_mismatch"}
            for outcome in cracking.outcomes
        ):
            console.print(_crack_failures(cracking, args.show_failures))

    if args.json:
        _write_json(args.json, payload)
        console.print(f"\nWrote JSON report to [bold]{args.json}[/bold]")

    if temp_db_dir:
        reset_db_engine()
        shutil.rmtree(temp_db_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
