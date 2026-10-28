#!/usr/bin/env python3
"""Benchmark layered recipe discovery and optional built-in cracking."""

from __future__ import annotations

import argparse
import json
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
from hashvault.layers import (
    DEFAULT_LAYER_CORPUS,
    benchmark_layers,
    load_layer_vectors,
)

console = Console()
PATTERNS_FILE = PROJECT_ROOT / "data" / "patterns" / "patterns.json"


def render(report, limit: int = 25) -> None:
    table = Table(title="HashVault Layered Recipe Benchmark")
    table.add_column("Case", style="cyan", no_wrap=True)
    table.add_column("Expected chain", style="dim")
    table.add_column("Actual chain", style="yellow")
    table.add_column("Pattern", style="green")
    table.add_column("Status", justify="center")
    table.add_column("Crack", justify="center")
    table.add_column("ms", justify="right")
    for outcome in report.outcomes[:limit]:
        crack = "-" if outcome.cracked is None else ("yes" if outcome.cracked else "no")
        table.add_row(
            outcome.id,
            " -> ".join(outcome.expected_operations) or "(bare)",
            " -> ".join(outcome.chain) or "(bare)",
            outcome.pattern or "-",
            "[green]PASS[/green]" if outcome.passed else "[red]FAIL[/red]",
            crack,
            f"{outcome.elapsed_ms:.1f}",
        )
    console.print(table)
    summary = report.summary()
    console.print(
        f"[bold]Layers:[/bold] {summary['passed']}/{summary['total']} passed, "
        f"chain {summary['chain_ok']}/{summary['total']}, "
        f"hash {summary['hash_ok']}/{summary['total']}, "
        f"mode {summary['mode_ok']}/{summary['total']}, "
        f"{summary['elapsed_seconds']:.2f}s"
    )
    if report.crack_requested:
        console.print(
            f"[bold]Cracking:[/bold] {summary['cracked']}/{summary['crack_attempted']} "
            "layered plaintexts verified"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_LAYER_CORPUS)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--crack", action="store_true")
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--show", type=int, default=25)
    parser.add_argument("--max-seconds", type=float, default=8.0)
    args = parser.parse_args()

    vectors = load_layer_vectors(args.corpus)
    if args.limit is not None:
        vectors = vectors[: max(0, args.limit)]
    config = load_config()
    with tempfile.TemporaryDirectory(prefix="hashvault-layer-bench-") as temp_dir:
        init_db(
            str(Path(temp_dir) / "layers.sqlite3"),
            seed_patterns_path=str(PATTERNS_FILE),
        )
        with get_db_session() as session:
            report = benchmark_layers(
                vectors,
                session,
                config,
                crack=args.crack,
                max_seconds=args.max_seconds,
            )
        reset_db_engine()
    payload = report.to_dict()
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        console.print(f"[green]Report written to[/green] {args.json}")
    render(report, args.show)
    return 0 if payload["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
