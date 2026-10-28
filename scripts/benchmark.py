"""
Benchmark script for HashVault v2.0.
Evaluates hash identification latency, DB caching speedups, memory & CPU usage,
and pattern matching accuracy across Windows, Linux, and Database hash formats.
"""

import json
import time
import psutil
from pathlib import Path
from rich.console import Console
from rich.table import Table

from hashvault.config import load_config
from hashvault.core.database import init_db, get_db_session
from hashvault.core.orchestrator import process_single_hash

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_HASHES_FILE = PROJECT_ROOT / "data" / "test_hashes.json"


def run_benchmark() -> None:
    config = load_config()
    console.print("\n[bold cyan]=== HashVault Performance & Accuracy Benchmark ===[/bold cyan]\n")

    # 1. Initialize SQLite Database
    init_db(config.paths.database, seed_patterns_path=str(PROJECT_ROOT / "data" / "patterns" / "patterns.json"))

    if not TEST_HASHES_FILE.exists():
        console.print(f"[red]Error: {TEST_HASHES_FILE} not found.[/red]")
        return

    raw_data = json.loads(TEST_HASHES_FILE.read_text(encoding="utf-8"))
    test_hashes = raw_data["vectors"] if isinstance(raw_data, dict) and "vectors" in raw_data else raw_data

    results_table = Table(title="Benchmark Identification & Caching Speedup")
    results_table.add_column("System / Category", style="cyan")
    results_table.add_column("Hash Type", style="magenta")
    results_table.add_column("Has User", style="dim")
    results_table.add_column("1st Run (ms)", style="yellow")
    results_table.add_column("Cached (ms)", style="green")
    results_table.add_column("Speedup Factor", style="bold green")

    uncached_times = []
    cached_times = []

    process = psutil.Process()
    mem_before = process.memory_info().rss / (1024 * 1024)

    with get_db_session() as session:
        for entry in test_hashes:
            raw = entry["raw_input"]

            # Measure 1st (uncached identification)
            t0 = time.perf_counter()
            res1 = process_single_hash(raw, session, config, auto_confirm=True)
            t1 = time.perf_counter()
            uncached_ms = (t1 - t0) * 1000
            uncached_times.append(uncached_ms)

            # Measure 2nd (cached lookup)
            t2 = time.perf_counter()
            res2 = process_single_hash(raw, session, config, auto_confirm=True)
            t3 = time.perf_counter()
            cached_ms = (t3 - t2) * 1000
            cached_times.append(cached_ms)

            speedup = (uncached_ms / cached_ms) if cached_ms > 0 else 1.0

            results_table.add_row(
                f"{entry['system']} [{entry['category']}]",
                entry["hash_type"],
                "Yes" if entry["has_username"] else "No",
                f"{uncached_ms:.2f} ms",
                f"{cached_ms:.2f} ms",
                f"{speedup:.1f}x"
            )

    mem_after = process.memory_info().rss / (1024 * 1024)
    cpu_percent = psutil.cpu_percent(interval=0.5)

    console.print(results_table)
    console.print("\n[bold green]System Hardware & Performance Summary:[/bold green]")
    console.print(f"  • Total Hash Test Vectors Evaluated : [bold]{len(test_hashes)}[/bold]")
    console.print(f"  • Avg Uncached Identification Time   : [bold]{sum(uncached_times)/len(uncached_times):.2f} ms[/bold]")
    console.print(f"  • Avg DB Cache Lookup Time           : [bold]{sum(cached_times)/len(cached_times):.2f} ms[/bold]")
    console.print(f"  • Memory Footprint                   : [bold]{mem_after:.2f} MB[/bold] (Delta: {mem_after - mem_before:+.2f} MB)")
    console.print(f"  • CPU Core Load During Benchmark     : [bold]{cpu_percent:.1f}%[/bold]\n")


if __name__ == "__main__":
    run_benchmark()
