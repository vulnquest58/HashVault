"""
Rich live view for the bounded analysis search.

The listener API lives in ``analysis.search``; this module is intentionally
presentation-only and is imported only when ``--live`` is requested.
"""

from __future__ import annotations

import time
from typing import List, Optional

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hashvault.analysis.recipe import AnalysisTrace
from hashvault.analysis.validators import InputProfile, summarize_hash


class RichAnalysisLive:
    """Streaming Rich view implementing the analysis listener protocol."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console(highlight=False)
        self.started = time.monotonic()
        self.depth = 0
        self.operation = ""
        self.nodes = 0
        self.profile: Optional[InputProfile] = None
        self.terminals: List[AnalysisTrace] = []
        self.best: Optional[AnalysisTrace] = None
        self.finished = False
        self._live: Optional[Live] = None

    def __enter__(self) -> "RichAnalysisLive":
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=10,
            transient=False,
            auto_refresh=True,
        )
        self._live.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.finished = True
        if self._live is not None:
            self._live.update(self._render(), refresh=True)
            self._live.stop()
            self._live = None

    def _render(self) -> Panel:
        elapsed = time.monotonic() - self.started
        header = Table.grid(expand=True)
        header.add_column(justify="left")
        header.add_column(justify="right")
        header.add_row(
            Text("HashVault Deep Analysis", style="bold cyan"),
            Text(
                f"{elapsed:5.2f}s  |  {self.nodes} nodes  |  depth {self.depth}",
                style="dim",
            ),
        )

        if self.profile is not None:
            state = Text(
                f"Input: {self.profile.kind}  "
                f"len={self.profile.length}  "
                f"hashes={self.profile.hash_tokens}  "
                f"entropy={self.profile.entropy:.2f}",
                style="white",
            )
            if self.operation and not self.finished:
                state.append(f"   probing: {self.operation}", style="yellow")
            elif self.finished:
                state.append("   complete", style="green")
        else:
            state = Text("Profiling input...", style="dim")

        table = Table(
            box=None,
            show_header=True,
            header_style="bold blue",
            expand=True,
            pad_edge=False,
        )
        table.add_column("Chain", style="cyan", ratio=3)
        table.add_column("Candidate", style="green", ratio=3)
        table.add_column("Score", justify="right", width=7)
        table.add_column("Layers", justify="right", width=6)

        traces = list(self.terminals[:5])
        if self.best is not None and self.best not in traces:
            traces.insert(0, self.best)
        for trace in traces:
            table.add_row(
                trace.describe(),
                summarize_hash(trace.finalized_input, 64),
                f"{trace.score:.2f}",
                str(trace.layers_applied),
            )
        if not traces:
            table.add_row("(searching)", "[dim]no terminal branch yet[/dim]", "", "")

        footer = Text(
            "Terminal hashes are ranked by structural confidence; "
            "the cracker receives the best candidate.",
            style="dim",
        )
        return Panel(
            Group(header, state, Text(""), table, footer),
            border_style="cyan" if not self.finished else "green",
            padding=(0, 1),
        )

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(self._render(), refresh=True)

    def on_start(self, raw_input: str, profile: InputProfile) -> None:
        self.profile = profile
        self.operation = ""
        self._refresh()

    def on_expand(self, depth: int, node, operation, score: float) -> None:
        self.depth = depth
        self.operation = operation.name
        self.nodes += 1
        self._refresh()

    def on_result(self, depth: int, node, operation, result, terminal: bool) -> None:
        if terminal:
            self.operation = f"{operation.name} -> terminal branch"

    def on_terminal(self, trace: AnalysisTrace) -> None:
        self.terminals.append(trace)
        self.terminals = sorted(
            {t.finalized_input: t for t in self.terminals}.values(),
            key=lambda item: item.score,
            reverse=True,
        )[:12]
        self._refresh()

    def on_complete(self, result) -> None:
        self.best = result.best
        self.nodes = result.nodes_expanded
        self.depth = result.best.layers_applied
        self.finished = True
        self._refresh()
