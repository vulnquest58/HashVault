"""Shared Rich rendering for the John conversion gallery."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

from hashvault.ingestors.john_catalog import GalleryRow


def render_conversion_gallery(
    console: Console,
    rows: tuple[GalleryRow, ...],
    *,
    title: str = "John Conversion Gallery",
    include_numbers: bool = False,
) -> None:
    """Render conversion profiles and runtime availability."""
    table = Table(
        title=title,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
    )
    if include_numbers:
        table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Profile", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta", no_wrap=True)
    table.add_column("Input", overflow="fold")
    table.add_column("Converter", style="green", overflow="fold")
    table.add_column("John", style="yellow", no_wrap=True)
    table.add_column("Status", overflow="fold")
    for index, row in enumerate(rows, 1):
        status = "ready" if row.available else row.reason
        status_text = (
            f"[green]{status}[/green]"
            if row.available
            else f"[yellow]{status}[/yellow]"
        )
        values = [
            row.profile.key,
            row.profile.category,
            row.profile.source_label,
            row.converter_name,
            row.profile.john_format or "auto",
            status_text,
        ]
        if include_numbers:
            values.insert(0, str(index))
        table.add_row(*values)
    console.print(table)
