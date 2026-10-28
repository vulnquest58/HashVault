"""Project banner: ASCII wordmark, project name and the maintainer link.

The wordmark is reproduced exactly as supplied, including its original
two-tone ANSI styling (bright cyan / cyan on white).  It is stored as raw ANSI
and converted with :meth:`rich.text.Text.from_ansi` so the colours survive
without hand-rebuilding the escape structure, and stripped for contexts that
cannot render colour (JSON output, redirected files, tests).
"""

from __future__ import annotations

import re

PROJECT_NAME = "vulnquest"
GITHUB_USER = "vulnquest58"
GITHUB_URL = "https://github.com/vulnquest58"
REPOSITORY_NAME = "HashVault"

RESET = "\x1b[0m"
BRIGHT_CYAN = "\x1b[0;96m"
CYAN = "\x1b[0;36m"
WHITE = "\x1b[0;37m"

# Verbatim wordmark, three rows.  Colour runs are preserved from the original.
def _mark(bc: str = BRIGHT_CYAN, c: str = CYAN, w: str = WHITE, r: str = RESET) -> list[str]:
    return [
        f"{bc}▄{w} {c}▄{w} {bc}▄{c}▄{w}  {bc}▄{c}▄▄{w}  "
        f"{bc}▄{w} {c}▄{w} {bc}▄{w} {c}▄{w} {bc}▄{c}▄{w}  "
        f"{bc}▄{w} {c}▄{w} {bc}▄{w}   {bc}▄{c}▄▄{r}",
        f"{c}█▄█{w} {c}█▄█{w} {c}▀▄{w}  {c}█▄█{w} {c}█{w} {c}█{w} "
        f"{c}█▄█{w} {c}█{w} {c}█{w} {c}█{w}    {c}█{r}",
        f"{c}█{w} {c}█{w} {c}█{w} {c}█{w} {c}▄▄▀{w} {c}█{w} {c}█{w} "
        f"{c}▀▄▀{w} {c}█{w} {c}█{w} {c}▀▄█{w} {c}█▄▄{w}  {c}█{r}",
    ]


BANNER_LINES: tuple[str, ...] = tuple(_mark())

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def banner_text() -> str:
    """Plain-text banner (wordmark + credits) with ANSI stripped.

    Used for JSON output, log files and tests so the identity of the tool is
    available without a terminal.
    """
    return "\n".join(strip_ansi(line) for line in BANNER_LINES)


def strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)


def credits_lines() -> list[str]:
    """Human-readable attribution shown under the wordmark."""
    return [
        f"  {PROJECT_NAME}",
        f"  {GITHUB_URL}",
        f"  {GITHUB_URL}/{REPOSITORY_NAME}",
    ]


def banner_payload() -> dict[str, str]:
    """Machine-readable identity block for ``--json`` consumers."""
    return {
        "project": PROJECT_NAME,
        "author": GITHUB_USER,
        "github": GITHUB_URL,
        "repository": f"{GITHUB_URL}/{REPOSITORY_NAME}",
        "wordmark": banner_text(),
    }


def render_banner(console) -> None:  # type: ignore[no-untyped-def]
    """Print the coloured banner and credits to a Rich console."""
    from rich.text import Text

    for line in BANNER_LINES:
        try:
            console.print(Text.from_ansi(line))
        except Exception:  # pragma: no cover - exotic terminal
            console.print(strip_ansi(line))

    console.print()
    console.print(f"  [bold bright_cyan]{PROJECT_NAME}[/bold bright_cyan]")
    console.print(f"  [dim]{GITHUB_URL}[/dim]")
    console.print(f"  [dim]{GITHUB_URL}/{REPOSITORY_NAME}[/dim]")
    console.print()
