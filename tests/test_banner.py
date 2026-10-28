"""Tests for the project banner (wordmark, credits, colour preservation)."""

from __future__ import annotations

from hashvault.ui.banner import (
    BANNER_LINES,
    GITHUB_URL,
    PROJECT_NAME,
    banner_payload,
    banner_text,
    credits_lines,
    strip_ansi,
)


def test_wordmark_has_three_rows():
    assert len(BANNER_LINES) == 3


def test_wordmark_keeps_every_glyph_when_stripped():
    """The plain form must be exactly the art with ANSI removed, nothing lost."""
    plain = banner_text().splitlines()
    assert len(plain) == 3
    for original, stripped in zip(BANNER_LINES, plain):
        assert stripped == strip_ansi(original)
        # No escape sequence may survive into the plain form.
        assert "\x1b" not in stripped


def test_wordmark_contains_the_expected_block_glyphs():
    plain = banner_text()
    for glyph in ("▄", "█", "▀"):
        assert glyph in plain


def test_colour_runs_survive_in_the_raw_lines():
    """Colours are part of the supplied art, not decoration we may drop."""
    joined = "\n".join(BANNER_LINES)
    assert "\x1b[" in joined
    assert "96m" in joined  # bright cyan
    assert "36m" in joined  # cyan
    assert "37m" in joined  # white
    for line in BANNER_LINES:
        assert line.endswith("\x1b[0m"), "each row must reset the style"


def test_rich_can_render_the_colours():
    """Rich must parse the art without losing characters."""
    from rich.text import Text

    for line in BANNER_LINES:
        rendered = Text.from_ansi(line).plain
        assert rendered == strip_ansi(line)
        assert rendered.strip()


def test_credits_show_name_and_github():
    lines = credits_lines()
    assert any(PROJECT_NAME in line for line in lines)
    assert any(GITHUB_URL in line for line in lines)


def test_payload_is_plain_text_and_complete():
    payload = banner_payload()
    assert payload["project"] == PROJECT_NAME
    assert payload["github"] == GITHUB_URL
    assert payload["author"] in payload["github"]
    assert "\x1b" not in payload["wordmark"]
    assert payload["wordmark"].count("\n") == 2


def test_strip_ansi_handles_plain_text():
    assert strip_ansi("no colours here") == "no colours here"
    assert strip_ansi("\x1b[0;96m▄\x1b[0m") == "▄"


def test_banner_command_runs():
    from typer.testing import CliRunner

    from hashvault.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["banner", "--plain"])
    assert result.exit_code == 0
    assert "vulnquest" in result.stdout
    assert "github.com/vulnquest58" in result.stdout


def test_banner_command_json_mode():
    import json

    from typer.testing import CliRunner

    from hashvault.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["banner", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["project"] == "vulnquest"
    assert payload["github"] == "https://github.com/vulnquest58"
