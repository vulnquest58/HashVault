"""Tests for the official auto2john component and conversion ranking bridge."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from typer.testing import CliRunner

import hashvault.ingestors.auto2john_bridge as bridge
from hashvault.auto2john import PROFILE_BY_KEY, Detection
from hashvault.auto2john import PROFILES as AUTO2JOHN_PROFILES
from hashvault.cli import app
from hashvault.ingestors.conversion_service import _rank_candidates
from hashvault.ingestors.john_catalog import find_profiles_for_path, get_profile

runner = CliRunner()


def _misnamed_docx(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
    return path


def _fake_tool_dir(tmp_path: Path) -> Path:
    store = tmp_path / "converters"
    archive_dir = store / "archives"
    archive_dir.mkdir(parents=True)
    (archive_dir / "zip2john.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "print(f'{Path(sys.argv[1]).name}:$zip$*0*1*616263')\n",
        encoding="utf-8",
    )
    return store


def test_vendored_engine_exposes_expected_profiles():
    assert len(AUTO2JOHN_PROFILES) == 57
    assert len({profile.key for profile in AUTO2JOHN_PROFILES}) == 57


def test_bridge_maps_auto2john_keys_to_gallery_profiles(monkeypatch):
    def fake_detect(_path: Path) -> Detection:
        return Detection(PROFILE_BY_KEY["applenotes"], "magic", "test")

    monkeypatch.setattr(bridge, "detect_profile", fake_detect)
    assert bridge.preferred_profile(Path("notes.sqlite")) is get_profile("notes")


def test_rank_candidates_uses_auto2john_for_misnamed_office(tmp_path):
    path = _misnamed_docx(tmp_path / "misnamed.zip")
    ranked = _rank_candidates(path, find_profiles_for_path(path))
    assert ranked[0].key == "office"


def test_rank_candidates_adds_auto2john_profile_without_gallery_match(tmp_path):
    path = _misnamed_docx(tmp_path / "misnamed.zip")
    assert [profile.key for profile in _rank_candidates(path, ())] == ["office"]


def test_cli_auto2john_lists_profiles():
    result = runner.invoke(app, ["auto2john", "--list", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload["profiles"]) == 57


def test_cli_auto2john_detects_misnamed_office(tmp_path):
    path = _misnamed_docx(tmp_path / "misnamed.zip")
    result = runner.invoke(
        app, ["auto2john", str(path), "--detect-only", "--json"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["detection"]["profile"] == "office"
    assert payload["detection"]["confidence"] == "magic"


def test_cli_auto2john_lists_managed_tools(tmp_path):
    store = _fake_tool_dir(tmp_path)
    result = runner.invoke(
        app,
        ["auto2john", "--list-tools", "--tool-dir", str(store), "--json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    by_profile = {row["profile"]: row for row in payload["tools"]}
    assert by_profile["zip"]["found"] is True


def test_cli_auto2john_converts_with_managed_store(tmp_path):
    path = tmp_path / "sample.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("hello.txt", "hello")
    store = _fake_tool_dir(tmp_path)
    out_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "auto2john",
            str(path),
            "--tool-dir",
            str(store),
            "--out-dir",
            str(out_dir),
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["detection"]["profile"] == "zip"
    assert payload["hashes"] == 1
    assert (out_dir / "sample.hash").exists()


def test_cli_auto2john_requires_target():
    result = runner.invoke(app, ["auto2john"])
    assert result.exit_code == 1
    assert "Provide a file path" in result.stdout
