"""Tests for the John conversion catalog, compatibility runner, and gallery CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import hashvault.ingestors.john_catalog as john_catalog
from hashvault.cli import app
from hashvault.ingestors.john_catalog import (
    PROFILES,
    GalleryRow,
    build_hashcat_command,
    build_john_command,
    convert_with_profile,
    filter_profiles,
    find_profiles_for_path,
    gallery_rows,
    get_profile,
    parse_converter_output,
)

runner = CliRunner()


def _fake_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "john-run"
    run_dir.mkdir()
    (run_dir / "john.exe").write_bytes(b"")
    (run_dir / "zip2john.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "name = Path(sys.argv[1]).name\n"
        "data = b'abc'\n"
        "print(f'{name}:$zip$*0*1*{data.encode(\"hex\")}')\n",
        encoding="utf-8",
    )
    (run_dir / "rar2john.exe").write_bytes(b"")
    return run_dir


def test_catalog_has_unique_profiles_and_formats():
    assert len(PROFILES) == 70
    assert len({profile.key for profile in PROFILES}) == len(PROFILES)
    assert get_profile("ZIP") is get_profile("zip")
    assert get_profile("zip2john") is get_profile("zip")


def test_find_profiles_prefers_exact_filename_hint(tmp_path):
    key4 = tmp_path / "key4.db"
    key4.write_bytes(b"")
    matches = find_profiles_for_path(key4)
    assert matches[0].key == "mozilla"


def test_find_profiles_detects_directory_markers(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "Manifest.plist").write_text("{}", encoding="utf-8")
    assert find_profiles_for_path(backup)[0].key == "itunes-backup"


def test_filter_profiles_matches_category_and_format():
    assert [profile.key for profile in filter_profiles("Password manager")] == [
        profile.key for profile in PROFILES if profile.category == "Password manager"
    ]
    assert filter_profiles("BitLocker")[0].key == "bitlocker"


def test_gallery_rows_reports_ready_and_missing(tmp_path, monkeypatch):
    run_dir = _fake_run_dir(tmp_path)
    monkeypatch.setattr(john_catalog, "john_run_dir", lambda _john_bin: run_dir)
    rows = gallery_rows("john", query="zip")
    by_key = {row.profile.key: row for row in rows}
    assert by_key["zip"].available
    assert by_key["zip"].runtime == "python"
    assert "converter not found" in by_key["7z"].reason


def test_parse_converter_output_filters_noise_and_duplicates():
    output = (
        "Warning: noisy\n"
        "# comment\n"
        "file.zip:$zip$one\n"
        "file.zip:$zip$one\n"
        "file.zip:$zip$two\n"
    )
    assert parse_converter_output(output) == [
        "file.zip:$zip$one",
        "file.zip:$zip$two",
    ]


def test_convert_with_profile_runs_legacy_python_helper(tmp_path, monkeypatch):
    run_dir = _fake_run_dir(tmp_path)
    monkeypatch.setattr(john_catalog, "john_run_dir", lambda _john_bin: run_dir)
    source = tmp_path / "sample.zip"
    source.write_bytes(b"not a real archive")
    result = convert_with_profile("zip", source, john_bin="john")
    assert result.success
    assert result.format_detected == "zip"
    assert result.hashes[0].raw_hash.endswith("$zip$*0*1*616263")
    assert result.hashes[0].tool_used == "zip2john"
    assert result.hashes[0].hashcat_mode == 17200


def test_build_commands_include_mode_and_quoting():
    profile = get_profile("zip")
    assert profile is not None
    assert build_hashcat_command(profile, "hashes.john", "words.txt").startswith(
        "hashcat -m 17200 -a 0"
    )
    command = build_john_command(profile, "hash file.john", "words.txt")
    assert '"hash file.john"' in command
    assert "--format=ZIP" in command
    assert build_hashcat_command(get_profile("dmg"), "hashes.john", "words.txt") == ""


def test_cli_gallery_json():
    result = runner.invoke(
        app,
        ["convert", "--gallery", "--json", "--filter", "keepass"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["profiles"][0]["profile"] == "keepass"
    assert data["profiles"][0]["hashcat_mode"] == 13400


def test_cli_profile_conversion_json_and_hash_out(tmp_path, monkeypatch):
    run_dir = _fake_run_dir(tmp_path)
    monkeypatch.setattr(john_catalog, "john_run_dir", lambda _john_bin: run_dir)
    source = tmp_path / "sample.zip"
    source.write_bytes(b"not a real archive")
    hash_out = tmp_path / "hashes.john"
    result = runner.invoke(
        app,
        [
            "convert",
            str(source),
            "--profile",
            "zip",
            "--json",
            "--hash-out",
            str(hash_out),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["success"]
    assert data["profile"] == "zip"
    assert data["commands"]["hashcat"].startswith("hashcat -m 17200")
    assert data["hashes"][0]["raw_hash"].endswith("$zip$*0*1*616263")
    assert hash_out.read_text(encoding="utf-8").endswith("$zip$*0*1*616263\n")


def test_interactive_gallery_selects_profile(tmp_path, monkeypatch):
    import hashvault.cli as cli_module
    from hashvault.config import load_config
    from hashvault.ui import interactive

    key_dir = tmp_path / "key dir"
    key_dir.mkdir()
    key = key_dir / "id_ed25519"
    key.write_text("not a real key", encoding="utf-8")

    class FakeCompleter:
        def refresh(self) -> None:
            pass

    class FakeSession:
        def __init__(self, *args, **kwargs) -> None:
            self.answers = iter([f'gallery "{key}"', "1", "exit"])

        def prompt(self, *args, **kwargs) -> str:
            return next(self.answers)

    calls = []

    class FakeApp:
        def __call__(self, args, standalone_mode=True) -> None:
            calls.append(args)

    monkeypatch.setattr(interactive, "PromptSession", FakeSession)
    monkeypatch.setattr(interactive, "RefreshableCompleter", FakeCompleter)
    monkeypatch.setattr(
        interactive, "get_secure_history_path", lambda: tmp_path / "history"
    )
    monkeypatch.setattr(cli_module, "app", FakeApp())

    ssh_profile = get_profile("ssh")
    assert ssh_profile is not None
    row = GalleryRow(
        profile=ssh_profile,
        converter_name="ssh2john.py",
        runtime="python",
        available=True,
        reason="",
    )
    monkeypatch.setattr(
        john_catalog, "gallery_rows", lambda *args, **kwargs: (row,)
    )

    interactive.start_interactive_shell(load_config())

    assert calls == [["convert", str(key), "--profile", "ssh"]]
