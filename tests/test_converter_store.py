"""Tests for the managed converter store and unified auto-conversion."""

from __future__ import annotations

import json
from pathlib import Path

from hashvault.ingestors import john_catalog
from hashvault.ingestors.conversion_service import convert_auto
from hashvault.ingestors.converter_store import (
    converter_store_status,
    find_stored_converter,
    sync_converters,
)
from hashvault.ingestors.john_catalog import get_profile


def _fake_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "john-run"
    run_dir.mkdir()
    (run_dir / "john.exe").write_bytes(b"")
    (run_dir / "zip2john.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "name = Path(sys.argv[1]).name\n"
        "print(f'{name}:$zip$*0*1*616263')\n",
        encoding="utf-8",
    )
    (run_dir / "rar2john.exe").write_bytes(b"")
    (run_dir / "jtrconf.pm").write_text("# shared module\n", encoding="utf-8")
    return run_dir


def test_sync_copies_converters_and_writes_manifest(tmp_path, monkeypatch):
    run_dir = _fake_run_dir(tmp_path)
    monkeypatch.setattr(john_catalog, "john_run_dir", lambda _john_bin: run_dir)
    destination = tmp_path / "store"
    profiles = [get_profile("zip"), get_profile("rar")]

    report = sync_converters(
        "john", destination, profiles=profiles
    )

    assert report.stored == 2
    assert (destination / "archive" / "zip2john.py").is_file()
    assert (destination / "archive" / "rar2john.exe").is_file()
    assert (destination / "lib" / "jtrconf.pm").is_file()
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert {item["profile"] for item in manifest["files"]} == {"zip", "rar"}
    assert find_stored_converter(get_profile("zip"), destination) == (
        destination / "archive" / "zip2john.py"
    )


def test_sync_keeps_existing_files_without_force(tmp_path, monkeypatch):
    run_dir = _fake_run_dir(tmp_path)
    monkeypatch.setattr(john_catalog, "john_run_dir", lambda _john_bin: run_dir)
    destination = tmp_path / "store"
    profiles = [get_profile("zip")]
    sync_converters("john", destination, profiles=profiles)
    target = destination / "archive" / "zip2john.py"
    target.write_text("local patch\n", encoding="utf-8")

    report = sync_converters("john", destination, profiles=profiles)

    assert report.entries[0].status == "kept"
    assert target.read_text(encoding="utf-8") == "local patch\n"


def test_converter_store_status_reports_missing_profiles(tmp_path):
    destination = tmp_path / "store"
    destination.mkdir()
    (destination / "archive").mkdir()
    (destination / "archive" / "zip2john.py").write_text("", encoding="utf-8")

    status = converter_store_status(
        destination, profiles=[get_profile("zip"), get_profile("rar")]
    )

    assert status.converters == 1
    assert status.missing == ["rar"]
    assert status.to_dict()["ok"] is False


def test_auto_conversion_uses_john_profile(tmp_path, monkeypatch):
    run_dir = _fake_run_dir(tmp_path)
    monkeypatch.setattr(john_catalog, "john_run_dir", lambda _john_bin: run_dir)
    source = tmp_path / "sample.zip"
    source.write_bytes(b"not a real archive")

    result = convert_auto(source, john_bin="john")

    assert result.success
    assert result.profile == "zip"
    assert result.format_detected == "zip"
    assert any("zip: success" in attempt for attempt in result.attempts)


def test_john_alias_resolves_converter_profile():
    assert get_profile("john2rar") is get_profile("rar")
    assert get_profile("john2zip") is get_profile("zip")
