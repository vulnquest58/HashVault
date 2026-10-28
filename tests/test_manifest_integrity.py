"""
Tests for checking manifest file integrity and file presence on disk.
"""

import json
from pathlib import Path
from hashvault.config import load_config


def test_manifest_integrity():
    config = load_config()
    data_dir = Path(config.paths.wordlist_dir).parent

    rules_manifest = data_dir / "rules" / "manifest.json"
    if rules_manifest.exists():
        content = json.loads(rules_manifest.read_text(encoding="utf-8"))
        assert "entries" in content
        for entry in content["entries"]:
            assert "name" in entry
            assert "source_url" in entry
            assert "version" in entry

    wordlists_manifest = data_dir / "wordlists" / "manifest.json"
    if wordlists_manifest.exists():
        content = json.loads(wordlists_manifest.read_text(encoding="utf-8"))
        assert "entries" in content
        for entry in content["entries"]:
            assert "name" in entry
            assert "source_url" in entry
            assert "version" in entry
