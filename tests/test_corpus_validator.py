"""Tests for the corpus schema and provenance validator."""

from __future__ import annotations

import json

from hashvault.core.corpus_validator import (
    validate_corpus_dir,
    validate_corpus_file,
)


def _write(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _entry(**overrides):
    entry = {
        "id": "case-1",
        "raw_input": "5f4dcc3b5aa765d61d8327deb882cf99",
        "mode": 0,
        "name": "MD5",
        "source": "test",
        "expected_plaintext": "password",
        "reference": "https://example.test/case",
        "usable_for_identification": True,
        "usable_for_cracking": True,
    }
    entry.update(overrides)
    return entry


def test_valid_corpus_file_has_no_errors(tmp_path):
    corpus = _write(
        tmp_path / "cases.json",
        {
            "schema_version": 1,
            "source": "test",
            "counts": {"total": 1, "with_plaintext": 1},
            "cases": [_entry()],
        },
    )
    report = validate_corpus_file(corpus)
    assert report.errors == []
    assert report.cases == 1


def test_count_mismatch_is_an_error(tmp_path):
    corpus = _write(
        tmp_path / "cases.json",
        {
            "schema_version": 1,
            "source": "test",
            "counts": {"total": 2},
            "cases": [_entry()],
        },
    )
    codes = [issue.code for issue in validate_corpus_file(corpus).errors]
    assert "count_mismatch" in codes


def test_duplicate_and_unstable_ids_are_reported(tmp_path):
    corpus = _write(
        tmp_path / "cases.json",
        {
            "schema_version": 1,
            "source": "test",
            "cases": [_entry(), _entry(id="case-1"), _entry(id="bad id")],
        },
    )
    issues = validate_corpus_file(corpus).issues
    assert any(issue.code == "duplicate_id" for issue in issues)
    assert any(issue.code == "unstable_id" for issue in issues)


def test_cracking_case_requires_plaintext_and_mode(tmp_path):
    corpus = _write(
        tmp_path / "cases.json",
        {
            "schema_version": 1,
            "source": "test",
            "cases": [
                _entry(expected_plaintext=None),
                _entry(id="case-2", mode=None),
            ],
        },
    )
    codes = {issue.code for issue in validate_corpus_file(corpus).errors}
    assert "cracking_without_plaintext" in codes
    assert "cracking_without_mode" in codes


def test_multiline_hash_is_rejected(tmp_path):
    corpus = _write(
        tmp_path / "cases.json",
        {
            "schema_version": 1,
            "source": "test",
            "cases": [_entry(raw_input="abc\ndef")],
        },
    )
    codes = {issue.code for issue in validate_corpus_file(corpus).errors}
    assert "multiline_raw_input" in codes


def test_cross_file_duplicate_ids_are_reported(tmp_path):
    _write(
        tmp_path / "a.json",
        {"schema_version": 1, "source": "test", "cases": [_entry()]},
    )
    _write(
        tmp_path / "b.json",
        {
            "schema_version": 1,
            "source": "test",
            "cases": [_entry(raw_input="another")],
        },
    )
    report = validate_corpus_dir(tmp_path)
    assert report.duplicate_ids == ["case-1"]
    assert not report.ok


def test_shipped_corpus_is_valid():
    report = validate_corpus_dir()
    assert report.ok, [issue.to_dict() for issue in report.errors]
    assert report.total_cases >= 680
