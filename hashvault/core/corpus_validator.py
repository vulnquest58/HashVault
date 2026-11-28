"""Validate curated corpus files before they are trusted as evidence.

The corpus is a public claim: every case should have a stable id, a source,
a usable hash value, and consistent counts.  This validator checks those
invariants and flags duplicate ids, missing provenance, and contradictory
identification/cracking flags.  It deliberately does not re-crack every case;
that is the job of ``hashvault evaluate`` and the test suite.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_COUNT_FIELDS = (
    "total",
    "with_plaintext",
    "identification_only",
    "usable_for_identification",
    "usable_for_cracking",
    "binary_only",
    "truncated",
    "with_mode",
)


@dataclass(frozen=True)
class CorpusIssue:
    severity: str
    code: str
    file: str
    case_id: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "file": self.file,
            "case_id": self.case_id,
            "message": self.message,
        }


@dataclass
class CorpusFileReport:
    path: str
    cases: int = 0
    issues: list[CorpusIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[CorpusIssue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[CorpusIssue]:
        return [issue for issue in self.issues if issue.severity == "warning"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "cases": self.cases,
            "errors": [issue.to_dict() for issue in self.errors],
            "warnings": [issue.to_dict() for issue in self.warnings],
        }


@dataclass
class CorpusValidationReport:
    files: list[CorpusFileReport] = field(default_factory=list)
    duplicate_ids: list[str] = field(default_factory=list)
    duplicate_hashes: list[str] = field(default_factory=list)

    @property
    def total_cases(self) -> int:
        return sum(item.cases for item in self.files)

    @property
    def errors(self) -> list[CorpusIssue]:
        return [issue for item in self.files for issue in item.errors]

    @property
    def warnings(self) -> list[CorpusIssue]:
        return [issue for item in self.files for issue in item.warnings]

    @property
    def ok(self) -> bool:
        return not self.errors and not self.duplicate_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.ok,
            "total_cases": self.total_cases,
            "files": [item.to_dict() for item in self.files],
            "errors": [issue.to_dict() for issue in self.errors],
            "warnings": [issue.to_dict() for issue in self.warnings],
            "duplicate_ids": self.duplicate_ids,
            "duplicate_hashes": self.duplicate_hashes,
        }


def _issue(
    file: str,
    case_id: str,
    severity: str,
    code: str,
    message: str,
) -> CorpusIssue:
    return CorpusIssue(severity, code, file, case_id, message)


def _entries(document: dict[str, Any]) -> list[Any] | None:
    for key in ("cases", "entries"):
        value = document.get(key)
        if isinstance(value, list):
            return value
    return None


def _expected_mode(entry: dict[str, Any]) -> Any:
    return entry.get("mode", entry.get("expected_mode"))


def _validate_entry(
    entry: Any,
    *,
    index: int,
    file_name: str,
    file_source: str,
    file_has_provenance: bool,
    issues: list[CorpusIssue],
) -> str:
    if not isinstance(entry, dict):
        issues.append(
            _issue(
                file_name,
                f"index:{index}",
                "error",
                "entry_not_object",
                "case entry must be a JSON object",
            )
        )
        return ""

    case_id = str(entry.get("id") or f"index:{index}")
    raw_input = entry.get("raw_input")
    if not isinstance(raw_input, str) or not raw_input.strip():
        issues.append(
            _issue(
                file_name,
                case_id,
                "error",
                "missing_raw_input",
                "raw_input must be a non-empty string",
            )
        )
    elif "\n" in raw_input or "\r" in raw_input:
        issues.append(
            _issue(
                file_name,
                case_id,
                "error",
                "multiline_raw_input",
                "raw_input must not contain line breaks",
            )
        )

    source = entry.get("source") or file_source
    if not isinstance(source, str) or not source.strip():
        issues.append(
            _issue(
                file_name,
                case_id,
                "error",
                "missing_source",
                "case has no source and the corpus file has no source",
            )
        )

    if "reference" not in entry and "url" not in entry and not file_has_provenance:
        issues.append(
            _issue(
                file_name,
                case_id,
                "warning",
                "missing_reference",
                "case has no reference or url",
            )
        )

    mode = _expected_mode(entry)
    if mode is not None and (
        isinstance(mode, bool) or not isinstance(mode, int) or mode < 0
    ):
        issues.append(
            _issue(
                file_name,
                case_id,
                "error",
                "invalid_mode",
                "mode must be a non-negative integer",
            )
        )

    expected_plaintext = entry.get("expected_plaintext")
    if expected_plaintext is not None and not isinstance(expected_plaintext, str):
        issues.append(
            _issue(
                file_name,
                case_id,
                "error",
                "invalid_plaintext",
                "expected_plaintext must be a string or null",
            )
        )

    for flag in ("usable_for_identification", "usable_for_cracking", "is_binary", "truncated"):
        if flag in entry and not isinstance(entry[flag], bool):
            issues.append(
                _issue(
                    file_name,
                    case_id,
                    "error",
                    "invalid_flag",
                    f"{flag} must be a boolean",
                )
            )

    usable_for_cracking = entry.get("usable_for_cracking")
    if usable_for_cracking is True:
        if not isinstance(expected_plaintext, str) or not expected_plaintext:
            issues.append(
                _issue(
                    file_name,
                    case_id,
                    "error",
                    "cracking_without_plaintext",
                    "usable_for_cracking cases must include expected_plaintext",
                )
            )
        if mode is None:
            issues.append(
                _issue(
                    file_name,
                    case_id,
                    "error",
                    "cracking_without_mode",
                    "usable_for_cracking cases must include a mode",
                )
            )
    elif (
        usable_for_cracking is False
        and isinstance(expected_plaintext, str)
        and not entry.get("is_binary")
        and not entry.get("truncated")
    ):
        issues.append(
            _issue(
                file_name,
                case_id,
                "warning",
                "plaintext_but_not_crackable",
                "case has a plaintext but is marked not usable for cracking",
            )
        )

    usable_for_identification = entry.get("usable_for_identification")
    if usable_for_identification is True and mode is None:
        issues.append(
            _issue(
                file_name,
                case_id,
                "warning",
                "identification_without_mode",
                "identification case has no mode",
            )
        )
    if usable_for_identification is False and not entry.get("unusable_reason"):
        issues.append(
            _issue(
                file_name,
                case_id,
                "warning",
                "unusable_without_reason",
                "case is marked unusable but has no unusable_reason",
            )
        )

    return case_id


def _count_actual(entries: list[Any], field_name: str) -> int:
    values = [entry for entry in entries if isinstance(entry, dict)]
    if field_name == "total":
        return len(entries)
    if field_name == "with_plaintext":
        return sum(entry.get("expected_plaintext") is not None for entry in values)
    if field_name == "identification_only":
        return sum(
            entry.get("usable_for_identification") is True
            and entry.get("usable_for_cracking") is False
            for entry in values
        )
    if field_name in ("usable_for_identification", "usable_for_cracking"):
        return sum(entry.get(field_name) is True for entry in values)
    if field_name == "binary_only":
        return sum(entry.get("is_binary") is True for entry in values)
    if field_name == "truncated":
        return sum(entry.get("truncated") is True for entry in values)
    if field_name == "with_mode":
        return sum(_expected_mode(entry) is not None for entry in values)
    return 0


def validate_corpus_file(path: str | Path) -> CorpusFileReport:
    target = Path(path)
    file_name = target.name
    report = CorpusFileReport(path=str(target))
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        report.issues.append(
            _issue(file_name, "", "error", "read_error", f"cannot read corpus: {exc}")
        )
        return report
    except json.JSONDecodeError as exc:
        report.issues.append(
            _issue(file_name, "", "error", "invalid_json", f"invalid JSON: {exc}")
        )
        return report

    if not isinstance(document, dict):
        report.issues.append(
            _issue(file_name, "", "error", "not_object", "corpus must be a JSON object")
        )
        return report

    version = document.get("schema_version", document.get("version"))
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        report.issues.append(
            _issue(
                file_name,
                "",
                "error",
                "invalid_schema_version",
                "schema_version or version must be a positive integer",
            )
        )

    entries = _entries(document)
    if entries is None:
        report.issues.append(
            _issue(
                file_name,
                "",
                "error",
                "missing_entries",
                "corpus must contain a cases or entries list",
            )
        )
        return report
    report.cases = len(entries)

    file_source = document.get("source")
    if not isinstance(file_source, str):
        file_source = ""
    file_has_provenance = isinstance(document.get("provenance"), dict) or bool(
        document.get("sources")
    )

    seen_ids: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        case_id = _validate_entry(
            entry,
            index=index,
            file_name=file_name,
            file_source=file_source,
            file_has_provenance=file_has_provenance,
            issues=report.issues,
        )
        if not case_id:
            continue
        if case_id in seen_ids:
            report.issues.append(
                _issue(
                    file_name,
                    case_id,
                    "error",
                    "duplicate_id",
                    f"duplicate case id {case_id!r}",
                )
            )
        seen_ids.add(case_id)
        if case_id.startswith("index:"):
            continue
        if not _ID_RE.match(case_id):
            report.issues.append(
                _issue(
                    file_name,
                    case_id,
                    "warning",
                    "unstable_id",
                    "case id should use letters, digits, dots, colons, dashes or underscores",
                )
            )

    counts = document.get("counts")
    if isinstance(counts, dict):
        for field_name in _COUNT_FIELDS:
            if field_name not in counts:
                continue
            declared = counts[field_name]
            if isinstance(declared, bool) or not isinstance(declared, int):
                report.issues.append(
                    _issue(
                        file_name,
                        "",
                        "error",
                        "invalid_count",
                        f"counts.{field_name} must be an integer",
                    )
                )
                continue
            actual = _count_actual(entries, field_name)
            if declared != actual:
                report.issues.append(
                    _issue(
                        file_name,
                        "",
                        "error",
                        "count_mismatch",
                        f"counts.{field_name} is {declared}, but {actual} entries match",
                    )
                )
    return report


def validate_corpus_dir(path: str | Path | None = None) -> CorpusValidationReport:
    if path is None:
        from hashvault.core.database import resolve_resource_path

        directory = Path(resolve_resource_path("data/corpus"))
    else:
        directory = Path(path)
    if directory.is_file():
        paths = [directory]
    else:
        paths = sorted(directory.glob("*.json"))
    report = CorpusValidationReport()
    id_owners: dict[str, str] = {}
    hash_owners: dict[str, str] = {}
    for corpus_path in paths:
        file_report = validate_corpus_file(corpus_path)
        report.files.append(file_report)
        try:
            document = json.loads(corpus_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        entries = _entries(document) if isinstance(document, dict) else None
        if entries is None:
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            case_id = entry.get("id")
            if isinstance(case_id, str) and case_id:
                if case_id in id_owners:
                    report.duplicate_ids.append(case_id)
                    report.files[-1].issues.append(
                        _issue(
                            corpus_path.name,
                            case_id,
                            "error",
                            "duplicate_id_across_files",
                            f"id also appears in {id_owners[case_id]}",
                        )
                    )
                else:
                    id_owners[case_id] = corpus_path.name
            raw_input = entry.get("raw_input")
            mode = _expected_mode(entry)
            if isinstance(raw_input, str) and raw_input and mode is not None:
                key = f"{mode}:{raw_input}"
                if key in hash_owners:
                    report.duplicate_hashes.append(key)
                    report.files[-1].issues.append(
                        _issue(
                            corpus_path.name,
                            str(case_id or ""),
                            "warning",
                            "duplicate_hash",
                            f"same mode/hash also appears in {hash_owners[key]}",
                        )
                    )
                else:
                    hash_owners[key] = corpus_path.name
    return report
