"""Corpus ingestion for password-dump, shadow, and generic credential files."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from hashvault.core.canonicalizer import split_credentials


@dataclass
class CorpusRecord:
    username: str | None
    hash_value: str
    source: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


def parse_corpus_text(text: str, *, source: str = "") -> list[CorpusRecord]:
    records: list[CorpusRecord] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(";"):
            continue
        record = _parse_line(line, source=source)
        if record is not None:
            records.append(record)
    return records


def parse_corpus_file(path: str | Path) -> list[CorpusRecord]:
    target = Path(path)
    return parse_corpus_text(
        target.read_text(encoding="utf-8", errors="replace"),
        source=str(target),
    )


def _parse_line(line: str, *, source: str) -> CorpusRecord | None:
    fields = line.split(":")
    if _is_pwdump(fields):
        username = fields[0]
        nt_hash = fields[3].strip()
        lm_hash = fields[2].strip()
        value = nt_hash if _is_hash_field(nt_hash) else lm_hash
        if not _is_hash_field(value):
            return None
        return CorpusRecord(
            username=username,
            hash_value=value,
            source=source,
            metadata={"format": "pwdump"},
        )

    if _is_shadow(fields):
        value = fields[1].strip()
        if not _is_hash_field(value):
            return None
        return CorpusRecord(
            username=fields[0],
            hash_value=value,
            source=source,
            metadata={"format": "shadow"},
        )

    username, value = split_credentials(line)
    value = value.strip()
    if not _is_hash_field(value):
        return None
    return CorpusRecord(username=username, hash_value=value, source=source)


def _is_pwdump(fields: list[str]) -> bool:
    if len(fields) < 7:
        return False
    return (
        bool(fields[0])
        and fields[1].strip().isdigit()
        and (_is_hash_field(fields[2].strip()) or _is_hash_field(fields[3].strip()))
    )


def _is_shadow(fields: list[str]) -> bool:
    if len(fields) < 9 or not fields[0]:
        return False
    value = fields[1].strip()
    return value.startswith(("$", "!")) and _is_hash_field(value)


def _is_hash_field(value: str) -> bool:
    if not value:
        return False
    return value not in {
        "*",
        "!",
        "!!",
        "LOCKED",
        "NO PASSWORD",
        "NO PASSWORD*********************",
    }
