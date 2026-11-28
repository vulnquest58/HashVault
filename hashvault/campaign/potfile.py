"""Import hashcat and John the Ripper potfiles into a campaign.

Potfiles are line-oriented ``hash:plaintext`` stores.  Hashcat may encode a
plaintext as ``$HEX[...]`` when it contains separators or non-printable bytes;
John uses the same convention in several formats.  Importing a potfile lets a
campaign reuse already-recovered values instead of spending work again.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PotfileEntry:
    hash_value: str
    plaintext: str
    source: str = ""
    line_number: int = 0


def _decode_plaintext(value: str) -> str:
    if value.startswith("$HEX[") and value.endswith("]"):
        raw = value[5:-1]
        try:
            decoded = bytes.fromhex(raw)
        except ValueError:
            return value
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.decode("latin-1", errors="replace")
    return value


def parse_potfile_text(
    text: str,
    *,
    source: str = "",
) -> list[PotfileEntry]:
    """Parse potfile text, ignoring comments and malformed lines."""
    entries: list[PotfileEntry] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        hash_value, plaintext = line.split(":", 1)
        hash_value = hash_value.strip()
        if not hash_value:
            continue
        entries.append(
            PotfileEntry(
                hash_value=hash_value,
                plaintext=_decode_plaintext(plaintext),
                source=source,
                line_number=line_number,
            )
        )
    return entries


def load_potfile(path: str | Path) -> list[PotfileEntry]:
    """Read a hashcat or John potfile from disk."""
    target = Path(path)
    return parse_potfile_text(
        target.read_text(encoding="utf-8", errors="replace"),
        source=str(target),
    )


def potfile_mapping(entries: list[PotfileEntry]) -> dict[str, str]:
    """Build a hash-to-plaintext map; later entries win."""
    return {entry.hash_value: entry.plaintext for entry in entries}
