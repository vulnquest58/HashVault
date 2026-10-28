"""
Source Format Parsers module for HashVault v2.0.
Extracts normalized hashes and username context from structural dump files.
"""
from dataclasses import dataclass
from typing import List, Tuple
from hashvault.core.normalizer import normalize_hash
from hashvault.core.registry import SourceFormat
from hashvault.exceptions import FormatParserError


@dataclass
class ParsedHashRecord:
    raw_input: str
    normalized_hash: str
    username: str | None
    detected_format: SourceFormat


def parse_source_file(file_content: str, format_hint: SourceFormat = SourceFormat.AUTO_DETECT) -> List[ParsedHashRecord]:
    """
    Parse a multiline input string according to the given or auto-detected source format.
    Returns a list of ParsedHashRecord entries.
    """
    lines = [line.strip() for line in file_content.splitlines() if line.strip() and not line.strip().startswith("#")]
    if not lines:
        return []

    if format_hint == SourceFormat.AUTO_DETECT:
        format_hint = detect_file_format(lines)

    records: List[ParsedHashRecord] = []
    for line in lines:
        parsed = parse_single_line(line, format_hint)
        if parsed:
            records.append(parsed)

    return records


def detect_file_format(sample_lines: List[str]) -> SourceFormat:
    """Analyze sample lines to auto-detect source format structure."""
    first_line = sample_lines[0]

    # Check for PWDUMP / Secretsdump pattern: user:rid:lmhash:nthash:::
    parts = first_line.split(":")
    if len(parts) >= 4 and parts[1].isdigit() and len(parts[3]) == 32:
        return SourceFormat.PWDUMP

    # Check for /etc/shadow pattern: user:$id$salt$hash:18123:0:99999:7:::
    if len(parts) >= 2 and parts[1].startswith("$"):
        return SourceFormat.SHADOW

    # Check for NetNTLMv2 Responder log: user::domain:challenge:ntlmv2_response:blob
    if "::" in first_line and len(parts) >= 6:
        return SourceFormat.RESPONDER_NTLMV2

    return SourceFormat.HASHCAT_JOHN_LIST


def parse_single_line(line: str, format_type: SourceFormat) -> ParsedHashRecord | None:
    """Parse an individual text line based on the explicitly identified format."""
    text = line.strip()
    if not text:
        return None

    if format_type in (SourceFormat.PWDUMP, SourceFormat.SECRETSDUMP):
        parts = text.split(":")
        if len(parts) >= 4:
            username = parts[0].strip()
            nt_hash = parts[3].strip()
            if len(nt_hash) == 32:
                norm, _ = normalize_hash(nt_hash)
                return ParsedHashRecord(
                    raw_input=text,
                    normalized_hash=norm,
                    username=username,
                    detected_format=format_type,
                )

    elif format_type == SourceFormat.SHADOW:
        parts = text.split(":")
        if len(parts) >= 2:
            username = parts[0].strip()
            hash_field = parts[1].strip()
            if hash_field and hash_field not in ("*", "!", "x"):
                norm, _ = normalize_hash(hash_field)
                return ParsedHashRecord(
                    raw_input=text,
                    normalized_hash=norm,
                    username=username,
                    detected_format=format_type,
                )

    elif format_type == SourceFormat.RESPONDER_NTLMV2:
        norm, user = normalize_hash(text)
        username = user or (text.split(":")[0] if ":" in text else None)
        return ParsedHashRecord(
            raw_input=text,
            normalized_hash=norm,
            username=username,
            detected_format=format_type,
        )

    # Fallback / Plain List parsing
    norm, user = normalize_hash(text)
    return ParsedHashRecord(
        raw_input=text,
        normalized_hash=norm,
        username=user,
        detected_format=SourceFormat.HASHCAT_JOHN_LIST,
    )
