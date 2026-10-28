"""
Structural validators for the deep-analysis pipeline.

These helpers intentionally avoid the database and regex catalogue so they can
be used while exploring thousands of speculative decode branches.  They answer
three questions:

* Does this string look like a *terminal* crackable hash?
* Is this output plausible text/code/config, or binary noise?
* Which hash-like tokens are embedded in a larger blob?

The identifier remains the final authority for algorithm selection.
"""

from __future__ import annotations

import json
import math
import re
import string
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

HEX_HASH_LENGTHS = frozenset({32, 40, 48, 56, 64, 96, 128})

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HEX_TOKEN_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32,128})(?![0-9a-fA-F])")
_DOLLAR_PREFIXES = (
    r"2[abxy]|1|5|6|7|y|gy|md5|sha1|sha224|sha256|sha384|sha512|"
    r"apr1|P|H|S|DCC2|NT|ms|krb5tgs|krb5asrep|krb5pa|7z|rar|rar5|"
    r"pkzip|keepass|pdf|office|bitcoin|ethereum|WPAPSK|WPA|HEX|"
    r"postgres|sntp-ms|sshng|"
    r"argon2(?:id|i|d)?|scrypt|yescrypt|gost-yescrypt|balloon|"
    r"pbkdf2(?:-sha(?:1|224|256|384|512))?|bcrypt-sha256"
)
_DOLLAR_RE = re.compile(
    rf"\$(?:{_DOLLAR_PREFIXES})\$[^\s\"'`<>]{{4,2048}}"
)
_DCC_RE = re.compile(r"[0-9A-Fa-f]{32}:\d+")
_WPA_FIELD_RE = re.compile(r"[0-9A-Fa-f]{32}\*[^\s*]+\*[^\s*]+\*[^\s*]+")
_MSSQL_RE = re.compile(r"0x(?:0100|0200)[0-9A-Fa-f]{64,}")
_NETNTLM_LOOSE_RE = re.compile(
    r"[^\s:]+::[^\s:]+:[0-9A-Fa-f]{16,}:[0-9A-Fa-f]{16,}:[0-9A-Fa-f]{8,}"
)
_LDAP_RE = re.compile(
    r"\{(?:SSHA|SSHA256|SSHA512|SHA|SMD5|MD5|CRYPT|SHA256|SHA512|WPA)\}"
    r"[A-Za-z0-9+/=._-]{6,512}",
    re.IGNORECASE,
)
_DJANGO_RE = re.compile(
    r"(?:pbkdf2|argon2|bcrypt_sha256|scrypt|sha1|sha256|sha512)"
    r"[_a-z0-9]*\$[^\s\"'`<>]{8,512}"
)
_MYSQL_RE = re.compile(r"(?<![0-9A-Fa-f])\*[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
_WPA_RE = re.compile(r"WPA\*0[1-9]\*[^\s\"'`<>]{20,512}")
_BITCOIN_RE = re.compile(r"\$(?:bitcoin|ethereum|keystore)\$[^\s\"'`<>]{16,2048}")
_NETNTLM_RE = re.compile(
    r"[^\s:]+::[^\s:]+:[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}:[0-9A-Fa-f]+"
)
_SHA_COLON_RE = re.compile(
    r"(?:sha1|sha256|sha512|pbkdf2)[_a-z0-9]*:\d+:[^\s:\"']+:[A-Za-z0-9+/=._-]+",
    re.IGNORECASE,
)
_WINGFTP_RE = re.compile(r"[0-9A-Fa-f]{64}:[^\s:\"']{1,256}")
_USER_HASH_RE = re.compile(
    r"(?<![\w.-])([^\s:]{1,128}):"
    r"(\$[^\s\"'`<>]{8,}|[0-9A-Fa-f]{32,128}(?::[^\s:]+)?)"
)

_SAFE_TEXT = set(string.printable)


def _is_known_hex(value: str) -> bool:
    return len(value) in HEX_HASH_LENGTHS and bool(_HEX_RE.fullmatch(value))


def is_terminal_hash(value: str) -> bool:
    """Return True when ``value`` is a complete, crackable hash structure.

    This is deliberately stricter than "contains hex": a 16-character hex
    string is usually hex-encoded plaintext, while a 32+ character hex token is
    almost certainly a digest.  Structured ``$...$``/colon formats are accepted
    as terminals so the search does not keep applying ROT/XOR to them.
    """
    s = (value or "").strip()
    if not s or len(s) > 4096 or "\n" in s or "\r" in s:
        return False
    if _is_known_hex(s):
        return True
    if _DOLLAR_RE.fullmatch(s):
        return True
    if _LDAP_RE.fullmatch(s):
        return True
    if _DJANGO_RE.fullmatch(s):
        return True
    if _MYSQL_RE.fullmatch(s) or _BITCOIN_RE.fullmatch(s):
        return True
    if _WPA_RE.fullmatch(s) or _NETNTLM_RE.fullmatch(s) or _NETNTLM_LOOSE_RE.fullmatch(s):
        return True
    if _DCC_RE.fullmatch(s) or _WPA_FIELD_RE.fullmatch(s) or _MSSQL_RE.fullmatch(s):
        return True
    if _SHA_COLON_RE.fullmatch(s):
        return True
    if _WINGFTP_RE.fullmatch(s) and not any(c.isspace() for c in s):
        return True
    # Common structured formats that are not covered by the catalogue loops.
    if re.fullmatch(r"sha(?:1|224|256|384|512)\$[^\s$]+\$[^\s$]+", s, re.I):
        return True
    if re.fullmatch(r"(?:md5|sha1|sha256|sha512)\$[^\s$]+\$[^\s$]+", s, re.I):
        return True
    # user:hash is crackable when the hash side is itself terminal.
    m = _USER_HASH_RE.fullmatch(s)
    if m and is_terminal_hash(m.group(2)):
        return True
    return False


def terminal_confidence(value: str) -> float:
    """Confidence bonus used to rank terminal hash branches."""
    s = (value or "").strip()
    if not is_terminal_hash(s):
        return 0.0
    if s.startswith("$") or s.startswith("*") or s.startswith("WPA*"):
        return 1.0
    if _LDAP_RE.fullmatch(s) or _DJANGO_RE.fullmatch(s):
        return 0.98
    if ":" in s and not _is_known_hex(s):
        return 0.92
    if len(s) in (64, 96, 128):
        return 0.9
    if len(s) in (32, 40, 56):
        return 0.85
    return 0.75


def _trim_token(token: str) -> str:
    token = token.strip().strip("\"'`")
    trailing = ".,;)]}>"
    while token and token[-1] in trailing:
        token = token[:-1]
    return token


def extract_hash_tokens(text: str) -> List[str]:
    """Extract every distinct hash-like token embedded in ``text``.

    Handles bare digests, modular crypt formats, LDAP ``{SSHA}`` strings,
    Django/PBKDF2 formats, NetNTLM, WPA, Bitcoin/Ethereum wallets, MySQL ``*``
    hashes, and ``user:hash`` credential pairs.
    """
    if not text:
        return []
    found: List[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        value = _trim_token(candidate)
        # For a credential pair, return the hash side, not the username.
        match = _USER_HASH_RE.fullmatch(value)
        if match and is_terminal_hash(match.group(2)):
            value = match.group(2)
        if value and value not in seen and is_terminal_hash(value):
            seen.add(value)
            found.append(value)

    for pattern in (
        _DOLLAR_RE,
        _LDAP_RE,
        _DJANGO_RE,
        _MYSQL_RE,
        _WPA_RE,
        _BITCOIN_RE,
        _NETNTLM_RE,
        _SHA_COLON_RE,
        _WINGFTP_RE,
    ):
        for match in pattern.finditer(text):
            add(match.group(0))

    for match in _HEX_TOKEN_RE.finditer(text):
        add(match.group(1))

    for match in _USER_HASH_RE.finditer(text):
        add(match.group(0))

    return found


def printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    good = sum(1 for c in value if c in _SAFE_TEXT or c in "\n\r\t")
    return good / len(value)


def looks_like_text(value: str, threshold: float = 0.85) -> bool:
    if not value:
        return False
    if "\x00" in value:
        return printable_ratio(value) >= 0.98
    return printable_ratio(value) >= threshold


def looks_like_binary(value: str) -> bool:
    if not value:
        return False
    if "\x00" in value:
        return True
    return printable_ratio(value) < 0.72


def looks_like_json(value: str) -> bool:
    s = value.strip()
    if len(s) < 2 or s[0] not in "{[" or s[-1] not in "}]":
        return False
    try:
        json.loads(s)
        return True
    except Exception:
        return False


_CODE_HINTS = re.compile(
    r"\b(?:def|class|function|const|let|var|return|import|from|require|"
    r"password|passwd|secret|token|api[_-]?key|hash|salt|digest|"
    r"config|database|username|user)\b",
    re.IGNORECASE,
)
_CONFIG_HINTS = re.compile(
    r"(?:^|\n)\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]\s*\S+",
    re.MULTILINE,
)


def looks_like_code(value: str) -> bool:
    s = value.strip()
    if not s:
        return False
    if any(marker in s for marker in ("=>", "::", "<?php", "</", "#include", "SELECT ", "INSERT ")):
        return True
    score = len(_CODE_HINTS.findall(s))
    if any(marker in s for marker in ("{", "}", ";", "(", ")")):
        score += 1
    return score >= 2 and "\n" in s


def looks_like_config(value: str) -> bool:
    s = value.strip()
    if not s:
        return False
    lines = [line for line in s.splitlines() if line.strip()]
    if not lines:
        return False
    matches = sum(1 for line in lines if _CONFIG_HINTS.match(line))
    return matches >= 1 and (matches / len(lines) >= 0.25 or "\n" not in s)


def entropy(value: str) -> float:
    """Shannon entropy in bits/character (useful for opaque blobs)."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


@dataclass
class InputProfile:
    """Cheap structural profile used for search ranking and diagnostics."""

    kind: str = "text"
    length: int = 0
    terminal: bool = False
    hash_tokens: int = 0
    printable_ratio: float = 0.0
    entropy: float = 0.0
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "length": self.length,
            "terminal": self.terminal,
            "hash_tokens": self.hash_tokens,
            "printable_ratio": round(self.printable_ratio, 3),
            "entropy": round(self.entropy, 3),
            "warnings": list(self.warnings),
        }


def profile_input(value: str) -> InputProfile:
    s = value or ""
    tokens = extract_hash_tokens(s)
    terminal = is_terminal_hash(s)
    pr = printable_ratio(s)
    if terminal:
        kind = "hash"
    elif not s.strip():
        kind = "empty"
    elif looks_like_json(s):
        kind = "json"
    elif looks_like_code(s):
        kind = "code"
    elif looks_like_config(s):
        kind = "config"
    elif looks_like_binary(s):
        kind = "binary"
    elif tokens:
        kind = "embedded-hash"
    else:
        kind = "text"
    warnings: List[str] = []
    if len(s) > 1_000_000:
        warnings.append("Input is larger than 1 MB; exploration is bounded.")
    return InputProfile(
        kind=kind,
        length=len(s),
        terminal=terminal,
        hash_tokens=len(tokens),
        printable_ratio=pr,
        entropy=entropy(s[:200_000]),
        warnings=warnings,
    )


def unique_preserving_order(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def summarize_hash(value: str, width: int = 80) -> str:
    s = (value or "").strip()
    if len(s) <= width:
        return s
    return f"{s[: max(8, width // 2)]}...{s[-max(8, width // 2):]}"


def safe_display(value: Optional[str], width: int = 80) -> str:
    if value is None:
        return ""
    return summarize_hash(value.replace("\x00", "\\0"), width=width)
