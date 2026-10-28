# hashvault/core/normalizer.py
"""
Hash normalization logic.
Deterministic algorithm for preparing hash values for identification.
"""

import re
from typing import List, Optional, Tuple

# Windows LM/NTLM "empty" placeholders found in pwdump/secretsdump output.
_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

_ALGO_LABELS = {
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "pbkdf2", "argon2", "argon2i", "argon2id", "argon2d",
    "scrypt", "bcrypt", "ntlm", "lm", "mysql", "mysql323",
    "mysql41", "mssql", "oracle", "phpass", "django",
    "werkzeug", "gogs", "gitea", "wpa",
    "netntlm", "netntlmv1", "netntlmv2",
}

_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/=._~!@#%^&*\-]+$")
_MD4_SPECIAL_RE = re.compile(r"^(md5|sha1|sha256|sha512)[A-Fa-f0-9]{16,}$", re.IGNORECASE)


def _looks_like_hash(value: str) -> bool:
    """Heuristic: does ``value`` look like an embedded password hash?

    Used only to decide whether a ``label:value`` line is ``user:hash``.
    Deliberately conservative so that salted ``hash:salt`` formats are not
    mistaken for credentials.
    """
    if not value:
        return False
    if value in ("!", "*", "!!", "x"):
        return True
    if value.startswith(("$", "{", "*")):
        return True
    if _MD4_SPECIAL_RE.match(value):
        return True
    if value.startswith("0x") and len(value) > 10:
        return True
    if _HEX_RE.fullmatch(value) and len(value) >= 32:
        return True
    # LDAP/base64-ish hashes without a prefix (e.g. {SSHA} handled above).
    if len(value) >= 24 and ":" not in value and _TOKEN_RE.fullmatch(value):
        return True
    return False


def _clean_token(value: str) -> str:
    return value.strip().strip('"').strip("'").strip()


def _normalize_hex(value: str) -> str:
    value = _clean_token(value)
    if _HEX_RE.fullmatch(value):
        return value.lower()
    return value


def _split_pwdump(parts: List[str]) -> Optional[Tuple[str, Optional[str]]]:
    """Parse ``user:rid:LM:NT:::`` lines from pwdump/secretsdump."""
    if len(parts) < 4:
        return None
    # RID is numeric in pwdump output.
    if not re.fullmatch(r"\d+", parts[1].strip()):
        return None

    lm = _clean_token(parts[2])
    nt = _clean_token(parts[3])
    lm_ok = len(lm) == 32 and bool(_HEX_RE.fullmatch(lm)) and lm.lower() not in ("", _EMPTY_LM)
    nt_ok = len(nt) == 32 and bool(_HEX_RE.fullmatch(nt)) and nt.lower() not in ("", _EMPTY_NT)

    if nt_ok:
        return nt.lower(), parts[0].strip() or None
    if lm_ok:
        return lm.lower(), parts[0].strip() or None
    # Both hashes are empty/placeholder: report the NT field so the caller can
    # emit a useful "empty password" diagnostic rather than an arbitrary label.
    if nt.lower() == _EMPTY_NT or lm.lower() == _EMPTY_LM:
        return "", parts[0].strip() or None
    return None


def _split_shadow(parts: List[str]) -> Optional[Tuple[str, Optional[str]]]:
    """Parse ``user:$6$salt$hash:lastchg:...`` shadow entries."""
    if len(parts) < 2:
        return None
    candidate = _clean_token(parts[1])
    if not _looks_like_hash(candidate):
        return None
    first = parts[0].strip()
    if first.lower() in _ALGO_LABELS or _looks_like_hash(first):
        return None
    return candidate, first or None


def normalize_hash(raw: str) -> Tuple[str, Optional[str]]:
    """
    Normalize a hash string.

    Returns tuple: (normalized_hash, username_or_None)

    Handles plain hashes, ``username:hash`` credentials, /etc/shadow lines,
    pwdump/secretsdump rows, and NetNTLM challenge/response lines.  The hash
    portion is lowercased only when it is pure hexadecimal; structured hashes
    (bcrypt, PHC, LDAP, etc.) are preserved byte-for-byte.
    """
    text = raw.strip().lstrip("\ufeff").strip()
    if not text:
        return "", None

    # Trim trailing comment/CSV artefacts without touching hash payloads.
    text = text.rstrip(",").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()

    parts = text.split(":")

    # NetNTLM (user::domain:challenge:response[:challenge]) must stay intact:
    # hashcat/John expect the full challenge-response line.  Require the empty
    # *second* field so trailing ":::" in pwdump/shadow rows is not mistaken
    # for a challenge-response hash.
    if "::" in text and not text.startswith("$") and len(parts) >= 4 and parts[1] == "":
        return text, None

    pwdump = _split_pwdump(parts)
    if pwdump is not None:
        return pwdump

    shadow = _split_shadow(parts)
    if shadow is not None:
        return shadow

    if len(parts) >= 2:
        first = _clean_token(parts[0])
        second = _clean_token(":".join(parts[1:])) if len(parts) > 2 else _clean_token(parts[1])

        # Algorithm-labelled value: md5:<hex>, sha256:<hex>, postgres:md5<hex>.
        if first.lower() in _ALGO_LABELS and _looks_like_hash(second):
            return _normalize_hex(second), None

        if ":" in text and not text.startswith("$"):
            # username:hash (hash may itself contain ':' -- keep the remainder)
            if not _looks_like_hash(first) and _looks_like_hash(second):
                return _normalize_hex(second), first or None

    normalized = _clean_token(text)
    return _normalize_hex(normalized), None


def normalize_with_context(raw: str, context: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """
    Normalize hash with additional context information.

    If context indicates a specific format, use specialized normalization.
    """
    normalized, username = normalize_hash(raw)

    if context:
        context_low = context.lower()
        if context_low in ("pwdump", "secretsdump", "sam", "ntds"):
            # normalize_hash already extracts the NT hash from pwdump rows.
            pass
        elif context_low == "shadow":
            pass

    return normalized, username


def is_hex_only(s: str) -> bool:
    """Check if string contains only hexadecimal characters."""
    return bool(re.fullmatch(r"[A-Fa-f0-9]+", s))


def is_base64_like(s: str) -> bool:
    """Check if string looks like valid Base64 encoding."""
    if not s:
        return False
    if len(s) % 4 != 0:
        return False
    return bool(re.fullmatch(r"^[A-Za-z0-9+/]+={0,2}$", s))
