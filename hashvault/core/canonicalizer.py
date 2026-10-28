"""
Canonicalizer — converts an identified hash into tool-ready payloads.

Given a (possibly wrapped, or credential-carrying) hash and its chosen pattern,
produce the exact strings hashcat / John would ingest, separate any username
from the hash body, and report which tools can handle the type. Conceptually the
"CANONICALIZER / FORMAT CONVERTER" layer of the deep-analysis pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional

from hashvault.core.normalizer import normalize_hash
from hashvault.core.registry import SourceFormat

# Hash types where a leading "user:" is a real username (NTLM, NetNTLM, DCC).
# For everything else a leading "label:" is part of the hash corpus (archive
# filenames etc.) and must be preserved.
_USERNAME_CAPABLE = {
    "NTLM", "LM Hash", "NetNTLMv1", "NetNTLMv2",
    "Domain Cached Credentials", "Domain Cached Credentials 2",
    "DCC2", "MSCache", "MSCache2", "Kerberos 5",
}

# Algorithms where the username is mathematically part of the hash and must be
# kept in the payload handed to the cracker (PostgreSQL, Oracle, ...).
_USERNAME_IN_HASH = {
    "postgresql", "postgres", "oracle", "sybase",
}

_LABEL_PREFIXES = ("$7z$", "$rar", "$RAR", "$pkzip", "$keepass$", "$pdf$",
                   "$office$", "$sshng$", "$veracrypt$")

_HEX_USER_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


@dataclass
class ToolCapability:
    """Which engines can process a given pattern."""

    hashcat: bool = False
    john: bool = False
    builtin: bool = False

    def available(self) -> bool:
        return self.hashcat or self.john or self.builtin


@dataclass
class CrackPayload:
    """Tool-ready representation of one hash payload."""

    raw: str
    canonical_hash: str
    username: Optional[str] = None
    hashcat_input: str = ""
    john_input: str = ""
    needs_username_flag: bool = False
    capability: ToolCapability = field(default_factory=ToolCapability)
    notes: list = field(default_factory=list)


def _is_username_capable(pattern) -> bool:
    if pattern is None:
        return False
    name = getattr(pattern, "name", "") or ""
    return any(tag.lower() in name.lower() for tag in _USERNAME_CAPABLE)


def _username_in_hash(pattern) -> bool:
    if pattern is None:
        return False
    name = (getattr(pattern, "name", "") or "").lower()
    return any(tag in name for tag in _USERNAME_IN_HASH)


def _builtin_supports(pattern) -> bool:
    if pattern is None:
        return False
    try:
        from hashvault.core.builtin import builtin_supports

        return builtin_supports(pattern)
    except Exception:
        return False


def split_credentials(raw: str, pattern=None) -> tuple[Optional[str], str]:
    """
    Split a ``user:hash`` payload into (username, hash_part).

    A leading field is treated as a username only when the type is username
    capable *or* the leading field is clearly not a hash token. Archive labels
    such as ``file.txt:$7z$...`` are never treated as usernames.
    """
    raw = raw.strip()
    if ":" not in raw:
        return None, raw

    if any(p in raw for p in _LABEL_PREFIXES):
        return None, raw

    user, _, rest = raw.partition(":")
    if pattern is not None and _is_username_capable(pattern):
        return user, rest
    # Heuristic without pattern: a long all-hex prefix is likely a hash body.
    if _HEX_USER_RE.fullmatch(user):
        return None, raw
    if user and len(user) <= 64:
        return user, rest
    return None, raw


def canonicalize(
    raw: str,
    pattern=None,
    source_format: Optional[SourceFormat] = None,
    username: Optional[str] = None,
    normalized: Optional[str] = None,
) -> CrackPayload:
    """
    Produce a CrackPayload ready for hashcat and John.

    ``normalized``/``username`` should be supplied when the caller already ran
    the normalizer (the orchestrator does); otherwise the raw value is parsed
    here.  The payload is *always* rebuilt from the normalized hash body rather
    than passing the original pwdump/shadow line to the cracker.
    """
    raw = raw.strip()
    if any(label in raw for label in _LABEL_PREFIXES):
        # Archive/container ``filename:$format$...`` labels are part of the
        # corpus, not usernames; never normalize them away.
        hash_part = raw
        username = None
    elif normalized is not None:
        hash_part = normalized.strip()
    else:
        hash_part, parsed_user = normalize_hash(raw)
        if username is None:
            username = parsed_user

    username_in_hash = _username_in_hash(pattern)
    pattern_name = (getattr(pattern, "name", "") or "").lower()
    if username_in_hash and username:
        if (
            "postgresql" in pattern_name
            and hash_part.lower().startswith("md5")
            and len(hash_part) == 35
        ):
            # hashcat mode 12 expects the challenge followed by the username:
            # md5(password + user) - the literal "md5" label is not part of it.
            hash_part = hash_part[3:]
            hash_part_for_tool = f"{hash_part}:{username}"
        else:
            # e.g. PostgreSQL: user:md5<hash>; Oracle: user:hash
            hash_part_for_tool = f"{username}:{hash_part}"
    else:
        hash_part_for_tool = hash_part

    capability = ToolCapability()
    if pattern is not None:
        capability.hashcat = pattern.hashcat_mode is not None
        capability.john = pattern.john_format is not None
        capability.builtin = _builtin_supports(pattern)

    notes: list = []
    if source_format in (
        SourceFormat.SECRETSDUMP, SourceFormat.PWDUMP,
        SourceFormat.NTDS_DIT, SourceFormat.CACHEDUMP,
    ) and username is None:
        notes.append("credential dump format without visible username")

    # For NTLM/LM the username is not needed by either tool and adding
    # --username to a bare hash makes hashcat reject the line.  NetNTLM lines
    # already carry the user as part of the challenge/response corpus.
    needs_username = username is not None and not username_in_hash
    if username_in_hash:
        notes.append("username is part of the hash algorithm")
    elif username and any(
        tag.lower() in ((getattr(pattern, "name", "") or "").lower())
        for tag in ("netntlm", "kerberos")
    ):
        notes.append("username already embedded in the hash line")

    hashcat_input = hash_part_for_tool
    john_input = hash_part_for_tool
    if username and not username_in_hash and _is_username_capable(pattern):
        # John benefits from user:hash; hashcat gets the bare body so that
        # colon-delimited usernames are never mistaken for hash fields.
        john_input = f"{username}:{hash_part}"
        if "netntlm" not in (getattr(pattern, "name", "") or "").lower():
            notes.append("username retained for reporting/John")

    return CrackPayload(
        raw=raw,
        canonical_hash=hash_part,
        username=username,
        hashcat_input=hashcat_input,
        john_input=john_input,
        needs_username_flag=needs_username,
        capability=capability,
        notes=notes,
    )


def capability_for(pattern) -> ToolCapability:
    """Return the tool capability of a pattern (hashcat mode / john format)."""
    return ToolCapability(
        hashcat=getattr(pattern, "hashcat_mode", None) is not None,
        john=getattr(pattern, "john_format", None) is not None,
        builtin=_builtin_supports(pattern),
    )
