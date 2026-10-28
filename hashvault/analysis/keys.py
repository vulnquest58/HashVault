"""
Key handling for explicit keyed analysis transforms.

The analysis engine never guesses encryption keys.  Users can pass named keys
with ``--key name=value``; values support raw text plus ``hex:``, ``b64:`` and
``utf8:`` prefixes.  Key names are case-insensitive.
"""

from __future__ import annotations

import base64
import binascii
from typing import Iterable, Mapping, Optional


class KeyError(ValueError):
    """Raised when a key specification is malformed."""


def _decode_value(value: str) -> bytes:
    text = value.strip()
    lower = text.lower()
    try:
        if lower.startswith("hex:"):
            raw = text[4:].strip()
            if len(raw) % 2:
                raw = "0" + raw
            return binascii.unhexlify(raw)
        if lower.startswith("b64:"):
            return base64.b64decode(text[4:].strip(), validate=False)
        if lower.startswith("utf8:"):
            return text[5:].encode("utf-8")
        return text.encode("utf-8")
    except (binascii.Error, ValueError) as exc:
        raise KeyError(f"Invalid key value encoding: {exc}") from exc


def parse_key_options(values: Optional[Iterable[str]]) -> dict[str, str]:
    """Parse repeated ``--key name=value`` options into a normalized mapping."""
    result: dict[str, str] = {}
    for item in values or ():
        spec = str(item)
        if "=" not in spec:
            raise KeyError(f"Key must be name=value, got {spec!r}")
        name, value = spec.split("=", 1)
        name = name.strip().lower()
        if not name:
            raise KeyError("Key name cannot be empty")
        if not value:
            raise KeyError(f"Key {name!r} has no value")
        result[name] = value
    return result


def parse_key_mapping(values: Optional[Mapping[str, str]]) -> dict[str, str]:
    if not values:
        return {}
    return {str(name).strip().lower(): str(value) for name, value in values.items()}


def require_keys(keys: Optional[Mapping[str, str]], *names: str) -> bool:
    if not keys:
        return False
    normalized = {str(key).lower() for key in keys}
    return all(name.lower() in normalized for name in names)


def key_bytes(
    keys: Optional[Mapping[str, str]],
    name: str,
    *,
    default: Optional[bytes] = None,
) -> Optional[bytes]:
    if not keys:
        return default
    target = name.lower()
    for key, value in keys.items():
        if str(key).lower() == target:
            return _decode_value(str(value))
    return default


def key_text(
    keys: Optional[Mapping[str, str]],
    name: str,
    *,
    default: Optional[str] = None,
) -> Optional[str]:
    raw = key_bytes(keys, name, default=None)
    return default if raw is None else raw.decode("utf-8", "replace")
