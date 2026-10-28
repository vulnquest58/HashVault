"""
CyberChef-style transform operations for HashVault's deep analysis pipeline.

Implements 6 CyberChef categories:
  1. Data format    — Base64/32/58/85/62, Hex, Charcode, Decimal, Binary, Octal,
                      Morse, Quoted-Printable, Punycode, Unicode escapes, JWT
  2. Encryption/Encoding — ROT13, ROT47, Atbash, Caesar, XOR (single-byte),
                           Vigenère (brute), Bacon, Affine
  3. Compression    — Gzip, Zlib, Bzip2, LZMA, Deflate-raw
  4. Hashing        — MD5/SHA1/SHA256/SHA512 round-trip detector, NTLM check
  5. Forensics      — Extract hashes, Extract base64 blobs, Remove null bytes,
                      Strip whitespace, Defang / Refang URLs
  6. Extractors     — Extract JWT payload, Extract IP addresses, Extract emails,
                      Extract URLs, Extract MAC addresses

Design mirrors CyberChef's model of small composable recipes:
  - every Operation is pure, composable, side-effect free
  - score() returns 0..1 heuristic confidence
  - apply() returns the decoded string or None
  - OPERATIONS tuple drives magic.py (auto-ranking) + recipe.py (recursive peel)
"""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import html
import io
import json
import lzma
import math
import re
import string
import struct
import tarfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, List
from urllib.parse import unquote, urlparse

from hashvault.analysis.keys import key_bytes, key_text
from hashvault.analysis.validators import (
    entropy,
    extract_hash_tokens,
    is_terminal_hash,
    looks_like_config,
    looks_like_json,
    looks_like_text,
)

# ============================================================================
# Shared helpers
# ============================================================================

_PRINTABLE = set(string.printable.rstrip())


def _looks_plain(text: str) -> bool:
    """Heuristic: is the text mostly printable ASCII / newline-terminated?"""
    if not text:
        return False
    printable = sum(1 for c in text if c in _PRINTABLE or c in "\n\r\t")
    return printable / len(text) >= 0.9


def _hash_likeness(text: str) -> float:
    """
    Crude 0..1 measure of how much the text resembles a bare, decodable hash
    (hex, base64, or a labelled/poly hash with '$' ':' separators). Used as a
    tie-breaker that biases the pipeline toward 'more canonical' outputs.
    """
    if not text:
        return 0.0
    stripped = text.strip()

    # Prefix/labelled hashes (e.g. $2y$..., user:hash, :1000:salt$hash)
    if re.search(r"^\$[0-9A-Za-z]+\$", stripped) or \
       re.search(r":\d+:", stripped) or \
       (":" in stripped and len(re.sub(r"[^:]", "", stripped)) in (1, 2, 3)):
        return 0.95

    # Clean hex
    if re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return 1.0
    # Base64-like
    if re.fullmatch(r"[A-Za-z0-9+/=]+", stripped) and len(stripped) % 4 == 0:
        return 0.9
    if re.fullmatch(r"[A-Z2-7=]+", stripped):
        return 0.8
    return 0.5


# ============================================================================
# Bounded decompression
# ============================================================================

# Decompression is the only operation family that can turn a few kilobytes of
# input into an unbounded amount of memory.  ``search.py`` caps the *result*,
# but a plain ``gzip.decompress()`` allocates the whole payload first, so a
# small compression bomb could exhaust RAM before that check ever runs.
# ``ArchiveExtract`` already streams with limits; these helpers give the
# single-stream codecs the same protection.
MAX_DECOMPRESS_BYTES = 8 * 1024 * 1024


def _decode_bytes(raw: bytes) -> Optional[str]:
    """Decode decompressed bytes, rejecting anything that is almost all NULs."""
    decoded = raw.decode("utf-8", "replace")
    if not _looks_plain(decoded):
        return None
    return decoded


def _bounded_decompress(
    kind: str,
    raw: bytes,
    limit: int = MAX_DECOMPRESS_BYTES,
) -> Optional[bytes]:
    """Decompress ``raw`` while never materialising more than ``limit`` bytes.

    Returns ``None`` when the stream is invalid, when the codec is unsupported,
    or when the output exceeds ``limit`` (the bomb case).
    """
    try:
        if kind == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                data = stream.read(limit + 1)
        elif kind == "zlib":
            data = zlib.decompressobj(zlib.MAX_WBITS).decompress(raw, limit + 1)
        elif kind == "deflate":
            # Negative window bits = raw DEFLATE with no zlib header.
            data = zlib.decompressobj(-15).decompress(raw, limit + 1)
        elif kind == "bz2":
            data = bz2.BZ2Decompressor().decompress(raw, max_length=limit + 1)
        elif kind == "lzma":
            data = lzma.LZMADecompressor().decompress(raw, max_length=limit + 1)
        else:
            return None
    except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
        return None
    if len(data) > limit:
        # Refuse oversized output instead of letting the caller clip a bomb.
        return None
    return data


# ============================================================================
# Base Operation class
# ============================================================================

@dataclass
class OperationResult:
    """One possible output of an operation.

    Multi-output operations (extractors, archives, code parsers) return several
    results with labels so the analysis trace can explain where each candidate
    came from.
    """

    text: str
    label: str = ""
    score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class Operation:
    """A single CyberChef-style transform operation.

    ``apply()`` remains the simple compatibility API.  New code should use
    ``apply_many()`` so an operation can expose multiple candidates without
    encoding them into one newline-separated string.
    """

    name: str = ""
    description: str = ""
    category: str = "Other"
    tier: str = "A"
    kind: str = "text"
    auto: bool = True
    reversible: bool = True
    requires_keys: tuple[str, ...] = ()
    max_output_bytes: int = 4 * 1024 * 1024

    def score(self, text: str) -> float:
        """Heuristic 0..1 confidence that ``text`` is encoded in this way."""
        raise NotImplementedError

    def apply(self, text: str) -> Optional[str]:
        """Decode/transform ``text``. Return None if not applicable."""
        raise NotImplementedError

    def apply_many(
        self,
        text: str,
        keys: Optional[Mapping[str, str]] = None,
    ) -> List[OperationResult]:
        """Return zero or more candidate outputs for ``text``."""
        result = self.apply(text)
        if result is None:
            return []
        return [OperationResult(text=result, score=float(self.score(text)))]

    def inverse(self, text: str) -> Optional[str]:
        """Best-effort reverse transform, used by round-trip validators."""
        return None

    def contract(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "tier": self.tier,
            "kind": self.kind,
            "auto": self.auto,
            "reversible": self.reversible,
            "requires_keys": list(self.requires_keys),
            "max_output_bytes": self.max_output_bytes,
        }


# ============================================================================
# CATEGORY 1 — Data format
# ============================================================================

class Base64Decode(Operation):
    name = "Base64"
    description = "Base64 decode (RFC 4648 standard + URL-safe alphabets)"
    category = "Data format"

    _STD = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    _URL = re.compile(r"^[A-Za-z0-9\-_]+={0,2}$")

    def score(self, text: str) -> float:
        s = text.strip()
        if len(s) < 8:
            return 0.0
        if self._STD.match(s) and len(s) % 4 == 0:
            return 0.7
        if self._URL.match(s) and len(s) % 4 == 0:
            return 0.65
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                pad = "=" * (-len(s) % 4)
                raw = fn(s + pad)
                if not raw:
                    continue
                # Fast path: printable text (most cases)
                decoded = raw.decode("utf-8", "replace")
                if _looks_plain(decoded):
                    return decoded
                # Binary passthrough: if decoded bytes are a known compression
                # magic (gzip, bzip2, lzma/xz), return as latin-1 so the
                # next operation (Gzip/Bzip2/LZMA) can decompress it.
                if (
                    raw[:2] == b"\x1f\x8b"          # gzip
                    or raw[:3] == b"BZh"             # bzip2
                    or raw[:6] == b"\xfd7zXZ\x00"   # xz/lzma
                    or (raw[:2] == b"\x5d\x00")      # lzma alone
                    or (len(raw) >= 2 and raw[0] == 0x78 and raw[1] in (0x01, 0x9C, 0xDA))  # zlib
                ):
                    return raw.decode("latin-1")
            except Exception:
                pass
        return None


class HexDecode(Operation):
    name = "Hex"
    description = "ASCII-hex decode (0xNN, NN NN, or raw even-length hex)"
    category = "Data format"

    # Accept plain hex, space-separated, 0x-prefixed, \x-prefixed, colon-delimited
    _PLAIN  = re.compile(r"^[0-9a-fA-F]+$")
    _SPACED = re.compile(r"^(?:[0-9a-fA-F]{2}\s+)+[0-9a-fA-F]{2}$")
    _COLON  = re.compile(r"^(?:[0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}$")
    _PREFX  = re.compile(r"^(?:0x[0-9a-fA-F]{2}\s*)+$")
    _SLASH  = re.compile(r"^(?:\\x[0-9a-fA-F]{2})+$")

    def score(self, text: str) -> float:
        s = text.strip()
        if len(s) < 4:
            return 0.0
        if self._SPACED.match(s) or self._COLON.match(s):
            return 0.85
        if self._PREFX.match(s) or self._SLASH.match(s):
            return 0.9
        if self._PLAIN.match(s) and len(s) % 2 == 0:
            return 0.3 if len(s) <= 64 else 0.75
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        # Normalise separators
        clean = re.sub(r"(0x|\\x|\s|:)", "", s, flags=re.I)
        if not re.fullmatch(r"[0-9a-fA-F]+", clean) or len(clean) % 2 != 0:
            return None
        try:
            raw = binascii.unhexlify(clean)
        except Exception:
            return None
        if not raw:
            return None
        if not all(32 <= b < 127 or b in (10, 13, 9) for b in raw):
            return None
        decoded = raw.decode("latin-1")
        return decoded if _looks_plain(decoded) else None


class Base32Decode(Operation):
    name = "Base32"
    description = "RFC 4648 Base32 decode"
    category = "Data format"

    _RE = re.compile(r"^[A-Z2-7]+=*$")

    def score(self, text: str) -> float:
        s = text.strip().upper()
        if len(s) < 8 or not self._RE.match(s):
            return 0.0
        return 0.5

    def apply(self, text: str) -> Optional[str]:
        s = text.strip().upper()
        try:
            pad = "=" * (-len(s) % 8)
            raw = base64.b32decode(s + pad)
            if not raw:
                return None
            decoded = raw.decode("utf-8", "replace")
            return decoded if _looks_plain(decoded) else None
        except Exception:
            return None


# Standard Bitcoin-style Base58 alphabet.
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_MAP = {c: i for i, c in enumerate(_BASE58_ALPHABET)}


class Base58Decode(Operation):
    name = "Base58"
    description = "Base58 decode (Bitcoin-style alphabet)"
    category = "Data format"

    def score(self, text: str) -> float:
        s = text.strip()
        if len(s) < 6 or not all(c in _BASE58_MAP for c in s):
            return 0.0
        return 0.45

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        num = 0
        try:
            for c in s:
                num = num * 58 + _BASE58_MAP[c]
        except KeyError:
            return None
        n_bytes = (num.bit_length() + 7) // 8
        raw = num.to_bytes(n_bytes, "big") if n_bytes > 0 else b""
        raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
        if not raw:
            return None
        decoded = raw.decode("utf-8", "replace")
        return decoded if _looks_plain(decoded) else None


class Base85Decode(Operation):
    name = "Base85"
    description = "Base85 / Ascii85 decode"
    category = "Data format"

    _CHARS = re.compile(r"^[!-u]+$")

    def score(self, text: str) -> float:
        s = text.strip()
        if len(s) < 5:
            return 0.0
        # Ascii85 streams start with <~ and end with ~>
        if s.startswith("<~") and s.endswith("~>"):
            return 0.9
        # Plain base85 chars
        if self._CHARS.match(s) and len(s) % 5 == 0:
            return 0.4
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        adobe = s.startswith("<~") and s.endswith("~>")
        try:
            if adobe:
                raw = base64.a85decode(s.encode("ascii"), adobe=True)
            else:
                raw = base64.a85decode(s.encode("ascii"), adobe=False)
        except Exception:
            try:
                raw = base64.b85decode(s.encode("ascii"))
            except Exception:
                return None
        if not raw:
            return None
        decoded = raw.decode("utf-8", "replace")
        return decoded if _looks_plain(decoded) else None


class Base62Decode(Operation):
    name = "Base62"
    description = "Base62 decode (0-9A-Za-z)"
    category = "Data format"

    _ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    _MAP = {c: i for i, c in enumerate(_ALPHA)}
    _RE = re.compile(r"^[0-9A-Za-z]{6,}$")

    def score(self, text: str) -> float:
        s = text.strip()
        if not self._RE.match(s):
            return 0.0
        return 0.3  # low default; context-driven

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        num = 0
        for c in s:
            if c not in self._MAP:
                return None
            num = num * 62 + self._MAP[c]
        n_bytes = (num.bit_length() + 7) // 8 or 1
        raw = num.to_bytes(n_bytes, "big")
        decoded = raw.decode("utf-8", "replace")
        return decoded if _looks_plain(decoded) else None


class FromCharcodeDecimal(Operation):
    """Space/comma-separated decimal char codes, e.g. '72 101 108 108 111'."""
    name = "FromCharcode"
    description = "From decimal char codes (e.g. '72 101 108')"
    category = "Data format"

    _RE = re.compile(r"^(?:\d{1,3}(?:[,\s]+\d{1,3})*)\s*$")

    def score(self, text: str) -> float:
        if not self._RE.match(text.strip()):
            return 0.0
        nums = [int(n) for n in re.split(r"[,\s]+", text.strip())]
        if len(nums) < 3:
            return 0.0
        if all(32 <= n < 127 for n in nums):
            return 0.75
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        nums = [int(n) for n in re.split(r"[,\s]+", text.strip()) if n]
        if not all(0 <= n <= 127 for n in nums):
            return None
        decoded = "".join(chr(n) for n in nums)
        return decoded if _looks_plain(decoded) else None


class FromDecimalNumber(Operation):
    """Single decimal integer → bytes."""
    name = "FromDecimal"
    description = "Decimal integer → UTF-8 bytes"
    category = "Data format"

    def score(self, text: str) -> float:
        s = text.strip()
        if re.fullmatch(r"\d{5,}", s):
            return 0.2
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        try:
            num = int(s)
        except ValueError:
            return None
        n_bytes = (num.bit_length() + 7) // 8 or 1
        raw = num.to_bytes(n_bytes, "big")
        decoded = raw.decode("utf-8", "replace")
        return decoded if _looks_plain(decoded) else None


class FromBinary(Operation):
    """Space or no-space binary string → text."""
    name = "Binary"
    description = "From binary (01-strings, optionally space-separated)"
    category = "Data format"

    _RE8  = re.compile(r"^(?:[01]{8}\s*)+$")
    _RE7  = re.compile(r"^(?:[01]{7}\s*)+$")

    def score(self, text: str) -> float:
        s = text.strip()
        if len(s) < 8:
            return 0.0
        if self._RE8.match(s) or self._RE7.match(s):
            return 0.85
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        chunks = re.findall(r"[01]{7,8}", s)
        if not chunks:
            return None
        try:
            raw = bytes(int(c, 2) for c in chunks)
            decoded = raw.decode("utf-8", "replace")
            return decoded if _looks_plain(decoded) else None
        except Exception:
            return None


class FromOctal(Operation):
    """Space-separated octal sequences."""
    name = "Octal"
    description = "From octal (space-separated, e.g. '110 145 154 154 157')"
    category = "Data format"

    _RE = re.compile(r"^(?:[0-7]{1,3}(?:\s+[0-7]{1,3})*)\s*$")

    def score(self, text: str) -> float:
        s = text.strip()
        if not self._RE.match(s):
            return 0.0
        nums = [int(n, 8) for n in s.split()]
        if len(nums) < 3 and all(32 <= n < 127 for n in nums):
            return 0.0
        return 0.7 if all(n < 256 for n in nums) else 0.0

    def apply(self, text: str) -> Optional[str]:
        try:
            nums = [int(n, 8) for n in text.strip().split()]
            raw = bytes(nums)
            decoded = raw.decode("utf-8", "replace")
            return decoded if _looks_plain(decoded) else None
        except Exception:
            return None


class URLDecode(Operation):
    name = "URLDecode"
    description = "Percent-encoding (URL) decode"
    category = "Data format"

    def score(self, text: str) -> float:
        return 0.8 if re.search(r"%[0-9A-Fa-f]{2}", text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        decoded = unquote(text)
        return decoded if decoded != text else None


class HTMLEntitiesDecode(Operation):
    name = "HTMLEntities"
    description = "HTML entity decode (&amp;, &#...; &...;)"
    category = "Data format"

    def score(self, text: str) -> float:
        return 0.7 if re.search(r"&(?:[a-zA-Z]+|#\d+|#x[0-9a-fA-F]+);", text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        decoded = html.unescape(text)
        return decoded if decoded != text else None


class UTF16Decode(Operation):
    name = "UTF-16"
    description = "UTF-16 LE/BE decode (interleaved zero bytes heuristic)"
    category = "Data format"

    def score(self, text: str) -> float:
        if _looks_plain(text):
            return 0.0
        total = len(text)
        if total < 6:
            return 0.0
        even_nul = text[0::2].count("\x00")
        odd_nul  = text[1::2].count("\x00")
        if even_nul / total > 0.25 or odd_nul / total > 0.25:
            return 0.85
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                raw = text.encode("latin-1", "replace")
                decoded = raw.decode(enc, "replace")
                if _looks_plain(decoded):
                    return decoded
            except Exception:
                pass
        return None


_ESCAPES = {
    "n": "\n", "r": "\r", "t": "\t", "0": "\x00", "\\": "\\",
    '"': '"', "'": "'", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
}


class RawUnescape(Operation):
    name = "RawUnescape"
    description = r"Decode literal escapes (\xNN, \uNNNN, \n, \t, ...)"
    category = "Data format"

    def score(self, text: str) -> float:
        return 0.6 if re.search(r"\\[xXuU0-7nrt\\\"']", text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        if len(s) >= 2 and s[0] == s[-1] == '"':
            s = s[1:-1]

        def _repl(m: "re.Match[str]") -> str:
            ch = m.group(0)[1:]
            if ch in _ESCAPES:
                return _ESCAPES[ch]
            if ch[0] in ("x", "X"):
                return chr(int(ch[1:3], 16))
            if ch[0] in ("u", "U"):
                return chr(int(ch[1:], 16))
            if ch[0] == "0" and len(ch) == 3:
                return chr(int(ch, 8))
            return m.group(0)

        decoded = re.sub(
            r"\\(?:[xuUX][0-9A-Fa-f]{2,8}|[0-7]{1,3}|[nrt\\\"'abfv0])", _repl, s
        )
        return decoded if decoded != text else None


class UnicodeEscapesDecode(Operation):
    """Decode Python/Java-style \\uXXXX or \\UXXXXXXXX unicode escapes."""
    name = "UnicodeEscape"
    description = r"Decode \uXXXX / \UXXXXXXXX unicode escapes"
    category = "Data format"

    def score(self, text: str) -> float:
        return 0.8 if re.search(r"\\u[0-9A-Fa-f]{4}", text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        try:
            decoded = text.encode("raw_unicode_escape").decode("unicode_escape")
            return decoded if decoded != text and _looks_plain(decoded) else None
        except Exception:
            return None


class QuotedPrintableDecode(Operation):
    """Quoted-Printable email encoding (=3D =20 ...)."""
    name = "QuotedPrintable"
    description = "Quoted-Printable decode (=3D =20 ...)"
    category = "Data format"

    def score(self, text: str) -> float:
        return 0.75 if re.search(r"=[0-9A-Fa-f]{2}", text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        import quopri
        try:
            raw = quopri.decodestring(text.encode("ascii", "replace"))
            decoded = raw.decode("utf-8", "replace")
            return decoded if decoded != text and _looks_plain(decoded) else None
        except Exception:
            return None


class MorseCodeDecode(Operation):
    """Morse code decode (. - / space)."""
    name = "MorseCode"
    description = "Morse code decode (dots and dashes)"
    category = "Data format"

    _MORSE = {
        ".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F",
        "--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L",
        "--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R",
        "...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X",
        "-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2",
        "...--":"3","....-":"4",".....":"5","-....":"6","--...":"7",
        "---..":"8","----.":"9","/":"/"
    }
    _RE = re.compile(r"^[.\-/ ]+$")

    def score(self, text: str) -> float:
        s = text.strip()
        if not self._RE.match(s) or len(s) < 3:
            return 0.0
        return 0.8 if "." in s and "-" in s else 0.0

    def apply(self, text: str) -> Optional[str]:
        words = text.strip().split(" / ")
        result = []
        for word in words:
            chars = []
            for code in word.split():
                ch = self._MORSE.get(code)
                if ch is None:
                    return None
                chars.append(ch)
            result.append("".join(chars))
        decoded = " ".join(result)
        return decoded if decoded and _looks_plain(decoded) else None


class JWTDecode(Operation):
    """Decode a JSON Web Token (extract header + payload)."""
    name = "JWT"
    description = "JWT decode (header + payload, no signature verification)"
    category = "Data format"

    _RE = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")

    def score(self, text: str) -> float:
        s = text.strip()
        if not self._RE.match(s):
            return 0.0
        parts = s.split(".")
        # First part decodes to JSON with 'alg' field
        try:
            hdr_raw = base64.urlsafe_b64decode(parts[0] + "==")
            hdr = json.loads(hdr_raw)
            if "alg" in hdr:
                return 0.95
        except Exception:
            pass
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        parts = s.split(".")
        if len(parts) < 2:
            return None
        out = {}
        try:
            for key, idx in (("header", 0), ("payload", 1)):
                raw = base64.urlsafe_b64decode(parts[idx] + "==")
                out[key] = json.loads(raw)
        except Exception:
            return None
        return json.dumps(out, indent=2, ensure_ascii=False)


# ============================================================================
# CATEGORY 2 — Encryption / Encoding
# ============================================================================

class ROT13(Operation):
    """ROT13 letter substitution cipher."""
    name = "ROT13"
    description = "ROT13 decode/encode (Caesar shift +13)"
    category = "Encryption / Encoding"

    def score(self, text: str) -> float:
        s = text.strip()
        if not s or not any(c.isalpha() for c in s):
            return 0.0
        # Only apply when the text is mostly printable ASCII (not binary data).
        # Binary payloads (e.g. gzip) passed as latin-1 strings can contain
        # alphabetic bytes that would trigger ROT13 erroneously.
        printable = sum(1 for c in s if 32 <= ord(c) < 127)
        if printable / len(s) < 0.90:
            return 0.0
        return 0.15  # very low priority: only when nothing else applies

    def apply(self, text: str) -> Optional[str]:
        result = []
        for c in text:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(c)
        decoded = "".join(result)
        return decoded if decoded != text else None



class ROT47(Operation):
    """ROT47 — rotates ASCII 33-126 by 47 positions."""
    name = "ROT47"
    description = "ROT47 decode/encode (printable ASCII rotation)"
    category = "Encryption / Encoding"

    def score(self, text: str) -> float:
        s = text.strip()
        if not s:
            return 0.0
        printable = sum(1 for c in s if 33 <= ord(c) <= 126)
        if printable / len(s) > 0.8:
            return 0.2
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        result = []
        for c in text:
            o = ord(c)
            if 33 <= o <= 126:
                result.append(chr((o - 33 + 47) % 94 + 33))
            else:
                result.append(c)
        decoded = "".join(result)
        return decoded if decoded != text else None


class Atbash(Operation):
    """Atbash cipher — mirrors the alphabet (A↔Z)."""
    name = "Atbash"
    description = "Atbash decode (A↔Z, mirror cipher)"
    category = "Encryption / Encoding"

    def score(self, text: str) -> float:
        s = text.strip()
        return 0.2 if s and all(c.isalpha() or c == " " for c in s) else 0.0

    def apply(self, text: str) -> Optional[str]:
        result = []
        for c in text:
            if "a" <= c <= "z":
                result.append(chr(ord("z") - (ord(c) - ord("a"))))
            elif "A" <= c <= "Z":
                result.append(chr(ord("Z") - (ord(c) - ord("A"))))
            else:
                result.append(c)
        decoded = "".join(result)
        return decoded if decoded != text else None


class XORSingleByte(Operation):
    """XOR with a single byte key — tries all 256 keys, returns best result."""
    name = "XOR"
    description = "XOR single-byte brute force (tries all 256 keys)"
    category = "Encryption / Encoding"

    def score(self, text: str) -> float:
        # Only useful when text contains mostly non-printable chars mixed with printable
        s = text.strip()
        if len(s) < 4:
            return 0.0
        non_print = sum(1 for c in s if not (32 <= ord(c) < 127))
        ratio = non_print / len(s)
        return 0.5 if 0.1 < ratio < 0.8 else 0.0

    def apply(self, text: str) -> Optional[str]:
        data = text.encode("latin-1", "replace")
        best_score = -1
        best_result = None
        for key in range(1, 256):
            xored = bytes(b ^ key for b in data)
            printable = sum(1 for b in xored if 32 <= b < 127)
            score = printable / len(xored)
            if score > best_score:
                best_score = score
                best_result = xored
        if best_score >= 0.9 and best_result:
            decoded = best_result.decode("latin-1", "replace")
            return decoded if _looks_plain(decoded) else None
        return None


class AffineDecrypt(Operation):
    """Affine cipher brute force (a ∈ {1,3,5,7,9,11,15,17,19,21,23,25})."""
    name = "Affine"
    description = "Affine cipher decode (brute force a,b)"
    category = "Encryption / Encoding"

    _COPRIMES = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    _MOD_INV = {1:1, 3:9, 5:21, 7:15, 9:3, 11:19, 15:7, 17:23, 19:11, 21:5, 23:17, 25:25}
    _ENGLISH = [
        8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
        0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
        6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
    ]

    def score(self, text: str) -> float:
        s = text.strip()
        return 0.15 if s and all(c.isalpha() or c.isspace() for c in s) else 0.0

    def apply(self, text: str) -> Optional[str]:
        data = [ord(c) - ord("A") for c in text.upper() if c.isalpha()]
        if not data:
            return None
        best_fitness = float("-inf")
        best_ioc = 0.0
        best_decoded: Optional[str] = None
        for a_inv in self._MOD_INV.values():
            for b in range(26):
                decrypted = [(a_inv * (c - b)) % 26 for c in data]
                freq = [0] * 26
                for c in decrypted:
                    freq[c] += 1
                n = len(decrypted)
                if n < 2:
                    continue
                ioc = sum(f * (f - 1) for f in freq) / (n * (n - 1))
                likelihood = sum(
                    math.log(self._ENGLISH[c] / 100.0 + 1e-6) for c in decrypted
                ) / n
                fitness = likelihood + ioc * 3.0
                if fitness > best_fitness:
                    best_fitness = fitness
                    best_ioc = ioc
                    best_decoded = "".join(chr(c + ord("A")) for c in decrypted)
        if best_decoded and (best_ioc >= 0.045 or len(data) >= 24):
            return best_decoded
        return None


class BaconDecode(Operation):
    """Bacon's cipher decode (AAAAA=A ... BBBBB=Z)."""
    name = "Bacon"
    description = "Bacon cipher decode (A/B binary encoding)"
    category = "Encryption / Encoding"

    _MAP = {
        "AAAAA":"A","AAAAB":"B","AAABA":"C","AAABB":"D","AABAA":"E",
        "AABAB":"F","AABBA":"G","AABBB":"H","ABAAA":"I","ABAAB":"J",
        "ABABA":"K","ABABB":"L","ABBAA":"M","ABBAB":"N","ABBBA":"O",
        "ABBBB":"P","BAAAA":"Q","BAAAB":"R","BAABA":"S","BAABB":"T",
        "BABAA":"U","BABAB":"V","BABBA":"W","BABBB":"X","BBAAA":"Y",
        "BBAAB":"Z",
    }
    _RE = re.compile(r"^[ABab\s]+$")

    def score(self, text: str) -> float:
        s = text.strip().upper()
        if not self._RE.match(s):
            return 0.0
        groups = s.split()
        if all(len(g) == 5 and all(c in "AB" for c in g) for g in groups):
            return 0.9
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip().upper()
        groups = s.split()
        result = []
        for g in groups:
            ch = self._MAP.get(g)
            if ch is None:
                return None
            result.append(ch)
        return "".join(result) if result else None


# ============================================================================
# CATEGORY 3 — Compression
# ============================================================================

class GzipDecompress(Operation):
    name = "Gzip"
    description = "gzip decompress"
    category = "Compression"

    def score(self, text: str) -> float:
        try:
            raw = text.encode("latin-1")
            return 0.9 if raw[:2] == b"\x1f\x8b" else 0.0
        except Exception:
            return 0.0

    def apply(self, text: str) -> Optional[str]:
        raw = _bounded_decompress("gzip", text.encode("latin-1"))
        return _decode_bytes(raw) if raw is not None else None


class ZlibDecompress(Operation):
    name = "Zlib"
    description = "zlib decompress (deflate with zlib header)"
    category = "Compression"

    def score(self, text: str) -> float:
        try:
            raw = text.encode("latin-1")
            # zlib magic bytes: 0x78 0x9C or 0x78 0xDA or 0x78 0x01
            if len(raw) >= 2 and raw[0] == 0x78 and raw[1] in (0x01, 0x9C, 0xDA):
                return 0.9
            return 0.0
        except Exception:
            return 0.0

    def apply(self, text: str) -> Optional[str]:
        raw = _bounded_decompress("zlib", text.encode("latin-1"))
        return _decode_bytes(raw) if raw is not None else None


class Bzip2Decompress(Operation):
    name = "Bzip2"
    description = "bzip2 decompress"
    category = "Compression"

    def score(self, text: str) -> float:
        try:
            raw = text.encode("latin-1")
            return 0.9 if raw[:3] == b"BZh" else 0.0
        except Exception:
            return 0.0

    def apply(self, text: str) -> Optional[str]:
        raw = _bounded_decompress("bz2", text.encode("latin-1"))
        return _decode_bytes(raw) if raw is not None else None


class LZMADecompress(Operation):
    name = "LZMA"
    description = "LZMA / XZ decompress"
    category = "Compression"

    def score(self, text: str) -> float:
        try:
            raw = text.encode("latin-1")
            # XZ magic: FD 37 7A 58 5A 00 | LZMA magic: 5D 00
            if raw[:6] == b"\xfd7zXZ\x00":
                return 0.9
            if raw[:2] == b"\x5d\x00":
                return 0.7
            return 0.0
        except Exception:
            return 0.0

    def apply(self, text: str) -> Optional[str]:
        raw = _bounded_decompress("lzma", text.encode("latin-1"))
        return _decode_bytes(raw) if raw is not None else None


class DeflateRaw(Operation):
    """Raw DEFLATE (no zlib header)."""
    name = "DeflateRaw"
    description = "Raw DEFLATE decompress (no zlib header)"
    category = "Compression"

    def score(self, text: str) -> float:
        return 0.0  # No reliable magic bytes; never auto-selected

    def apply(self, text: str) -> Optional[str]:
        raw = _bounded_decompress("deflate", text.encode("latin-1"))
        return _decode_bytes(raw) if raw is not None else None


# ============================================================================
# CATEGORY 4 — Hashing (identity / round-trip check)
# ============================================================================

class HashDetector(Operation):
    """
    Not a decoder — identifies if the *input itself* IS a hash by length/pattern
    and annotates (returns input unchanged).  Score >0 means 'input looks like
    a known hash format', which tells the recipe engine to stop peeling.
    """
    name = "HashDetector"
    description = "Detect if input is already a bare hash (stops peeling)"
    category = "Hashing"

    _KNOWN_LENS = {32, 40, 48, 56, 64, 80, 96, 128}  # md5..sha512
    _PREFIX = re.compile(
        r"^\$(?:2[ayb]\$|5\$|6\$|argon2|apr1\$|sha[0-9]+\$|pbkdf2|"
        r"scrypt|bcrypt|[0-9]+\$)"
    )

    def score(self, text: str) -> float:
        s = text.strip()
        if self._PREFIX.match(s):
            return 1.0  # Definitely already a hash — stop
        if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) in self._KNOWN_LENS:
            return 1.0
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        # Identity: return as-is so the recipe engine recognises it as stable.
        return text.strip()


# ============================================================================
# CATEGORY 5 — Forensics
# ============================================================================

class RemoveNullBytes(Operation):
    """Strip null bytes from a string — only when text is mostly printable ASCII."""
    name = "RemoveNullBytes"
    description = "Remove null bytes (\\x00) from string (text-only, not binary)"
    category = "Forensics"

    def score(self, text: str) -> float:
        if "\x00" not in text:
            return 0.0
        # Only apply when non-null content is mostly printable.
        # Avoids corrupting binary payloads (gzip, bzip2, lzma) that
        # contain null bytes as part of their compression format headers.
        non_null_chars = [c for c in text if c != "\x00"]
        if not non_null_chars:
            return 0.0
        printable = sum(1 for c in non_null_chars if 32 <= ord(c) < 127 or c in "\n\r\t")
        if printable / len(non_null_chars) < 0.75:
            return 0.0  # Looks like binary data — skip
        return 0.6

    def apply(self, text: str) -> Optional[str]:
        cleaned = text.replace("\x00", "")
        return cleaned if cleaned != text else None


class StripWhitespace(Operation):
    """Collapse all whitespace and trim — useful for copy-pasted hashes."""
    name = "StripWhitespace"
    description = "Strip / collapse extra whitespace"
    category = "Forensics"

    def score(self, text: str) -> float:
        if re.search(r"\s{2,}", text) or text != text.strip():
            return 0.4
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        cleaned = re.sub(r"\s+", "", text).strip()
        return cleaned if cleaned != text else None


class ExtractHashFromLine(Operation):
    """Extract a bare hash from a line that contains extra context."""
    name = "ExtractHash"
    description = "Extract hex hash from a line (e.g. 'Password: deadbeef...')"
    category = "Forensics"

    _RE = re.compile(r"\b([0-9a-fA-F]{32,128})\b")

    def score(self, text: str) -> float:
        s = text.strip()
        m = self._RE.search(s)
        if m and len(m.group(1)) in {32, 40, 48, 56, 64, 96, 128}:
            # Only peel if there's surrounding context
            if m.group(1) != s:
                return 0.7
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        m = self._RE.search(text)
        if m and len(m.group(1)) in {32, 40, 48, 56, 64, 96, 128}:
            candidate = m.group(1)
            if candidate != text.strip():
                return candidate
        return None


class DefangURL(Operation):
    """Re-fang a defanged URL (hxxp[s]://... → https://...)."""
    name = "Refang"
    description = "Re-fang defanged URLs (hxxp → http, [.] → .)"
    category = "Forensics"

    def score(self, text: str) -> float:
        s = text.strip()
        if re.search(r"hxxps?://|hxxp|[\[\(]\.\]|https?\[:\]//", s, re.I):
            return 0.85
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        s = text.strip()
        s = re.sub(r"hxxp", "http", s, flags=re.I)
        s = re.sub(r"[\[\(]\.\][\)\]]?", ".", s)
        s = re.sub(r"http\[:\]//", "http://", s, flags=re.I)
        return s if s != text.strip() else None


# ============================================================================
# CATEGORY 6 — Extractors
# ============================================================================

class ExtractBase64Blobs(Operation):
    """Find and return the longest Base64 blob embedded in surrounding text."""
    name = "ExtractBase64"
    description = "Extract longest Base64 blob from mixed text"
    category = "Extractors"

    _RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

    def score(self, text: str) -> float:
        m = self._RE.search(text)
        if m and m.group() != text.strip():
            return 0.6
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        matches = self._RE.findall(text)
        if not matches:
            return None
        # Return the longest match that decodes cleanly
        for blob in sorted(matches, key=len, reverse=True):
            try:
                pad = "=" * (-len(blob) % 4)
                raw = base64.b64decode(blob + pad)
                decoded = raw.decode("utf-8", "replace")
                if _looks_plain(decoded):
                    return decoded
            except Exception:
                pass
        return None


class ExtractIPAddresses(Operation):
    """Extract all IPv4 addresses from text."""
    name = "ExtractIP"
    description = "Extract IPv4 addresses from text"
    category = "Extractors"

    _RE = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )

    def score(self, text: str) -> float:
        return 0.7 if self._RE.search(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        ips = self._RE.findall(text)
        return "\n".join(ips) if ips else None


class ExtractEmails(Operation):
    """Extract email addresses from text."""
    name = "ExtractEmails"
    description = "Extract email addresses from text"
    category = "Extractors"

    _RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

    def score(self, text: str) -> float:
        return 0.75 if self._RE.search(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        emails = self._RE.findall(text)
        return "\n".join(emails) if emails else None


class ExtractURLs(Operation):
    """Extract URLs from text."""
    name = "ExtractURLs"
    description = "Extract URLs (http/https/ftp) from text"
    category = "Extractors"

    _RE = re.compile(r"https?://[^\s\"'>]+|ftp://[^\s\"'>]+", re.I)

    def score(self, text: str) -> float:
        return 0.7 if self._RE.search(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        urls = self._RE.findall(text)
        return "\n".join(urls) if urls else None


class ExtractMACAddresses(Operation):
    """Extract MAC addresses from text."""
    name = "ExtractMAC"
    description = "Extract MAC addresses (XX:XX:XX:XX:XX:XX) from text"
    category = "Extractors"

    _RE = re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
    )

    def score(self, text: str) -> float:
        return 0.8 if self._RE.search(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        macs = self._RE.findall(text)
        return "\n".join(macs) if macs else None


class ExtractJWTPayload(Operation):
    """Extract the decoded payload from a JWT string."""
    name = "ExtractJWTPayload"
    description = "Extract decoded payload from JWT (header.payload.sig)"
    category = "Extractors"

    _RE = re.compile(r"^[A-Za-z0-9\-_]+\.([A-Za-z0-9\-_]+)\.[A-Za-z0-9\-_]*$")

    def score(self, text: str) -> float:
        s = text.strip()
        m = self._RE.match(s)
        if not m:
            return 0.0
        try:
            raw = base64.urlsafe_b64decode(m.group(1) + "==")
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return 0.95
        except Exception:
            pass
        return 0.0

    def apply(self, text: str) -> Optional[str]:
        m = self._RE.match(text.strip())
        if not m:
            return None
        try:
            raw = base64.urlsafe_b64decode(m.group(1) + "==")
            return json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
        except Exception:
            return None


# ============================================================================
# Global registry — ordered by typical confidence (high→low)
# Auto-selected operations: excluded are HashDetector (stop-signal, special),
# DeflateRaw (no magic), Extractors (used on demand), Affine/Bacon (low priority).
# ============================================================================

OPERATIONS: tuple[Operation, ...] = (
    # --- Compression (reliable magic bytes → high priority) ---
    GzipDecompress(),
    Bzip2Decompress(),
    LZMADecompress(),
    ZlibDecompress(),
    DeflateRaw(),

    # --- Data format (high confidence first) ---
    JWTDecode(),
    URLDecode(),
    HTMLEntitiesDecode(),
    QuotedPrintableDecode(),
    UnicodeEscapesDecode(),
    RawUnescape(),
    Base64Decode(),
    Base85Decode(),
    Base32Decode(),
    Base58Decode(),
    Base62Decode(),
    HexDecode(),
    MorseCodeDecode(),
    FromBinary(),
    FromOctal(),
    FromCharcodeDecimal(),
    FromDecimalNumber(),
    UTF16Decode(),

    # --- Forensics ---
    RemoveNullBytes(),
    ExtractHashFromLine(),
    StripWhitespace(),
    DefangURL(),

    # --- Extractors ---
    ExtractJWTPayload(),
    ExtractBase64Blobs(),
    ExtractIPAddresses(),
    ExtractEmails(),
    ExtractURLs(),
    ExtractMACAddresses(),

    # --- Encryption / Encoding (low auto-score; applied when other ops fail) ---
    ROT13(),
    ROT47(),
    Atbash(),
    XORSingleByte(),
    BaconDecode(),
    AffineDecrypt(),

    # --- Hashing (stop-signal — stable hash detected) ---
    HashDetector(),
)

# Extended operations live in a separate module to keep this compatibility
# surface readable.  Importing them here (after the base classes/registry are
# defined) keeps ``OPERATIONS`` as the single source of truth for callers.
from hashvault.analysis.operations_extra import EXTRA_OPERATIONS  # noqa: E402

OPERATIONS = (*OPERATIONS, *EXTRA_OPERATIONS)

OPERATION_BY_NAME: dict[str, Operation] = {op.name: op for op in OPERATIONS}
OPERATIONS_BY_CATEGORY: dict[str, list[Operation]] = {}
for _op in OPERATIONS:
    OPERATIONS_BY_CATEGORY.setdefault(_op.category, []).append(_op)
