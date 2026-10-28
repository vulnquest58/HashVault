"""
Built-in, dependency-light cracking engine.

This is the offline fallback used when hashcat/John are unavailable (or when a
format has no external mode).  It supports dictionary, hashcat-rule and mask
attacks for the most common password hashes and verifies candidates in-process.

The engine intentionally verifies candidates instead of generating hash tables:
memory use stays constant regardless of wordlist size, and it can handle salted
formats without precomputation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import logging
import re
import string
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Sequence

from hashvault.config import Config
from hashvault.core.cracker import (
    BaseCracker,
    CrackResult,
    compute_timeout,
    create_crack_session,
    release_session_artifacts,
)
from hashvault.models.orm import CrackSession, Pattern
from hashvault.models.schemas import PatternSchema

logger = logging.getLogger("hashvault.builtin")

_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


# ---------------------------------------------------------------------------
# MD4 (hashlib does not provide it; NTLM needs it)
# ---------------------------------------------------------------------------
def _md4(data: bytes) -> bytes:
    """Pure-Python RFC 1320 MD4."""
    msg = bytearray(data)
    bit_len = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    mask = 0xFFFFFFFF

    def rol(value: int, bits: int) -> int:
        value &= mask
        return ((value << bits) | (value >> (32 - bits))) & mask

    for offset in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[offset:offset + 64]))
        aa, bb, cc, dd = a, b, c, d

        for i in range(16):
            k = i
            s = (3, 7, 11, 19)[i % 4]
            f = (b & c) | (~b & d)
            a = rol(a + f + x[k], s)
            a, b, c, d = d, a, b, c

        for i in range(16):
            k = (i % 4) * 4 + i // 4
            s = (3, 5, 9, 13)[i % 4]
            f = (b & c) | (b & d) | (c & d)
            a = rol(a + f + x[k] + 0x5A827999, s)
            a, b, c, d = d, a, b, c

        for i in range(16):
            k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i]
            s = (3, 9, 11, 15)[i % 4]
            f = b ^ c ^ d
            a = rol(a + f + x[k] + 0x6ED9EBA1, s)
            a, b, c, d = d, a, b, c

        a = (a + aa) & mask
        b = (b + bb) & mask
        c = (c + cc) & mask
        d = (d + dd) & mask

    return struct.pack("<4I", a, b, c, d)


def _nt_hash(password: str) -> bytes:
    return _md4(password.encode("utf-16-le"))


# ---------------------------------------------------------------------------
# Passlib bridge (optional)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from passlib.hash import (
        apr_md5_crypt as _passlib_apr_md5_crypt,
        bsdi_crypt as _passlib_bsdi_crypt,
        des_crypt as _passlib_des_crypt,
        lmhash as _passlib_lmhash,
        md5_crypt as _passlib_md5_crypt,
        msdcc as _passlib_msdcc,
        msdcc2 as _passlib_msdcc2,
        mysql323 as _passlib_mysql323,
        mysql41 as _passlib_mysql41,
        phpass as _passlib_phpass,
        sha1_crypt as _passlib_sha1_crypt,
        sha256_crypt as _passlib_sha256_crypt,
        sha512_crypt as _passlib_sha512_crypt,
    )
    _HAS_PASSLIB = True
except Exception:  # pragma: no cover
    _HAS_PASSLIB = False

try:  # pragma: no cover - optional dependency
    import bcrypt as _bcrypt
except Exception:  # pragma: no cover
    _bcrypt = None


def _passlib_verify(hasher, password: str, target: str) -> bool:
    if not _HAS_PASSLIB:
        return False
    try:
        return bool(hasher.verify(password, target))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Drupal 7 (SHA-512 phpass variant)
# ---------------------------------------------------------------------------
def _drupal_b64(data: bytes, count: int) -> str:
    out: List[str] = []
    i = 0
    while i < count:
        value = data[i]
        i += 1
        out.append(_ITOA64[value & 0x3F])
        if i < count:
            value |= data[i] << 8
        out.append(_ITOA64[(value >> 6) & 0x3F])
        if i >= count:
            break
        i += 1
        if i < count:
            value |= data[i] << 16
        out.append(_ITOA64[(value >> 12) & 0x3F])
        if i >= count:
            break
        i += 1
        out.append(_ITOA64[(value >> 18) & 0x3F])
    return "".join(out)


def _drupal_hash(password: str, target: str) -> str:
    if len(target) < 12 or not target.startswith("$S$"):
        return ""
    count_log2 = _ITOA64.find(target[3])
    if count_log2 < 0:
        return ""
    count = 1 << count_log2
    salt = target[4:12].encode()
    pw = password.encode("utf-8")
    digest = hashlib.sha512(salt + pw).digest()
    # Drupal's do/while executes ``count`` more rounds after the first hash.
    for _ in range(count):
        digest = hashlib.sha512(digest + pw).digest()
    # Encode the full digest, then truncate to DRUPAL_HASH_LENGTH (55).
    return (target[:12] + _drupal_b64(digest, 64))[:55]


# ---------------------------------------------------------------------------
# NetNTLM helpers
# ---------------------------------------------------------------------------
def _des_encrypt(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # pragma: no cover - older cryptography
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    key = (key + b"\x00" * 8)[:8]
    # Single-key TripleDES (K1 == K2 == K3) is plain DES without the
    # deprecated 8-byte-key constructor.
    encryptor = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _des_key_from_7(seven: bytes) -> bytes:
    b = (seven + b"\x00" * 7)[:7]
    key = [
        b[0],
        ((b[0] << 7) | (b[1] >> 1)) & 0xFF,
        ((b[1] << 6) | (b[2] >> 2)) & 0xFF,
        ((b[2] << 5) | (b[3] >> 3)) & 0xFF,
        ((b[3] << 4) | (b[4] >> 4)) & 0xFF,
        ((b[4] << 3) | (b[5] >> 5)) & 0xFF,
        ((b[5] << 2) | (b[6] >> 6)) & 0xFF,
        (b[6] << 1) & 0xFF,
    ]
    return bytes(k | 0x01 for k in key)


def _ntlmv1_response(nt_hash: bytes, challenge: bytes) -> bytes:
    return b"".join(
        _des_encrypt(_des_key_from_7(chunk + b"\x00" * 7), challenge)
        for chunk in (nt_hash[0:7], nt_hash[7:14], nt_hash[14:16])
    )


def _ntlmv2_response(user: str, domain: str, password: str, challenge: bytes, blob: bytes) -> bytes:
    nt_hash = _nt_hash(password)
    identity = (user.upper() + domain).encode("utf-16-le")
    v2_hash = hmac.new(nt_hash, identity, hashlib.md5).digest()
    return hmac.new(v2_hash, challenge + blob, hashlib.md5).digest()


# ---------------------------------------------------------------------------
# Candidate sources
# ---------------------------------------------------------------------------
class _RuleError(ValueError):
    pass


def _tokenize_rule(rule: str) -> List[str]:
    """Tokenize a hashcat rule line, including concatenated operations."""
    ops: List[str] = []
    i = 0
    one_char = set(":lucCtrdf{}[]kKqE")
    while i < len(rule):
        ch = rule[i]
        if ch.isspace():
            i += 1
            continue
        if ch in one_char:
            ops.append(ch)
            i += 1
            continue
        if ch in "$^@T'DNzpZp":
            if i + 1 >= len(rule):
                raise _RuleError(rule)
            ops.append(rule[i:i + 2])
            i += 2
            continue
        if ch in "s":
            if i + 2 >= len(rule):
                raise _RuleError(rule)
            ops.append(rule[i:i + 3])
            i += 3
            continue
        if ch in "iox":
            if i + 2 >= len(rule):
                raise _RuleError(rule)
            ops.append(rule[i:i + 3])
            i += 3
            continue
        if ch in "<>_!/()=%":
            # Reject rules are not evaluated; skip this line's candidate.
            raise _RuleError(rule)
        # Unknown operation: treat it as invalid rather than guessing.
        raise _RuleError(rule)
    return ops


class _Rule:
    __slots__ = ("ops",)

    def __init__(self, ops: List[str]) -> None:
        self.ops = ops

    def apply(self, word: str) -> Optional[str]:
        value = word
        try:
            for op in self.ops:
                if op == ":":  # no-op
                    continue
                if op == "l":
                    value = value.lower()
                elif op == "u":
                    value = value.upper()
                elif op == "c":
                    value = value.capitalize()
                elif op == "C":
                    value = value[:1].lower() + value[1:].upper()
                elif op == "t":
                    value = "".join(c.swapcase() for c in value)
                elif op == "r":
                    value = value[::-1]
                elif op == "d":
                    value = value + value
                elif op == "f":
                    value = value + value[::-1]
                elif op == "[":
                    value = value[1:]
                elif op == "]":
                    value = value[:-1]
                elif op == "{":
                    value = value[1:] + value[:1]
                elif op == "}":
                    value = value[-1:] + value[:-1]
                elif op == "k":
                    value = value[1:2] + value[0:1] + value[2:] if len(value) >= 2 else value
                elif op == "K":
                    value = value[:-2] + value[-1:] + value[-2:-1] if len(value) >= 2 else value
                elif op == "q":
                    value = "".join(c * 2 for c in value)
                elif op == "E":
                    value = " ".join(part.capitalize() for part in value.split(" "))
                elif op.startswith("$"):
                    value += op[1]
                elif op.startswith("^"):
                    value = op[1] + value
                elif op.startswith("T"):
                    idx = int(op[1]) if op[1].isdigit() else None
                    if idx is not None and 0 <= idx < len(value):
                        value = value[:idx] + value[idx].swapcase() + value[idx + 1:]
                elif op.startswith("'"):
                    idx = int(op[1]) if op[1].isdigit() else len(value)
                    value = value[:idx]
                elif op.startswith("s"):
                    if len(op) >= 3:
                        value = value.replace(op[1], op[2])
                elif op.startswith("@"):
                    value = value.replace(op[1], "")
                elif op.startswith("i"):
                    idx = int(op[1]) if op[1].isdigit() else 0
                    value = value[:idx] + op[2] + value[idx:]
                elif op.startswith("o"):
                    idx = int(op[1]) if op[1].isdigit() else 0
                    if 0 <= idx < len(value):
                        value = value[:idx] + op[2] + value[idx + 1:]
                elif op.startswith("D"):
                    idx = int(op[1]) if op[1].isdigit() else 0
                    if 0 <= idx < len(value):
                        value = value[:idx] + value[idx + 1:]
                elif op.startswith("x"):
                    start = int(op[1]) if op[1].isdigit() else 0
                    length = int(op[2]) if op[2].isdigit() else 0
                    value = value[start:start + length]
                elif op.startswith("z"):
                    n = int(op[1]) if op[1].isdigit() else 0
                    value = value[:1] * n + value
                elif op.startswith("Z"):
                    n = int(op[1]) if op[1].isdigit() else 0
                    value = value + value[-1:] * n
                elif op.startswith("p"):
                    n = int(op[1]) if op[1].isdigit() else 0
                    value = value * (n + 1)
                else:
                    return None
            return value
        except (IndexError, ValueError):
            return None


def load_rules(path: str | Path | None) -> List[_Rule]:
    if not path:
        return []
    rules: List[_Rule] = []
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rules.append(_Rule(_tokenize_rule(line)))
            except _RuleError:
                continue
    except OSError:
        return []
    return rules


_MASK_CHARSETS = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": " " + string.punctuation,
    "a": string.ascii_letters + string.digits + " " + string.punctuation,
    "h": string.hexdigits[:16],
    "H": string.hexdigits[:16].upper(),
}


def _expand_mask(mask: str) -> Iterator[str]:
    positions: List[Sequence[str]] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?":
            if i + 1 >= len(mask):
                positions.append(("?",))
                i += 1
                continue
            key = mask[i + 1].lower()
            if key == "?":
                positions.append(("?",))
            elif key in _MASK_CHARSETS:
                positions.append(_MASK_CHARSETS[key])
            else:
                raise ValueError(f"Unsupported mask charset '?{mask[i + 1]}'")
            i += 2
            continue
        positions.append((ch,))
        i += 1
    if not positions:
        return
    for combo in itertools.product(*positions):
        yield "".join(combo)


def _iter_wordlist(path: str | Path) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.rstrip("\r\n")
            if word:
                yield word


def _iter_candidates(
    wordlist_path: str | Path,
    rules: Sequence[_Rule],
    attack_mode: str,
    mask: Optional[str],
) -> Iterator[str]:
    if attack_mode in ("mask", "hybrid") and mask:
        mask_iter = _expand_mask(mask)
        if attack_mode == "mask":
            yield from mask_iter
        else:
            for word in _iter_wordlist(wordlist_path):
                if rules:
                    bases = (rule.apply(word) for rule in rules)
                else:
                    bases = (word,)
                for base in bases:
                    if base is None:
                        continue
                    for suffix in _expand_mask(mask):
                        yield base + suffix
        return

    for word in _iter_wordlist(wordlist_path):
        if not rules:
            yield word
            continue
        for rule in rules:
            candidate = rule.apply(word)
            if candidate is not None:
                yield candidate


# ---------------------------------------------------------------------------
# Verifier construction
# ---------------------------------------------------------------------------
class BuiltinUnsupported(ValueError):
    pass


@dataclass
class _Verifier:
    fn: Callable[[str], bool]
    description: str


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=False)
    except Exception:
        return b""


def _ab64decode(value: str) -> bytes:
    """Decode passlib's adapted-base64 (``.``/``/`` instead of ``+``/``/``)."""
    try:
        value = value.replace(".", "+")
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except Exception:
        return b""


def _make_verifier(hash_value: str, pattern: Pattern | PatternSchema) -> _Verifier:
    mode = getattr(pattern, "hashcat_mode", None)
    name = (getattr(pattern, "name", "") or "").lower()
    target = hash_value.strip()
    target_low = target.lower()

    # Raw fast hashes -----------------------------------------------------
    raw_algs = {0: "md5", 100: "sha1", 1300: "sha224", 1400: "sha256",
                1700: "sha512", 10800: "sha384"}
    if mode in raw_algs and _HEX_RE.fullmatch(target):
        alg = raw_algs[mode]
        expected = target_low

        def verify_raw(password: str) -> bool:
            return hmac.compare_digest(
                hashlib.new(alg, password.encode("utf-8")).hexdigest(), expected
            )

        return _Verifier(verify_raw, f"raw {alg.upper()}")

    if mode == 1000 and _HEX_RE.fullmatch(target):
        def verify_ntlm(password: str) -> bool:
            return hmac.compare_digest(_nt_hash(password).hex(), target_low)

        return _Verifier(verify_ntlm, "NTLM")

    if mode == 900 and _HEX_RE.fullmatch(target):
        expected = target_low

        def verify_md4(password: str) -> bool:
            return hmac.compare_digest(_md4(password.encode("utf-8")).hex(), expected)

        return _Verifier(verify_md4, "MD4")

    if mode in (131, 132):
        if not target.startswith("0x0100"):
            raise BuiltinUnsupported("Malformed MSSQL hash")
        try:
            raw = bytes.fromhex(target[6:])
        except ValueError as exc:
            raise BuiltinUnsupported("Malformed MSSQL hash") from exc
        if mode == 131 and len(raw) == 44:
            salt, expected = raw[:4], raw[24:44]

            def verify_mssql2000(password: str) -> bool:
                digest = hashlib.sha1(
                    password.upper().encode("utf-16-le") + salt
                ).digest()
                return hmac.compare_digest(digest, expected)

            return _Verifier(verify_mssql2000, "MSSQL 2000")
        if mode == 132 and len(raw) == 24:
            salt, expected = raw[:4], raw[4:24]

            def verify_mssql2005(password: str) -> bool:
                digest = hashlib.sha1(
                    password.encode("utf-16-le") + salt
                ).digest()
                return hmac.compare_digest(digest, expected)

            return _Verifier(verify_mssql2005, "MSSQL 2005")
        raise BuiltinUnsupported("Malformed MSSQL hash length")

    if mode == 3000:
        if not _HAS_PASSLIB:
            raise BuiltinUnsupported("LM verification needs passlib")
        if len(target) == 16 and _HEX_RE.fullmatch(target):
            half = target_low

            def verify_lm_half(password: str) -> bool:
                return hmac.compare_digest(_passlib_lmhash.hash(password)[:16], half)

            return _Verifier(verify_lm_half, "LM")
        return _Verifier(lambda pw: _passlib_verify(_passlib_lmhash, pw, target), "LM")

    # MySQL / PostgreSQL ------------------------------------------------
    if mode == 200:
        if not _HAS_PASSLIB:
            raise BuiltinUnsupported("MySQL323 needs passlib")
        return _Verifier(lambda pw: _passlib_verify(_passlib_mysql323, pw, target), "MySQL323")

    if mode == 300:
        if not _HAS_PASSLIB:
            raise BuiltinUnsupported("MySQL4.1 needs passlib")
        mysql_target = target
        if not mysql_target.startswith("*") and _HEX_RE.fullmatch(mysql_target):
            mysql_target = "*" + mysql_target.upper()
        return _Verifier(
            lambda pw: _passlib_verify(_passlib_mysql41, pw, mysql_target),
            "MySQL4.1",
        )

    if mode == 12 or "postgresql md5" in name:
        body = target
        username = ""
        if body.lower().startswith("md5") and len(body) == 35 and _HEX_RE.fullmatch(body[3:]):
            body = body[3:]
        if ":" in body:
            body, username = body.split(":", 1)
        if not username:
            raise BuiltinUnsupported("PostgreSQL MD5 requires the username (user:md5...)")
        expected = body.lower()

        def verify_pg(password: str) -> bool:
            return hmac.compare_digest(
                hashlib.md5((password + username).encode("utf-8")).hexdigest(), expected
            )

        return _Verifier(verify_pg, "PostgreSQL MD5")

    # LDAP salted digests ----------------------------------------------
    if mode in (111, 1411, 1711):
        marker, digest_len, alg = {
            111: ("{SSHA}", 20, "sha1"),
            1411: ("{SSHA256}", 32, "sha256"),
            1711: ("{SSHA512}", 64, "sha512"),
        }[mode]
        if not target.startswith(marker):
            raise BuiltinUnsupported("Malformed LDAP salted hash")
        payload = _b64decode(target[len(marker):])
        if len(payload) < digest_len:
            raise BuiltinUnsupported("Malformed LDAP salted hash")
        expected, salt = payload[:digest_len], payload[digest_len:]

        def verify_ldap_salted(password: str) -> bool:
            digest = hashlib.new(alg, password.encode("utf-8") + salt).digest()
            return hmac.compare_digest(digest, expected)

        return _Verifier(verify_ldap_salted, f"SSHA-{alg.upper()}")

    # crypt(3) family ---------------------------------------------------
    if mode in (400, 500, 1500, 1600, 1800, 7400, 12400, 15100) and not _HAS_PASSLIB:
        raise BuiltinUnsupported("crypt(3) verification needs passlib")
    if mode == 1500:
        return _Verifier(lambda pw: _passlib_verify(_passlib_des_crypt, pw, target), "descrypt")
    if mode == 12400:
        return _Verifier(lambda pw: _passlib_verify(_passlib_bsdi_crypt, pw, target), "BSDi crypt")
    if mode == 15100:
        return _Verifier(lambda pw: _passlib_verify(_passlib_sha1_crypt, pw, target), "sha1crypt")
    if mode == 500:
        return _Verifier(lambda pw: _passlib_verify(_passlib_md5_crypt, pw, target), "md5crypt")
    if mode == 1600:
        return _Verifier(lambda pw: _passlib_verify(_passlib_apr_md5_crypt, pw, target), "apr1")
    if mode == 7400:
        return _Verifier(lambda pw: _passlib_verify(_passlib_sha256_crypt, pw, target), "sha256crypt")
    if mode == 1800:
        return _Verifier(lambda pw: _passlib_verify(_passlib_sha512_crypt, pw, target), "sha512crypt")
    if mode == 3200:
        if _bcrypt is None:
            raise BuiltinUnsupported("bcrypt verification needs the bcrypt package")

        def verify_bcrypt(password: str) -> bool:
            try:
                return bool(_bcrypt.checkpw(password.encode("utf-8")[:72], target.encode("utf-8")))
            except Exception:
                return False

        return _Verifier(verify_bcrypt, "bcrypt")
    if mode == 400:
        return _Verifier(lambda pw: _passlib_verify(_passlib_phpass, pw, target), "phpass")

    if mode == 7900 or target.startswith("$S$"):
        expected = target

        def verify_drupal(password: str) -> bool:
            return hmac.compare_digest(_drupal_hash(password, expected), expected)

        return _Verifier(verify_drupal, "Drupal7")

    # Django SHA-1 ------------------------------------------------------
    if mode == 124 or target.startswith("sha1$"):
        parts = target.split("$")
        if len(parts) != 3 or parts[0].lower() != "sha1":
            raise BuiltinUnsupported("Malformed Django SHA-1 hash")
        salt = parts[1].encode("utf-8")
        expected = parts[2].lower()
        if not _HEX_RE.fullmatch(expected) or len(expected) != 40:
            raise BuiltinUnsupported("Malformed Django SHA-1 digest")

        def verify_django_sha1(password: str) -> bool:
            digest = hashlib.sha1(salt + password.encode("utf-8")).hexdigest()
            return hmac.compare_digest(digest, expected)

        return _Verifier(verify_django_sha1, "Django SHA-1")

    # PBKDF2 variants ---------------------------------------------------
    if target.startswith(("$pbkdf2$", "$pbkdf2-sha1$", "$pbkdf2-sha256$", "$pbkdf2-sha512$")):
        parts = target.split("$")
        if len(parts) != 5:
            raise BuiltinUnsupported("Malformed passlib PBKDF2 hash")
        alg = "sha1" if parts[1] == "pbkdf2" else parts[1].split("-", 1)[1]
        iterations = int(parts[2])
        salt = _ab64decode(parts[3])
        expected = _ab64decode(parts[4])
        if not salt or not expected:
            raise BuiltinUnsupported("Malformed passlib PBKDF2 salt/digest")
        expected_len = len(expected)

        def verify_passlib_pbkdf2(password: str) -> bool:
            digest = hashlib.pbkdf2_hmac(
                alg, password.encode("utf-8"), salt, iterations, expected_len
            )
            return hmac.compare_digest(digest, expected)

        return _Verifier(verify_passlib_pbkdf2, f"PBKDF2-{alg.upper()}")

    if target.startswith("{PKCS5S2}") or mode == 12001:
        raw = _b64decode(target[len("{PKCS5S2}"):])
        if len(raw) != 48:
            raise BuiltinUnsupported("Malformed Atlassian PBKDF2 hash")
        salt, expected = raw[:16], raw[16:]

        def verify_atlassian(password: str) -> bool:
            digest = hashlib.pbkdf2_hmac(
                "sha1", password.encode("utf-8"), salt, 10000, 32
            )
            return hmac.compare_digest(digest, expected)

        return _Verifier(verify_atlassian, "Atlassian PBKDF2-SHA1")

    if mode == 8900 or target.startswith("SCRYPT:"):
        parts = target.split(":")
        if len(parts) != 6:
            raise BuiltinUnsupported("Malformed scrypt hash")
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = _b64decode(parts[4])
        expected = _b64decode(parts[5])
        if not salt or not expected:
            raise BuiltinUnsupported("Malformed scrypt salt/digest")
        expected_len = len(expected)

        def verify_scrypt(password: str) -> bool:
            try:
                digest = hashlib.scrypt(
                    password.encode("utf-8"),
                    salt=salt,
                    n=n,
                    r=r,
                    p=p,
                    dklen=expected_len,
                    maxmem=128 * r * n * 2,
                )
            except (ValueError, MemoryError):
                return False
            return hmac.compare_digest(digest, expected)

        return _Verifier(verify_scrypt, "scrypt")

    if mode == 10000 or target.startswith("pbkdf2_sha256$") or target.startswith("pbkdf2_sha1$"):
        parts = target.split("$")
        if len(parts) != 4:
            raise BuiltinUnsupported("Malformed Django PBKDF2 hash")
        alg = "sha256" if parts[0].endswith("sha256") else "sha1"
        iterations = int(parts[1])
        salt = parts[2].encode("utf-8")
        expected = parts[3]

        def verify_django(password: str) -> bool:
            digest = hashlib.pbkdf2_hmac(alg, password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(base64.b64encode(digest).decode(), expected)

        return _Verifier(verify_django, f"Django PBKDF2-{alg.upper()}")

    if mode in (10900, 12000, 12100) and ":" in target:
        parts = target.split(":")
        if len(parts) != 4:
            raise BuiltinUnsupported("Malformed generic PBKDF2 hash")
        alg = parts[0].lower()
        iterations = int(parts[1])
        salt = _b64decode(parts[2]) or parts[2].encode()
        expected = _b64decode(parts[3])
        if expected is None:
            raise BuiltinUnsupported("Malformed generic PBKDF2 digest")
        expected_len = len(expected)

        def verify_pbkdf2(password: str) -> bool:
            digest = hashlib.pbkdf2_hmac(
                alg,
                password.encode("utf-8"),
                salt,
                iterations,
                dklen=expected_len,
            )
            return hmac.compare_digest(digest, expected)

        return _Verifier(verify_pbkdf2, f"PBKDF2-{alg.upper()}")

    if target.startswith("pbkdf2:") or "werkzeug pbkdf2" in name:
        parts = target.split("$")
        if len(parts) != 3 or parts[0].count(":") != 2:
            raise BuiltinUnsupported("Malformed Werkzeug PBKDF2 hash")
        method, iterations_s = parts[0].split(":")[1:]
        alg = method.lower()
        iterations = int(iterations_s)
        salt = parts[1].encode("utf-8")
        expected = parts[2].lower()

        def verify_werkzeug_pbkdf2(password: str) -> bool:
            digest = hashlib.pbkdf2_hmac(alg, password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(digest.hex(), expected)

        return _Verifier(verify_werkzeug_pbkdf2, f"Werkzeug PBKDF2-{alg.upper()}")

    if target.startswith("pbkdf2$") or "gogs" in name or "gitea" in name:
        parts = target.split("$")
        if len(parts) != 5:
            raise BuiltinUnsupported("Malformed Gogs/Gitea PBKDF2 hash")
        iterations = int(parts[1])
        key_len = int(parts[2])
        salt = _b64decode(parts[3])
        expected = parts[4]

        def verify_gogs(password: str) -> bool:
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, iterations, dklen=key_len
            )
            return hmac.compare_digest(base64.b64encode(digest).decode(), expected)

        return _Verifier(verify_gogs, "Gogs/Gitea PBKDF2")

    # Werkzeug HMAC -----------------------------------------------------
    if mode in (30000, 30120):
        parts = target.split("$")
        if len(parts) != 3:
            raise BuiltinUnsupported("Malformed Werkzeug HMAC hash")
        alg = hashlib.md5 if mode == 30000 else hashlib.sha256
        salt = parts[1].encode("utf-8")
        expected = parts[2].lower()

        def verify_werkzeug_hmac(password: str) -> bool:
            digest = hmac.new(salt, password.encode("utf-8"), alg).hexdigest()
            return hmac.compare_digest(digest, expected)

        return _Verifier(verify_werkzeug_hmac, f"Werkzeug HMAC-{alg().name.upper()}")

    # Windows cached credentials ---------------------------------------
    if mode == 1100:
        if not _HAS_PASSLIB:
            raise BuiltinUnsupported("MSCache needs passlib")
        checksum, _, rid = target.partition(":")
        if not rid:
            raise BuiltinUnsupported("MSCache requires the RID (hash:rid)")

        def verify_mscache(password: str) -> bool:
            try:
                return bool(_passlib_msdcc.verify(password, checksum, user=rid))
            except Exception:
                return False

        return _Verifier(verify_mscache, "MSCache")

    if mode == 2100:
        if not _HAS_PASSLIB:
            raise BuiltinUnsupported("DCC2 needs passlib")
        if target.startswith("$DCC2$"):
            parts = target.split("#")
            if len(parts) != 3:
                raise BuiltinUnsupported("Malformed DCC2 hash")
            iterations, user, checksum = parts[0][6:], parts[1], parts[2]
        elif ":" in target:
            checksum, user = target.split(":", 1)
            iterations = "10240"
        else:
            raise BuiltinUnsupported("DCC2 requires username/iterations")
        if iterations != "10240":
            raise BuiltinUnsupported("Only DCC2 with 10240 iterations is supported")

        def verify_dcc2(password: str) -> bool:
            try:
                return bool(_passlib_msdcc2.verify(password, checksum, user=user))
            except Exception:
                return False

        return _Verifier(verify_dcc2, "DCC2")

    # NetNTLM -----------------------------------------------------------
    if mode == 5500:
        parts = target.split(":")
        if len(parts) < 6:
            raise BuiltinUnsupported("Malformed NetNTLMv1 hash")
        challenge = bytes.fromhex(parts[-1])
        nt_resp = parts[-2].lower()
        lm_resp = parts[-3].lower()
        # Extended Session Security: the LM slot carries an 8-byte client
        # nonce followed by 16 zero bytes.  The effective challenge is
        # MD5(server_challenge || client_nonce)[:8].
        if len(lm_resp) == 48 and lm_resp.endswith("0" * 32):
            try:
                client_nonce = bytes.fromhex(lm_resp[:16])
                challenge = hashlib.md5(challenge + client_nonce).digest()[:8]
            except ValueError:
                pass

        def verify_netntlmv1(password: str) -> bool:
            response = _ntlmv1_response(_nt_hash(password), challenge).hex()
            return hmac.compare_digest(response, nt_resp)

        return _Verifier(verify_netntlmv1, "NetNTLMv1")

    if mode == 5600:
        parts = target.split(":")
        if len(parts) < 6:
            raise BuiltinUnsupported("Malformed NetNTLMv2 hash")
        user, domain = parts[0], parts[2]
        challenge = bytes.fromhex(parts[-3])
        expected = parts[-2].lower()
        blob = bytes.fromhex(parts[-1])

        def verify_netntlmv2(password: str) -> bool:
            response = _ntlmv2_response(user, domain, password, challenge, blob).hex()
            return hmac.compare_digest(response, expected)

        return _Verifier(verify_netntlmv2, "NetNTLMv2")

    # WPA PMKID ---------------------------------------------------------
    if mode in (16800, 22000):
        if target.startswith("WPA*"):
            fields = target.split("*")
            if len(fields) < 6 or fields[1] != "01":
                raise BuiltinUnsupported("Only WPA PMKID (WPA*01) is supported")
            pmkid, ap, sta, ssid_field = fields[2], fields[3], fields[4], fields[5]
        elif "*" in target:
            fields = target.split("*")
            if len(fields) != 4:
                raise BuiltinUnsupported("Malformed WPA PMKID hash")
            pmkid, ap, sta, ssid_field = fields
        elif ":" in target:
            fields = target.split(":")
            if len(fields) != 4:
                raise BuiltinUnsupported("Malformed WPA PMKID hash")
            pmkid, ap, sta, ssid_field = fields
        else:
            raise BuiltinUnsupported("Malformed WPA PMKID hash")

        expected = pmkid.lower()
        ap_b = bytes.fromhex(ap)
        sta_b = bytes.fromhex(sta)
        ssid = bytes.fromhex(ssid_field) if _HEX_RE.fullmatch(ssid_field) and len(ssid_field) % 2 == 0 else ssid_field.encode()

        def verify_pmkid(password: str) -> bool:
            pmk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), ssid, 4096, 32)
            digest = hmac.new(pmk, b"PMK Name" + ap_b + sta_b, hashlib.sha1).digest()[:16]
            return hmac.compare_digest(digest.hex(), expected)

        return _Verifier(verify_pmkid, "WPA PMKID")

    raise BuiltinUnsupported(
        f"No built-in verifier for pattern '{getattr(pattern, 'name', '?')}' "
        f"(mode={mode})."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
_SUPPORTED_MODES = {
    0, 12, 100, 111, 124, 131, 132, 200, 300, 400, 500, 900, 1000, 1100,
    1300, 1400, 1411, 1500, 1600, 1700, 1711, 1800, 2100, 3000, 3200,
    5500, 5600, 7400, 7900, 8900, 10000, 10800, 10900, 12000, 12001, 12100,
    12400, 15100, 16800, 20200, 20300, 20400, 22000, 30000, 30120,
}
_PASSLIB_MODES = {
    200, 300, 400, 500, 1100, 1500, 1600, 1800, 2100, 3000, 7400, 12400,
    15100,
}


def builtin_supports(pattern: Pattern | PatternSchema) -> bool:
    """Return True when the pure-Python engine can verify this pattern."""
    mode = getattr(pattern, "hashcat_mode", None)
    if mode in _SUPPORTED_MODES:
        if mode in _PASSLIB_MODES and not _HAS_PASSLIB:
            return False
        if mode == 3200 and _bcrypt is None:
            return False
        return True
    name = (getattr(pattern, "name", "") or "").lower()
    if any(marker in name for marker in ("werkzeug pbkdf2", "gogs", "gitea")):
        return True
    if "postgresql md5" in name:
        return True
    return False


def verify_plaintext(
    hash_value: str,
    pattern: Pattern | PatternSchema,
    plaintext: str,
) -> Optional[bool]:
    """Verify a plaintext against a stored hash; None means no built-in verifier."""
    try:
        verifier = _make_verifier(hash_value, pattern)
    except BuiltinUnsupported:
        return None
    return bool(verifier.fn(plaintext))


class BuiltinCracker(BaseCracker):
    """In-process cracking fallback (dictionary, rules, mask)."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def crack(
        self,
        hash_value: str,
        pattern: Pattern | PatternSchema,
        wordlist_path: str | Path,
        session: CrackSession,
        rule_path: str | Path | None = None,
        *,
        attack_mode: str = "dictionary",
        mask: str | None = None,
        use_username: bool | None = None,
        timeout_seconds: int | None = None,
        max_candidates: int | None = None,
    ) -> CrackResult:
        try:
            verifier = _make_verifier(hash_value, pattern)
        except BuiltinUnsupported as exc:
            session.status = "failed"
            session.finished_at = datetime.now(timezone.utc)
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=str(exc),
                engine_error=True,
            )

        if attack_mode not in ("mask", "hybrid") and not Path(wordlist_path).exists():
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Wordlist not found: {wordlist_path}",
                engine_error=True,
            )
        if attack_mode in ("mask", "hybrid") and not mask:
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message="Mask attack requested without a mask.",
                engine_error=True,
            )

        try:
            rules = load_rules(rule_path)
        except Exception as exc:
            session.status = "failed"
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Failed to load rules: {exc}",
                engine_error=True,
            )

        limit = max_candidates
        if limit is None:
            limit = int(getattr(self.config.strategy, "builtin_max_candidates", 0) or 0)
        timeout_sec = timeout_seconds or compute_timeout(pattern, self.config)

        logger.info(
            "Built-in engine session %s (%s, %s attack, timeout=%ss)...",
            session.session_id, verifier.description, attack_mode, timeout_sec,
        )
        tested = 0
        check_interval = 16 if getattr(pattern, "is_slow", False) else 4096
        started = datetime.now(timezone.utc)
        started_monotonic = time.monotonic()
        timed_out = False
        try:
            for candidate in _iter_candidates(wordlist_path, rules, attack_mode, mask):
                tested += 1
                if limit and tested > limit:
                    break
                if tested % check_interval == 0 and time.monotonic() - started_monotonic > timeout_sec:
                    timed_out = True
                    break
                if verifier.fn(candidate):
                    Path(session.outfile_path).write_text(candidate + "\n", encoding="utf-8")
                    session.cracked_count = 1
                    session.status = "completed"
                    session.finished_at = datetime.now(timezone.utc)
                    return CrackResult(
                        success=True,
                        session_id=session.session_id,
                        plaintext=candidate,
                    )
                if tested % 250_000 == 0:
                    logger.info(
                        "Built-in engine: %s candidates tested (%.1fs)",
                        f"{tested:,}", (datetime.now(timezone.utc) - started).total_seconds(),
                    )
        except (OSError, ValueError) as exc:
            session.status = "failed"
            session.finished_at = datetime.now(timezone.utc)
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Built-in engine error: {exc}",
                engine_error=True,
            )

        if timed_out:
            session.status = "timeout"
            session.finished_at = datetime.now(timezone.utc)
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=(
                    f"Built-in engine timed out after {timeout_sec} seconds "
                    f"({tested:,} candidates tested)."
                ),
            )

        session.status = "completed"
        session.finished_at = datetime.now(timezone.utc)
        suffix = " (candidate limit reached)" if limit and tested > limit else ""
        return CrackResult(
            success=False,
            session_id=session.session_id,
            error_message=(
                f"Hash not cracked by built-in engine after {tested:,} candidates{suffix}."
            ),
        )


def crack_with_builtin(
    hash_value: str,
    pattern: Pattern | PatternSchema,
    wordlist_path: str | Path,
    config: Config,
    *,
    attack_mode: str = "dictionary",
    mask: str | None = None,
    rule_path: str | Path | None = None,
    max_candidates: int | None = None,
) -> CrackResult:
    """Convenience wrapper for callers that do not manage sessions."""
    session = create_crack_session(config.paths.sessions_dir)
    result = BuiltinCracker(config).crack(
        hash_value=hash_value,
        pattern=pattern,
        wordlist_path=wordlist_path,
        session=session,
        rule_path=rule_path,
        attack_mode=attack_mode,
        mask=mask,
        max_candidates=max_candidates,
    )
    release_session_artifacts(
        session, keep=getattr(config.strategy, "keep_session_artifacts", False)
    )
    return result
