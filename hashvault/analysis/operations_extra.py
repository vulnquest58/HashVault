"""
Extended CyberChef-style operations for HashVault.

Kept separate from the original operations module so the compatibility surface
stays small.  ``operations.py`` registers these classes at import time.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
import zipfile
from typing import Any, Iterable, List, Mapping, Optional

from hashvault.analysis.keys import key_bytes, key_text
from hashvault.analysis.operations import Operation, OperationResult
from hashvault.analysis.validators import (
    extract_hash_tokens,
    is_terminal_hash,
    looks_like_config,
    looks_like_json,
    looks_like_text,
)


def _unescape_literal(body: str) -> str:
    """Decode common string-literal escapes without corrupting Unicode."""
    replacements = {
        r"\n": "\n",
        r"\r": "\r",
        r"\t": "\t",
        r"\0": "\x00",
        r"\'": "'",
        r'\"': '"',
        r"\`": "`",
        r"\\": "\\",
    }
    out = body
    for source, target in replacements.items():
        out = out.replace(source, target)
    out = re.sub(
        r"\\x([0-9a-fA-F]{2})",
        lambda match: chr(int(match.group(1), 16)),
        out,
    )
    out = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda match: chr(int(match.group(1), 16)),
        out,
    )
    return out


class ExtractEmbeddedHashes(Operation):
    """Find complete hash structures embedded in arbitrary text or source."""

    name = "ExtractEmbeddedHash"
    description = "Extract complete hashes embedded in text, source code, or config"
    category = "Forensics"
    tier = "A"
    kind = "hash"
    auto = True

    def score(self, text: str) -> float:
        tokens = extract_hash_tokens(text)
        if not tokens:
            return 0.0
        stripped = text.strip()
        if len(tokens) == 1 and tokens[0] == stripped:
            return 0.0
        return 0.95

    def apply(self, text: str) -> Optional[str]:
        tokens = extract_hash_tokens(text)
        stripped = text.strip()
        for token in tokens:
            if token != stripped:
                return token
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        stripped = text.strip()
        return [
            OperationResult(
                text=token,
                label=f"embedded hash #{index + 1}",
                score=0.95,
                metadata={"source": "hash-token"},
            )
            for index, token in enumerate(extract_hash_tokens(text))
            if token != stripped
        ]


class ExtractQuotedStrings(Operation):
    """Extract printable string literals and simple concatenations from code."""

    name = "ExtractQuotedStrings"
    description = "Extract string literals (and adjacent concatenations) from source"
    category = "Code / Config"
    tier = "A"
    kind = "text"
    auto = True

    _QUOTED_RE = re.compile(
        r"""(["'`])((?:\\.|(?!\1).){1,4096}?)\1""",
        re.DOTALL,
    )

    def score(self, text: str) -> float:
        matches = self._QUOTED_RE.findall(text)
        if not matches:
            return 0.0
        if any(is_terminal_hash(_unescape_literal(body)) for _, body in matches):
            return 0.9
        return 0.62 if ("=" in text or ":" in text or "\n" in text) else 0.35

    def _literals(self, text: str) -> List[str]:
        values: List[str] = []
        for _, body in self._QUOTED_RE.findall(text):
            value = _unescape_literal(body)
            if value and value not in values:
                values.append(value)
        return values

    def apply(self, text: str) -> Optional[str]:
        values = self._literals(text)
        return values[0] if values else None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        values = self._literals(text)
        results = [
            OperationResult(
                text=value,
                label=f"quoted literal #{index + 1}",
                score=0.62,
                metadata={"source": "string-literal"},
            )
            for index, value in enumerate(values[:32])
            if len(value) >= 4
        ]

        joined: set[str] = set(values)
        for line in text.splitlines():
            line_values = self._literals(line)
            if len(line_values) >= 2:
                combined = "".join(line_values)
                if combined not in joined and len(combined) >= 8:
                    joined.add(combined)
                    results.append(
                        OperationResult(
                            text=combined,
                            label="quoted concatenation",
                            score=0.72,
                            metadata={"source": "string-literal-concat"},
                        )
                    )
        if 2 <= len(values) <= 24:
            combined = "".join(values)
            if combined not in joined and len(combined) >= 8:
                results.append(
                    OperationResult(
                        text=combined,
                        label="all-quoted concatenation",
                        score=0.55,
                        metadata={"source": "string-literal-concat"},
                    )
                )
        return results


class ExtractJSONValues(Operation):
    """Recursively extract candidate strings from JSON documents."""

    name = "ExtractJSONValues"
    description = "Extract candidate strings from JSON values"
    category = "Code / Config"
    tier = "A"
    kind = "json"
    auto = True

    def score(self, text: str) -> float:
        return 0.9 if looks_like_json(text) else 0.0

    def _walk(self, value: Any, path: str = "$") -> Iterable[tuple[str, str]]:
        if isinstance(value, str):
            yield path, value
        elif isinstance(value, dict):
            for key, child in value.items():
                yield from self._walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from self._walk(child, f"{path}[{index}]")

    def apply(self, text: str) -> Optional[str]:
        try:
            obj = json.loads(text)
        except Exception:
            return None
        for _, value in self._walk(obj):
            if len(value) >= 4:
                return value
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        try:
            obj = json.loads(text)
        except Exception:
            return []
        results: List[OperationResult] = []
        for path, value in self._walk(obj):
            if len(value) < 4:
                continue
            if is_terminal_hash(value) or len(value) >= 12 or extract_hash_tokens(value):
                results.append(
                    OperationResult(
                        text=value,
                        label=f"JSON {path}",
                        score=0.8 if is_terminal_hash(value) else 0.5,
                        metadata={"source": "json", "path": path},
                    )
                )
            if len(results) >= 64:
                break
        return results


class ExtractConfigValues(Operation):
    """Extract values from INI/YAML/.env/XML/property style configuration."""

    name = "ExtractConfigValues"
    description = "Extract values from INI, YAML, .env, and XML configuration"
    category = "Code / Config"
    tier = "A"
    kind = "config"
    auto = True

    _ASSIGN_RE = re.compile(
        r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.+?)\s*$",
        re.MULTILINE,
    )
    _XML_RE = re.compile(
        r"<([A-Za-z_][A-Za-z0-9_.:-]*)>([^<]{2,4096})</\1>",
        re.DOTALL,
    )

    def score(self, text: str) -> float:
        values = self._values(text)
        if not values:
            return 0.0
        if looks_like_config(text):
            return 0.78
        return 0.55

    def _values(self, text: str) -> List[tuple[str, str]]:
        values: List[tuple[str, str]] = []
        for match in self._ASSIGN_RE.finditer(text):
            name = match.group(1)
            value = match.group(2).strip().rstrip(",")
            if value.startswith(("'", '"')) and value[-1:] == value[0]:
                value = _unescape_literal(value[1:-1])
            # A Base64/Base85 string ending in "==" is not a config line.
            if not value or value.strip("= \t") == "":
                continue
            if len(name) >= 24 and len(value) <= 2 and not text.count("\n"):
                continue
            if not value.startswith(("#", "//", "/*", "*")):
                values.append((name, value))
        for match in self._XML_RE.finditer(text):
            values.append((match.group(1), match.group(2).strip()))
        return values

    def apply(self, text: str) -> Optional[str]:
        values = self._values(text)
        return values[0][1] if values else None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        results: List[OperationResult] = []
        seen: set[str] = set()
        for name, value in self._values(text):
            if len(value) < 4 or value in seen:
                continue
            seen.add(value)
            results.append(
                OperationResult(
                    text=value,
                    label=f"config {name}",
                    score=0.72 if is_terminal_hash(value) else 0.5,
                    metadata={"source": "config", "field": name},
                )
            )
            if len(results) >= 48:
                break
        return results


class ExtractPEMBody(Operation):
    """Extract the Base64 body of a PEM/SSH armored block."""

    name = "ExtractPEMBody"
    description = "Extract Base64 body from PEM/SSH armored blocks"
    category = "Forensics"
    tier = "A"
    kind = "text"
    auto = True

    _RE = re.compile(
        r"-----BEGIN ([A-Z0-9 ]+)-----\s*(.+?)\s*-----END \1-----",
        re.DOTALL,
    )

    def score(self, text: str) -> float:
        return 0.8 if self._RE.search(text) else 0.0

    def _blocks(self, text: str) -> List[tuple[str, str]]:
        return [
            (match.group(1), re.sub(r"\s+", "", match.group(2)))
            for match in self._RE.finditer(text)
        ]

    def apply(self, text: str) -> Optional[str]:
        blocks = self._blocks(text)
        return blocks[0][1] if blocks else None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        return [
            OperationResult(
                text=body,
                label=f"PEM {label}",
                score=0.7,
                metadata={"source": "pem", "block": label},
            )
            for label, body in self._blocks(text)
        ]


class ArchiveExtract(Operation):
    """Safely enumerate text entries from ZIP/TAR archives in memory."""

    name = "ArchiveExtract"
    description = "Read text entries from ZIP/TAR archives (in-memory, size-limited)"
    category = "Compression"
    tier = "A"
    kind = "archive"
    auto = True
    max_output_bytes = 32 * 1024 * 1024
    _MAX_ENTRIES = 24
    _MAX_ENTRY_BYTES = 8 * 1024 * 1024
    _MAX_TOTAL_BYTES = 32 * 1024 * 1024

    def _raw(self, text: str) -> bytes:
        return text.encode("latin-1", "ignore")

    def score(self, text: str) -> float:
        raw = self._raw(text)
        if raw.startswith(b"PK\x03\x04") or raw.startswith(b"PK\x05\x06"):
            return 0.96
        if len(raw) > 262 and raw[257:262] == b"ustar":
            return 0.9
        return 0.0

    def _decode_entry(self, name: str, data: bytes) -> Optional[str]:
        if not data or len(data) > self._MAX_ENTRY_BYTES:
            return None
        if data.startswith(
            (b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")
        ):
            return data.decode("latin-1")
        decoded = data.decode("utf-8", "replace")
        if looks_like_text(decoded, 0.82) or extract_hash_tokens(decoded):
            return decoded
        return None

    def _zip_entries(self, raw: bytes) -> List[tuple[str, bytes]]:
        entries: List[tuple[str, bytes]] = []
        total = 0
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
                for info in infos[: self._MAX_ENTRIES]:
                    if info.flag_bits & 0x1:
                        continue
                    if info.file_size > self._MAX_ENTRY_BYTES:
                        continue
                    if info.file_size and info.compress_size:
                        if info.file_size / max(1, info.compress_size) > 250:
                            continue
                    data = archive.read(info)
                    total += len(data)
                    if total > self._MAX_TOTAL_BYTES:
                        break
                    entries.append((info.filename, data))
        except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
            return []
        return entries

    def _tar_entries(self, raw: bytes) -> List[tuple[str, bytes]]:
        entries: List[tuple[str, bytes]] = []
        total = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
                members = [member for member in archive.getmembers() if member.isfile()]
                for member in members[: self._MAX_ENTRIES]:
                    if member.size > self._MAX_ENTRY_BYTES:
                        continue
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    data = handle.read(self._MAX_ENTRY_BYTES + 1)
                    total += len(data)
                    if total > self._MAX_TOTAL_BYTES:
                        break
                    entries.append((member.name, data))
        except (OSError, tarfile.TarError, EOFError, ValueError):
            return []
        return entries

    def _entries(self, text: str) -> List[tuple[str, bytes]]:
        raw = self._raw(text)
        if raw.startswith(b"PK"):
            return self._zip_entries(raw)
        return self._tar_entries(raw)

    def apply(self, text: str) -> Optional[str]:
        for name, data in self._entries(text):
            decoded = self._decode_entry(name, data)
            if decoded is not None:
                return decoded
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        results: List[OperationResult] = []
        for name, data in self._entries(text):
            decoded = self._decode_entry(name, data)
            if decoded is None:
                continue
            results.append(
                OperationResult(
                    text=decoded,
                    label=f"archive entry {name}",
                    score=0.82,
                    metadata={"source": "archive", "entry": name, "bytes": len(data)},
                )
            )
        return results


class A1Z26Decode(Operation):
    """Decode A1Z26 numeric letter codes (1=A ... 26=Z)."""

    name = "A1Z26"
    description = "Decode A1Z26 numeric letter encoding"
    category = "Data format"
    tier = "A"

    _RE = re.compile(r"^\s*(?:\d{1,2}[\s,;.-]+){2,}\d{1,2}\s*$")

    def score(self, text: str) -> float:
        if not self._RE.match(text):
            return 0.0
        numbers = [int(n) for n in re.findall(r"\d{1,2}", text)]
        return 0.75 if numbers and all(1 <= n <= 26 for n in numbers) else 0.0

    def apply(self, text: str) -> Optional[str]:
        numbers = [int(n) for n in re.findall(r"\d{1,2}", text)]
        if not numbers or not all(1 <= n <= 26 for n in numbers):
            return None
        return "".join(chr(ord("A") + n - 1) for n in numbers)


class RailFenceDecode(Operation):
    """Decode a rail-fence transposition using an explicit rail count."""

    name = "RailFence"
    description = "Decode rail-fence transposition with rail_fence_rails key"
    category = "Keyed transforms"
    tier = "B"
    kind = "text"
    auto = False
    reversible = True
    requires_keys = ("rail_fence_rails",)

    def score(self, text: str) -> float:
        return 0.35 if len(text) >= 8 and looks_like_text(text) else 0.0

    def _rails(self, keys: Optional[Mapping[str, str]]) -> Optional[int]:
        raw = key_text(keys, "rail_fence_rails")
        if not raw:
            return None
        try:
            rails = int(raw)
        except ValueError:
            return None
        return rails if 2 <= rails <= 32 else None

    def apply(self, text: str) -> Optional[str]:
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        rails = self._rails(keys)
        if rails is None or rails >= len(text):
            return []
        pattern: List[int] = []
        rail = 0
        direction = 1
        for _ in text:
            pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        counts = [pattern.count(index) for index in range(rails)]
        offsets: List[int] = []
        total = 0
        for count in counts:
            offsets.append(total)
            total += count
        rows: List[List[str]] = []
        for index, count in enumerate(counts):
            rows.append(list(text[offsets[index]: offsets[index] + count]))
        positions = [0] * rails
        result: List[str] = []
        for rail in pattern:
            result.append(rows[rail][positions[rail]])
            positions[rail] += 1
        return [
            OperationResult(
                text="".join(result),
                label=f"rail-fence {rails}",
                score=0.35,
            )
        ]


class VigenereDecrypt(Operation):
    """Vigenere decrypt with an explicit key."""

    name = "Vigenere"
    description = "Vigenere decrypt with vigenere_key"
    category = "Keyed transforms"
    tier = "B"
    auto = False
    requires_keys = ("vigenere_key",)

    def score(self, text: str) -> float:
        alpha = sum(1 for char in text if char.isalpha())
        return 0.4 if len(text) >= 4 and alpha / max(1, len(text)) > 0.55 else 0.0

    def apply(self, text: str) -> Optional[str]:
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        key = key_text(keys, "vigenere_key")
        if not key:
            return []
        letters = [char for char in key if char.isalpha()]
        if not letters:
            return []
        key_nums = [ord(char.lower()) - ord("a") for char in letters]
        out: List[str] = []
        index = 0
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                shift = key_nums[index % len(key_nums)]
                out.append(chr((ord(char) - base - shift) % 26 + base))
                index += 1
            else:
                out.append(char)
        return [OperationResult(text="".join(out), label="vigenere", score=0.4)]


class XORRepeating(Operation):
    """Repeating-key XOR decrypt with an explicit key."""

    name = "XORRepeating"
    description = "Repeating-key XOR decrypt with xor_key"
    category = "Keyed transforms"
    tier = "B"
    auto = False
    requires_keys = ("xor_key",)

    def score(self, text: str) -> float:
        return 0.42 if text and not is_terminal_hash(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        key = key_bytes(keys, "xor_key")
        if not key:
            return []
        raw = text.encode("latin-1", "ignore")
        out = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(raw))
        for encoding in ("utf-8", "latin-1"):
            try:
                decoded = out.decode(encoding)
            except UnicodeDecodeError:
                continue
            if looks_like_text(decoded) or is_terminal_hash(decoded.strip()):
                return [OperationResult(text=decoded, label="xor-repeating", score=0.42)]
        return []


class RC4Decrypt(Operation):
    """RC4 decrypt with an explicit key."""

    name = "RC4"
    description = "RC4 decrypt with rc4_key"
    category = "Keyed transforms"
    tier = "B"
    auto = False
    requires_keys = ("rc4_key",)

    def score(self, text: str) -> float:
        return 0.4 if text and not is_terminal_hash(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        return None

    def _rc4(self, data: bytes, key: bytes) -> bytes:
        state = list(range(256))
        j = 0
        for i in range(256):
            j = (j + state[i] + key[i % len(key)]) % 256
            state[i], state[j] = state[j], state[i]
        i = j = 0
        out = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + state[i]) % 256
            state[i], state[j] = state[j], state[i]
            out.append(byte ^ state[(state[i] + state[j]) % 256])
        return bytes(out)

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        key = key_bytes(keys, "rc4_key")
        if not key:
            return []
        raw = text.encode("latin-1", "ignore")
        decoded_bytes = self._rc4(raw, key)
        try:
            decoded = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decoded = decoded_bytes.decode("latin-1")
        if looks_like_text(decoded) or is_terminal_hash(decoded.strip()):
            return [OperationResult(text=decoded, label="RC4", score=0.4)]
        return []


def _aes_material(
    keys: Optional[Mapping[str, str]],
    key_name: str,
    iv_name: str,
    iv_sizes: Iterable[int],
) -> Optional[tuple[bytes, bytes]]:
    key = key_bytes(keys, key_name)
    iv = key_bytes(keys, iv_name)
    if not key or not iv or len(key) not in (16, 24, 32) or len(iv) not in tuple(iv_sizes):
        return None
    return key, iv


class AESDecryptCBC(Operation):
    """AES-CBC decrypt with explicit key/IV and PKCS#7 padding."""

    name = "AES-CBC"
    description = "AES-CBC decrypt with aes_key and aes_iv"
    category = "Keyed transforms"
    tier = "B"
    auto = False
    requires_keys = ("aes_key", "aes_iv")

    def score(self, text: str) -> float:
        return 0.4 if text and not is_terminal_hash(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        material = _aes_material(keys, "aes_key", "aes_iv", (16,))
        if material is None:
            return []
        try:
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except Exception:
            return []
        key, iv = material
        raw = text.encode("latin-1", "ignore")
        if not raw or len(raw) % 16:
            return []
        try:
            decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            padded = decryptor.update(raw) + decryptor.finalize()
            unpad = padding.PKCS7(128).unpadder()
            data = unpad.update(padded) + unpad.finalize()
        except Exception:
            return []
        for encoding in ("utf-8", "latin-1"):
            try:
                decoded = data.decode(encoding)
            except UnicodeDecodeError:
                continue
            if looks_like_text(decoded) or is_terminal_hash(decoded.strip()):
                return [OperationResult(text=decoded, label="AES-CBC", score=0.4)]
        return []


class AESDecryptCTR(Operation):
    """AES-CTR decrypt with explicit key/nonce."""

    name = "AES-CTR"
    description = "AES-CTR decrypt with aes_key and aes_nonce"
    category = "Keyed transforms"
    tier = "B"
    auto = False
    requires_keys = ("aes_key", "aes_nonce")

    def score(self, text: str) -> float:
        return 0.4 if text and not is_terminal_hash(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        material = _aes_material(keys, "aes_key", "aes_nonce", (8, 12, 16))
        if material is None:
            return []
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except Exception:
            return []
        key, nonce = material
        raw = text.encode("latin-1", "ignore")
        try:
            decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
            data = decryptor.update(raw) + decryptor.finalize()
        except Exception:
            return []
        for encoding in ("utf-8", "latin-1"):
            try:
                decoded = data.decode(encoding)
            except UnicodeDecodeError:
                continue
            if looks_like_text(decoded) or is_terminal_hash(decoded.strip()):
                return [OperationResult(text=decoded, label="AES-CTR", score=0.4)]
        return []


class AESDecryptGCM(Operation):
    """AES-GCM decrypt with explicit key/nonce/tag."""

    name = "AES-GCM"
    description = "AES-GCM decrypt with aes_key, aes_nonce, and aes_tag"
    category = "Keyed transforms"
    tier = "B"
    auto = False
    requires_keys = ("aes_key", "aes_nonce", "aes_tag")

    def score(self, text: str) -> float:
        return 0.4 if text and not is_terminal_hash(text) else 0.0

    def apply(self, text: str) -> Optional[str]:
        return None

    def apply_many(
        self, text: str, keys: Optional[Mapping[str, str]] = None
    ) -> List[OperationResult]:
        material = _aes_material(keys, "aes_key", "aes_nonce", (8, 12, 16))
        tag = key_bytes(keys, "aes_tag")
        if material is None or not tag or len(tag) not in (12, 13, 14, 15, 16):
            return []
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except Exception:
            return []
        key, nonce = material
        raw = text.encode("latin-1", "ignore")
        try:
            data = AESGCM(key).decrypt(nonce, raw + tag, None)
        except Exception:
            return []
        for encoding in ("utf-8", "latin-1"):
            try:
                decoded = data.decode(encoding)
            except UnicodeDecodeError:
                continue
            if looks_like_text(decoded) or is_terminal_hash(decoded.strip()):
                return [OperationResult(text=decoded, label="AES-GCM", score=0.4)]
        return []


EXTRA_OPERATIONS: tuple[Operation, ...] = (
    ExtractEmbeddedHashes(),
    ExtractQuotedStrings(),
    ExtractJSONValues(),
    ExtractConfigValues(),
    ExtractPEMBody(),
    ArchiveExtract(),
    A1Z26Decode(),
    RailFenceDecode(),
    VigenereDecrypt(),
    XORRepeating(),
    RC4Decrypt(),
    AESDecryptCBC(),
    AESDecryptCTR(),
    AESDecryptGCM(),
)
