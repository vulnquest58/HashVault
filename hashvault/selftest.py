"""
Self-test matrix for the layered analysis and cracking pipeline.

The matrix is intentionally self-contained: it builds inputs from known
encodings, runs the same bounded search used by the CLI, and reports whether
each transform or keyed cipher reaches its expected output.  ``--crack`` adds
a small, curated cracking section so the command also exercises the engine
handoff without turning the matrix into a full wordlist benchmark.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import html
import json
import lzma
import quopri
import time
import zlib
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from hashvault.analysis.analyzer import prepare_input
from hashvault.analysis.keys import key_bytes
from hashvault.analysis.operations import OPERATION_BY_NAME, OPERATIONS

MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
SHA1 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
SHA256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
SHA512 = (
    "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb9"
    "80b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....",
    "7": "--...", "8": "---..", "9": "----.", "/": "/",
}


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def _b32(value: str) -> str:
    return base64.b32encode(value.encode()).decode()


def _b85(value: str) -> str:
    return base64.a85encode(value.encode(), adobe=True).decode()


def _b58(value: str) -> str:
    raw = value.encode()
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _B58[remainder] + encoded
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * zeros + (encoded or "1")


def _b62(value: str) -> str:
    raw = value.encode()
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 62)
        encoded = _B62[remainder] + encoded
    return encoded or "0"


def _binary(value: str) -> str:
    return " ".join(f"{byte:08b}" for byte in value.encode())


def _octal(value: str) -> str:
    return " ".join(f"{byte:03o}" for byte in value.encode())


def _charcode(value: str) -> str:
    return " ".join(str(byte) for byte in value.encode())


def _decimal(value: str) -> str:
    return str(int.from_bytes(value.encode(), "big"))


def _utf16(value: str) -> str:
    return value.encode("utf-16-le").decode("latin-1")


def _morse(value: str) -> str:
    return " ".join(_MORSE[char.upper()] for char in value if char.upper() in _MORSE)


def _bacon(value: str) -> str:
    table = {
        letter: "".join("B" if bit == "1" else "A" for bit in f"{index:05b}")
        for index, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    }
    return " ".join(table[char.upper()] for char in value if char.upper() in table)


def _rot13(value: str) -> str:
    return "".join(
        chr((ord(char) - ord("a") + 13) % 26 + ord("a"))
        if "a" <= char <= "z"
        else chr((ord(char) - ord("A") + 13) % 26 + ord("A"))
        if "A" <= char <= "Z"
        else char
        for char in value
    )


def _rot47(value: str) -> str:
    return "".join(
        chr((ord(char) - 33 + 47) % 94 + 33) if 33 <= ord(char) <= 126 else char
        for char in value
    )


def _atbash(value: str) -> str:
    return "".join(
        chr(ord("z") - (ord(char) - ord("a")))
        if "a" <= char <= "z"
        else chr(ord("Z") - (ord(char) - ord("A")))
        if "A" <= char <= "Z"
        else char
        for char in value
    )


def _affine(value: str, a: int = 5, b: int = 8) -> str:
    return "".join(
        chr(((a * (ord(char.upper()) - ord("A")) + b) % 26) + ord("A"))
        if char.isalpha()
        else char
        for char in value
    )


def _vigenere(value: str, key: str = "KEY") -> str:
    letters = [ord(char.lower()) - ord("a") for char in key if char.isalpha()]
    out: List[str] = []
    index = 0
    for char in value:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = letters[index % len(letters)]
            out.append(chr((ord(char) - base + shift) % 26 + base))
            index += 1
        else:
            out.append(char)
    return "".join(out)


def _rail_fence(value: str, rails: int = 3) -> str:
    pattern: List[int] = []
    rail = 0
    direction = 1
    for _ in value:
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    rows = ["" for _ in range(rails)]
    for char, row in zip(value, pattern):
        rows[row] += char
    return "".join(rows)


def _xor(value: str, key: bytes) -> str:
    raw = value.encode()
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(raw)).decode("latin-1")


def _rc4(value: str, key: bytes) -> str:
    state = list(range(256))
    j = 0
    for index in range(256):
        j = (j + state[index] + key[index % len(key)]) % 256
        state[index], state[j] = state[j], state[index]
    i = j = 0
    out = bytearray()
    for byte in value.encode():
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) % 256])
    return bytes(out).decode("latin-1")


def _aes_cbc(value: str, key: bytes, iv: bytes) -> str:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    padder = padding.PKCS7(128).padder()
    padded = padder.update(value.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return (encryptor.update(padded) + encryptor.finalize()).decode("latin-1")


def _aes_ctr(value: str, key: bytes, nonce: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return (encryptor.update(value.encode()) + encryptor.finalize()).decode("latin-1")


def _aes_gcm(value: str, key: bytes, nonce: bytes) -> Tuple[str, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    sealed = AESGCM(key).encrypt(nonce, value.encode(), None)
    return sealed[:-16].decode("latin-1"), sealed[-16:]


def _deflate_raw(value: str) -> str:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return (compressor.compress(value.encode()) + compressor.flush()).decode("latin-1")


def _jwt(payload: Mapping[str, Any]) -> str:
    def _part(value: Mapping[str, Any]) -> str:
        encoded = base64.urlsafe_b64encode(json.dumps(value).encode()).decode()
        return encoded.rstrip("=")

    return f"{_part({'alg': 'none', 'typ': 'JWT'})}.{_part(payload)}."


@dataclass
class MatrixCase:
    name: str
    category: str
    payload: str
    expected: str
    operation: str = ""
    mode: str = "unwrap"
    keys: Dict[str, str] = field(default_factory=dict)
    contains: bool = False
    expected_ops: Tuple[str, ...] = ()


@dataclass
class MatrixResult:
    name: str
    category: str
    operation: str
    expected: str
    actual: str
    chain: str
    terminal: bool
    status: str
    elapsed: float
    detail: str = ""


@dataclass
class MatrixOperationCoverage:
    """Per-operation coverage and failure detail for the JSON matrix."""

    name: str
    category: str
    tier: str
    cases: List[str] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        return bool(self.cases)

    @property
    def passed(self) -> int:
        return len(self.cases) - len(self.failures)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "tier": self.tier,
            "covered": self.covered,
            "passed": self.passed,
            "failed": len(self.failures),
            "cases": list(self.cases),
            "failures": list(self.failures),
        }


@dataclass
class MatrixReport:
    results: List[MatrixResult]
    total_operations: int
    covered_operations: List[str]
    missing_operations: List[str]
    elapsed: float
    operation_coverage: List[MatrixOperationCoverage] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for item in self.results if item.status == "pass")

    @property
    def failed(self) -> int:
        return sum(1 for item in self.results if item.status == "fail")

    @property
    def failed_operations(self) -> List[str]:
        return [item.name for item in self.operation_coverage if item.failures]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "cases": len(self.results),
                "passed": self.passed,
                "failed": self.failed,
                "elapsed_seconds": round(self.elapsed, 3),
                "operations_total": self.total_operations,
                "operations_covered": len(self.covered_operations),
                "operations_missing": self.missing_operations,
                "operations_failed": self.failed_operations,
            },
            "operations": [item.to_dict() for item in self.operation_coverage],
            "results": [asdict(item) for item in self.results],
        }


def build_matrix_cases() -> List[MatrixCase]:
    key = b"matrix-key-01234"
    iv = b"0123456789abcdef"
    nonce = b"0123456789ab"
    ctr_nonce = b"0123456789abcdef"
    aes_key = key.hex()
    gm_ct, gm_tag = _aes_gcm(MD5, key, nonce)

    return [
        MatrixCase("Base64-wrapped MD5", "Data format", _b64(MD5), MD5, expected_ops=("Base64",)),
        MatrixCase("Base32-wrapped MD5", "Data format", _b32(MD5), MD5, expected_ops=("Base32",)),
        MatrixCase("Base58-wrapped MD5", "Data format", _b58(MD5), MD5, expected_ops=("Base58",)),
        MatrixCase("Base85-wrapped MD5", "Data format", _b85(MD5), MD5, expected_ops=("Base85",)),
        MatrixCase("Base62-wrapped MD5", "Data format", _b62(MD5), MD5, expected_ops=("Base62",)),
        MatrixCase("Hex-wrapped SHA1", "Data format", SHA1.encode().hex(), SHA1, expected_ops=("Hex",)),
        MatrixCase("Binary-wrapped MD5", "Data format", _binary(MD5), MD5, expected_ops=("Binary",)),
        MatrixCase("Octal-wrapped MD5", "Data format", _octal(MD5), MD5, expected_ops=("Octal",)),
        MatrixCase("Charcode-wrapped MD5", "Data format", _charcode(MD5), MD5, expected_ops=("FromCharcode",)),
        MatrixCase("Decimal-wrapped MD5", "Data format", _decimal(MD5), MD5, expected_ops=("FromDecimal",)),
        MatrixCase("UTF16-wrapped MD5", "Data format", _utf16(MD5), MD5, expected_ops=("UTF-16",)),
        MatrixCase("Morse HELLO", "Data format", _morse("HELLO"), "HELLO", "MorseCode", "direct"),
        MatrixCase("JWT payload MD5", "Data format", _jwt({"hash": MD5}), MD5, expected_ops=("JWT", "ExtractJSONValues")),
        MatrixCase("QuotedPrintable-wrapped hash", "Data format", f"hash=3D{MD5}", MD5, expected_ops=("QuotedPrintable", "ExtractEmbeddedHash")),
        MatrixCase("URL-encoded hash", "Data format", f"hash%3D{MD5}", MD5, expected_ops=("URLDecode", "ExtractEmbeddedHash")),
        MatrixCase("HTML-encoded hash", "Data format", f"&lt;{MD5}&gt;", MD5, expected_ops=("HTMLEntities", "ExtractEmbeddedHash")),
        MatrixCase("Unicode-escaped MD5", "Data format", "".join(f"\\u{ord(char):04x}" for char in MD5), MD5, expected_ops=("UnicodeEscape",)),
        MatrixCase("Raw-escaped MD5", "Data format", "".join(f"\\x{ord(char):02x}" for char in MD5), MD5, expected_ops=("RawUnescape",)),
        MatrixCase("A1Z26 HELLO", "Data format", "8 5 12 12 15", "HELLO", "A1Z26", "direct"),
        MatrixCase("Gzip-wrapped MD5", "Compression", gzip.compress(MD5.encode()).decode("latin-1"), MD5, expected_ops=("Gzip",)),
        MatrixCase("Bzip2-wrapped MD5", "Compression", bz2.compress(MD5.encode()).decode("latin-1"), MD5, expected_ops=("Bzip2",)),
        MatrixCase("LZMA-wrapped MD5", "Compression", lzma.compress(MD5.encode()).decode("latin-1"), MD5, expected_ops=("LZMA",)),
        MatrixCase("Zlib-wrapped MD5", "Compression", zlib.compress(MD5.encode()).decode("latin-1"), MD5, expected_ops=("Zlib",)),
        MatrixCase(
            "DeflateRaw HELLO",
            "Compression",
            _deflate_raw("HELLO"),
            "HELLO",
            "DeflateRaw",
            "direct",
        ),
        MatrixCase("ROT13 HELLO", "Encryption / Encoding", _rot13("HELLO"), "HELLO", "ROT13", "direct"),
        MatrixCase("ROT47 HELLO", "Encryption / Encoding", _rot47("HELLO"), "HELLO", "ROT47", "direct"),
        MatrixCase("Atbash HELLO", "Encryption / Encoding", _atbash("HELLO"), "HELLO", "Atbash", "direct"),
        MatrixCase("XOR single-byte MD5", "Encryption / Encoding", _xor(MD5, b"\x20"), MD5, expected_ops=("XOR",)),
        MatrixCase("Bacon HELLO", "Encryption / Encoding", _bacon("HELLO"), "HELLO", "Bacon", "direct"),
        MatrixCase(
            "Affine pangram",
            "Encryption / Encoding",
            _affine("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"),
            "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
            "Affine",
            "direct",
        ),
        MatrixCase("HashDetector identity", "Hashing", MD5, MD5, "HashDetector", "direct"),
        MatrixCase("StripWhitespace hash", "Forensics", f"  {MD5}  ", MD5, "StripWhitespace", "direct"),
        MatrixCase("RemoveNullBytes", "Forensics", "has\x00h", "hash", "RemoveNullBytes", "direct"),
        MatrixCase("ExtractHash from line", "Forensics", f"password: {MD5}", MD5, "ExtractHash", "direct"),
        MatrixCase("Refang URL", "Forensics", "hxxp://example[.]com", "http://example.com", "Refang", "direct"),
        MatrixCase("ExtractEmbeddedHash code", "Forensics", 'const h = "' + MD5 + '";', MD5, expected_ops=("ExtractEmbeddedHash",)),
        MatrixCase("ExtractIP", "Extractors", "ip=10.1.2.3", "10.1.2.3", "ExtractIP", "direct", expected_ops=("ExtractIP",)),
        MatrixCase("ExtractEmails", "Extractors", "admin@example.com", "admin@example.com", "ExtractEmails", "direct"),
        MatrixCase("ExtractURLs", "Extractors", "see https://example.com/x", "https://example.com/x", "ExtractURLs", "direct"),
        MatrixCase("ExtractMAC", "Extractors", "mac AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF", "ExtractMAC", "direct"),
        MatrixCase("ExtractBase64 blob", "Extractors", f"blob: {_b64(MD5)}", MD5, expected_ops=("ExtractBase64",)),
        MatrixCase("ExtractJWTPayload", "Extractors", _jwt({"hash": MD5}), MD5, "ExtractJWTPayload", "direct", contains=True),
        MatrixCase("ExtractQuotedStrings", "Code / Config", 'const h = "' + MD5 + '";', MD5, expected_ops=("ExtractQuotedStrings",)),
        MatrixCase("ExtractJSONValues", "Code / Config", json.dumps({"h": MD5}), MD5, expected_ops=("ExtractJSONValues",)),
        MatrixCase("ExtractConfigValues", "Code / Config", f"HASH={MD5}", MD5, expected_ops=("ExtractConfigValues",)),
        MatrixCase("ExtractConfigValues direct", "Code / Config", f"HASH={MD5}", MD5, "ExtractConfigValues", "direct"),
        MatrixCase("ExtractJSONValues direct", "Code / Config", json.dumps({"h": MD5}), MD5, "ExtractJSONValues", "direct"),
        MatrixCase("ExtractQuotedStrings direct", "Code / Config", 'const h = "' + MD5 + '";', MD5, "ExtractQuotedStrings", "direct"),
        MatrixCase("ExtractPEMBody direct", "Forensics", "-----BEGIN KEY-----\n" + _b64(MD5) + "\n-----END KEY-----", _b64(MD5), "ExtractPEMBody", "direct"),
        MatrixCase("HTMLEntities direct", "Data format", "&lt;x&gt;", "<x>", "HTMLEntities", "direct"),
        MatrixCase("JWT direct", "Data format", _jwt({"hash": MD5}), MD5, "JWT", "direct", contains=True),
        MatrixCase("LZMA direct", "Compression", lzma.compress(MD5.encode()).decode("latin-1"), MD5, "LZMA", "direct"),
        MatrixCase("RawUnescape direct", "Data format", "".join(f"\\x{ord(char):02x}" for char in MD5), MD5, "RawUnescape", "direct"),
        MatrixCase(
            "ExtractPEMBody",
            "Forensics",
            "-----BEGIN PUBLIC KEY-----\n" + _b64(MD5) + "\n-----END PUBLIC KEY-----",
            MD5,
            expected_ops=("ExtractPEMBody", "Base64"),
        ),
        MatrixCase(
            "Keyed RailFence MD5",
            "Keyed transforms",
            _rail_fence("value=" + MD5, 3),
            MD5,
            keys={"rail_fence_rails": "3"},
            expected_ops=("RailFence",),
        ),
        MatrixCase("Vigenere HELLO", "Keyed transforms", _vigenere("HELLO"), "HELLO", "Vigenere", "direct", {"vigenere_key": "KEY"}),
        MatrixCase("Keyed XOR MD5", "Keyed transforms", _xor(MD5, b"matrix"), MD5, keys={"xor_key": "hex:" + b"matrix".hex()}, expected_ops=("XORRepeating",)),
        MatrixCase("Keyed RC4 MD5", "Keyed transforms", _rc4(MD5, b"matrix"), MD5, keys={"rc4_key": "hex:" + b"matrix".hex()}, expected_ops=("RC4",)),
        MatrixCase(
            "Keyed AES-CBC MD5",
            "Keyed transforms",
            _aes_cbc(MD5, key, iv),
            MD5,
            keys={"aes_key": "hex:" + aes_key, "aes_iv": "hex:" + iv.hex()},
            expected_ops=("AES-CBC",),
        ),
        MatrixCase(
            "Keyed AES-CTR MD5",
            "Keyed transforms",
            _aes_ctr(MD5, key, ctr_nonce),
            MD5,
            keys={"aes_key": "hex:" + aes_key, "aes_nonce": "hex:" + ctr_nonce.hex()},
            expected_ops=("AES-CTR",),
        ),
        MatrixCase(
            "Keyed AES-GCM MD5",
            "Keyed transforms",
            gm_ct,
            MD5,
            keys={"aes_key": "hex:" + aes_key, "aes_nonce": "hex:" + nonce.hex(), "aes_tag": "hex:" + gm_tag.hex()},
            expected_ops=("AES-GCM",),
        ),
        MatrixCase("SHA1 terminal", "Terminal hashes", SHA1, SHA1, mode="terminal"),
        MatrixCase("SHA256 terminal", "Terminal hashes", SHA256, SHA256, mode="terminal"),
        MatrixCase("SHA512 terminal", "Terminal hashes", SHA512, SHA512, mode="terminal"),
        MatrixCase(
            "bcrypt terminal",
            "Terminal hashes",
            "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxQS2rW4lY7BvHfQeH8aQn3XKzO",
            "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxQS2rW4lY7BvHfQeH8aQn3XKzO",
            mode="terminal",
        ),
        MatrixCase(
            "sha512crypt terminal",
            "Terminal hashes",
            "$6$rounds=5000$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG",
            "$6$rounds=5000$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG",
            mode="terminal",
        ),
    ]


def build_archive_cases() -> List[MatrixCase]:
    import io
    import tarfile
    import zipfile

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("hash.txt", MD5)
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        data = MD5.encode()
        info = tarfile.TarInfo("hash.txt")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return [
        MatrixCase("ZIP archive MD5", "Compression", zip_buffer.getvalue().decode("latin-1"), MD5, expected_ops=("ArchiveExtract",)),
        MatrixCase("TAR archive MD5", "Compression", tar_buffer.getvalue().decode("latin-1"), MD5, expected_ops=("ArchiveExtract",)),
    ]


def _direct_result(case: MatrixCase) -> Tuple[str, str, bool]:
    operation = OPERATION_BY_NAME.get(case.operation)
    if operation is None:
        return "", f"unknown operation {case.operation}", False
    outputs = operation.apply_many(case.payload, keys=case.keys)
    if not outputs:
        return "", "operation returned no output", False
    actual = outputs[0].text
    if case.contains:
        passed = case.expected in actual
    else:
        passed = actual == case.expected
    return actual, actual, passed


def run_matrix(
    *,
    max_layers: int = 12,
    beam_width: int = 8,
    check_crack: bool = False,
    include_archives: bool = True,
    on_result: Optional[Callable[[MatrixResult], None]] = None,
) -> MatrixReport:
    cases = build_matrix_cases()
    if include_archives:
        cases.extend(build_archive_cases())

    started = time.monotonic()
    results: List[MatrixResult] = []
    covered: set[str] = set()
    coverage_cases: Dict[str, List[str]] = {}
    coverage_failures: Dict[str, List[str]] = {}

    for case in cases:
        case_started = time.monotonic()
        chain = ""
        terminal = False
        status = "fail"
        detail = ""
        actual = ""
        tested_ops: set[str] = set()

        if case.mode == "direct":
            actual, detail, passed = _direct_result(case)
            chain = case.operation
            covered.add(case.operation)
            tested_ops.add(case.operation)
            status = "pass" if passed else "fail"
        elif case.mode == "terminal":
            from hashvault.analysis.validators import is_terminal_hash

            actual = case.payload
            terminal = is_terminal_hash(actual)
            status = "pass" if terminal and actual == case.expected else "fail"
            chain = "HashDetector"
            covered.add("HashDetector")
            tested_ops.add("HashDetector")
            if not terminal:
                detail = "input was not recognised as terminal"
        else:
            try:
                handoff = prepare_input(
                    case.payload,
                    max_layers=max_layers,
                    beam_width=beam_width,
                    allow_extractors=True,
                    keys=case.keys,
                    max_seconds=5.0,
                )
                actual = handoff.primary
                chain = handoff.trace.describe()
                terminal = handoff.trace.terminal
                tested_ops.update(layer.operation for layer in handoff.trace.layers)
                covered.update(tested_ops)
                passed = (
                    (case.expected in actual if case.contains else actual == case.expected)
                    and (terminal or not case.expected_ops)
                )
                if handoff.discovery.truncated:
                    detail = "search budget reached"
                status = "pass" if passed else "fail"
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
                tested_ops.update(case.expected_ops)
                status = "fail"

        for operation_name in tested_ops:
            names = coverage_cases.setdefault(operation_name, [])
            if case.name not in names:
                names.append(case.name)
            if status != "pass":
                failures = coverage_failures.setdefault(operation_name, [])
                if case.name not in failures:
                    failures.append(case.name)

        item = MatrixResult(
            name=case.name,
            category=case.category,
            operation=chain or case.operation,
            expected=case.expected,
            actual=actual,
            chain=chain,
            terminal=terminal,
            status=status,
            elapsed=round(time.monotonic() - case_started, 4),
            detail=detail,
        )
        results.append(item)
        if on_result is not None:
            on_result(item)

    all_names = [operation.name for operation in OPERATIONS]
    operation_coverage = [
        MatrixOperationCoverage(
            name=operation.name,
            category=operation.category,
            tier=operation.tier,
            cases=list(coverage_cases.get(operation.name, [])),
            failures=list(coverage_failures.get(operation.name, [])),
        )
        for operation in OPERATIONS
    ]
    missing = sorted(name for name in all_names if name not in covered)
    report = MatrixReport(
        results=results,
        total_operations=len(all_names),
        covered_operations=sorted(covered),
        missing_operations=missing,
        elapsed=time.monotonic() - started,
        operation_coverage=operation_coverage,
    )
    if check_crack:
        crack_results = run_crack_cases(on_result=on_result)
        report.results.extend(crack_results)
        report.elapsed = time.monotonic() - started
    return report


def run_crack_cases(
    on_result: Optional[Callable[[MatrixResult], None]] = None,
) -> List[MatrixResult]:
    """Small curated engine handoff section for ``selftest --crack``."""
    import tempfile
    from pathlib import Path
    from sqlalchemy.orm import Session

    from hashvault.config import load_config
    from hashvault.core.database import init_db, reset_db_engine
    from hashvault.core.orchestrator import process_single_hash
    from hashvault.core.registry import CrackTool

    vectors = [
        ("MD5 password", MD5, "password", "MD5"),
        ("SHA1 password", SHA1, "password", "SHA1"),
        ("SHA256 password", SHA256, "password", "SHA2-256"),
        ("NTLM password", "8846f7eaee8fb117ad06bdd830b7586c", "password", "NTLM"),
    ]
    results: List[MatrixResult] = []
    config = load_config()
    original_database = config.paths.database
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            config.paths.database = str(Path(temp_dir) / "matrix.db")
            reset_db_engine()
            engine = init_db(config.paths.database, seed_patterns_path="data/patterns/patterns.json")
            session = Session(engine)
            try:
                for name, target, expected, pattern in vectors:
                    started = time.monotonic()
                    try:
                        result = process_single_hash(
                            raw_hash=target,
                            db_session=session,
                            config=config,
                            tool=CrackTool.BUILTIN,
                            auto_confirm=True,
                            forced_pattern=pattern,
                            unwrap=False,
                        )
                        status = "pass" if result.cracked and result.plaintext == expected else "fail"
                        detail = result.error_message or ""
                        actual = result.plaintext or ""
                        chain = result.tool_used
                    except Exception as exc:
                        status = "fail"
                        actual = ""
                        chain = "builtin"
                        detail = f"{type(exc).__name__}: {exc}"
                    item = MatrixResult(
                        name=name,
                        category="Cracking",
                        operation=chain,
                        expected=expected,
                        actual=actual,
                        chain=chain,
                        terminal=True,
                        status=status,
                        elapsed=round(time.monotonic() - started, 4),
                        detail=detail,
                    )
                    results.append(item)
                    if on_result is not None:
                        on_result(item)
            finally:
                session.close()
                reset_db_engine()
    finally:
        config.paths.database = original_database
        reset_db_engine()
        init_db(original_database, seed_patterns_path="data/patterns/patterns.json")
    return results
