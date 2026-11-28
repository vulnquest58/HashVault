"""
File-to-hash conversion engine (Ingestors / Converters).

This module implements Layer 1 of the deep-analysis pipeline: converting an
encrypted/locked file from its native format into the hash string that
hashcat/John actually cracks.

Supported formats
-----------------
- ZIP  (.zip)       → zip2john  / pkzip2john
- RAR  (.rar)       → rar2john
- 7-Zip (.7z)       → 7z2john / john --format=7z
- KeePass (.kdbx, .kdb) → keepass2john
- MS Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt) → office2john
- PDF  (.pdf)       → pdf2john
- SSH private keys  (.pem, id_rsa, id_ed25519, …) → ssh2john
- LUKS  (.img, raw) → luks2john
- VeraCrypt (.vc, .veracrypt) → veracrypt2john (tc_aes_xts)
- NTDS.dit          → secretsdump / ntds2john workflow (manual)
- Bitcoin wallet    (.wallet, wallet.dat) → bitcoin2john
- Ethereum keystore (.json UTC--…)       → ethereum2john

Design
------
Each format is handled by a FileIngestor subclass that:
  1. Detects whether the file matches its format.
  2. Runs the appropriate extractor (john helper / custom logic).
  3. Returns an ExtractedHash with the raw hash string and metadata.

All subprocess calls use shell=False for security.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type

logger = logging.getLogger("hashvault.ingestors")

# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------


@dataclass
class ExtractedHash:
    """One hash string extracted from a file, ready for the analysis pipeline."""

    raw_hash: str
    """The hash string in hashcat/John format."""

    source_file: str
    """Original file path."""

    format_hint: str = ""
    """Detected format name (e.g. 'zip', 'keepass', 'office2016')."""

    tool_used: str = ""
    """Extractor tool that produced the hash (e.g. 'zip2john', 'office2john')."""

    hashcat_mode: Optional[int] = None
    """Suggested hashcat -m value if known at extraction time."""

    john_format: Optional[str] = None
    """Suggested John --format value if known at extraction time."""

    notes: List[str] = field(default_factory=list)


@dataclass
class ConversionResult:
    """Aggregated result of a convert_file() call."""

    source_file: str
    success: bool
    hashes: List[ExtractedHash] = field(default_factory=list)
    error: Optional[str] = None
    format_detected: str = ""
    profile: str = ""
    attempts: List[str] = field(default_factory=list)

    @property
    def first_hash(self) -> Optional[str]:
        return self.hashes[0].raw_hash if self.hashes else None


# ---------------------------------------------------------------------------
# Extension / magic-byte detection table
# ---------------------------------------------------------------------------

SUPPORTED_EXTENSIONS: Dict[str, str] = {
    ".zip":       "zip",
    ".rar":       "rar",
    ".7z":        "7z",
    ".kdbx":      "keepass",
    ".kdb":       "keepass",
    ".docx":      "office",
    ".xlsx":      "office",
    ".pptx":      "office",
    ".doc":       "office",
    ".xls":       "office",
    ".ppt":       "office",
    ".pdf":       "pdf",
    ".pem":       "ssh",
    ".key":       "ssh",
    ".id_rsa":    "ssh",
    ".vc":        "veracrypt",
    ".veracrypt": "veracrypt",
    ".wallet":    "bitcoin",
    ".json":      "ethereum",  # checked more carefully by magic
}

# Magic-byte fingerprints (offset, bytes, format)
_MAGIC: List[Tuple[int, bytes, str]] = [
    (0,  b"PK\x03\x04",                  "zip"),
    (0,  b"PK\x05\x06",                  "zip"),    # empty zip
    (0,  b"Rar!\x1a\x07\x00",            "rar"),    # RAR4
    (0,  b"Rar!\x1a\x07\x01\x00",        "rar"),    # RAR5
    (0,  b"7z\xbc\xaf\x27\x1c",          "7z"),
    (0,  b"\x03\xd9\xa2\x9a",            "keepass"), # KDB
    (0,  b"\x03\xd9\xa2\x9b",            "keepass"), # KDBX
    (0,  b"%PDF-",                        "pdf"),
    (0,  b"-----BEGIN ",                  "ssh"),
    (0,  b"openssh-key-v1",              "ssh"),
    (0,  b"\x4c\x55\x4b\x53",            "luks"),
]


def detect_file_type(path: Path) -> str:
    """
    Return a format string ('zip', 'keepass', …) for *path*, or '' if unknown.

    Prefers magic-byte detection over extension matching so that mislabelled
    files are still handled correctly.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(512)
    except OSError:
        return path.suffix.lower().lstrip(".")

    for offset, magic, fmt in _MAGIC:
        if data[offset:offset + len(magic)] == magic:
            return fmt

    # Special Ethereum UTC keystore: JSON with "crypto" key.  Only inspect
    # reasonably small JSON documents so a multi-gigabyte wallet/backup cannot
    # be pulled into memory during detection.
    if path.suffix.lower() == ".json":
        try:
            if path.stat().st_size > 8 * 1024 * 1024:
                return SUPPORTED_EXTENSIONS.get(path.suffix.lower(), "")
            obj = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(obj, dict) and "crypto" in obj:
                return "ethereum"
        except Exception:
            pass

    return SUPPORTED_EXTENSIONS.get(path.suffix.lower(), "")


# ---------------------------------------------------------------------------
# Base ingestor class
# ---------------------------------------------------------------------------


class FileIngestor:
    """Abstract base for file-to-hash extractors."""

    format_name: str = ""
    """Human-readable format tag used in ExtractedHash.format_hint."""

    def accepts(self, path: Path) -> bool:
        """Return True if this ingestor handles *path*."""
        return detect_file_type(path) == self.format_name

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        """
        Extract hash(es) from *path*.

        Parameters
        ----------
        path:
            Absolute path to the source file.
        john_bin:
            Path or name of the John the Ripper binary (used to locate helper
            scripts that ship with John, e.g. zip2john, office2john …).

        Returns
        -------
        list of ExtractedHash
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# John helper-script runner (shared utility)
# ---------------------------------------------------------------------------

def _project_root() -> Path:
    """Repository root (``hashvault/ingestors/converters.py`` -> root)."""
    return Path(__file__).resolve().parent.parent.parent


def _helper_candidate_dirs(john_bin: str) -> List[Path]:
    """Return the *trusted* directories that may contain a John helper.

    Helpers are executables that we then run, so the search has to be narrow
    and deterministic.  ``shutil.which(helper)`` is deliberately excluded: on
    Windows it also resolves relative entries such as ``.\\zip2john.exe``,
    which lets an attacker drop a binary in the working directory and have it
    executed (binary planting).  Only the configured John installation and the
    bundled ``tools/john/run`` tree are trusted.
    """
    dirs: List[Path] = []

    resolved = shutil.which(john_bin)
    if resolved:
        john_path = Path(resolved)
        dirs.append(john_path.parent)
        dirs.append(john_path.parent / "run")
    elif john_bin:
        configured = Path(john_bin)
        dirs.append(configured if configured.is_dir() else configured.parent)
        dirs.append((configured if configured.is_dir() else configured.parent) / "run")

    tools_john = _project_root() / "tools" / "john"
    dirs.extend([tools_john / "run", tools_john])

    # De-duplicate while preserving order; drop anything that is not absolute.
    seen: set[Path] = set()
    unique: List[Path] = []
    for directory in dirs:
        try:
            candidate = directory.resolve()
        except OSError:
            continue
        if candidate in seen or not candidate.is_dir():
            continue
        seen.add(candidate)
        unique.append(candidate)
    return unique


def _resolve_john_helper(helper: str, john_bin: str) -> Optional[Path]:
    """Locate a John helper inside the trusted directories only."""
    # A helper name must never be a path fragment.
    if not helper or "/" in helper or "\\" in helper or helper.startswith("."):
        logger.warning("Refusing unsafe John helper name: %r", helper)
        return None

    names = [helper, f"{helper}.exe"]
    for directory in _helper_candidate_dirs(john_bin):
        for name in names:
            candidate = directory / name
            if not candidate.is_file():
                continue
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            # Defence in depth: the resolved path must stay inside the dir.
            try:
                resolved.relative_to(directory)
            except ValueError:
                logger.warning("John helper escaped its directory: %s", resolved)
                continue
            if os.name != "nt" and not os.access(resolved, os.X_OK):
                continue
            return resolved
    return None


def _run_john_helper(
    helper: str,
    path: Path,
    john_bin: str = "john",
    extra_args: Optional[List[str]] = None,
) -> Tuple[str, str]:
    """
    Run a John helper script (zip2john, office2john, etc.) and return
    (stdout, stderr).

    The helper is only searched in the configured John installation and the
    bundled ``tools/john`` tree (see :func:`_helper_candidate_dirs`).
    """
    helper_path = _resolve_john_helper(helper, john_bin)
    if helper_path is None:
        logger.debug("Helper '%s' not found in trusted John directories.", helper)
        return "", (
            f"Helper '{helper}' not found in the configured John installation "
            f"or tools/john. Install John the Ripper to enable this converter."
        )

    # ``path.resolve()`` always yields an absolute path, so a file named like
    # "--help" cannot be reinterpreted as an option by the helper's parser.
    cmd = [str(helper_path), str(path.resolve())]
    if extra_args:
        cmd.extend(str(arg) for arg in extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "", "Helper timed out."
    except Exception as exc:
        return "", str(exc)


# ---------------------------------------------------------------------------
# Concrete ingestors
# ---------------------------------------------------------------------------


class ZipIngestor(FileIngestor):
    """Extract ZIP archive password hash via zip2john."""

    format_name = "zip"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        stdout, stderr = _run_john_helper("zip2john", path, john_bin)
        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "$pkzip" in line.lower():
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="zip",
                        tool_used="zip2john",
                        hashcat_mode=17200,   # PKZIP (Compressed)
                        john_format="pkzip",
                    ))
        if not hashes and stderr:
            logger.warning(f"zip2john stderr: {stderr[:200]}")
        return hashes


class RarIngestor(FileIngestor):
    """Extract RAR archive password hash via rar2john."""

    format_name = "rar"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        stdout, stderr = _run_john_helper("rar2john", path, john_bin)
        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and ("$rar" in line.lower() or "$RAR" in line):
                    # RAR3 = hashcat mode 12500, RAR5 = 13000
                    if "$rar5" in line.lower():
                        hm, jf = 13000, "rar5"
                    else:
                        hm, jf = 12500, "rar"
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="rar",
                        tool_used="rar2john",
                        hashcat_mode=hm,
                        john_format=jf,
                    ))
        if not hashes and stderr:
            logger.warning(f"rar2john stderr: {stderr[:200]}")
        return hashes


class SevenZipIngestor(FileIngestor):
    """Extract 7-Zip archive password hash via 7z2john (or john --format=7z)."""

    format_name = "7z"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        # Try 7z2john first
        stdout, stderr = _run_john_helper("7z2john", path, john_bin)
        if not stdout:
            # Fallback: use the bundled perl script 7z2john.pl
            stdout, stderr = _run_john_helper("7z2john.pl", path, john_bin)

        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and "$7z$" in line:
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="7z",
                        tool_used="7z2john",
                        hashcat_mode=11600,
                        john_format="7z",
                    ))
        if not hashes and stderr:
            logger.warning(f"7z2john stderr: {stderr[:200]}")
        return hashes


class KeePassIngestor(FileIngestor):
    """Extract KeePass database hash via keepass2john."""

    format_name = "keepass"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        stdout, stderr = _run_john_helper("keepass2john", path, john_bin)
        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and "$keepass$" in line.lower():
                    # KeePass 1 = 13400, KeePass 2 = 13400 (same mode)
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="keepass",
                        tool_used="keepass2john",
                        hashcat_mode=13400,
                        john_format="keepass",
                    ))
        if not hashes and stderr:
            logger.warning(f"keepass2john stderr: {stderr[:200]}")
        return hashes


class OfficeIngestor(FileIngestor):
    """Extract MS Office document password hash via office2john."""

    format_name = "office"

    # Office format → hashcat mode mapping
    _MODE_MAP = {
        "2007": 9400,
        "2010": 9500,
        "2013": 9600,
        "2016": 9600,
        "2019": 9600,
        "365":  9600,
        "97":   9700,
        "2000": 9700,
        "2003": 9700,
    }

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        stdout, stderr = _run_john_helper("office2john", path, john_bin)
        if not stdout:
            # Try the Python script variant
            stdout, stderr = _run_john_helper("office2john.py", path, john_bin)
        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and "$office$" in line.lower():
                    # Determine version from hash body
                    hm = None
                    for ver, mode in self._MODE_MAP.items():
                        if f"*{ver}*" in line or f"office$*{ver}" in line.lower():
                            hm = mode
                            break
                    if hm is None:
                        # Default to modern (2013+) mode
                        hm = 9600
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="office",
                        tool_used="office2john",
                        hashcat_mode=hm,
                        john_format="office",
                    ))
        if not hashes and stderr:
            logger.warning(f"office2john stderr: {stderr[:200]}")
        return hashes


class PdfIngestor(FileIngestor):
    """Extract PDF password hash via pdf2john."""

    format_name = "pdf"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        stdout, stderr = _run_john_helper("pdf2john", path, john_bin)
        if not stdout:
            stdout, stderr = _run_john_helper("pdf2john.pl", path, john_bin)
        if not stdout:
            stdout, stderr = _run_john_helper("pdf2john.py", path, john_bin)
        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and "$pdf$" in line.lower():
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="pdf",
                        tool_used="pdf2john",
                        hashcat_mode=10500,
                        john_format="pdf",
                    ))
        if not hashes and stderr:
            logger.warning(f"pdf2john stderr: {stderr[:200]}")
        return hashes


class SSHIngestor(FileIngestor):
    """Extract encrypted SSH private key hash via ssh2john."""

    format_name = "ssh"

    # Detect if key file is actually encrypted (has a passphrase).
    _ENCRYPTED_MARKERS = (b"ENCRYPTED", b"Proc-Type: 4,ENCRYPTED")

    def _is_encrypted(self, path: Path) -> bool:
        try:
            data = path.read_bytes()
            return any(m in data for m in self._ENCRYPTED_MARKERS)
        except OSError:
            return False

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        if not self._is_encrypted(path):
            return [ExtractedHash(
                raw_hash="",
                source_file=str(path),
                format_hint="ssh",
                notes=["SSH key appears unencrypted — no passphrase to crack."],
            )]

        stdout, stderr = _run_john_helper("ssh2john", path, john_bin)
        if not stdout:
            stdout, stderr = _run_john_helper("ssh2john.py", path, john_bin)

        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and "$sshng$" in line.lower():
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="ssh",
                        tool_used="ssh2john",
                        hashcat_mode=22921,   # RSA/DSA/EC/OpenSSH Private Keys
                        john_format="ssh",
                    ))
        if not hashes and stderr:
            logger.warning(f"ssh2john stderr: {stderr[:200]}")
        return hashes


class EthereumIngestor(FileIngestor):
    """
    Extract Ethereum UTC keystore hash (Web3 Secret Storage Definition).

    This ingestor works without an external tool — the hash is assembled
    directly from the JSON keystore fields.
    """

    format_name = "ethereum"

    def accepts(self, path: Path) -> bool:
        return detect_file_type(path) == "ethereum"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            return [ExtractedHash(
                raw_hash="",
                source_file=str(path),
                format_hint="ethereum",
                notes=[f"Failed to parse JSON: {exc}"],
            )]

        crypto = obj.get("crypto") or obj.get("Crypto", {})
        kdf = crypto.get("kdf", "")
        kdfparams = crypto.get("kdfparams", {})
        ciphertext = crypto.get("ciphertext", "")
        mac = crypto.get("mac", "")
        iv = crypto.get("cipherparams", {}).get("iv", "")
        salt = kdfparams.get("salt", "")
        n = kdfparams.get("n", 262144)
        r = kdfparams.get("r", 8)
        p = kdfparams.get("p", 1)
        dklen = kdfparams.get("dklen", 32)
        c = kdfparams.get("c", 262144)    # for pbkdf2

        if kdf == "scrypt":
            # Hashcat mode 15600 — ethereum-scrypt
            raw = f"$ethereum$s*{n}*{r}*{p}*{salt}*{iv}*{ciphertext}*{mac}"
            hm, jf = 15600, "ethereum-scrypt"
        elif kdf == "pbkdf2":
            # Hashcat mode 15700 — ethereum-pbkdf2
            raw = f"$ethereum$p*{c}*{dklen}*{salt}*{iv}*{ciphertext}*{mac}"
            hm, jf = 15700, "ethereum-pbkdf2"
        else:
            return [ExtractedHash(
                raw_hash="",
                source_file=str(path),
                format_hint="ethereum",
                notes=[f"Unsupported KDF: {kdf}"],
            )]

        return [ExtractedHash(
            raw_hash=raw,
            source_file=str(path),
            format_hint="ethereum",
            tool_used="internal",
            hashcat_mode=hm,
            john_format=jf,
        )]


class BitcoinIngestor(FileIngestor):
    """Extract Bitcoin Core wallet hash via bitcoin2john."""

    format_name = "bitcoin"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        stdout, stderr = _run_john_helper("bitcoin2john", path, john_bin)
        if not stdout:
            stdout, stderr = _run_john_helper("bitcoin2john.py", path, john_bin)

        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and "$bitcoin$" in line.lower():
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="bitcoin",
                        tool_used="bitcoin2john",
                        hashcat_mode=11300,
                        john_format="bitcoin",
                    ))
        if not hashes and stderr:
            logger.warning(f"bitcoin2john stderr: {stderr[:200]}")
        return hashes


class LuksIngestor(FileIngestor):
    """Extract LUKS disk image hash via luks2john."""

    format_name = "luks"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        stdout, stderr = _run_john_helper("luks2john", path, john_bin)
        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and "$luks$" in line.lower():
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="luks",
                        tool_used="luks2john",
                        hashcat_mode=14600,
                        john_format="LUKS",
                    ))
        if not hashes and stderr:
            logger.warning(f"luks2john stderr: {stderr[:200]}")
        return hashes


class VeraCryptIngestor(FileIngestor):
    """
    Extract VeraCrypt/TrueCrypt volume hash.

    VeraCrypt volumes are detected by reading the first 512 bytes (header).
    The hash is assembled as a raw header slice for hashcat mode 13711-13773.
    """

    format_name = "veracrypt"

    def extract(self, path: Path, john_bin: str = "john") -> List[ExtractedHash]:
        stdout, stderr = _run_john_helper("veracrypt2john", path, john_bin)
        if not stdout:
            stdout, stderr = _run_john_helper("tc_aes_xts", path, john_bin)
        hashes = []
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    hashes.append(ExtractedHash(
                        raw_hash=line,
                        source_file=str(path),
                        format_hint="veracrypt",
                        tool_used="veracrypt2john",
                        hashcat_mode=13711,   # VeraCrypt PBKDF2-HMAC-RIPEMD160 + AES
                        john_format="tc_aes_xts",
                    ))
        if not hashes and stderr:
            logger.warning(f"veracrypt2john stderr: {stderr[:200]}")
        return hashes


# ---------------------------------------------------------------------------
# Ingestor registry and main entry point
# ---------------------------------------------------------------------------

_INGESTORS: List[FileIngestor] = [
    ZipIngestor(),
    RarIngestor(),
    SevenZipIngestor(),
    KeePassIngestor(),
    OfficeIngestor(),
    PdfIngestor(),
    SSHIngestor(),
    EthereumIngestor(),
    BitcoinIngestor(),
    LuksIngestor(),
    VeraCryptIngestor(),
]


def _find_ingestor(path: Path) -> Optional[FileIngestor]:
    """Return the first ingestor that accepts *path*, or None."""
    for ing in _INGESTORS:
        if ing.accepts(path):
            return ing
    return None


def convert_file(
    file_path: str | Path,
    john_bin: str = "john",
    *,
    format_override: str = "",
) -> ConversionResult:
    """
    Convert an encrypted file to crackable hash string(s).

    Parameters
    ----------
    file_path:
        Path to the encrypted file.
    john_bin:
        John the Ripper binary path/name (used to locate helper scripts).
    format_override:
        Force a specific format ('zip', 'keepass', etc.) instead of
        auto-detection.

    Returns
    -------
    ConversionResult
        Always returned even on failure (check .success and .error).
    """
    path = Path(file_path).resolve()
    if not path.exists():
        return ConversionResult(
            source_file=str(path),
            success=False,
            error=f"File not found: {path}",
        )

    # Format detection
    fmt = format_override.lower() if format_override else detect_file_type(path)
    if not fmt:
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected="unknown",
            error=(
                f"Unsupported or unrecognised file format for: {path.name}\n"
                f"Supported: {', '.join(sorted(set(SUPPORTED_EXTENSIONS.values())))}"
            ),
        )

    # Find ingestor
    ingestor = _find_ingestor(path)
    if ingestor is None:
        # No ingestor for this format — look up by format name
        ingestor = next(
            (i for i in _INGESTORS if i.format_name == fmt), None
        )

    if ingestor is None:
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=fmt,
            error=f"No ingestor registered for format '{fmt}'.",
        )

    logger.info(f"Converting {path.name!r} using {type(ingestor).__name__}")
    try:
        hashes = ingestor.extract(path, john_bin=john_bin)
    except Exception as exc:
        logger.exception(f"Ingestor {type(ingestor).__name__} raised an exception.")
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=fmt,
            error=str(exc),
        )

    # Filter out empty hashes (unencrypted files etc.)
    valid = [h for h in hashes if h.raw_hash]
    if not valid and hashes:
        # All hashes were empty — propagate notes from first result
        note = hashes[0].notes[0] if hashes[0].notes else "No hash extracted."
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=fmt,
            error=note,
        )

    if not valid:
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=fmt,
            error="Ingestor returned no hashes — file may not be encrypted.",
        )

    return ConversionResult(
        source_file=str(path),
        success=True,
        format_detected=fmt,
        hashes=valid,
    )
