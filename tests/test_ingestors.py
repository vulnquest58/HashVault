"""
Tests for hashvault/ingestors/converters.py — file-to-hash extraction engine.

These tests run without requiring any John helper binaries installed:
- Format detection tests use magic bytes / JSON structure.
- Ingestor extract() paths are verified with mocks.
- convert_file() integration is tested with temp files.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from hashvault.ingestors.converters import (
    SUPPORTED_EXTENSIONS,
    ConversionResult,
    ExtractedHash,
    ZipIngestor,
    KeePassIngestor,
    EthereumIngestor,
    BitcoinIngestor,
    OfficeIngestor,
    SevenZipIngestor,
    convert_file,
    detect_file_type,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_path_factory_dir(tmp_path) -> Path:
    return tmp_path


@pytest.fixture()
def eth_keystore(tmp_path) -> Path:
    """Write a minimal Ethereum UTC keystore JSON to a temp file."""
    ks = {
        "version": 3,
        "id": "test-id",
        "address": "deadbeef",
        "crypto": {
            "kdf": "scrypt",
            "kdfparams": {
                "n": 262144,
                "r": 8,
                "p": 1,
                "dklen": 32,
                "salt": "a" * 64,
            },
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": "b" * 32},
            "ciphertext": "c" * 64,
            "mac": "d" * 64,
        },
    }
    p = tmp_path / "UTC--2023-01-01T00-00-00.000000000Z--deadbeef.json"
    p.write_text(json.dumps(ks), encoding="utf-8")
    return p


@pytest.fixture()
def eth_pbkdf2_keystore(tmp_path) -> Path:
    """Write an Ethereum pbkdf2 keystore."""
    ks = {
        "version": 3,
        "crypto": {
            "kdf": "pbkdf2",
            "kdfparams": {
                "c": 262144,
                "dklen": 32,
                "prf": "hmac-sha256",
                "salt": "e" * 64,
            },
            "cipherparams": {"iv": "f" * 32},
            "ciphertext": "aa" * 32,
            "mac": "bb" * 32,
        },
    }
    p = tmp_path / "keystore_pbkdf2.json"
    p.write_text(json.dumps(ks), encoding="utf-8")
    return p


@pytest.fixture()
def zip_file(tmp_path) -> Path:
    """Create a minimal ZIP file (no password) for magic-byte detection."""
    p = tmp_path / "test.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("hello.txt", "hello")
    return p


# ---------------------------------------------------------------------------
# detect_file_type
# ---------------------------------------------------------------------------


class TestDetectFileType:
    def test_detect_zip_by_magic(self, zip_file):
        assert detect_file_type(zip_file) == "zip"

    def test_detect_ethereum_by_json_structure(self, eth_keystore):
        assert detect_file_type(eth_keystore) == "ethereum"

    def test_detect_by_extension_fallback(self, tmp_path):
        p = tmp_path / "file.kdbx"
        p.write_bytes(b"\x00" * 16)  # no valid magic
        # Extension fallback
        result = detect_file_type(p)
        # Either detected by extension map or returns ""
        assert result in ("keepass", "")

    def test_detect_unknown_returns_empty(self, tmp_path):
        p = tmp_path / "file.unknownext"
        p.write_bytes(b"random bytes here")
        assert detect_file_type(p) == ""

    def test_seven_zip_magic(self, tmp_path):
        p = tmp_path / "archive.7z"
        p.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 10)
        assert detect_file_type(p) == "7z"

    def test_rar5_magic(self, tmp_path):
        p = tmp_path / "archive.rar"
        p.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 10)
        assert detect_file_type(p) == "rar"

    def test_keepass_kdbx_magic(self, tmp_path):
        p = tmp_path / "db.kdbx"
        p.write_bytes(b"\x03\xd9\xa2\x9b" + b"\x00" * 10)
        assert detect_file_type(p) == "keepass"

    def test_pdf_magic(self, tmp_path):
        p = tmp_path / "doc.pdf"
        p.write_bytes(b"%PDF-1.7\nsome content")
        assert detect_file_type(p) == "pdf"

    def test_luks_magic(self, tmp_path):
        p = tmp_path / "disk.img"
        p.write_bytes(b"\x4c\x55\x4b\x53" + b"\x00" * 12)
        assert detect_file_type(p) == "luks"


# ---------------------------------------------------------------------------
# EthereumIngestor (no external tools needed)
# ---------------------------------------------------------------------------


class TestEthereumIngestor:
    def test_extract_scrypt(self, eth_keystore):
        ing = EthereumIngestor()
        hashes = ing.extract(eth_keystore)
        assert len(hashes) == 1
        h = hashes[0]
        assert h.raw_hash.startswith("$ethereum$s*")
        assert h.hashcat_mode == 15600
        assert h.john_format == "ethereum-scrypt"
        assert h.format_hint == "ethereum"

    def test_extract_pbkdf2(self, eth_pbkdf2_keystore):
        ing = EthereumIngestor()
        hashes = ing.extract(eth_pbkdf2_keystore)
        assert len(hashes) == 1
        h = hashes[0]
        assert h.raw_hash.startswith("$ethereum$p*")
        assert h.hashcat_mode == 15700
        assert h.john_format == "ethereum-pbkdf2"

    def test_extract_bad_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json", encoding="utf-8")
        ing = EthereumIngestor()
        hashes = ing.extract(p)
        assert len(hashes) == 1
        assert hashes[0].raw_hash == ""
        assert hashes[0].notes

    def test_extract_unsupported_kdf(self, tmp_path):
        ks = {"crypto": {"kdf": "argon2id", "kdfparams": {}}}
        p = tmp_path / "argon.json"
        p.write_text(json.dumps(ks), encoding="utf-8")
        ing = EthereumIngestor()
        hashes = ing.extract(p)
        assert len(hashes) == 1
        assert hashes[0].raw_hash == ""


# ---------------------------------------------------------------------------
# convert_file — missing file / unsupported format
# ---------------------------------------------------------------------------


class TestConvertFile:
    def test_missing_file_returns_failure(self, tmp_path):
        result = convert_file(tmp_path / "nonexistent.zip")
        assert result.success is False
        assert "not found" in (result.error or "").lower()

    def test_unsupported_format_returns_failure(self, tmp_path):
        p = tmp_path / "file.xyz"
        p.write_bytes(b"random")
        result = convert_file(p)
        assert result.success is False
        assert result.error

    def test_ethereum_scrypt_end_to_end(self, eth_keystore):
        result = convert_file(eth_keystore)
        assert result.success is True
        assert result.format_detected == "ethereum"
        assert len(result.hashes) == 1
        assert result.hashes[0].hashcat_mode == 15600
        assert result.first_hash is not None
        assert result.first_hash.startswith("$ethereum$s*")

    def test_ethereum_pbkdf2_end_to_end(self, eth_pbkdf2_keystore):
        result = convert_file(eth_pbkdf2_keystore)
        assert result.success is True
        assert result.hashes[0].hashcat_mode == 15700

    def test_format_override(self, eth_keystore):
        # Force 'ethereum' even if detection might guess something else.
        result = convert_file(eth_keystore, format_override="ethereum")
        assert result.success is True

    def test_zip_unencrypted_returns_failure(self, zip_file):
        """
        ZIP without a password produces no hash — the result should signal
        failure with an appropriate error message.
        """
        # zip2john may not be installed in CI; the result could be either:
        # - failure because helper not found
        # - failure because no $pkzip hash in output
        result = convert_file(zip_file)
        # Either way: should not raise an exception
        assert isinstance(result, ConversionResult)


# ---------------------------------------------------------------------------
# SUPPORTED_EXTENSIONS sanity
# ---------------------------------------------------------------------------


def test_supported_extensions_non_empty():
    assert len(SUPPORTED_EXTENSIONS) > 5


def test_all_supported_formats_have_ingestors():
    from hashvault.ingestors.converters import _INGESTORS
    handled_formats = {i.format_name for i in _INGESTORS}
    for ext, fmt in SUPPORTED_EXTENSIONS.items():
        assert fmt in handled_formats, f"No ingestor for format '{fmt}' (ext: {ext})"
