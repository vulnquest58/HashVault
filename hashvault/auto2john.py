#!/usr/bin/env python3
"""Official vendored auto2john engine for HashVault.

Detect protected files, run the matching John the Ripper *2john helper, and
write the extracted hash lines to a permission-restricted output file.

The tool prefers built-in magic-byte signatures and ZIP container inspection.
It can optionally use python-magic as an additional MIME hint when available.

Source: https://github.com/vulnquest58/auto2john (version 0.1.0). Keep this
vendored copy synchronized with the upstream release when converter profiles,
detection signatures, or safety behavior change.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.0"
DEFAULT_TIMEOUT = 120.0
MAX_HEAD_BYTES = 65536
MAX_TOOL_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_STDERR_CHARS = 2000

MIME_HINTS = {
    "application/pdf": "pdf",
    "application/x-rar": "rar",
    "application/x-rar-compressed": "rar",
    "application/x-7z-compressed": "7z",
    "application/pgp-encrypted": "gpg",
    "application/x-pcap": "pcap",
    "application/vnd.tcpdump.pcap": "pcap",
    "application/x-sqlite3": None,
    "application/zip": "zip",
}


class Auto2JohnError(Exception):
    """Base error for expected CLI failures."""


class AmbiguousFormat(Auto2JohnError):
    """Raised when more than one profile matches a file."""

    def __init__(self, message: str, candidates: Sequence[str]):
        super().__init__(message)
        self.candidates = tuple(candidates)


class ToolError(Auto2JohnError):
    """Raised when a converter cannot be resolved or fails."""


@dataclass(frozen=True)
class Profile:
    key: str
    tool: str
    category: str
    description: str
    extensions: tuple[str, ...] = ()
    filename_hints: tuple[str, ...] = ()
    magic: tuple[Callable[[Path, bytes], bool], ...] = ()
    magic_specificity: int = 50
    input_kind: str = "file"
    extra_args: tuple[str, ...] = ()
    weak_extension: bool = False


@dataclass(frozen=True)
class Detection:
    profile: Profile
    confidence: str
    reason: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResolvedTool:
    path: Path
    command_prefix: tuple[str, ...]
    searched: tuple[str, ...]


@dataclass(frozen=True)
class Conversion:
    detection: Detection
    tool: ResolvedTool
    command: tuple[str, ...]
    output: Path
    hash_count: int
    dry_run: bool
    tool_args: tuple[str, ...] = field(default_factory=tuple)


def _read_head(path: Path, size: int = MAX_HEAD_BYTES) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def _read_tail(path: Path, size: int = 1024) -> bytes:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            length = handle.tell()
            handle.seek(max(0, length - size))
            return handle.read(size)
    except OSError:
        return b""


def _text(head: bytes) -> str:
    return head.decode("utf-8", errors="ignore")


def _zip_names(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as archive:
            return [name.replace("\\", "/") for name in archive.namelist()[:2000]]
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return []


def _is_zip(path: Path, head: bytes) -> bool:
    return head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))


def _is_ooxml(path: Path, head: bytes) -> bool:
    if not _is_zip(path, head):
        return False
    names = _zip_names(path)
    if "[Content_Types].xml" not in names:
        return False
    return any(
        name.startswith(("word/", "xl/", "ppt/")) for name in names
    )


def _is_iwork(path: Path, head: bytes) -> bool:
    if not _is_zip(path, head):
        return False
    names = _zip_names(path)
    return any(name.startswith(("Index/", "Metadata/")) for name in names)


def _is_pdf(path: Path, head: bytes) -> bool:
    return b"%PDF-" in head[:1024]


def _is_rar(path: Path, head: bytes) -> bool:
    return head.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"))


def _is_7z(path: Path, head: bytes) -> bool:
    return head.startswith(b"7z\xbc\xaf\x27\x1c")


def _is_keepass(path: Path, head: bytes) -> bool:
    return head.startswith((b"\x03\xd9\xa2\x9a", b"\x9a\xa2\xd9\x03"))


def _is_bitlocker(path: Path, head: bytes) -> bool:
    return len(head) >= 11 and head[3:11] == b"-FVE-FS-"


def _is_luks(path: Path, head: bytes) -> bool:
    return head.startswith(b"LUKS\xba\xbe")


def _is_dmg(path: Path, head: bytes) -> bool:
    tail = _read_tail(path, 512)
    return tail.startswith(b"koly") or head.startswith(b"koly")


def _is_pcap(path: Path, head: bytes) -> bool:
    return head.startswith(
        (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")
    )


def _is_putty(path: Path, head: bytes) -> bool:
    return head.startswith(b"PuTTY-User-Key-File-")


def _is_ssh_private(path: Path, head: bytes) -> bool:
    text = _text(head)
    return "-----BEGIN" in text and "PRIVATE KEY" in text


def _is_pem_certificate(path: Path, head: bytes) -> bool:
    return b"-----BEGIN CERTIFICATE-----" in head


def _is_openssl_encrypted(path: Path, head: bytes) -> bool:
    text = _text(head)
    return "-----BEGIN" in text and "ENCRYPTED" in text


def _is_pgp(path: Path, head: bytes) -> bool:
    return b"-----BEGIN PGP" in head


def _is_sqlite(path: Path, head: bytes) -> bool:
    return head.startswith(b"SQLite format 3\x00")


def _is_bdb(path: Path, head: bytes) -> bool:
    return head.startswith(
        (
            b"\x00\x06\x15\x61",
            b"\x00\x05\x31\x62",
            b"\x00\x04\x22\x53",
            b"\x00\x04\x09\x88",
        )
    )


def _is_ccache(path: Path, head: bytes) -> bool:
    return head.startswith((b"\x05\x04", b"\x05\x03"))


def _is_android_backup(path: Path, head: bytes) -> bool:
    return head.startswith(b"ANDROID BACKUP")


def _is_ansible_vault(path: Path, head: bytes) -> bool:
    return head.startswith(b"$ANSIBLE_VAULT;")


def _is_pdml(path: Path, head: bytes) -> bool:
    return b"<pdml" in head[:4096]


def _is_filezilla_xml(path: Path, head: bytes) -> bool:
    return b"<FileZilla3" in head[:4096]


def _is_encfs_xml(path: Path, head: bytes) -> bool:
    return b"<encfs" in head[:4096]


def _is_vmx(path: Path, head: bytes) -> bool:
    text = _text(head)
    return "config.version" in text and ".encoding" in text


def _is_vdi(path: Path, head: bytes) -> bool:
    return b"<<< Oracle VM VirtualBox Disk Image >>>" in head[:256]


def _is_unix_passwd(path: Path, head: bytes) -> bool:
    if b"\x00" in head[:4096]:
        return False
    lines = _text(head[:4096]).splitlines()
    return any(line.count(":") >= 6 for line in lines[:20])


def _is_mozilla_profile(path: Path, head: bytes) -> bool:
    if not path.is_dir():
        return False
    return (path / "prefs.js").is_file() or (path / "key4.db").is_file()


def _is_audio(path: Path, head: bytes) -> bool:
    return head.startswith((b"RIFF", b"ID3", b"fLaC", b"OggS"))


def _json_text(head: bytes) -> str:
    return _text(head)


def _is_ethereum_json(path: Path, head: bytes) -> bool:
    text = _json_text(head)
    return bool(re.search(r'"crypto"\s*:', text)) and bool(
        re.search(r'"(cipher|kdf)"\s*:', text)
    )


def _is_bitwarden_json(path: Path, head: bytes) -> bool:
    text = _json_text(head)
    return bool(re.search(r'"encrypted"\s*:\s*true', text)) and all(
        token in text for token in ('"data"', '"salt"')
    )


def _is_electrum_json(path: Path, head: bytes) -> bool:
    text = _json_text(head)
    return '"seed_version"' in text and '"wallet_type"' in text


def _is_blockchain_json(path: Path, head: bytes) -> bool:
    text = _json_text(head)
    return '"pbkdf2_iterations"' in text or (
        '"payload"' in text and '"version"' in text
    )


def _is_dashlane(path: Path, head: bytes) -> bool:
    return path.name.lower() == "dashlane_db" and _is_sqlite(path, head)


def _is_enpass(path: Path, head: bytes) -> bool:
    return path.name.lower() == "walletx.db" and _is_sqlite(path, head)


def _is_applenotes(path: Path, head: bytes) -> bool:
    return path.name.lower() == "notes.sqlite" and _is_sqlite(path, head)


PROFILES: tuple[Profile, ...] = (
    Profile("zip", "zip2john", "Archives", "ZIP archive", ("zip",), magic=(_is_zip,), magic_specificity=10),
    Profile("rar", "rar2john", "Archives", "RAR archive", ("rar",), magic=(_is_rar,), magic_specificity=90),
    Profile("7z", "7z2john.pl", "Archives", "7-Zip archive", ("7z",), magic=(_is_7z,), magic_specificity=90),
    Profile("apex", "apex2john.py", "Archives", "Apex archive", ("apx",)),
    Profile("pdf", "pdf2john.pl", "Documents", "PDF document", ("pdf",), magic=(_is_pdf,), magic_specificity=90),
    Profile(
        "office",
        "office2john.py",
        "Documents",
        "Microsoft Office document",
        ("docx", "xlsx", "pptx", "doc", "xls", "ppt"),
        magic=(_is_ooxml,),
        magic_specificity=70,
        weak_extension=True,
    ),
    Profile("iwork", "iwork2john.py", "Documents", "Apple iWork document", ("pages", "numbers", "key"), magic=(_is_iwork,), magic_specificity=70),
    Profile("applenotes", "applenotes2john.py", "Documents", "Apple Notes database", filename_hints=("notes.sqlite",), magic=(_is_applenotes,), magic_specificity=70),
    Profile("keepass", "keepass2john", "Password managers", "KeePass database", ("kdbx", "kdb"), magic=(_is_keepass,), magic_specificity=90),
    Profile("bitwarden", "bitwarden2john.py", "Password managers", "Bitwarden export", ("json",), filename_hints=("bitwarden",), magic=(_is_bitwarden_json,), magic_specificity=70),
    Profile("1password", "1password2john.py", "Password managers", "1Password 1PIF vault", ("1pif",)),
    Profile("dashlane", "dashlane2john.py", "Password managers", "Dashlane database", filename_hints=("dashlane_db",), magic=(_is_dashlane,), magic_specificity=70),
    Profile("enpass", "enpass2john.py", "Password managers", "Enpass database", filename_hints=("walletx.db",), magic=(_is_enpass,), magic_specificity=70),
    Profile("andotp", "andotp2john.py", "Password managers", "andOTP encrypted backup", ("json.aes",)),
    Profile("authenticator", "authenticator2john.py", "Password managers", "Authenticator backup", filename_hints=("authenticator",)),
    Profile("bitcoin", "bitcoin2john.py", "Wallets", "Bitcoin Core wallet", ("dat",), filename_hints=("wallet.dat",), magic=(_is_bdb,), magic_specificity=70, weak_extension=True),
    Profile("ethereum", "ethereum2john.py", "Wallets", "Ethereum keystore", ("json",), filename_hints=("ethereum",), magic=(_is_ethereum_json,), magic_specificity=70),
    Profile("electrum", "electrum2john.py", "Wallets", "Electrum wallet", ("json",), filename_hints=("electrum",), magic=(_is_electrum_json,), magic_specificity=70),
    Profile("blockchain", "blockchain2john.py", "Wallets", "Blockchain.com wallet", ("aes.json",), magic=(_is_blockchain_json,), magic_specificity=70),
    Profile("cardano", "cardano2john.py", "Wallets", "Cardano wallet", filename_hints=("cardano",)),
    Profile("bitshares", "bitshares2john.py", "Wallets", "BitShares wallet", ("bin",), filename_hints=("bitshares",), weak_extension=True),
    Profile("keplr", "keplr2john.py", "Wallets", "Keplr wallet data", filename_hints=("keplr_data",)),
    Profile("bitlocker", "bitlocker2john.py", "Disk encryption", "BitLocker volume", ("img", "vhd", "vhdx"), magic=(_is_bitlocker,), magic_specificity=90, extra_args=("-i",)),
    Profile("dmg", "dmg2john", "Disk encryption", "Apple DMG image", ("dmg",), magic=(_is_dmg,), magic_specificity=90),
    Profile("luks", "luks2john", "Disk encryption", "LUKS volume", ("img",), magic=(_is_luks,), magic_specificity=90),
    Profile("truecrypt", "truecrypt2john.py", "Disk encryption", "TrueCrypt volume", ("tc",)),
    Profile("diskcryptor", "diskcryptor2john.py", "Disk encryption", "DiskCryptor volume"),
    Profile("bestcrypt", "bestcrypt2john.py", "Disk encryption", "BestCrypt container", ("jbc",)),
    Profile("bestcryptve", "bestcryptve2john.py", "Disk encryption", "BestCrypt volume encryption", ("bde",)),
    Profile("encfs", "encfs2john.py", "Disk encryption", "EncFS configuration", ("encfs6.xml",), filename_hints=(".encfs6.xml",), magic=(_is_encfs_xml,), magic_specificity=70),
    Profile("ecryptfs", "ecryptfs2john.py", "Disk encryption", "eCryptfs wrapped passphrase", filename_hints=("wrapped-passphrase",)),
    Profile("androidfde", "androidfde2john.py", "Disk encryption", "Android full-disk encryption footer", ("img",), filename_hints=("footer.img",)),
    Profile("geli", "geli2john.py", "Disk encryption", "FreeBSD GELI provider"),
    Profile("axcrypt", "axcrypt2john.py", "Disk encryption", "AxCrypt file", ("axx",)),
    Profile("ssh", "ssh2john.py", "Keys", "SSH private key", ("pem", "key"), magic=(_is_ssh_private,), magic_specificity=85),
    Profile("putty", "putty2john", "Keys", "PuTTY private key", ("ppk",), magic=(_is_putty,), magic_specificity=90),
    Profile("gpg", "gpg2john", "Keys", "GnuPG key", ("gpg", "asc"), magic=(_is_pgp,), magic_specificity=70),
    Profile("pem", "pem2john.py", "Keys", "PEM certificate", ("pem",), magic=(_is_pem_certificate,), magic_specificity=80),
    Profile("pfx", "pfx2john.py", "Keys", "PKCS#12 bundle", ("pfx", "p12")),
    Profile("openssl", "openssl2john.py", "Keys", "Encrypted OpenSSL key", ("key",), magic=(_is_openssl_encrypted,), magic_specificity=80),
    Profile("bks", "bks2john.py", "Keys", "Bouncy Castle keystore", ("bks",)),
    Profile("pcap", "pcap2john", "Network", "Packet capture", ("pcap", "pcapng"), magic=(_is_pcap,), magic_specificity=90),
    Profile("krb", "krb2john.py", "Network", "Kerberos PDML export", ("pdml",), magic=(_is_pdml,), magic_specificity=80),
    Profile("ccache", "ccache2john.py", "Network", "Kerberos credential cache", filename_hints=("krb5cc",), magic=(_is_ccache,), magic_specificity=80),
    Profile("apop", "apop2john", "Network", "APOP capture"),
    Profile("aruba", "aruba2john.py", "Network", "Aruba capture"),
    Profile("aix", "aix2john", "System", "AIX passwd file", filename_hints=("passwd", "shadow"), magic=(_is_unix_passwd,), magic_specificity=60),
    Profile("racf", "racf2john", "System", "RACF database", filename_hints=("racf",)),
    Profile("dpapimk", "DPAPImk2john.py", "System", "Windows DPAPI masterkey directory", input_kind="dir", extra_args=("-d",)),
    Profile("androidbackup", "androidbackup2john.py", "System", "Android backup", ("ab",), magic=(_is_android_backup,), magic_specificity=90),
    Profile("ansible", "ansible2john.py", "Misc", "Ansible vault", magic=(_is_ansible_vault,), magic_specificity=90),
    Profile("filezilla", "filezilla2john.py", "Misc", "FileZilla sitemanager", ("xml",), filename_hints=("sitemanager.xml",), magic=(_is_filezilla_xml,), magic_specificity=70),
    Profile("deepsound", "deepsound2john.py", "Misc", "DeepSound audio carrier", ("wav", "mp3", "flac", "ogg"), magic=(_is_audio,), magic_specificity=20, weak_extension=True),
    Profile("pse", "pse2john.py", "Misc", "PSE file", ("pse",)),
    Profile("vmx", "vmx2john.py", "Misc", "VMware VMX configuration", ("vmx",), magic=(_is_vmx,), magic_specificity=80),
    Profile("vdi", "vdi2john.pl", "Misc", "VirtualBox VDI disk", ("vdi",), magic=(_is_vdi,), magic_specificity=90),
    Profile("mozilla", "mozilla2john.py", "Misc", "Mozilla profile directory", input_kind="dir", magic=(_is_mozilla_profile,), magic_specificity=80),
)

PROFILE_BY_KEY = {profile.key: profile for profile in PROFILES}


def _matches_extension(path: Path, extensions: Sequence[str]) -> bool:
    name = path.name.lower()
    return any(name.endswith("." + extension.lower()) for extension in extensions)


def _matches_filename(path: Path, hints: Sequence[str]) -> bool:
    name = path.name.lower()
    return any(hint.lower() in name for hint in hints)


def _matches_magic(path: Path, head: bytes, profile: Profile) -> bool:
    return any(predicate(path, head) for predicate in profile.magic)


def _libmagic_profile(path: Path) -> str | None:
    try:
        import magic
    except (ImportError, OSError):
        return None
    mime = None
    with suppress(Exception):
        mime = magic.from_file(str(path), mime=True)
    return MIME_HINTS.get(mime) if mime else None


def _choose(candidates: Sequence[Profile], path: Path) -> Profile | None:
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    extension_matches = [p for p in candidates if _matches_extension(path, p.extensions)]
    if len(extension_matches) == 1:
        return extension_matches[0]
    filename_matches = [p for p in candidates if _matches_filename(path, p.filename_hints)]
    if len(filename_matches) == 1:
        return filename_matches[0]
    return None


def detect_profile(
    path: Path,
    profile_key: str | None = None,
    *,
    use_libmagic: bool = True,
) -> Detection:
    if not path.exists():
        raise Auto2JohnError(f"Input does not exist: {path}")

    if profile_key:
        profile = PROFILE_BY_KEY.get(profile_key)
        if profile is None:
            raise Auto2JohnError(
                f"Unknown profile '{profile_key}'. Use --list to see profiles."
            )
        return Detection(profile, "override", "selected with --profile")

    head = b"" if path.is_dir() else _read_head(path)
    magic_matches = [p for p in PROFILES if _matches_magic(path, head, p)]
    if magic_matches:
        top_specificity = max(profile.magic_specificity for profile in magic_matches)
        top = [p for p in magic_matches if p.magic_specificity == top_specificity]
        chosen = _choose(top, path)
        if chosen is not None:
            warnings = ()
            if chosen.input_kind == "dir" and not path.is_dir():
                warnings = (f"{chosen.key} normally expects a directory",)
            return Detection(chosen, "magic", "magic signature", warnings)
        keys = ", ".join(sorted(profile.key for profile in top))
        raise AmbiguousFormat(
            f"Ambiguous magic match for {path}: {keys}. Use --profile.",
            [profile.key for profile in top],
        )

    filename_matches = [p for p in PROFILES if _matches_filename(path, p.filename_hints)]
    if filename_matches:
        chosen = _choose(filename_matches, path)
        if chosen is not None:
            return Detection(chosen, "filename", "filename hint")
        keys = ", ".join(sorted(profile.key for profile in filename_matches))
        raise AmbiguousFormat(
            f"Ambiguous filename match for {path}: {keys}. Use --profile.",
            [profile.key for profile in filename_matches],
        )

    extension_matches = [p for p in PROFILES if _matches_extension(path, p.extensions)]
    if extension_matches:
        chosen = _choose(extension_matches, path)
        if chosen is not None:
            warnings = ()
            if chosen.weak_extension:
                warnings = (
                    f"'{chosen.key}' was selected by extension only; verify the file type",
                )
            return Detection(chosen, "extension", "file extension", warnings)
        keys = ", ".join(sorted(profile.key for profile in extension_matches))
        raise AmbiguousFormat(
            f"Ambiguous extension for {path}: {keys}. Use --profile.",
            [profile.key for profile in extension_matches],
        )

    if use_libmagic:
        hint = _libmagic_profile(path)
        if hint:
            profile = PROFILE_BY_KEY.get(hint)
            if profile is not None:
                return Detection(profile, "libmagic", "python-magic MIME hint")

    keys = ", ".join(sorted(PROFILE_BY_KEY))
    raise Auto2JohnError(
        f"Could not detect a converter for {path}. Use --profile KEY. "
        f"Available profiles: {keys}"
    )


def _tool_variants(tool: str) -> tuple[str, ...]:
    if Path(tool).suffix:
        return (tool,)
    return (tool, f"{tool}.py", f"{tool}.pl", f"{tool}.sh", f"{tool}.exe")


def _search_roots(
    tool_dirs: Sequence[Path],
    john_bin: str | None,
) -> list[Path]:
    roots: list[Path] = []
    for directory in tool_dirs:
        roots.append(directory.expanduser())
    for raw in os.environ.get("AUTO2JOHN_TOOL_DIRS", "").split(os.pathsep):
        if raw.strip():
            roots.append(Path(raw).expanduser())
    raw_run_dir = os.environ.get("JOHN_RUN_DIR")
    if raw_run_dir:
        roots.append(Path(raw_run_dir).expanduser())
    if john_bin:
        candidate = Path(john_bin).expanduser()
        if candidate.is_dir():
            roots.append(candidate)
        else:
            if candidate.parent != Path("."):
                roots.append(candidate.parent)
            resolved = shutil.which(john_bin)
            if resolved:
                roots.append(Path(resolved).parent)
    roots.extend(
        [
            Path.home() / "john" / "run",
            Path.home() / "john-jumbo" / "run",
            Path("/usr/share/john"),
            Path("/usr/local/share/john"),
            Path("/opt/john/run"),
            Path("/usr/lib/john"),
            Path.cwd() / "tools" / "converters",
            Path.cwd(),
        ]
    )
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root)
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def _command_prefix(path: Path) -> tuple[str, ...]:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return (sys.executable, str(path))
    if suffix == ".pl":
        perl = shutil.which("perl")
        if not perl:
            raise ToolError(f"Perl is required to run {path}, but 'perl' was not found")
        return (perl, str(path))
    if suffix == ".sh":
        shell = shutil.which("bash") or shutil.which("sh")
        if not shell:
            raise ToolError(f"A shell is required to run {path}")
        return (shell, str(path))
    if os.access(path, os.X_OK):
        return (str(path),)
    try:
        first_line = path.read_text(encoding="utf-8", errors="ignore").splitlines()[0]
    except (OSError, IndexError):
        first_line = ""
    if first_line.startswith("#!"):
        interpreter = first_line[2:].strip().split()
        if interpreter:
            name = Path(interpreter[0]).name
            if name.startswith("python"):
                return (sys.executable, str(path))
            if name == "perl":
                perl = shutil.which("perl")
                if perl:
                    return (perl, str(path))
    raise ToolError(f"Converter is not executable and has no supported interpreter: {path}")


def resolve_tool(
    profile: Profile,
    *,
    tool_dirs: Sequence[Path] = (),
    john_bin: str | None = None,
    explicit_tool: str | None = None,
) -> ResolvedTool:
    if explicit_tool:
        candidate = Path(explicit_tool).expanduser()
        if candidate.is_file():
            return ResolvedTool(candidate.resolve(), _command_prefix(candidate), ())
        if candidate.parent != Path("."):
            raise ToolError(f"Explicit converter not found: {candidate}")
        names = (explicit_tool,)
    else:
        names = _tool_variants(profile.tool)

    roots = _search_roots(tool_dirs, john_bin)
    searched: list[str] = []
    for root in roots:
        if not root.is_dir():
            continue
        directories = [root]
        try:
            directories.extend(
                child for child in root.iterdir() if child.is_dir()
            )
        except OSError:
            pass
        for directory in directories:
            searched.append(str(directory))
            for name in names:
                path = directory / name
                if path.is_file():
                    return ResolvedTool(
                        path.resolve(), _command_prefix(path), tuple(searched)
                    )

    for name in names:
        path = shutil.which(name)
        if path:
            resolved = Path(path)
            return ResolvedTool(
                resolved, _command_prefix(resolved), tuple(searched)
            )

    location_text = ", ".join(str(root) for root in roots)
    raise ToolError(
        f"Converter '{profile.tool}' was not found. Searched: {location_text}. "
        "Use --tool-dir or --john-bin."
    )


def build_command(
    tool: ResolvedTool,
    profile: Profile,
    input_path: Path,
    tool_args: Sequence[str] = (),
) -> tuple[str, ...]:
    return (
        *tool.command_prefix,
        *profile.extra_args,
        *tool_args,
        str(input_path),
    )


def _output_path(
    input_path: Path,
    *,
    out: Path | None,
    out_dir: Path | None,
) -> Path:
    if out is not None and out_dir is not None:
        raise Auto2JohnError("--out and --out-dir cannot be used together")
    if out is not None:
        return out.expanduser()
    directory = (out_dir or Path("hashes")).expanduser()
    stem = input_path.name
    if input_path.is_dir():
        stem = input_path.name
    else:
        stem = Path(stem).stem or "hash"
    return directory / f"{stem}.hash"


def _write_hashes(path: Path, content: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise Auto2JohnError(
            f"Refusing to overwrite {path}; use --force to replace it"
        )
    if path.is_symlink():
        raise Auto2JohnError(f"Refusing to write through symlink: {path}")
    if path.exists() and path.is_dir():
        raise Auto2JohnError(f"Output path is a directory: {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise Auto2JohnError(f"Cannot create output directory {path.parent}: {exc}") from exc

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        if path.exists() and not force:
            raise Auto2JohnError(
                f"Refusing to overwrite {path}; use --force to replace it"
            )
        os.replace(temporary, path)
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _run_tool(command: Sequence[str], timeout: float) -> tuple[str, int]:
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"Converter executable not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Converter timed out after {timeout:g} seconds") from exc
    except OSError as exc:
        raise ToolError(f"Could not run converter: {exc}") from exc

    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if len(stdout) > MAX_TOOL_OUTPUT_BYTES:
        raise ToolError("Converter output exceeded the safety limit")
    if completed.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > MAX_STDERR_CHARS:
            detail = detail[-MAX_STDERR_CHARS:]
        raise ToolError(
            f"Converter exited with status {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    text = stdout.decode("utf-8", errors="replace")
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines:
        detail = stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > MAX_STDERR_CHARS:
            detail = detail[-MAX_STDERR_CHARS:]
        raise ToolError(
            "Converter produced no hash lines"
            + (f": {detail}" if detail else "")
        )
    return "\n".join(lines) + "\n", len(lines)


def convert(
    input_path: Path,
    *,
    profile_key: str | None = None,
    out: Path | None = None,
    out_dir: Path | None = None,
    tool_dirs: Sequence[Path] = (),
    john_bin: str | None = None,
    explicit_tool: str | None = None,
    tool_args: Sequence[str] = (),
    force: bool = False,
    dry_run: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    use_libmagic: bool = True,
) -> Conversion:
    if not input_path.exists():
        raise Auto2JohnError(f"Input does not exist: {input_path}")
    if not timeout > 0:
        raise Auto2JohnError("--timeout must be greater than 0")
    detection = detect_profile(
        input_path, profile_key, use_libmagic=use_libmagic
    )
    if detection.profile.input_kind == "dir" and not input_path.is_dir():
        raise Auto2JohnError(
            f"Profile '{detection.profile.key}' expects a directory input"
        )
    if detection.profile.input_kind == "file" and input_path.is_dir():
        raise Auto2JohnError(
            f"Profile '{detection.profile.key}' expects a file input"
        )
    output = _output_path(input_path, out=out, out_dir=out_dir)
    tool = resolve_tool(
        detection.profile,
        tool_dirs=tool_dirs,
        john_bin=john_bin,
        explicit_tool=explicit_tool,
    )
    command = build_command(tool, detection.profile, input_path, tool_args)
    if dry_run:
        return Conversion(
            detection=detection,
            tool=tool,
            command=command,
            output=output,
            hash_count=0,
            dry_run=True,
            tool_args=tuple(tool_args),
        )
    content, count = _run_tool(command, timeout)
    _write_hashes(output, content, force=force)
    return Conversion(
        detection=detection,
        tool=tool,
        command=command,
        output=output,
        hash_count=count,
        dry_run=False,
        tool_args=tuple(tool_args),
    )


def _profile_rows() -> list[dict[str, object]]:
    return [
        {
            "key": profile.key,
            "category": profile.category,
            "tool": profile.tool,
            "description": profile.description,
            "extensions": list(profile.extensions),
            "input": profile.input_kind,
        }
        for profile in PROFILES
    ]


def _print_profiles(as_json: bool) -> None:
    rows = _profile_rows()
    if as_json:
        print(json.dumps({"profiles": rows}, indent=2))
        return
    for row in rows:
        extensions = ", ".join(row["extensions"]) if row["extensions"] else "-"
        print(
            f"{row['key']:<16} {row['category']:<18} "
            f"{row['tool']:<28} {extensions}"
        )


def _print_tools(
    *,
    tool_dirs: Sequence[Path],
    john_bin: str | None,
    as_json: bool,
) -> int:
    rows: list[dict[str, object]] = []
    missing = 0
    for profile in PROFILES:
        try:
            tool = resolve_tool(
                profile, tool_dirs=tool_dirs, john_bin=john_bin
            )
        except ToolError as exc:
            missing += 1
            rows.append(
                {
                    "profile": profile.key,
                    "tool": profile.tool,
                    "found": False,
                    "error": str(exc),
                }
            )
        else:
            rows.append(
                {
                    "profile": profile.key,
                    "tool": profile.tool,
                    "found": True,
                    "path": str(tool.path),
                }
            )
    if as_json:
        print(json.dumps({"tools": rows, "missing": missing}, indent=2))
    else:
        for row in rows:
            status = row.get("path") if row["found"] else "MISSING"
            print(f"{row['profile']:<16} {row['tool']:<28} {status}")
    return 0


def _detection_payload(detection: Detection) -> dict[str, object]:
    return {
        "profile": detection.profile.key,
        "description": detection.profile.description,
        "confidence": detection.confidence,
        "reason": detection.reason,
        "warnings": list(detection.warnings),
    }


def _emit_error(message: str, *, as_json: bool, candidates: Sequence[str] = ()) -> None:
    if as_json:
        payload: dict[str, object] = {"ok": False, "error": message}
        if candidates:
            payload["candidates"] = list(candidates)
        print(json.dumps(payload, indent=2))
    else:
        print(f"error: {message}", file=sys.stderr)
        if candidates:
            print(
                "candidates: " + ", ".join(candidates),
                file=sys.stderr,
            )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto2john",
        description=(
            "Detect a protected file, run the matching John the Ripper *2john "
            "helper, and save the hash as <input>.hash."
        ),
    )
    parser.add_argument("input", nargs="?", help="file or directory to convert")
    parser.add_argument("--profile", help="force a profile key instead of detection")
    parser.add_argument("--out", type=Path, help="explicit output hash file")
    parser.add_argument("--out-dir", type=Path, help="output directory (default: hashes)")
    parser.add_argument("--tool", help="explicit converter path or name")
    parser.add_argument(
        "--tool-dir",
        action="append",
        default=[],
        type=Path,
        help="converter search directory; may be repeated",
    )
    parser.add_argument(
        "--john-bin",
        help="John binary or run directory used to locate converters",
    )
    parser.add_argument(
        "--tool-arg",
        action="append",
        default=[],
        help="extra converter argument; may be repeated",
    )
    parser.add_argument("--force", action="store_true", help="overwrite the output file")
    parser.add_argument("--dry-run", action="store_true", help="show the command without running it")
    parser.add_argument("--detect-only", action="store_true", help="detect and print the profile only")
    parser.add_argument("--list", action="store_true", help="list supported profiles")
    parser.add_argument("--list-tools", action="store_true", help="resolve and list converters")
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument("--no-libmagic", action="store_true", help="disable python-magic hints")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"converter timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    as_json = bool(args.json)

    if args.list:
        _print_profiles(as_json)
        return 0
    if args.list_tools:
        return _print_tools(
            tool_dirs=args.tool_dir,
            john_bin=args.john_bin,
            as_json=as_json,
        )
    if not args.input:
        parser.error("the following arguments are required: input")

    input_path = Path(args.input).expanduser()
    try:
        if args.detect_only:
            detection = detect_profile(
                input_path,
                args.profile,
                use_libmagic=not args.no_libmagic,
            )
            payload = {"ok": True, "input": str(input_path), "detection": _detection_payload(detection)}
            if as_json:
                print(json.dumps(payload, indent=2))
            else:
                print(
                    f"{detection.profile.key}: {detection.profile.description} "
                    f"({detection.confidence}: {detection.reason})"
                )
                for warning in detection.warnings:
                    print(f"warning: {warning}", file=sys.stderr)
            return 0

        conversion = convert(
            input_path,
            profile_key=args.profile,
            out=args.out,
            out_dir=args.out_dir,
            tool_dirs=args.tool_dir,
            john_bin=args.john_bin,
            explicit_tool=args.tool,
            tool_args=args.tool_arg,
            force=args.force,
            dry_run=args.dry_run,
            timeout=args.timeout,
            use_libmagic=not args.no_libmagic,
        )
    except AmbiguousFormat as exc:
        _emit_error(str(exc), as_json=as_json, candidates=exc.candidates)
        return 2
    except (Auto2JohnError, OSError) as exc:
        _emit_error(str(exc), as_json=as_json)
        return 2
    except KeyboardInterrupt:
        _emit_error("interrupted", as_json=as_json)
        return 130

    if as_json:
        payload = {
            "ok": True,
            "input": str(input_path),
            "detection": _detection_payload(conversion.detection),
            "tool": str(conversion.tool.path),
            "command": list(conversion.command),
            "output": str(conversion.output),
            "hashes": conversion.hash_count,
            "dry_run": conversion.dry_run,
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(
        f"Detected: {conversion.detection.profile.key} "
        f"({conversion.detection.reason})"
    )
    for warning in conversion.detection.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if conversion.dry_run:
        print("Command: " + " ".join(conversion.command))
        print(f"Would write: {conversion.output}")
        return 0
    print(f"Tool: {conversion.tool.path}")
    print(f"Hash written: {conversion.output} ({conversion.hash_count} line(s))")
    print(f"Crack with: john --wordlist=rockyou.txt {conversion.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
