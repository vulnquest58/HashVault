"""Curated John the Ripper conversion profiles and converter bridge.

The gallery exposes source formats that are converted by the helper programs
shipped with John the Ripper jumbo.  Conversion is restricted to named
profiles, runs each helper with ``shell=False``, and reports missing runtimes
instead of attempting unsafe fallbacks.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import warnings
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional, Sequence

from hashvault.ingestors.converters import ConversionResult, ExtractedHash

CONVERTER_SUFFIXES: tuple[str, ...] = (".exe", ".py", ".pl", ".js", ".lua")
PY3_COMPAT_RUNNER = Path(__file__).with_name("john_py3_compat.py")


@dataclass(frozen=True)
class ConversionProfile:
    """One selectable John conversion workflow."""

    key: str
    title: str
    category: str
    extensions: tuple[str, ...]
    converter: str
    john_formats: tuple[str, ...] = ()
    hashcat_mode: Optional[int] = None
    description: str = ""
    filename_hints: tuple[str, ...] = ()
    directory_markers: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def john_format(self) -> str:
        return self.john_formats[0] if self.john_formats else ""

    @property
    def source_label(self) -> str:
        labels = [ext if ext.startswith(".") else f".{ext}" for ext in self.extensions]
        labels.extend(self.filename_hints)
        if self.directory_markers:
            labels.append("directory")
        return " ".join(dict.fromkeys(labels)) or "explicit"


@dataclass(frozen=True)
class ConverterAvailability:
    """Resolved converter path and runtime state for one profile."""

    profile: ConversionProfile
    converter_path: Optional[Path]
    runtime: str
    available: bool
    reason: str = ""


@dataclass(frozen=True)
class GalleryRow:
    """Display-oriented availability record."""

    profile: ConversionProfile
    converter_name: str
    runtime: str
    available: bool
    reason: str


def _profile(
    key: str,
    title: str,
    category: str,
    extensions: Sequence[str],
    converter: str,
    john_formats: Sequence[str] = (),
    hashcat_mode: Optional[int] = None,
    description: str = "",
    filename_hints: Sequence[str] = (),
    directory_markers: Sequence[str] = (),
    notes: Sequence[str] = (),
) -> ConversionProfile:
    return ConversionProfile(
        key=key,
        title=title,
        category=category,
        extensions=tuple(ext.lower() for ext in extensions),
        converter=converter,
        john_formats=tuple(john_formats),
        hashcat_mode=hashcat_mode,
        description=description,
        filename_hints=tuple(hint.lower() for hint in filename_hints),
        directory_markers=tuple(directory_markers),
        notes=tuple(notes),
    )


PROFILES: tuple[ConversionProfile, ...] = (
    _profile(
        "zip", "ZIP / PKZIP archive", "Archive", (".zip",), "zip2john",
        ("ZIP",), 17200, "Encrypted ZIP archives and multi-member archives.",
    ),
    _profile(
        "rar", "RAR archive", "Archive", (".rar",), "rar2john",
        ("rar", "RAR5"), 12500, "RAR3 and RAR5 archives.",
        notes=("RAR5 hashes normally need --format=RAR5.",),
    ),
    _profile(
        "7z", "7-Zip archive", "Archive", (".7z",), "7z2john",
        ("7z",), 11600, "7-Zip archives, including split volumes.",
        notes=("Requires Perl with Compress::Raw::Lzma.",),
    ),
    _profile(
        "dmg", "Apple DMG image", "Archive", (".dmg",), "dmg2john",
        ("dmg",), None, "Encrypted Apple disk images.",
    ),
    _profile(
        "android-backup", "Android backup", "Archive", (".ab", ".backup"),
        "androidbackup2john", ("AndroidBackup",), 18900,
        "Password-protected Android adb backup files.",
    ),
    _profile(
        "itunes-backup", "iOS backup", "Archive", (), "itunes_backup2john",
        ("itunes-backup",), 14700, "Encrypted iTunes/Finder iOS backups.",
        directory_markers=("Manifest.plist",),
        notes=("Requires Perl and a backup directory containing Manifest.plist.",),
    ),
    _profile(
        "vdi", "VirtualBox encrypted disk", "Archive", (".vbox",), "vdi2john",
        ("vdi",), None, "VirtualBox .vbox descriptor for an encrypted .vdi disk.",
        notes=("The encrypted .vdi must be next to the .vbox descriptor.",),
    ),
    _profile(
        "vmx", "VMware VMX", "Archive", (".vmx",), "vmx2john",
        ("vmx",), 27400, "VMware VMX encryption parameters and disk data.",
    ),
    _profile(
        "office", "Microsoft Office document", "Document",
        (".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"), "office2john",
        ("Office", "oldoffice"), 9600, "Modern and legacy Office documents.",
        notes=("Legacy $oldoffice$ output needs --format=oldoffice.",),
    ),
    _profile(
        "pdf", "PDF document", "Document", (".pdf",), "pdf2john",
        ("PDF",), 10500, "Encrypted PDF user and owner passwords.",
        notes=("Requires Perl and the converter's ExifTool library.",),
    ),
    _profile(
        "libreoffice", "LibreOffice / OpenDocument", "Document",
        (".odt", ".ods", ".odp"), "libreoffice2john", ("ODF",), None,
        "Password-protected OpenDocument files.",
    ),
    _profile(
        "iwork", "Apple iWork document", "Document",
        (".pages", ".numbers", ".key"), "iwork2john", ("iwork",), 23300,
        "Password-protected Pages, Numbers, and Keynote documents.",
    ),
    _profile(
        "notes", "Apple Notes database", "Document", (".storedata",),
        "applenotes2john", ("notes",), None, "Password-protected Apple Notes stores.",
    ),
    _profile(
        "keepass", "KeePass database", "Password manager", (".kdbx", ".kdb"),
        "keepass2john", ("KeePass",), 13400, "KeePass 1.x and 2.x databases.",
    ),
    _profile(
        "1password", "1Password vault", "Password manager",
        (".agilekeychain", ".cloudkeychain", ".opvault"), "1password2john",
        ("agilekeychain", "cloudkeychain"), 6600, "1Password keychain and vault data.",
    ),
    _profile(
        "bitwarden", "Bitwarden vault", "Password manager", (".json",),
        "bitwarden2john", ("Bitwarden",), 23400, "Local Bitwarden vault data.",
    ),
    _profile(
        "lastpass", "LastPass vault", "Password manager", (".json",),
        "lastpass2john", ("lp",), 6800, "LastPass vault data and iteration files.",
    ),
    _profile(
        "enpass", "Enpass vault", "Password manager", (".json", ".db"),
        "enpass2john", ("enpass",), None, "Enpass password manager databases.",
    ),
    _profile(
        "dashlane", "Dashlane vault", "Password manager", (".dash", ".aes"),
        "dashlane2john", ("dashlane",), None, "Dashlane local vault data.",
    ),
    _profile(
        "pwsafe", "Password Safe database", "Password manager", (".psafe3",),
        "pwsafe2john", ("pwsafe",), 5200, "Password Safe v2 and v3 databases.",
    ),
    _profile(
        "keychain", "Apple keychain", "Password manager",
        (".keychain", ".keychain-db"), "keychain2john", ("keychain",), 23100,
        "macOS login and system keychains.",
    ),
    _profile(
        "mozilla", "Mozilla password store", "Password manager", (".db",),
        "mozilla2john", ("mozilla",), 26000, "Firefox key3.db/key4.db and logins data.",
        filename_hints=("key3.db", "key4.db"),
    ),
    _profile(
        "luks", "LUKS volume", "Disk encryption", (".img", ".luks"),
        "luks2john", ("LUKS",), 14600, "LUKS v1 encrypted volume headers.",
    ),
    _profile(
        "truecrypt", "TrueCrypt volume", "Disk encryption", (".tc", ".hc"),
        "truecrypt2john", (), 29311, "TrueCrypt system and standard volumes.",
        notes=("John auto-detects the TrueCrypt cipher and hash variant.",),
    ),
    _profile(
        "veracrypt", "VeraCrypt volume", "Disk encryption", (".vc", ".veracrypt"),
        "veracrypt2john", ("tc_aes_xts",), 13711, "VeraCrypt volume headers.",
        notes=("Requires a VeraCrypt-capable extractor; TrueCrypt-only builds fail.",),
    ),
    _profile(
        "bitlocker", "BitLocker volume", "Disk encryption",
        (".img", ".vhd", ".vhdx"), "bitlocker2john", ("BitLocker",), 22100,
        "BitLocker recovery and user password material.",
    ),
    _profile(
        "bestcrypt", "BestCrypt volume", "Disk encryption", (".jbc",),
        "bestcrypt2john", ("BestCrypt",), None, "BestCrypt encrypted containers.",
    ),
    _profile(
        "diskcryptor", "DiskCryptor volume", "Disk encryption", (".dcv",),
        "diskcryptor2john", ("diskcryptor",), None, "DiskCryptor encrypted volumes.",
    ),
    _profile(
        "encfs", "EncFS directory", "Disk encryption", (".xml",), "encfs2john",
        ("EncFS",), None, "EncFS configuration and encrypted files.",
        filename_hints=(".encfs6.xml",),
    ),
    _profile(
        "ecryptfs", "eCryptfs directory", "Disk encryption", (), "ecryptfs2john",
        ("eCryptfs",), 12200, "eCryptfs wrapped passphrase data.",
        directory_markers=(".ecryptfs",),
    ),
    _profile(
        "geli", "FreeBSD GELI volume", "Disk encryption", (".eli",),
        "geli2john", ("geli",), None, "FreeBSD GELI encrypted providers.",
    ),
    _profile(
        "openbsd-softraid", "OpenBSD softraid volume", "Disk encryption",
        (".img",), "openbsd_softraid2john", ("OpenBSD-SoftRAID",), None,
        "OpenBSD softraid crypto metadata.",
    ),
    _profile(
        "padlock", "Padlock volume", "Disk encryption", (".padlock",),
        "padlock2john", ("Padlock",), None, "Padlock encrypted containers.",
    ),
    _profile(
        "pgpdisk", "PGP Disk volume", "Disk encryption", (".pgd",),
        "pgpdisk2john", ("pgpdisk",), None, "PGP Disk encrypted volumes.",
    ),
    _profile(
        "axcrypt", "AxCrypt file", "Disk encryption", (".axx",),
        "axcrypt2john", ("AxCrypt",), 23500, "AxCrypt 1.x and 2.x encrypted files.",
    ),
    _profile(
        "android-fde", "Android full-disk encryption", "Disk encryption",
        (".img",), "androidfde2john", ("fde",), 8800,
        "Android FDE images up to Android 4.3.",
    ),
    _profile(
        "ssh", "OpenSSH private key", "Private key", (".pem", ".key"),
        "ssh2john", ("SSH",), 22941, "Encrypted OpenSSH and PEM private keys.",
        filename_hints=("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"),
    ),
    _profile(
        "pem", "PEM private key", "Private key", (".pem", ".key"),
        "pem2john", ("PEM",), 24410, "Encrypted PKCS#8 and PEM private keys.",
    ),
    _profile(
        "pfx", "PKCS#12 / PFX bundle", "Private key", (".pfx", ".p12"),
        "pfx2john", ("pfx",), None, "Encrypted PKCS#12 certificate bundles.",
    ),
    _profile(
        "putty", "PuTTY private key", "Private key", (".ppk",),
        "putty2john", ("PuTTY",), None, "Passphrase-protected PuTTY keys.",
    ),
    _profile(
        "gpg", "GnuPG secret key", "Private key", (".gpg", ".pgp"),
        "gpg2john", ("gpg",), 17010, "GnuPG secret keys and symmetric files.",
    ),
    _profile(
        "openssl", "OpenSSL encrypted file", "Private key", (".enc",),
        "openssl2john", ("openssl-enc",), None, "Files encrypted with openssl enc.",
    ),
    _profile(
        "keystore", "Java keystore", "Private key", (".jks", ".keystore"),
        "keystore2john", ("keystore",), None, "Java JKS keystore entries.",
    ),
    _profile(
        "bks", "Bouncy Castle keystore", "Private key", (".bks",),
        "bks2john", ("BKS",), None, "Bouncy Castle BKS keystore entries.",
    ),
    _profile(
        "dpapi", "Windows DPAPI masterkey", "Windows", (".mk",),
        "DPAPImk2john", ("DPAPImk",), 15300, "Windows DPAPI masterkey files.",
    ),
    _profile(
        "racf", "IBM RACF database", "Enterprise", (".txt",),
        "racf2john", ("RACF",), 8500, "RACF password hashes from database extracts.",
    ),
    _profile(
        "adxcsouf", "IBM/Toshiba ADXCSOUF", "Enterprise", (".dat",),
        "adxcsouf2john", ("adxcrypt",), None, "ADXCSOUF and ADXEPW0F password files.",
        filename_hints=("adxcsouf.dat", "adxepw0f.dat"),
    ),
    _profile(
        "aix", "AIX password hashes", "Enterprise", (".txt",),
        "aix2john", ("aix-ssha256",), None, "AIX /etc/security/passwd extracts.",
    ),
    _profile(
        "sap", "SAP password hash", "Enterprise", (".txt",),
        "sap2john", ("sapb",), 7700, "SAP CODVN B/F/G/H password hashes.",
        notes=("John format depends on the SAP hash variant.",),
    ),
    _profile(
        "known-hosts", "OpenSSH known_hosts", "Enterprise", (),
        "known_hosts2john", ("known_hosts",), None, "Hashed OpenSSH known_hosts entries.",
        filename_hints=("known_hosts",),
    ),
    _profile(
        "krb5", "Kerberos capture", "Enterprise", (".pcap",),
        "krb2john", ("krb5asrep",), 18200, "AS-REP, pre-auth, and TGS material from captures.",
        notes=("John format depends on the Kerberos exchange and encryption type.",),
    ),
    _profile(
        "kirbi", "Kerberos .kirbi ticket", "Enterprise", (".kirbi",),
        "kirbi2john", ("krb5tgs",), 13100, "Kerberoastable service tickets.",
    ),
    _profile(
        "ccache", "Kerberos credential cache", "Enterprise", (".ccache",),
        "ccache2john", ("krb5tgs",), 13100, "Active Directory TGS material from ccache files.",
    ),
    _profile(
        "kdcdump", "KDC dump", "Enterprise", (".txt",),
        "kdcdump2john", ("krb5-18",), 28800, "Kerberos KDC database dump output.",
    ),
    _profile(
        "mongodb", "MongoDB server key", "Database", (".js",),
        "mongodb2john", ("MongoDB",), 24100, "MongoDB SCRAM server key material.",
    ),
    _profile(
        "radius", "RADIUS shared secret", "Network", (".pcap",),
        "radius2john", ("radius",), None, "RADIUS authenticator captures.",
    ),
    _profile(
        "ike", "IKE pre-shared key", "Network", (".txt",),
        "ikescan2john", ("IKE",), 5300, "ike-scan output for aggressive-mode PSK audits.",
    ),
    _profile(
        "sip", "SIP digest authentication", "Network", (".dump",),
        "sipdump2john", ("SIP",), 11400, "sipdump capture output.",
    ),
    _profile(
        "wpa", "Wi-Fi WPA/WPA2 handshake", "Wireless",
        (".cap", ".hccap", ".hccapx", ".pcap"), "wpapcap2john",
        ("wpapsk",), 2500, "WPA/WPA2 EAPOL handshakes.",
        notes=("Use hccapx2john.py for standalone .hccapx files.",),
    ),
    _profile(
        "bitcoin", "Bitcoin Core wallet", "Wallet", (".dat",),
        "bitcoin2john", ("Bitcoin",), 11300, "Bitcoin Core wallet.dat files.",
        filename_hints=("wallet.dat",),
    ),
    _profile(
        "ethereum", "Ethereum keystore", "Wallet", (".json",),
        "ethereum2john", ("ethereum",), 15600, "Web3 UTC keystore JSON files.",
    ),
    _profile(
        "electrum", "Electrum wallet", "Wallet", (".wallet",),
        "electrum2john", ("electrum",), 16600, "Electrum wallet files.",
    ),
    _profile(
        "monero", "Monero wallet", "Wallet", (".keys", ".wallet"),
        "monero2john", ("monero",), None, "Monero wallet key material.",
    ),
    _profile(
        "multibit", "MultiBit wallet", "Wallet", (".wallet",),
        "multibit2john", ("multibit",), 22500, "MultiBit Classic and HD wallets.",
    ),
    _profile(
        "blockchain", "Blockchain.com wallet", "Wallet", (".wallet",),
        "blockchain2john", ("Blockchain",), 12700, "Blockchain.com My Wallet files.",
    ),
    _profile(
        "signal", "Signal database", "Application", (".db",),
        "signal2john", ("Signal",), None, "Signal Desktop and Android local databases.",
    ),
    _profile(
        "telegram", "Telegram local data", "Application", (".xml", ".map"),
        "telegram2john", ("telegram",), 24500, "Telegram Desktop and Android passcodes.",
    ),
    _profile(
        "andotp", "andOTP backup", "Application", (".json",),
        "andotp2john", ("andOTP",), None, "Encrypted andOTP backup files.",
    ),
    _profile(
        "ansible", "Ansible Vault", "Application", (".yml", ".yaml"),
        "ansible2john", ("ansible",), None, "Ansible Vault encrypted files.",
    ),
    _profile(
        "sspr", "Windows SSPR / MFA", "Application", (".json",),
        "sspr2john", ("sspr",), None, "SSPR and AEM credential material.",
    ),
)


_PROFILE_INDEX = {profile.key.lower(): profile for profile in PROFILES}
_FORMAT_INDEX = {
    john_format.lower(): profile
    for profile in PROFILES
    for john_format in profile.john_formats
}
_CONVERTER_INDEX = {
    Path(profile.converter).stem.lower(): profile for profile in PROFILES
}


def get_profile(key: str) -> Optional[ConversionProfile]:
    """Return a profile by key, John format, or converter stem."""
    normalized = key.strip().lower()
    if not normalized:
        return None
    return (
        _PROFILE_INDEX.get(normalized)
        or _FORMAT_INDEX.get(normalized)
        or _CONVERTER_INDEX.get(normalized)
    )


def filter_profiles(query: str = "") -> tuple[ConversionProfile, ...]:
    """Return profiles matching a key, format, category, extension, or converter."""
    normalized = query.strip().lower()
    if not normalized:
        return PROFILES
    selected = []
    for profile in PROFILES:
        haystack = " ".join(
            (
                profile.key,
                profile.title,
                profile.category,
                profile.converter,
                profile.description,
                " ".join(profile.john_formats),
                " ".join(profile.extensions),
                " ".join(profile.filename_hints),
            )
        ).lower()
        if normalized in haystack:
            selected.append(profile)
    return tuple(selected)


def find_profiles_for_path(path: Path) -> tuple[ConversionProfile, ...]:
    """Return profiles whose extension, filename, or directory markers match."""
    suffix = path.suffix.lower()
    filename = path.name.lower()
    ranked: list[tuple[int, ConversionProfile]] = []
    for profile in PROFILES:
        priority = 0
        if filename and any(
            filename == hint or filename.startswith(hint)
            for hint in profile.filename_hints
        ):
            priority = 1
        elif path.is_dir() and profile.directory_markers and any(
            (path / marker).exists() for marker in profile.directory_markers
        ):
            priority = 2
        elif suffix in profile.extensions:
            priority = 3
        if priority:
            ranked.append((priority, profile))
    ranked.sort(key=lambda item: item[0])
    return tuple(profile for _, profile in ranked)


def john_run_dir(john_bin: str) -> Optional[Path]:
    """Locate the John run directory from a binary, directory, PATH, or project tree."""
    candidate = Path(john_bin).expanduser()
    if candidate.exists():
        if candidate.is_dir():
            nested = candidate / "run"
            if (nested / "john.exe").exists() or (nested / "john").exists():
                return nested
            return candidate
        return candidate.parent

    resolved = shutil.which(john_bin)
    if resolved:
        return Path(resolved).parent

    project_run = Path(__file__).resolve().parents[2] / "tools" / "john" / "run"
    if (project_run / "john.exe").exists() or (project_run / "john").exists():
        return project_run
    return None


def discover_converters(john_bin: str) -> dict[str, list[Path]]:
    """Return bundled converter paths grouped by converter stem."""
    run_dir = john_run_dir(john_bin)
    if run_dir is None or not run_dir.is_dir():
        return {}
    converters: dict[str, list[Path]] = {}
    for path in sorted(run_dir.glob("*2john*")):
        if not path.is_file() or path.suffix.lower() not in CONVERTER_SUFFIXES:
            continue
        converters.setdefault(path.stem, []).append(path)
    return converters


def resolve_converter(profile: ConversionProfile, john_bin: str) -> Optional[Path]:
    """Resolve the best available converter for a profile."""
    run_dir = john_run_dir(john_bin)
    if run_dir is None or not run_dir.is_dir():
        return None
    requested = Path(profile.converter)
    exact = run_dir / requested.name
    if exact.is_file():
        return exact
    stem = requested.stem.lower()
    candidates = [
        path
        for path in run_dir.glob(f"{glob_escape(stem)}.*")
        if path.is_file()
        and path.suffix.lower() in CONVERTER_SUFFIXES
        and path.stem.lower() == stem
    ]
    order = {suffix: index for index, suffix in enumerate(CONVERTER_SUFFIXES)}
    candidates.sort(key=lambda path: order.get(path.suffix.lower(), 99))
    return candidates[0] if candidates else None


def glob_escape(value: str) -> str:
    """Escape glob metacharacters in a converter stem."""
    translation = str.maketrans({"*": "[*]", "?": "[?]", "[": "[[]"})
    return value.translate(translation)


@lru_cache(maxsize=1)
def _python2_command() -> Optional[tuple[str, ...]]:
    launcher = shutil.which("py")
    candidates: list[tuple[str, ...]] = []
    if launcher:
        candidates.append((launcher, "-2"))
    python2 = shutil.which("python2")
    if python2:
        candidates.append((python2,))
    for command in candidates:
        try:
            completed = subprocess.run(
                [*command, "-c", "import sys"],
                capture_output=True,
                timeout=5,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0:
            return command
    return None


def _python3_can_parse(path: Path) -> bool:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            ast.parse(source)
    except (OSError, SyntaxError, ValueError):
        return False
    return True


def resolve_runtime(
    converter_path: Path,
    *,
    python_bin: str = "",
) -> tuple[tuple[str, ...], str, str]:
    """Return the interpreter prefix, runtime label, and failure reason."""
    suffix = converter_path.suffix.lower()
    if suffix == ".exe":
        return (), "native", ""
    if suffix == ".py":
        interpreter = python_bin or sys.executable
        if python_bin or _python3_can_parse(converter_path):
            if PY3_COMPAT_RUNNER.is_file():
                return (
                    (interpreter, str(PY3_COMPAT_RUNNER)),
                    "python",
                    "",
                )
            return (interpreter,), "python", ""
        python2 = _python2_command()
        if python2:
            return python2, "python2", ""
        return (), "python", (
            "requires Python 2; the script does not parse under Python 3 "
            "and no Python 2 runtime was found"
        )
    if suffix == ".pl":
        perl = shutil.which("perl")
        if perl:
            return (perl,), "perl", ""
        return (), "perl", "Perl executable not found on PATH"
    if suffix == ".js":
        node = shutil.which("node")
        if node:
            return (node,), "node", ""
        return (), "node", "Node.js executable not found on PATH"
    if suffix == ".lua":
        lua = shutil.which("lua")
        if lua:
            return (lua,), "lua", ""
        return (), "lua", "Lua executable not found on PATH"
    return (), "unknown", f"unsupported converter runtime: {converter_path.suffix}"


def profile_availability(
    profile: ConversionProfile,
    john_bin: str,
    *,
    python_bin: str = "",
) -> ConverterAvailability:
    """Resolve converter and runtime availability for a profile."""
    converter_path = resolve_converter(profile, john_bin)
    if converter_path is None:
        run_dir = john_run_dir(john_bin)
        location = str(run_dir) if run_dir else john_bin
        return ConverterAvailability(
            profile=profile,
            converter_path=None,
            runtime="missing",
            available=False,
            reason=f"converter not found in {location}",
        )
    _, runtime, reason = resolve_runtime(converter_path, python_bin=python_bin)
    return ConverterAvailability(
        profile=profile,
        converter_path=converter_path,
        runtime=runtime,
        available=not reason,
        reason=reason,
    )


def gallery_rows(
    john_bin: str,
    *,
    query: str = "",
    python_bin: str = "",
) -> tuple[GalleryRow, ...]:
    """Return display rows for the filtered conversion gallery."""
    rows = []
    for profile in filter_profiles(query):
        availability = profile_availability(
            profile, john_bin, python_bin=python_bin
        )
        converter_name = (
            availability.converter_path.name
            if availability.converter_path
            else profile.converter
        )
        rows.append(
            GalleryRow(
                profile=profile,
                converter_name=converter_name,
                runtime=availability.runtime,
                available=availability.available,
                reason=availability.reason,
            )
        )
    return tuple(rows)


def parse_converter_output(output: str) -> list[str]:
    """Extract John-compatible hash lines from converter output."""
    hashes: list[str] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith(
            ("warning", "error", "usage", "version", "ver ", "using ")
        ):
            continue
        if "$" not in line and not re.search(r":[0-9a-fA-F]{16,}", line):
            continue
        if line in seen:
            continue
        seen.add(line)
        hashes.append(line)
    return hashes


def convert_with_profile(
    profile: ConversionProfile | str,
    file_path: str | Path,
    john_bin: str = "john",
    *,
    python_bin: str = "",
    timeout: int = 120,
) -> ConversionResult:
    """Run one selected John converter and return extracted hash strings."""
    selected = get_profile(profile) if isinstance(profile, str) else profile
    if selected is None:
        return ConversionResult(
            source_file=str(file_path),
            success=False,
            error=f"Unknown John conversion profile: {profile}",
        )
    path = Path(file_path).resolve()
    if not path.exists():
        return ConversionResult(
            source_file=str(path),
            success=False,
            error=f"File not found: {path}",
        )
    availability = profile_availability(
        selected, john_bin, python_bin=python_bin
    )
    if not availability.available or availability.converter_path is None:
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=selected.key,
            error=(
                f"Converter unavailable for {selected.key}: "
                f"{availability.reason or 'unknown runtime error'}"
            ),
        )
    runtime_prefix, _, runtime_error = resolve_runtime(
        availability.converter_path, python_bin=python_bin
    )
    if runtime_error:
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=selected.key,
            error=f"Converter unavailable for {selected.key}: {runtime_error}",
        )
    command = [
        *runtime_prefix,
        str(availability.converter_path),
        str(path),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=selected.key,
            error=f"Converter timed out after {timeout}s.",
        )
    except OSError as exc:
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=selected.key,
            error=f"Converter failed to start: {exc}",
        )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    hash_lines = parse_converter_output(stdout)
    if not hash_lines:
        detail = (stderr or stdout or "Converter returned no output.").strip()
        return ConversionResult(
            source_file=str(path),
            success=False,
            format_detected=selected.key,
            error=detail[:1000],
        )
    extracted = [
        ExtractedHash(
            raw_hash=line,
            source_file=str(path),
            format_hint=selected.key,
            tool_used=availability.converter_path.stem,
            hashcat_mode=selected.hashcat_mode,
            john_format=selected.john_format or None,
            notes=list(selected.notes),
        )
        for line in hash_lines
    ]
    return ConversionResult(
        source_file=str(path),
        success=True,
        hashes=extracted,
        format_detected=selected.key,
    )


def _quote_command_part(part: str) -> str:
    if not part or any(character.isspace() for character in part):
        return f'"{part}"'
    return part


def build_john_command(
    profile: ConversionProfile,
    hash_path: str | Path,
    wordlist_path: str | Path | None = None,
    *,
    rules: bool = True,
    session: str | None = None,
) -> str:
    """Build a suggested John invocation for an extracted hash file."""
    parts = ["john"]
    if profile.john_format:
        parts.append(f"--format={profile.john_format}")
    if wordlist_path:
        parts.append(f"--wordlist={wordlist_path}")
    if rules:
        parts.append("--rules")
    if session:
        parts.append(f"--session={session}")
    parts.append(str(hash_path))
    return " ".join(_quote_command_part(part) for part in parts)


def build_john_show_command(
    profile: ConversionProfile,
    hash_path: str | Path,
) -> str:
    """Build a suggested John --show invocation."""
    parts = ["john", "--show"]
    if profile.john_format:
        parts.append(f"--format={profile.john_format}")
    parts.append(str(hash_path))
    return " ".join(_quote_command_part(part) for part in parts)


def build_hashcat_command(
    profile: ConversionProfile,
    hash_path: str | Path,
    wordlist_path: str | Path,
) -> str:
    """Build a suggested hashcat invocation when a mode is known."""
    if not profile.hashcat_mode:
        return ""
    parts = ["hashcat", "-m", str(profile.hashcat_mode)]
    parts.extend(["-a", "0", str(hash_path), str(wordlist_path)])
    return " ".join(_quote_command_part(part) for part in parts)


def available_profile_keys(
    john_bin: str,
    *,
    python_bin: str = "",
) -> set[str]:
    """Return keys for profiles whose converter and runtime are available."""
    return {
        row.profile.key
        for row in gallery_rows(john_bin, python_bin=python_bin)
        if row.available
    }
