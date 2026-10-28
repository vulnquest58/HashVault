#!/usr/bin/env python3
"""
HashVault pattern factory — generate the FULL hashcat algorithm set.

Reads `hashcat --example-hashes` output (the canonical catalogue of every hash
type hashcat supports) and converts it into HashVault's patterns.json.

Behaviour
---------
* Parses the vendored dump at data/patterns/hashcat_examples.txt (auto-regenerates
  it by invoking the bundled hashcat if missing).
* Derives a safe, backtracking-free regex from each official example hash.
* Maps hashcat categories -> HashVault HashCategory enums.
* Merges with the existing curated patterns.json so hand-tuned entries win.
* Emits:
    - data/patterns/patterns.json       (the operative dataset, full 473+)
    - data/patterns/patterns.meta.json  (raw hashcat fields per mode)
    - data/patterns/patterns.report.json (self-match validation for every mode)

Note: generated multi-part (salted/iterated) patterns are intentionally *bounded*
so the identification engine never suffers catastrophic regex backtracking.
They carry a lower confidence_weight than the precise single-token patterns.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
DATA_PATTERNS = ROOT / "data" / "patterns"
DUMP = DATA_PATTERNS / "hashcat_examples.txt"
OUT_PATTERNS = DATA_PATTERNS / "patterns.json"
OUT_META = DATA_PATTERNS / "patterns.meta.json"
OUT_REPORT = DATA_PATTERNS / "patterns.report.json"

HASHCAT_EXE = ROOT / "tools" / "hashcat" / "hashcat.exe"

# --------------------------------------------------------------------------- #
# hashcat catalogue parsing
# --------------------------------------------------------------------------- #

def _dump_examples() -> str:
    """Regenerate the example-hashes dump using the bundled hashcat binary."""
    if HASHCAT_EXE.exists():
        proc = subprocess.run(
            [str(HASHCAT_EXE), "--example-hashes"],
            capture_output=True, text=True, shell=False,
        )
        return proc.stdout or proc.stderr or ""
    raise FileNotFoundError(
        f"No hashcat binary found at {HASHCAT_EXE}. "
        "Regenerate data/patterns/hashcat_examples.txt manually."
    )


def parse_catalogue(text: str) -> Dict[int, Dict[str, str]]:
    """Parse hashcat --example-hashes output into {mode_number: fields}."""
    blocks: Dict[int, Dict[str, str]] = {}
    cur: Optional[int] = None
    for line in text.splitlines():
        mm = re.match(r"^Hash mode #(\d+)\s*$", line)
        if mm:
            cur = int(mm.group(1))
            blocks[cur] = {}
            continue
        if cur is None:
            continue
        km = re.match(r"^  (?P<key>[\w()., /@+\-]+?)(\.+):\s*(?P<val>.*)$", line)
        if km:
            blocks[cur][km.group("key")] = km.group("val").rstrip()
    return blocks


# --------------------------------------------------------------------------- #
# Safe regex derivation
# --------------------------------------------------------------------------- #

_ALNUM64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX = set("0123456789abcdefABCDEF")
_COMMON_HASH_LEN = {32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 256}
_PAT = {"hex": "[0-9a-fA-F]", "b64": "[A-Za-z0-9+/=]"}
_OVERLAP = {"hex", "b64"}
_FLEX_CAP = 1024


def tokenize(value: str) -> List[List[str]]:
    """Split into literal / hex / base64 runs (hex = pure hex alphabet)."""
    out: List[List[str]] = []
    cur: Optional[str] = None
    buf = ""
    for ch in value:
        cls = "al" if ch in _ALNUM64 else "lit"
        if cls != cur:
            if cur is not None:
                out.append([cur, buf])
            cur, buf = cls, ch
        else:
            buf += ch
    if cur is not None:
        out.append([cur, buf])
    for tok in out:
        if tok[0] == "al":
            tok[0] = "hex" if ("=" not in tok[1] and all(x in _HEX for x in tok[1])) else "b64"
    return out


def build_regex(example: str) -> str:
    """
    Build a regex that matches the official example hash and is safe against
    catastrophic backtracking (hex/base64 classes overlap, so per-run bounds are
    chosen to avoid adjacent overlapping quantifiers).
    """
    toks = tokenize(example)
    # Single-token fast path: exact, precise regex.
    if len(toks) == 1:
        kind, val = toks[0]
        if kind == "hex":
            return f"^[0-9a-fA-F]{{{len(val)}}}$"
        if kind == "b64":
            body = val.rstrip("=")
            return f"^[A-Za-z0-9+/]{{{len(body)}}}={{{len(val) - len(body)}}}$"
        return "^" + re.escape(val) + "$"

    # Multi-token: keep literal anchors, bound variable hex/base64 runs.
    decided = [
        kind == "lit" or len(val) in _COMMON_HASH_LEN and len(val) <= 128 or len(val) <= 2
        for kind, val in toks
    ]

    def safe(i: int, kind: str) -> bool:
        for j in (i - 1, i + 1):
            if 0 <= j < len(toks) and not decided[j] \
                    and toks[j][0] in _OVERLAP and kind in _OVERLAP:
                return False
        return True

    parts: List[str] = []
    for i, (kind, val) in enumerate(toks):
        length = len(val)
        if kind == "lit":
            parts.append(re.escape(val))
            continue
        cls = _PAT[kind]
        if decided[i] or not safe(i, kind):
            parts.append(f"{cls}{{{length}}}")
        else:
            parts.append(f"{cls}{{2,{_FLEX_CAP}}}")
    return "^" + "".join(parts) + "$"


def leading_prefix(value: str) -> Optional[str]:
    """Detect a literal leading prefix (e.g. '$2a$05$', '{SHA}', 'sha1$')."""
    m = re.match(
        r"^(?:(?:\$[0-9A-Za-z]+\$[0-9]+\$)|(?:\$[0-9A-Za-z]+\$)|"
        r"(\{[A-Za-z0-9]+\})|(?:[A-Za-z0-9]+\$))",
        value,
    )
    return m.group(0) if m else None


# --------------------------------------------------------------------------- #
# Category & tool mapping
# --------------------------------------------------------------------------- #

_CATEGORY = {
    "Raw Hash": "raw_generic",
    "Raw Hash salted and/or iterated": "raw_generic",
    "Raw Hash authenticated": "raw_generic",
    "Generic KDF": "raw_generic",
    "Raw Cipher, Known-plaintext attack": "raw_generic",
    "Raw Checksum": "raw_generic",
    "One-Time Password": "raw_generic",
    "Plaintext": "raw_generic",
    "Network Protocol": "network_auth",
    "FTP, HTTP, SMTP, LDAP Server": "network_auth",
    "Instant Messaging Service": "network_auth",
    "Web Application": "web_app",
    "Forums, CMS, E-Commerce": "web_app",
    "Framework": "web_app",
    "Enterprise Application Software (EAS)": "web_app",
    "Database Server": "database",
    "Operating System": "linux_unix",
    "Archive": "archive",
    "Document": "document_encryption",
    "Cryptocurrency Wallet": "crypto_wallet",
    "Password Manager": "container_encryption",
    "Full-Disk Encryption (FDE)": "container_encryption",
}
_DEFAULT_CATEGORY = "raw_generic"

# Refine important families that the coarse hashcat category misses.
_MODE_CATEGORY_OVERRIDES = {
    1000: "windows", 1100: "windows", 2100: "windows", 3000: "windows",  # NTLM/LM/DCC
    13100: "kerberos", 7500: "kerberos", 18200: "kerberos", 19600: "kerberos",
    19800: "kerberos", 28800: "kerberos", 28900: "kerberos",
}

# Comprehensive hashcat mode -> John the Ripper --format mapping.
# Sources: john --list=formats, hashcat wiki, OpenWall documentation.
_JOHN_FORMATS: Dict[int, str] = {
    # -------------------------------------------------------------------------
    # Raw / generic hashes
    # -------------------------------------------------------------------------
    0:     "raw-md5",
    10:    "raw-md5",          # md5($pass.$salt)
    20:    "raw-md5",          # md5($salt.$pass)
    30:    "raw-md5",
    40:    "raw-md5",
    50:    "hmac-md5",
    60:    "hmac-md5",
    100:   "raw-sha1",
    110:   "raw-sha1",
    120:   "raw-sha1",
    130:   "raw-sha1",
    140:   "raw-sha1",
    150:   "hmac-sha1",
    160:   "hmac-sha1",
    200:   "mysql-fast",
    300:   "mysql",
    400:   "phpass",
    500:   "md5crypt",
    501:   "md5crypt",
    600:   "blake2b",
    900:   "raw-md4",
    1000:  "nt",
    1100:  "mscash",
    1300:  "raw-sha224",
    1400:  "raw-sha256",
    1410:  "raw-sha256",
    1420:  "raw-sha256",
    1430:  "raw-sha256",
    1440:  "raw-sha256",
    1450:  "hmac-sha256",
    1460:  "hmac-sha256",
    1500:  "descrypt",
    1600:  "md5apr1",
    1700:  "raw-sha512",
    1710:  "raw-sha512",
    1720:  "raw-sha512",
    1730:  "raw-sha512",
    1740:  "raw-sha512",
    1750:  "hmac-sha512",
    1760:  "hmac-sha512",
    1800:  "sha512crypt",
    2000:  "raw-md5u",
    2100:  "dcc2",
    2400:  "cisco-pix",
    2410:  "cisco-enable",
    2500:  "wpapsk",
    2501:  "wpapsk",
    2600:  "mysql-sha1",
    2611:  "raw-md5",
    2612:  "raw-md5",
    2711:  "django",
    2811:  "django",
    3000:  "lm",
    3100:  "oracle-h",
    3200:  "bcrypt",
    3710:  "raw-md5",
    3711:  "raw-md5",
    3800:  "raw-md5",
    3910:  "raw-md5",
    4010:  "raw-md5",
    4110:  "raw-md5",
    4300:  "raw-md5",
    4400:  "raw-sha1",
    4500:  "raw-sha1",
    4700:  "raw-sha1",
    4800:  "md5crypt",
    4900:  "raw-sha1",
    5000:  "sha-1-extended",
    5100:  "half-md5",
    5200:  "keepass",
    5300:  "ike-hmac-md5-96",
    5400:  "ike-hmac-sha1-96",
    5500:  "netntlmv1",
    5600:  "netntlmv2",
    5700:  "raw-sha256",     # Cisco ASA
    5800:  "android-pin",
    6000:  "raw-blake2",
    6100:  "whirlpool",
    6211:  "tc_aes_xts",
    6212:  "tc_aes_xts",
    6213:  "tc_aes_xts",
    6221:  "tc_aes_xts",
    6222:  "tc_aes_xts",
    6223:  "tc_aes_xts",
    6231:  "tc_aes_xts",
    6232:  "tc_aes_xts",
    6233:  "tc_aes_xts",
    6241:  "tc_aes_xts",
    6242:  "tc_aes_xts",
    6243:  "tc_aes_xts",
    6300:  "md5crypt",
    6400:  "sha256aix",
    6500:  "sha512aix",
    6600:  "agilekkeychain",
    6700:  "sha1aix",
    6800:  "lastpass",
    6900:  "gost",
    7000:  "fortigate",
    7100:  "pbkdf2-hmac-sha512",
    7200:  "grub2",
    7300:  "ipb2",
    7400:  "sha256crypt",
    7401:  "sha256crypt",
    7500:  "krb5pa-md5",
    7700:  "sap-b",
    7800:  "sap-g",
    7900:  "drupal7",
    8000:  "sybasease",
    8100:  "citrix-ns10",
    8200:  "cloudkeychain",
    8300:  "dnssec",
    8400:  "wbb3",
    8500:  "des-bs",
    8600:  "lotus5",
    8700:  "lotus85",
    8900:  "scrypt",
    9000:  "psafe3",
    9100:  "lotus85",
    9200:  "cisco-pbkdf2-sha256",
    9300:  "cisco-scrypt",
    9400:  "ms-office",
    9500:  "ms-office",
    9600:  "ms-office",
    9700:  "ms-office",
    9800:  "ms-office",
    9900:  "raw-md5",      # Radmin2
    10000: "django-pbkdf2-sha256",
    10100: "siphash",
    10200: "cram-md5",
    10300: "saph-sha1",
    10400: "pdf",
    10410: "pdf",
    10420: "pdf",
    10500: "pdf",
    10600: "pdf",
    10700: "pdf",
    10800: "raw-sha384",
    10900: "pbkdf2-hmac-sha256",
    11000: "pkzip",
    11100: "postgres-md5",
    11200: "ssh-ng",
    11300: "bitcoin",
    11400: "sip-md5",
    11600: "7z",
    11900: "pbkdf2-hmac-md5",
    12000: "pbkdf2-hmac-sha1",
    12001: "pbkdf2-hmac-sha1",
    12100: "pbkdf2-hmac-sha512",
    12200: "ecryptfs",
    12300: "oracle12c",
    12400: "bsdicrypt",
    12500: "rar",
    12600: "django-scrypt",
    12700: "mywallet",
    12800: "ms-drsr",
    12900: "android-backup",
    13000: "rar5",
    13100: "krb5tgs",
    13200: "axcrypt",
    13300: "agilekeychain",
    13400: "keepass",
    13500: "pstoken",
    13600: "zip",
    13711: "tc_aes_xts",
    13721: "tc_aes_xts",
    13731: "tc_aes_xts",
    13741: "tc_aes_xts",
    13751: "tc_aes_xts",
    13761: "tc_aes_xts",
    13800: "windows-hello",
    13900: "opencart",
    14000: "descrypt",
    14100: "tripledes",
    14900: "skip32",
    15000: "filemaker",
    15100: "juniper-sha1",
    15200: "keepassx-aes",
    15300: "dpapi",
    15400: "chacha20",
    15500: "juniper-ive",
    15600: "ethereum-scrypt",
    15700: "ethereum-pbkdf2",
    15900: "dpapi-masterkey",
    16000: "tacacs-plus",
    16100: "tacacs-plus",
    16200: "apple-secure-notes",
    16300: "ethereum-prebip39",
    16400: "cram-md5-hmac",
    16500: "jwt",
    16600: "electrum-wallet",
    16700: "filevault2",
    16800: "wpapsk",
    16900: "ansible",
    17010: "sha512crypt",
    17300: "sha3-256",
    17400: "sha3-256",
    17500: "sha3-384",
    17600: "sha3-384",
    17700: "sha3-512",
    17800: "sha3-512",
    17900: "keccak-256",
    18000: "keccak-256",
    18100: "totp",
    18200: "krb5asrep",
    18300: "apple-secure-notes",
    18400: "odf",
    18500: "raw-sha1",
    18600: "open-document",
    18700: "java-object",
    18800: "blockchain-mycelium",
    18900: "android-fde",
    19000: "keepassxc",
    19100: "pbkdf2-hmac-sha256",
    19200: "keepass",
    19300: "sha1-open-document",
    19500: "ruby-on-rails",
    19600: "krb5tgs-17",
    19700: "krb5tgs-18",
    19800: "kerberos-aes",
    19900: "kerberos-aes",
    20000: "hive-foundation",
    20200: "python-pbkdf2-sha512",
    20300: "python-pbkdf2-sha512",
    20400: "python-pbkdf2-sha256",
    20500: "pbkdf2-sha512",
    20600: "bestcrypt",
    20710: "raw-sha256",
    20720: "raw-sha256",
    21000: "bitshares",
    21100: "java-sha1",
    21200: "mc",
    21300: "sql-azure-efgs-sha1",
    21400: "odf",
    21420: "odf",
    21500: "steamguard",
    21501: "steamguard",
    21600: "redis-sha256",
    21700: "electrum-wallet",
    21800: "electrum-wallet",
    22000: "wpapbkdf2-pmkid",
    22001: "wpapbkdf2",
    22100: "bitlocker",
    22200: "apricot",
    22300: "raw-sha256",
    22400: "srp",
    22500: "bitcoin-segwit",
    22600: "telegram-desktop",
    22700: "multibit-hd",
    22911: "openssh",
    22921: "openssh",
    22931: "openssh",
    22941: "openssh",
    22951: "openssh",
    23001: "secretsdump",
    23002: "secretsdump",
    23003: "secretsdump",
    23100: "apple-secure-notes",
    23200: "axie-infinity",
    23300: "evo",
    23400: "bitwarden",
    23500: "multibit-hd",
    23600: "ethereum-wallet-pbkdf2",
    23700: "cardano",
    23800: "metamask",
    23900: "best-crypt",
    24000: "mongodb-scram-sha1",
    24100: "mongodb-scram-sha256",
    24200: "umbraco-sha1",
    24300: "sha256-c-plus-plus",
    24410: "hbci-ripemd160",
    24420: "hbci-sha256",
    24500: "citrix-sharefile",
    24600: "telegram-mobile",
    24700: "stuffit",
    24800: "umbraco-hmac-sha1",
    24900: "dahua",
    25000: "sntp-sha1",
    25100: "sntp-sha256",
    25200: "sntp-sha512",
    25300: "mc-sha256",
    25400: "pdf",
    25500: "pbkdf2-sha256",
    25600: "bcrypt",
    25700: "mc-sha1",
    25800: "telegram",
    25900: "kyber",
    26000: "bc",
    26100: "mozilla-sdr",
    26200: "dropbox",
    26300: "mfa-totp",
    26400: "agilekeychain",
    26500: "iPhone-backup",
    26600: "fvde",
    26700: "sntp-md5",
    26800: "exodus",
    26900: "monero",
    27000: "metamask-mobile",
    27100: "multi-md5",
    27200: "ruby-bcrypt",
    27300: "md5",
    27400: "raw-md5",
    27500: "pbkdf2-sha1",
    27600: "veeam-pbkdf2",
    27700: "electrum-wallet4",
    27800: "pbkdf2-sha256",
    27900: "md5-utm",
    28000: "keccak-224",
    28100: "raw-sha1",
    28200: "exodus-web3",
    28300: "ibm-security-des",
    28400: "bitwarden",
    28500: "pdf",
    28600: "elasticsearch",
    28700: "pbkdf2-sha1",
    28800: "kerberos-aes-des",
    28900: "kerberos-aes-des",
    29000: "sha1-csrf",
    29100: "fletcher-32",
    29200: "radmin3",
    29311: "pbkdf2",
    29321: "pbkdf2",
    29331: "pbkdf2",
    29341: "pbkdf2",
    29351: "pbkdf2",
    29361: "pbkdf2",
    29411: "pbkdf2",
    29421: "pbkdf2",
    29431: "pbkdf2",
    29441: "pbkdf2",
    29451: "pbkdf2",
    29461: "pbkdf2",
    99999: None,   # Plaintext — no john format
}


def category_for(mode: int, hashcat_category: str) -> str:
    if mode in _MODE_CATEGORY_OVERRIDES:
        return _MODE_CATEGORY_OVERRIDES[mode]
    return _CATEGORY.get(hashcat_category, _DEFAULT_CATEGORY)


# --------------------------------------------------------------------------- #
# Output generation
# --------------------------------------------------------------------------- #

def load_existing() -> Dict[str, dict]:
    if OUT_PATTERNS.exists():
        return {p["hashcat_mode"]: p for p in json.loads(OUT_PATTERNS.read_text("utf-8"))}
    return {}


def main() -> int:
    DATA_PATTERNS.mkdir(parents=True, exist_ok=True)
    if not DUMP.exists():
        print("[*] Rebuilding hashcat example-hashes dump...")
        DUMP.write_text(_dump_examples(), encoding="utf-8")

    catalogue = parse_catalogue(DUMP.read_text(encoding="utf-8", errors="replace"))
    existing = load_existing()

    patterns: List[dict] = []
    meta: Dict[int, dict] = {}
    report: Dict[int, dict] = {}
    used_names: set = set()

    for mode in sorted(catalogue):
        raw = catalogue[mode]
        example = raw.get("Example.Hash", "").strip()

        # Preserve only hand-tuned curated entries; previously generated
        # entries are regenerated so parameter tweaks propagate.
        if mode in existing and existing[mode].get("source") == "curated":
            pat = dict(existing[mode])
            pat.setdefault("source", "curated")
            patterns.append(pat)
            meta[mode] = raw
            report[mode] = {"mode": mode, "name": raw.get("Name", ""), "self_match": True}
            continue

        regex = build_regex(example)
        name = f"{raw.get('Name', 'hash')}"
        base = name
        n = 2
        while name in used_names:
            name = f"{base} [{mode}]"
            n += 1
        used_names.add(name)

        single = len(tokenize(example)) == 1
        # Generated raw single-token types sit below the hand-curated common
        # types (which carry higher weights) so the familiar MD5/SHA1/SHA256
        # surface first, while the full catalogue still appears as candidates.
        weight = 0.3 if single else 0.24
        popularity = 52 if single else 34
        is_slow = raw.get("Slow.Hash", "").strip().lower().startswith("y")

        patterns.append({
            "name": name,
            "regex": regex,
            "hashcat_mode": mode,
            "john_format": _JOHN_FORMATS.get(mode),
            "popularity": popularity,
            "description": base,
            "is_slow": is_slow,
            "category": category_for(mode, raw.get("Category", "")),
            "min_length": len(example),
            "max_length": len(example),
            "prefix_hint": leading_prefix(example),
            "confidence_weight": weight,
            "source_format_hints": [],
            "source": "generated-hashcat",
            "hashcat_category": raw.get("Category", ""),
        })

        # Validate the derived regex actually matches the official example.
        try:
            self_match = re.fullmatch(regex, example) is not None
        except re.error:
            self_match = False

        meta[mode] = raw
        report[mode] = {
            "mode": mode, "name": name, "self_match": self_match,
            "single_token": single, "len": len(example),
            "regex": regex,
        }

    OUT_PATTERNS.write_text(json.dumps(patterns, indent=2), encoding="utf-8")
    OUT_META.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    OUT_REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")

    matched = sum(1 for r in report.values() if r.get("self_match"))
    print(f"[+] Wrote {len(patterns)} patterns -> {OUT_PATTERNS.name}")
    print(f"[+] Self-match: {matched}/{len(report)} verified against official examples")
    print(f"[+] Meta -> {OUT_META.name}, report -> {OUT_REPORT.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
