# hashvault/core/registry.py
"""
Central registry for all enumerations in HashVault.
Single source of truth for all limited-choice values.
"""

from enum import Enum
from typing import Dict


class HashCategory(str, Enum):
    """Major hash categories - used in --hint and patterns.category."""
    WINDOWS = "windows"
    LINUX_UNIX = "linux_unix"
    KERBEROS = "kerberos"
    WEB_APP = "web_app"
    DATABASE = "database"
    NETWORK_AUTH = "network_auth"
    ARCHIVE = "archive"
    CRYPTO_WALLET = "crypto_wallet"
    VPN_CERT = "vpn_cert"
    RAW_GENERIC = "raw_generic"
    CONTAINER_ENCRYPTION = "container_encryption"
    DOCUMENT_ENCRYPTION = "document_encryption"


class SourceFormat(str, Enum):
    """Extraction formats - used in --format."""
    PWDUMP = "pwdump"
    SECRETSDUMP = "secretsdump"
    SHADOW = "shadow"
    RESPONDER_NTLMV2 = "responder_ntlmv2"
    RESPONDER_NTLMV1 = "responder_ntlmv1"
    PLAIN_LIST = "plain_list"
    HASHCAT_JOHN_LIST = "hashcat_john_list"
    CACHEDUMP = "cachedump"
    LSASS_DUMP = "lsass_dump"
    KEEPASS = "keepass"
    OFFICE_DOC = "office_doc"
    ZIP_ARCHIVE = "zip"
    RAR_ARCHIVE = "rar"
    SEVEN_ZIP = "7z"
    WINGFTP = "wingftp"
    NTDS_DIT = "ntds_dit"
    AUTO_DETECT = "auto"


class CrackTool(str, Enum):
    """Cracking tools supported."""
    HASHCAT = "hashcat"
    JOHN = "john"
    BUILTIN = "builtin"
    AUTO = "auto"


class OutputFormat(str, Enum):
    """Output formats supported."""
    TABLE = "table"
    JSON = "json"
    CSV = "csv"


class SessionStatus(str, Enum):
    """Session status values."""
    RUNNING = "running"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    FAILED = "failed"


class ResolutionMethod(str, Enum):
    """Methods used for hash identification resolution."""
    PREFIX = "prefix"
    SINGLE_MATCH = "single_match"
    CONFIDENCE_MARGIN = "confidence_margin"
    SOURCE_CONTEXT = "source_context"
    EMPIRICAL_TRIAL = "empirical_trial"
    AMBIGUOUS = "ambiguous"


# Descriptions for display purposes
CATEGORY_DESCRIPTIONS: Dict[HashCategory, str] = {
    HashCategory.WINDOWS: "Windows authentication (NTLM, LM, MSCache/DCC)",
    HashCategory.LINUX_UNIX: "Linux/Unix shadow passwords (crypt variants)",
    HashCategory.KERBEROS: "Kerberos authentication tickets (Kerberoast/ASREPRoast)",
    HashCategory.WEB_APP: "Web application hashes (WordPress, Drupal, Django, JWT, etc.)",
    HashCategory.DATABASE: "Database credentials (MySQL, PostgreSQL, MSSQL, Oracle, etc.)",
    HashCategory.NETWORK_AUTH: "Network authentication (NetNTLM, WPA, RADIUS, Cisco, VoIP)",
    HashCategory.ARCHIVE: "Compressed archive passwords (ZIP, RAR, 7z, PKZIP)",
    HashCategory.CRYPTO_WALLET: "Cryptocurrency wallet passwords (Bitcoin, Ethereum, Electrum, Blockchain.info)",
    HashCategory.VPN_CERT: "VPN / IPSec pre-shared-key and appliance credentials",
    HashCategory.RAW_GENERIC: "Raw generic hashes without context (MD5, SHA1, SHA2/3, GOST, etc.)",
    HashCategory.CONTAINER_ENCRYPTION: (
        "Encrypted disk/volume/credential containers "
        "(LUKS, VeraCrypt/TrueCrypt, FileVault2/APFS, DPAPI masterkey, "
        "KeePass 1/2/4, Password Safe v3, 1Password, Apple Secure Notes)"
    ),
    HashCategory.DOCUMENT_ENCRYPTION: (
        "Encrypted office documents and PDFs (MS Office 97-365, PDF Acrobat 5-11)"
    ),
}

FORMAT_DESCRIPTIONS: Dict[SourceFormat, str] = {
    SourceFormat.PWDUMP: "Classic pwdump format (LM:NTLM)",
    SourceFormat.SECRETSDUMP: "Impacket secretsdump.py -ntds output",
    SourceFormat.SHADOW: "/etc/shadow file format",
    SourceFormat.RESPONDER_NTLMV2: "NetNTLMv2 captures from Responder",
    SourceFormat.RESPONDER_NTLMV1: "NetNTLMv1 captures from Responder",
    SourceFormat.PLAIN_LIST: "Plain hash list, one per line",
    SourceFormat.HASHCAT_JOHN_LIST: "Hashcat/John compatible hash list",
    SourceFormat.CACHEDUMP: "Windows Cached Domain Credentials (MSCache)",
    SourceFormat.LSASS_DUMP: "LSASS process memory dump",
    SourceFormat.KEEPASS: "KeePass KDB/KDBX encrypted database",
    SourceFormat.OFFICE_DOC: "Encrypted documents (docx/xlsx/pptx/pdf)",
    SourceFormat.ZIP_ARCHIVE: "ZIP archive encryption",
    SourceFormat.RAR_ARCHIVE: "RAR archive encryption",
    SourceFormat.SEVEN_ZIP: "7-Zip archive encryption",
    SourceFormat.WINGFTP: "WingFTP Server SHA-256 credential format",
    SourceFormat.NTDS_DIT: "NTDS.dit domain database dump",
    SourceFormat.AUTO_DETECT: "Auto-detect format using identifier",
}

TOOL_DESCRIPTIONS: Dict[CrackTool, str] = {
    CrackTool.HASHCAT: "hashcat - world's fastest password cracker",
    CrackTool.JOHN: "John the Ripper - password security auditing tool",
    CrackTool.BUILTIN: "Built-in pure-Python engine (no external dependencies)",
    CrackTool.AUTO: "Auto-select best tool based on hash type",
}
