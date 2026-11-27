"""
HashVault deep-analysis pipeline — CyberChef-style encoding layer detection.

Public API
----------
from hashvault.analysis import (
    # Main entry points
    analyze_input,          # Full pipeline (unwrap + identify + DB log)
    quick_detect,           # Lightweight: describe encoding of text
    list_operations,        # List all registered operations by category

    # Recipe engine
    unpack_layers,          # Recursively peel encoding layers
    AnalysisTrace,          # Result of unpack_layers()
    Layer,                  # One decoded layer in a trace

    # Magic detector
    detect,                 # Rank all ops by confidence for a given text
    best_operation,         # Best single op for a given text
    describe_text,          # Human-readable summary of detected encoding

    # Operations
    OPERATIONS,             # Tuple of all Operation instances
    OPERATION_BY_NAME,      # Dict[name, Operation]
    OPERATIONS_BY_CATEGORY, # Dict[category, List[Operation]]

    # Result types
    AnalysisResult,         # Full pipeline result
    OperationCandidate,     # (operation, score) pair from magic detector
)

CyberChef categories implemented
---------------------------------
  Data format       : Base64, Base32, Base58, Base85, Base62, Hex, Binary,
                      Octal, Charcode, Decimal, UTF-16, Morse, JWT,
                      QuotedPrintable, URLDecode, HTMLEntities,
                      UnicodeEscape, RawUnescape
  Encryption/Enc.   : ROT13, ROT47, Atbash, XOR (brute), Bacon, Affine
  Compression       : Gzip, Bzip2, LZMA, Zlib, DeflateRaw
  Hashing           : HashDetector (stop-signal)
  Forensics         : ExtractHash, StripWhitespace, RemoveNullBytes, Defang
  Extractors        : ExtractBase64, ExtractJWTPayload, ExtractIP,
                      ExtractEmails, ExtractURLs, ExtractMAC
"""

from hashvault.analysis.analyzer import (
    AnalysisHandoff,
    AnalysisResult,
    BranchAnalysis,
    analyze_input,
    list_operation_contracts,
    list_operations,
    prepare_input,
    quick_detect,
)
from hashvault.analysis.magic import (
    OperationCandidate,
    best_operation,
    describe_text,
    detect,
)
from hashvault.analysis.operations import (
    OPERATION_BY_NAME,
    OPERATIONS,
    OPERATIONS_BY_CATEGORY,
    Operation,
    OperationResult,
)
from hashvault.analysis.recipe import AnalysisTrace, Layer, unpack_layers
from hashvault.analysis.search import (
    AnalysisListener,
    AnalysisNode,
    DiscoveryResult,
    SearchConfig,
    discover_layers,
    discover_trace,
)
from hashvault.analysis.validators import (
    InputProfile,
    extract_hash_tokens,
    is_terminal_hash,
    profile_input,
    terminal_confidence,
)

__all__ = [
    # Main pipeline
    "analyze_input",
    "prepare_input",
    "quick_detect",
    "list_operations",
    "list_operation_contracts",
    # Search
    "discover_layers",
    "discover_trace",
    "SearchConfig",
    "AnalysisNode",
    "DiscoveryResult",
    "AnalysisListener",
    # Recipe
    "unpack_layers",
    "AnalysisTrace",
    "Layer",
    # Magic
    "detect",
    "best_operation",
    "describe_text",
    "OperationCandidate",
    # Operations
    "Operation",
    "OperationResult",
    "OPERATIONS",
    "OPERATION_BY_NAME",
    "OPERATIONS_BY_CATEGORY",
    # Validators
    "InputProfile",
    "profile_input",
    "is_terminal_hash",
    "terminal_confidence",
    "extract_hash_tokens",
    # Results
    "AnalysisResult",
    "AnalysisHandoff",
    "BranchAnalysis",
]
