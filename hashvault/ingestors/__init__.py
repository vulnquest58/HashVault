"""
HashVault Ingestors — File-to-hash extraction pipeline.

Converts encrypted files from their native container format into a hash string
that hashcat/John can ingest.  Each ingestor wraps a specific extractor tool
(john2zip, zip2john, rar2john, office2john, keepass2john, pdf2john, etc.)
and returns a unified ExtractedHash result.
"""

from hashvault.ingestors.converters import (
    ExtractedHash,
    ConversionResult,
    FileIngestor,
    convert_file,
    detect_file_type,
    SUPPORTED_EXTENSIONS,
)
from hashvault.ingestors.john_catalog import (
    PROFILES,
    ConversionProfile,
    ConverterAvailability,
    GalleryRow,
    available_profile_keys,
    build_hashcat_command,
    build_john_command,
    build_john_show_command,
    convert_with_profile,
    discover_converters,
    filter_profiles,
    find_profiles_for_path,
    gallery_rows,
    get_profile,
    profile_availability,
    resolve_converter,
)

__all__ = [
    "ExtractedHash",
    "ConversionResult",
    "FileIngestor",
    "convert_file",
    "detect_file_type",
    "SUPPORTED_EXTENSIONS",
    "PROFILES",
    "ConversionProfile",
    "ConverterAvailability",
    "GalleryRow",
    "available_profile_keys",
    "build_hashcat_command",
    "build_john_command",
    "build_john_show_command",
    "convert_with_profile",
    "discover_converters",
    "filter_profiles",
    "find_profiles_for_path",
    "gallery_rows",
    "get_profile",
    "profile_availability",
    "resolve_converter",
]
