"""Unified automatic file-to-hash conversion.

``convert_file`` handles HashVault's built-in extractors.  ``john_catalog``
handles the much larger set of helpers shipped with John the Ripper.  This
module combines both behind one predictable entry point:

1. honour an explicit profile/format,
2. rank John profiles by filename, directory markers, extension, and magic,
3. try available converters in that order,
4. fall back to the built-in extractor,
5. return every attempt so the CLI can explain what happened.
"""

from __future__ import annotations

from pathlib import Path

from hashvault.ingestors.auto2john_bridge import rank_with_auto2john
from hashvault.ingestors.converters import (
    SUPPORTED_EXTENSIONS,
    ConversionResult,
    convert_file,
    detect_file_type,
)
from hashvault.ingestors.john_catalog import (
    ConversionProfile,
    convert_with_profile,
    find_profiles_for_path,
    get_profile,
    profile_availability,
)


def _internal_conversion(
    path: Path,
    john_bin: str,
    format_override: str = "",
) -> ConversionResult:
    result = convert_file(path, john_bin=john_bin, format_override=format_override)
    if result.success and not result.profile:
        result.profile = result.format_detected
    return result


def _rank_candidates(
    path: Path,
    candidates: tuple[ConversionProfile, ...],
) -> list[ConversionProfile]:
    """Rank candidates by built-in magic, then by the auto2john detection hint."""
    if not candidates:
        return rank_with_auto2john(path, ())
    detected = detect_file_type(path)
    if not detected:
        return rank_with_auto2john(path, candidates)
    normalized = detected.lower()
    preferred: list[ConversionProfile] = []
    rest: list[ConversionProfile] = []
    for profile in candidates:
        formats = {fmt.lower() for fmt in profile.john_formats}
        if profile.key.lower() == normalized or normalized in formats:
            preferred.append(profile)
        else:
            rest.append(profile)
    return rank_with_auto2john(path, preferred + rest)


def convert_auto(
    file_path: str | Path,
    john_bin: str = "john",
    *,
    format_override: str = "",
    python_bin: str = "",
    timeout: int = 120,
) -> ConversionResult:
    """Convert a protected file using the best available converter.

    The result always contains ``attempts`` entries describing every converter
    that was considered.  A successful result sets ``profile`` to the selected
    conversion profile (or the built-in format name when no John profile ran).
    """
    path = Path(file_path).resolve()
    if not path.exists():
        return ConversionResult(
            source_file=str(path),
            success=False,
            error=f"File not found: {path}",
        )

    if format_override:
        selected = get_profile(format_override)
        if selected is not None:
            result = convert_with_profile(
                selected,
                path,
                john_bin=john_bin,
                python_bin=python_bin,
                timeout=timeout,
            )
            result.profile = selected.key
            result.attempts = [
                f"{selected.key}: {'success' if result.success else result.error or 'failed'}"
            ]
            return result
        result = _internal_conversion(path, john_bin, format_override)
        result.attempts = [
            f"{format_override}: {'success' if result.success else result.error or 'failed'}"
        ]
        return result

    candidates = _rank_candidates(path, find_profiles_for_path(path))
    attempts: list[str] = []
    last_error = ""
    for profile in candidates:
        availability = profile_availability(
            profile, john_bin, python_bin=python_bin
        )
        if not availability.available:
            attempts.append(
                f"{profile.key}: unavailable ({availability.reason or 'runtime missing'})"
            )
            last_error = availability.reason or "converter runtime unavailable"
            continue
        result = convert_with_profile(
            profile,
            path,
            john_bin=john_bin,
            python_bin=python_bin,
            timeout=timeout,
        )
        if result.success:
            result.profile = profile.key
            result.attempts = attempts + [f"{profile.key}: success"]
            return result
        attempts.append(f"{profile.key}: {result.error or 'failed'}")
        last_error = result.error or "converter returned no hashes"

    internal = _internal_conversion(path, john_bin)
    if internal.success:
        internal.attempts = attempts + [f"{internal.format_detected}: success"]
        return internal
    if internal.error:
        last_error = internal.error
    attempts.append(f"{internal.format_detected or 'builtin'}: {internal.error or 'failed'}")

    if candidates:
        hint = (
            "Tried: "
            + ", ".join(profile.key for profile in candidates)
            + ". Run `hashvault convert --gallery` for all profiles."
        )
    else:
        supported = ", ".join(sorted(set(SUPPORTED_EXTENSIONS.values())))
        hint = (
            "No John profile matched this path. "
            f"Built-in formats: {supported}. "
            "Run `hashvault convert --gallery` for the full list."
        )
    return ConversionResult(
        source_file=str(path),
        success=False,
        format_detected=internal.format_detected or "",
        error=f"{last_error or 'conversion failed'}\n{hint}",
        attempts=attempts,
    )
