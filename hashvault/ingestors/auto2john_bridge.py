"""Bridge between the official auto2john engine and HashVault profiles.

The standalone auto2john project owns a focused detection and tool-resolution
engine. HashVault keeps its own larger John conversion gallery, so this module
maps an auto2john detection to a HashVault profile and uses it as a ranking
hint without replacing the existing gallery or converter store.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from hashvault.auto2john import AmbiguousFormat, Auto2JohnError, detect_profile
from hashvault.ingestors.john_catalog import ConversionProfile, get_profile

_AUTO2JOHN_KEY_ALIASES = {
    "applenotes": "notes",
    "androidbackup": "android-backup",
}


def preferred_profile(path: Path) -> ConversionProfile | None:
    """Return the HashVault profile suggested by auto2john, if any."""
    try:
        detection = detect_profile(path)
    except (AmbiguousFormat, Auto2JohnError, OSError):
        return None
    key = _AUTO2JOHN_KEY_ALIASES.get(detection.profile.key, detection.profile.key)
    return get_profile(key)


def rank_with_auto2john(
    path: Path,
    candidates: Sequence[ConversionProfile],
) -> list[ConversionProfile]:
    """Put an auto2john-detected profile first without dropping other candidates."""
    preferred = preferred_profile(path)
    if preferred is None:
        return list(candidates)
    ranked = [preferred]
    ranked.extend(profile for profile in candidates if profile.key != preferred.key)
    return ranked
