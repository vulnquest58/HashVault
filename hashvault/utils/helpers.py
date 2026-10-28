"""
General helper functions for HashVault v2.0.
Provides path security validation, hash masking for sensitive history logging, and formatting tools.
"""
from pathlib import Path
from hashvault.exceptions import ConfigError


def validate_safe_path(path: str | Path, base_dir: str | Path) -> Path:
    """
    Resolve and validate that target path remains safely enclosed within base_dir.
    Prevents path traversal vulnerabilities.
    """
    resolved_target = Path(path).resolve()
    resolved_base = Path(base_dir).resolve()

    try:
        resolved_target.relative_to(resolved_base)
    except ValueError:
        raise ConfigError(f"Security error: Path '{path}' attempts path traversal outside '{base_dir}'")

    return resolved_target


def mask_sensitive_hash(raw_hash: str) -> str:
    """
    Mask raw sensitive hashes or passwords for sanitized interactive shell history logging.
    Example: '5f4dcc3b5aa765d61d8327deb882cf99' -> '5f4dcc3b...'
    """
    text = raw_hash.strip()
    if len(text) <= 8:
        return text
    return f"{text[:8]}..."


def sanitize_cmd_args(args: list[str]) -> list[str]:
    """Sanitize raw interactive arguments for prompt_toolkit command history recording."""
    sanitized = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            sanitized.append(mask_sensitive_hash(arg))
            skip_next = False
            continue

        if arg in ("crack", "identify", "check") and i == len(args) - 2:
            sanitized.append(arg)
        elif not arg.startswith("-") and i > 0 and args[i-1] in ("crack", "identify", "check"):
            sanitized.append(mask_sensitive_hash(arg))
        else:
            sanitized.append(arg)

    return sanitized
