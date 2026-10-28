"""
System diagnostics and external tool detection utilities for HashVault.
Handles hashcat/john binary checking and GPU device detection with safe CPU fallback.
"""
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from hashvault.exceptions import ToolNotFoundError

logger = logging.getLogger("hashvault.system")


@dataclass
class GPUInfo:
    available: bool
    device_flag: str
    details: str = ""
    backend: str = "auto"


def find_executable(tool_name: str, custom_path: str | None = None) -> str:
    """
    Locate an executable binary via custom path or system PATH.
    Raises ToolNotFoundError if binary cannot be resolved.

    Resolution order is deterministic: an explicit custom path wins, then the
    bundled ``tools/<name>`` tree, then ``PATH``.  Binaries found inside the
    bundled tree must resolve to a file that lives inside that tree, so a
    symlink or an odd layout cannot redirect execution elsewhere.
    """
    if custom_path:
        p = Path(custom_path)
        if p.exists() and p.is_file():
            return str(p.resolve())
        resolved = shutil.which(custom_path)
        if resolved:
            return resolved
        raise ToolNotFoundError(tool_name, custom_path)

    # Fallback check inside local tools directory
    project_root = Path(__file__).resolve().parent.parent.parent
    local_tool_dir = project_root / "tools" / tool_name
    if local_tool_dir.is_dir():
        tool_dir = local_tool_dir.resolve()
        # Deterministic order: the canonical binary name first, then a sorted
        # scan.  ``glob`` order is filesystem-dependent, which previously made
        # the selected binary vary between machines.
        candidates: list[Path] = []
        for pattern in (f"{tool_name}.exe", f"{tool_name}", "*.exe"):
            candidates.extend(tool_dir.rglob(pattern))
        for exe in sorted(candidates, key=lambda item: (len(item.parts), str(item))):
            if not exe.is_file():
                continue
            try:
                resolved_exe = exe.resolve()
                resolved_exe.relative_to(tool_dir)
            except (OSError, ValueError):
                logger.warning("Ignoring %s: resolves outside %s", exe, tool_dir)
                continue
            return str(resolved_exe)

    resolved = shutil.which(tool_name)
    if resolved:
        return resolved

    raise ToolNotFoundError(tool_name, custom_path)


_GPU_TYPE_RE = re.compile(r"Type\s*\.*\s*:\s*GPU", re.IGNORECASE)
_CUDA_BROKEN_MARKERS = (
    "cuda sdk toolkit not installed",
    "failed to initialize nvidia rtc",
    "cuda sdk toolkit required",
)


def _run_device_probe(binary_path: str, timeout_seconds: int, ignore_cuda: bool) -> str:
    cmd = [binary_path, "-I"]
    if ignore_cuda:
        cmd.append("--backend-ignore-cuda")
    b_path = Path(binary_path)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        shell=False,
        cwd=str(b_path.parent) if b_path.is_file() else None,
    )
    return (result.stdout or "") + "\n" + (result.stderr or "")


@lru_cache(maxsize=16)
def _probe_gpu_cached(binary_path: str, timeout_seconds: int, backend: str) -> GPUInfo:
    """Cached hashcat backend probe.

    Probing is expensive (hashcat initialises every compute backend), so the
    result is memoised for the lifetime of the process.  By default we probe
    with ``--backend-ignore-cuda``: a broken/missing CUDA toolkit makes every
    hashcat invocation spend ~30 seconds falling back to OpenCL, which dwarfs
    the actual cracking time for fast hashes.
    """
    backend = (backend or "auto").lower()
    if backend == "cpu":
        return GPUInfo(False, "-D 1", "CPU backend requested", "cpu")

    errors: list[str] = []
    attempts: list[tuple[bool, bool]] = []
    if backend == "cuda":
        attempts = [(False, True), (True, False)]
    else:
        attempts = [(True, False)]

    for ignore_cuda, allow_cuda in attempts:
        try:
            output = _run_device_probe(binary_path, timeout_seconds, ignore_cuda)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            errors.append(str(exc))
            continue

        lower = output.lower()
        has_gpu = bool(_GPU_TYPE_RE.search(output))
        cuda_broken = any(marker in lower for marker in _CUDA_BROKEN_MARKERS)
        if has_gpu and allow_cuda and cuda_broken:
            # CUDA was explicitly requested but cannot initialise; retry OpenCL.
            errors.append("CUDA backend unavailable; falling back to OpenCL")
            continue
        if has_gpu:
            flag = "-D 2"
            if ignore_cuda or cuda_broken:
                flag += " --backend-ignore-cuda"
            mode = "opencl" if ignore_cuda or cuda_broken else "cuda"
            logger.info("GPU acceleration detected for hashcat (%s).", mode)
            return GPUInfo(True, flag, output[:500], mode)

        # A previous attempt may have simply found no CUDA devices; try OpenCL.
        if allow_cuda and not ignore_cuda:
            errors.append("No CUDA device reported")
            continue

    details = "\n".join(errors)[:500] or "No GPU device reported by hashcat"
    logger.info("No usable GPU detected by hashcat. Using CPU-only (-D 1).")
    return GPUInfo(False, "-D 1", details, "cpu")


def detect_gpu(
    hashcat_bin: str = "hashcat",
    timeout_seconds: int = 15,
    backend: str = "auto",
) -> GPUInfo:
    """
    Query hashcat device info (``-I``) to check for available GPU acceleration.

    Results are cached per (binary, timeout, backend).  Returns a ``GPUInfo``
    whose ``device_flag`` can be appended verbatim to a hashcat command line;
    the safe fallback is ``-D 1`` (CPU-only).
    """
    try:
        binary_path = find_executable("hashcat", hashcat_bin)
    except (FileNotFoundError, ToolNotFoundError) as exc:
        logger.warning("GPU detection skipped: %s", exc)
        return GPUInfo(False, "-D 1", str(exc), "cpu")

    try:
        return _probe_gpu_cached(binary_path, timeout_seconds, backend)
    except Exception as exc:  # defensive: never break cracking because of probing
        logger.warning("GPU detection failed (%s). Falling back to CPU-only.", exc)
        return GPUInfo(False, "-D 1", str(exc), "cpu")


def clear_gpu_cache() -> None:
    """Clear the memoised backend probe (used by tests/config reloads)."""
    _probe_gpu_cached.cache_clear()


def verify_system_environment(hashcat_bin: str, john_bin: str) -> dict[str, bool]:
    """Verify presence of hashcat and john binaries."""
    status = {}
    try:
        find_executable("hashcat", hashcat_bin)
        status["hashcat"] = True
    except ToolNotFoundError:
        status["hashcat"] = False

    try:
        find_executable("john", john_bin)
        status["john"] = True
    except ToolNotFoundError:
        status["john"] = False

    return status
