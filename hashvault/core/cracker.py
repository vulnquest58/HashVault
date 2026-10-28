"""
Execution engine for external hash cracking tools (Hashcat and John the Ripper).
Enforces session isolation (sessions/<uuid>/), parameter sanitization, and safe subprocess execution (shell=False).
"""
import logging
import os
import re
import shutil
import stat
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4

from hashvault.config import Config
from hashvault.exceptions import CrackTimeoutError, SessionError, ToolNotFoundError
from hashvault.models.orm import CrackSession, Pattern
from hashvault.models.schemas import PatternSchema

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKABCDHF]|\x1b\][^\x07]*\x07|\x1b[\[\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><~]')

def _strip_ansi(text: str) -> str:
    """Remove ANSI terminal escape codes from a string."""
    return _ANSI_RE.sub('', text)


# Markers that mean "the engine could not run the attack", as opposed to
# "the wordlist was exhausted".  A bare substring search for "error" produced
# false positives (any path or hash containing that word), which made AUTO
# replay the same search with every other engine for no benefit.
_ENGINE_ERROR_MARKERS = (
    "no hashes loaded",
    "no password hashes loaded",
    "token length exception",
    "separator unmatched",
    "unknown hash-type",
    "unknown ciphertext format",
    "no devices found",
    "no opencl platforms found",
    "cannot use device",
    "device not found",
    "invalid device",
    "failed to initialize",
    "clbuildprogram",
    "clcreatecontext",
    "insufficient memory",
    "out of memory",
    "cuda sdk toolkit",
    "salt-value exception",
    "hash-encoding exception",
    "line-length exception",
    "signature unmatched",
    "argument expected",
    "invalid argument",
    "not enough arguments",
    "must be specified",
)

_DEVICE_ERROR_MARKERS = (
    "no devices found",
    "no opencl platforms found",
    "cannot use device",
    "failed to initialize",
    "clbuildprogram",
    "clcreatecontext",
    "out of memory",
    "device not found",
    "invalid device",
    "backend-ignore-cuda",
    "cuda sdk toolkit",
    "insufficient memory",
)


def _looks_like_device_error(output: str) -> bool:
    """Return True when hashcat output indicates a compute-backend failure."""
    low = _strip_ansi(output or "").lower()
    return any(marker in low for marker in _DEVICE_ERROR_MARKERS)


# John prints "plaintext<2+ spaces>(username)".  ``[^()]*`` keeps usernames
# that contain spaces working, and a lazy plaintext group preserves colons.
_JOHN_CRACKED_RE = re.compile(r"^(?P<plaintext>.*?)\s{2,}\((?P<user>[^()]*)\)\s*$")


def _looks_like_engine_error(output: str) -> bool:
    """Return True when the output reports a tool/format failure."""
    low = _strip_ansi(output or "").lower()
    return any(marker in low for marker in _ENGINE_ERROR_MARKERS)


def _restrict_permissions(path: Path) -> None:
    """Make an artifact readable/writable by the owner only (best effort)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - Windows ACLs / read-only mounts
        pass


def read_plaintext_from_outfile(outfile_path: str | Path) -> Optional[str]:
    """Return the last non-empty plaintext line from a session outfile.

    ``--outfile-format 2`` writes plaintext only (one per line), so the whole
    line is the password and must never be split on ':'.
    """
    path = Path(outfile_path)
    if not path.exists() or path.stat().st_size == 0:
        return None
    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return None
    lines = [line for line in content.splitlines() if line.strip()]
    return lines[-1].strip() if lines else None


def _plaintext_from_show_output(output: str, target_hash: str) -> Optional[str]:
    """Parse ``john --show`` output into a plaintext.

    John emits ``ciphertext:plaintext``.  Some hash formats contain ':' inside
    the ciphertext (NetNTLM, PostgreSQL, Oracle), so splitting on every colon
    and taking field 1 returned garbage.  The cracked value is known here, so
    strip that exact prefix first and only fall back to a single split.
    """
    target = (target_hash or "").strip()
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Skip the trailing "N password hash cracked" summary.
        if line[0].isdigit():
            continue
        if target and line.startswith(target + ":"):
            value = line[len(target) + 1:].strip()
        elif ":" in line:
            value = line.split(":", 1)[1].strip()
        else:
            continue
        if value:
            return value
    return None


def release_session_artifacts(
    session: CrackSession,
    *,
    keep: bool = False,
) -> list[Path]:
    """Delete the potfile and hash file of a finished session.

    Every attempt leaves ``target.hash``, ``hashcat.pot`` and ``out.txt`` on
    disk, and the potfile/outfile contain the recovered plaintext.  The value
    is already persisted in the database by the caller, so keeping copies is
    pure exposure.  Set ``keep=True`` (``strategy.keep_session_artifacts``) to
    retain them for debugging.
    """
    if keep:
        return []

    session_dir = Path(session.outfile_path).parent
    removed: list[Path] = []
    for name in ("hashcat.pot", "john.pot", "target.hash", "out.txt"):
        candidate = session_dir / name
        try:
            if candidate.is_file():
                candidate.unlink()
                removed.append(candidate)
        except OSError as exc:  # pragma: no cover - file locked by another process
            logger.debug("Could not remove %s: %s", candidate, exc)
    return removed


def purge_session_dirs(
    sessions_dir: str | Path,
    *,
    dry_run: bool = False,
    min_age_seconds: float = 0.0,
) -> list[Path]:
    """Remove session directories created by HashVault.

    Only directories whose name is a UUID are considered, so unrelated files a
    user keeps in ``sessions/`` are never deleted.  ``min_age_seconds`` keeps
    recent directories (``--older-than-days``), and ``dry_run`` returns the
    candidates without touching the filesystem.
    """
    root = Path(sessions_dir)
    if not root.is_dir():
        return []
    cutoff = time.time() - min_age_seconds if min_age_seconds > 0 else None
    removed: list[Path] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        try:
            UUID(entry.name)
        except ValueError:
            continue
        if cutoff is not None:
            try:
                if entry.stat().st_mtime > cutoff:
                    continue
            except OSError:
                continue
        removed.append(entry)
        if dry_run:
            continue
        try:
            shutil.rmtree(entry, ignore_errors=False)
        except OSError as exc:  # pragma: no cover - locked file
            logger.warning("Could not purge %s: %s", entry, exc)
            removed.pop()
    return removed

from hashvault.utils.system import detect_gpu, find_executable

logger = logging.getLogger("hashvault.cracker")


@dataclass
class CrackResult:
    success: bool
    session_id: str
    plaintext: str | None = None
    stdout: str = ""
    stderr: str = ""
    error_message: str | None = None
    # True when the engine could not run the attack correctly (missing binary,
    # bad mode/format, unsupported input, subprocess failure).  A normal
    # exhausted wordlist leaves this False so AUTO mode does not repeat the
    # same search with every other engine.
    engine_error: bool = False


def create_crack_session(
    sessions_dir: str | Path,
    *,
    target_hash: Optional[str] = None,
    pattern_id: Optional[int] = None,
    tool_used: Optional[str] = None,
) -> CrackSession:
    """
    Create an isolated session record and dedicated output directory.
    Prevents potfile lock conflicts across concurrent cracking runs.

    ``target_hash``/``pattern_id``/``tool_used`` are persisted on the session
    row; without them ``hashvault sessions`` displayed empty columns for every
    run, because nothing ever populated them.
    """
    session_id = str(uuid4())
    s_dir = Path(sessions_dir) / session_id
    s_dir.mkdir(parents=True, exist_ok=True)

    outfile = s_dir / "out.txt"
    potfile = s_dir / "hashcat.pot"

    return CrackSession(
        session_id=session_id,
        started_at=datetime.now(timezone.utc),
        hashes_processed=1,
        cracked_count=0,
        outfile_path=str(outfile.resolve()),
        potfile_path=str(potfile.resolve()),
        status="running",
        target_hash=target_hash,
        pattern_id=pattern_id,
        tool_used=tool_used,
    )


def compute_timeout(pattern: Pattern | PatternSchema, config: Config) -> int:
    """Determine operational execution timeout based on hash complexity (is_slow)."""
    if pattern.is_slow:
        return config.timeouts.slow_hash_seconds
    return config.timeouts.fast_hash_seconds


class BaseCracker(ABC):
    """Abstract base cracker execution wrapper."""

    @abstractmethod
    def crack(
        self,
        hash_value: str,
        pattern: Pattern | PatternSchema,
        wordlist_path: str | Path,
        session: CrackSession,
        rule_path: str | Path | None = None,
        *,
        attack_mode: str = "dictionary",
        mask: str | None = None,
        use_username: bool | None = None,
        timeout_seconds: int | None = None,
        max_candidates: int | None = None,
    ) -> CrackResult:
        pass


class HashcatCracker(BaseCracker):
    """Hashcat execution implementation using safe subprocess lists."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def crack(
        self,
        hash_value: str,
        pattern: Pattern | PatternSchema,
        wordlist_path: str | Path,
        session: CrackSession,
        rule_path: str | Path | None = None,
        *,
        attack_mode: str = "dictionary",
        mask: str | None = None,
        use_username: bool | None = None,
        timeout_seconds: int | None = None,
        max_candidates: int | None = None,
    ) -> CrackResult:
        if pattern.hashcat_mode is None:
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Pattern '{pattern.name}' has no hashcat_mode defined.",
                engine_error=True,
            )

        try:
            binary = find_executable("hashcat", self.config.paths.hashcat_bin)
        except ToolNotFoundError as e:
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=str(e),
                engine_error=True,
            )

        # Write target hash to a temporary file in session directory
        session_dir = Path(session.outfile_path).parent
        session_dir.mkdir(parents=True, exist_ok=True)
        target_hash_file = session_dir / "target.hash"
        target_hash_file.write_text(hash_value, encoding="utf-8")
        _restrict_permissions(target_hash_file)

        if attack_mode not in ("mask", "hybrid") and not Path(wordlist_path).exists():
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Wordlist not found: {wordlist_path}",
                engine_error=True,
            )
        if attack_mode in ("mask", "hybrid") and not mask:
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message="Mask attack requested without a mask.",
                engine_error=True,
            )

        backend = getattr(self.config.strategy, "hashcat_backend", "auto")
        gpu_info = detect_gpu(
            binary,
            self.config.timeouts.gpu_detection_seconds,
            backend=backend,
        )

        # --username tells hashcat to discard the field before the first ':'.
        # The pipeline canonicalizer emits either a bare hash or a hash whose
        # colon-delimited fields are part of the algorithm (NetNTLM, PostgreSQL
        # mode 12, Oracle), so enabling it automatically corrupts those inputs.
        # Callers that deliberately pass ``user:hash`` can opt in explicitly.
        if use_username is None:
            use_username = False

        workload = int(getattr(self.config.strategy, "hashcat_workload_profile", 0) or 0)

        def build_cmd(device_flag: str) -> list[str]:
            cmd = [
                binary,
                "-m",
                str(pattern.hashcat_mode),
                "--outfile",
                session.outfile_path,
                "--outfile-format",
                "2",
                "--potfile-path",
                session.potfile_path,
                "--quiet",
                "--hwmon-disable",
            ]
            if workload:
                cmd.extend(["-w", str(workload)])
            if device_flag:
                cmd.extend(device_flag.split())
            if use_username:
                cmd.append("--username")
            if attack_mode == "mask":
                cmd.extend(["-a", "3", str(target_hash_file.resolve()), mask or ""])
            elif attack_mode == "hybrid":
                cmd.extend([
                    "-a", "6",
                    str(target_hash_file.resolve()),
                    str(Path(wordlist_path).resolve()),
                    mask or "",
                ])
            else:
                cmd.extend([
                    "-a", "0",
                    str(target_hash_file.resolve()),
                    str(Path(wordlist_path).resolve()),
                ])
            if rule_path and Path(rule_path).exists():
                cmd.extend(["-r", str(Path(rule_path).resolve())])
            return cmd

        timeout_sec = timeout_seconds or compute_timeout(pattern, self.config)
        bin_path = Path(binary)

        def execute(device_flag: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                build_cmd(device_flag),
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                shell=False,  # MANDATORY SECURITY RULE
                cwd=str(bin_path.parent) if bin_path.is_file() else None,
            )

        try:
            logger.info(
                "Executing Hashcat session %s (mode=%s, backend=%s, timeout=%ss)...",
                session.session_id,
                attack_mode,
                gpu_info.backend,
                timeout_sec,
            )
            proc = execute(gpu_info.device_flag)

            # If the selected backend is unusable, retry once with the portable
            # OpenCL path.  hashcat 6.2.6 does not ship a CPU backend unless an
            # OpenCL CPU runtime is installed, so "-D 1" is *not* a safe
            # fallback here -- --backend-ignore-cuda is.
            if (
                proc.returncode != 0
                and _looks_like_device_error(proc.stdout + proc.stderr)
            ):
                if "--backend-ignore-cuda" not in (gpu_info.device_flag or ""):
                    logger.warning(
                        "Hashcat device backend failed; retrying session %s via OpenCL.",
                        session.session_id,
                    )
                    proc = execute("-D 2 --backend-ignore-cuda")

            # Check for results in isolated session outfile.
            # --outfile-format 2 writes *plaintext only* (one per line), so the
            # whole line is the password -- never split on ':'.
            plaintext = read_plaintext_from_outfile(session.outfile_path)

            if plaintext:
                session.cracked_count = 1
                session.status = "completed"
                session.finished_at = datetime.now(timezone.utc)
                return CrackResult(
                    success=True,
                    session_id=session.session_id,
                    plaintext=plaintext,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                )

            session.status = "completed"
            session.finished_at = datetime.now(timezone.utc)
            err_msg = "Hash not cracked by dictionary/rules/mask."
            combined = _strip_ansi((proc.stdout or "") + "\n" + (proc.stderr or ""))
            engine_error = _looks_like_engine_error(combined)
            if engine_error:
                # Surface the first line that actually carries the failure.
                for line in combined.splitlines():
                    clean = line.strip()
                    if clean and _looks_like_engine_error(clean):
                        err_msg = clean
                        break
            return CrackResult(
                success=False,
                session_id=session.session_id,
                stdout=proc.stdout,
                stderr=proc.stderr,
                error_message=err_msg,
                engine_error=engine_error,
            )

        except subprocess.TimeoutExpired:
            session.status = "timeout"
            session.finished_at = datetime.now(timezone.utc)
            logger.warning(f"Hashcat execution timed out for session {session.session_id}")
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Cracking operation timed out after {timeout_sec} seconds.",
            )
        except Exception as e:
            session.status = "failed"
            session.finished_at = datetime.now(timezone.utc)
            logger.error(f"Execution error in Hashcat session {session.session_id}: {e}")
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Subprocess error: {e}",
                engine_error=True,
            )


class JohnCracker(BaseCracker):
    """John the Ripper execution implementation using safe subprocess lists."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def crack(
        self,
        hash_value: str,
        pattern: Pattern | PatternSchema,
        wordlist_path: str | Path,
        session: CrackSession,
        rule_path: str | Path | None = None,
        *,
        attack_mode: str = "dictionary",
        mask: str | None = None,
        use_username: bool | None = None,
        timeout_seconds: int | None = None,
        max_candidates: int | None = None,
    ) -> CrackResult:
        if pattern.john_format is None:
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Pattern '{pattern.name}' has no john_format defined.",
                engine_error=True,
            )

        try:
            binary = find_executable("john", self.config.paths.john_bin)
        except ToolNotFoundError as e:
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=str(e),
                engine_error=True,
            )

        session_dir = Path(session.outfile_path).parent
        session_dir.mkdir(parents=True, exist_ok=True)
        target_hash_file = session_dir / "target.hash"
        target_hash_file.write_text(hash_value, encoding="utf-8")
        _restrict_permissions(target_hash_file)

        cmd = [
            binary,
            f"--format={pattern.john_format}",
            f"--pot={session.potfile_path}",
        ]
        if attack_mode in ("mask", "hybrid") and mask:
            cmd.append(f"--mask={mask}")
        else:
            if not Path(wordlist_path).exists():
                return CrackResult(
                    success=False,
                    session_id=session.session_id,
                    error_message=f"Wordlist not found: {wordlist_path}",
                    engine_error=True,
                )
            cmd.append(f"--wordlist={Path(wordlist_path).resolve()}")

        cmd.append(str(target_hash_file.resolve()))

        if rule_path and Path(rule_path).exists():
            cmd.append(f"--rules={Path(rule_path).resolve()}")

        timeout_sec = timeout_seconds or compute_timeout(pattern, self.config)

        try:
            logger.info(f"Executing John session {session.session_id} (timeout={timeout_sec}s)...")
            bin_path = Path(binary)
            bin_cwd = str(bin_path.parent) if bin_path.is_file() else None
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                shell=False,
                cwd=bin_cwd,
            )

            logger.debug(f"John stdout: {proc.stdout[:500]!r}")
            logger.debug(f"John stderr: {proc.stderr[:500]!r}")

            # --- Layer 1: parse John's live output (stdout + stderr) ---
            # John prints cracked passwords as: "plaintext   (username)"
            # On Windows, this may appear in stderr instead of stdout.
            # Parsing is delegated to a module-level regex so a plaintext that
            # contains ':' or an embedded double space is preserved intact.
            plaintext = None
            combined_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            for line in combined_output.splitlines():
                stripped = line.strip()
                match = _JOHN_CRACKED_RE.match(stripped)
                if match and match.group("plaintext"):
                    plaintext = match.group("plaintext")
                    break

            # --- Layer 2: --show potfile query (session pot only; never the
            # user's global potfile, which would leak results across sessions) ---
            if not plaintext:
                show_cmd = [
                    binary,
                    f"--format={pattern.john_format}",
                    f"--pot={session.potfile_path}",
                    "--show",
                    str(target_hash_file.resolve()),
                ]
                show_proc = subprocess.run(
                    show_cmd, capture_output=True, text=True, timeout=10,
                    shell=False, cwd=bin_cwd,
                )
                logger.debug(f"John --show stdout: {show_proc.stdout[:300]!r}")
                plaintext = _plaintext_from_show_output(
                    show_proc.stdout, hash_value
                )

            if plaintext:
                session.cracked_count = 1
                session.status = "completed"
                session.finished_at = datetime.now(timezone.utc)
                # Write to outfile for session persistence consistency
                Path(session.outfile_path).write_text(f"{plaintext}\n", encoding="utf-8")
                return CrackResult(
                    success=True,
                    session_id=session.session_id,
                    plaintext=plaintext,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                )

            session.status = "completed"
            session.finished_at = datetime.now(timezone.utc)
            engine_error = _looks_like_engine_error(combined_output)
            return CrackResult(
                success=False,
                session_id=session.session_id,
                stdout=proc.stdout,
                stderr=proc.stderr,
                error_message="Hash not cracked by John.",
                engine_error=engine_error,
            )

        except subprocess.TimeoutExpired:
            session.status = "timeout"
            session.finished_at = datetime.now(timezone.utc)
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"John execution timed out after {timeout_sec}s.",
            )
        except Exception as e:
            session.status = "failed"
            session.finished_at = datetime.now(timezone.utc)
            return CrackResult(
                success=False,
                session_id=session.session_id,
                error_message=f"Subprocess error: {e}",
                engine_error=True,
            )
