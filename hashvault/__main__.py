"""HashVault v2.0 main application entry point.

Launches the interactive shell when invoked without CLI arguments, or
dispatches to the Typer CLI otherwise.
"""

import sys


def _enable_windows_ansi() -> None:
    """Enable ANSI processing and UTF-8 output on Windows consoles."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        import ctypes.wintypes
        import io

        kernel32 = ctypes.windll.kernel32

        kernel32.SetConsoleOutputCP(65001)
        kernel32.SetConsoleCP(65001)

        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.wintypes.DWORD()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)

        if hasattr(sys.stdout, "buffer") and sys.stdout.encoding.lower() != "utf-8":
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
            )
        if hasattr(sys.stderr, "buffer") and sys.stderr.encoding.lower() != "utf-8":
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
            )

    except Exception:
        pass


_enable_windows_ansi()


from hashvault.cli import app  # noqa: E402
from hashvault.config import load_config  # noqa: E402
from hashvault.core.database import init_db, resolve_resource_path  # noqa: E402
from hashvault.ui.interactive import start_interactive_shell  # noqa: E402


def main() -> None:
    if len(sys.argv) == 1:
        config = load_config()
        init_db(
            config.paths.database,
            seed_patterns_path=str(
                resolve_resource_path("data/patterns/patterns.json")
            ),
        )
        start_interactive_shell(config)
    else:
        app()


if __name__ == "__main__":
    main()
