"""
Custom key bindings for HashVault interactive shell.
Properly handles Ctrl+C (KeyboardInterrupt) and Ctrl+D (EOFError / Exit).
"""
from prompt_toolkit.key_binding import KeyBindings

kb = KeyBindings()


@kb.add("c-c")
def handle_ctrl_c(event):  # type: ignore
    """Cancel the current input without leaving the interactive shell."""
    event.app.current_buffer.reset()


@kb.add("c-d")
def handle_ctrl_d(event):  # type: ignore
    """Exit session or raise EOFError on Ctrl+D when line is empty."""
    buff = event.app.current_buffer
    if not buff.text:
        event.app.exit(exception=EOFError)
    else:
        buff.delete()
