"""Shared Typer application instance.

Kept free of command logic and imports from ``cli.commands`` so that command
modules can import ``app`` from here without creating an import cycle. See
``cli/__init__.py`` for how commands get registered onto this instance.
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
import typer._completion_shared as _typer_completion_shared
import typer.completion as _typer_completion

app = typer.Typer()


def _detect_shell_with_env_fallback() -> str | None:
    """Detect the current shell for ``--show-completion``/``--install-completion``.

    Tries ``shellingham``'s process-tree walk first (the Typer default), then
    falls back to the basename of ``$SHELL``. The process-tree walk can fail
    in non-interactive/sandboxed execution contexts (e.g. each command run as
    a fresh subprocess rather than an attached interactive shell) even though
    ``$SHELL`` is set correctly.
    """
    name = _typer_get_shell_name()
    if name:
        return name
    return Path(os.environ.get("SHELL", "")).name or None


# Both `typer.completion` and `typer._completion_shared` bind their own
# reference to this function at import time, so both must be patched.
_typer_get_shell_name = _typer_completion_shared._get_shell_name
_typer_completion._get_shell_name = _detect_shell_with_env_fallback  # type: ignore[attr-defined]  # ty: ignore[invalid-assignment]
_typer_completion_shared._get_shell_name = _detect_shell_with_env_fallback  # ty: ignore[invalid-assignment]


@app.callback()
def _main() -> None:
    """trace-log-sec: parse web/auth logs, detect suspicious activity, and correlate incidents."""
