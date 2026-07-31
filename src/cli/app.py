"""Shared Typer application instance.

Kept free of command logic and imports from ``cli.commands`` so that command
modules can import ``app`` from here without creating an import cycle. See
``cli/__init__.py`` for how commands get registered onto this instance.
"""

from __future__ import annotations

import typer

app = typer.Typer()


@app.callback()
def _main() -> None:
    """trace-log-sec: parse web/auth logs, detect suspicious activity, and correlate incidents."""
