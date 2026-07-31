"""Command-line interface for trace-log-sec."""

from __future__ import annotations

from cli import commands as _commands  # noqa: F401  (import for registration side effect)
from cli.app import app

__all__ = ["app"]
