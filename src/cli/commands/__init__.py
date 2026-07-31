"""Importing this package registers every subcommand on ``cli.app.app``."""

from __future__ import annotations

from cli.commands import analyze, list_reports  # noqa: F401  (import for registration side effect)

__all__ = ["analyze", "list_reports"]
