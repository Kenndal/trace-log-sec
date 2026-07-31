"""Every custom exception raised by this project, kept in one place.

Modules that need one of these import it from here rather than defining
their own local exception class, so the full set of project-specific error
types has a single, obvious home.
"""

from __future__ import annotations

from pathlib import Path


class TraceLogSecError(Exception):
    """Base class for every custom exception raised by this project."""


class ConfigError(TraceLogSecError):
    """Raised when the YAML config at a given path can't be read or is invalid."""

    def __init__(self, path: str | Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"invalid config at {path!r}: {reason}")


class MalformedLineError(TraceLogSecError):
    """Raised by a parser when a line cannot be parsed."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RuleConfigError(TraceLogSecError):
    """Raised when a rule spec, constructor argument, or preset name is invalid."""


class CliInputError(TraceLogSecError):
    """Raised when CLI-supplied arguments (e.g. log file paths) fail validation."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ReportError(TraceLogSecError):
    """Raised when an HTML report can't be written to disk.

    Wraps the underlying ``OSError`` (e.g. permission denied, unwritable
    output directory) so callers get one consistent, informative failure type
    — mirroring how ``ConfigError`` normalizes config-load failures.
    """

    def __init__(self, path: str | Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"could not write report to {path!r}: {reason}")
