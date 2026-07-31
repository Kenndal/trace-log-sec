"""Data models dedicated to :mod:`engine.parsers`.

Log entries are frozen/immutable value objects (safe to share across rules).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class AuthOutcome(Enum):
    """Single-valued classification of an auth.log message."""

    FAILURE = "failure"
    INVALID_USER = "invalid_user"
    SUCCESS = "success"
    OTHER = "other"


@dataclass(frozen=True, kw_only=True)
class LogEntry:
    """Base for every parsed line.

    Rules and the correlator rely only on the normalized ``timestamp`` and
    ``source_ip`` present here.
    """

    timestamp: datetime
    source: str
    raw: str
    line_no: int
    source_ip: str | None = None


@dataclass(frozen=True, kw_only=True)
class WebLogEntry(LogEntry):
    """A parsed NCSA Combined access-log line.

    ``target`` is the request target exactly as sent — path *and* query string
    (e.g. ``/search?q=' OR 1=1``). Use the ``path``/``query`` convenience
    properties to split it.
    """

    method: str | None = None
    target: str | None = None
    protocol: str | None = None
    status: int | None = None
    size: int = 0
    identity: str | None = None
    user: str | None = None
    referrer: str | None = None
    user_agent: str | None = None

    def _split_target(self) -> tuple[str | None, str | None]:
        """Split target into (path, query). Returns (target, None) if no query string."""
        if self.target is None:
            return None, None
        parts = self.target.split("?", 1)
        return parts[0], parts[1] if len(parts) > 1 else None

    @property
    def path(self) -> str | None:
        """The request target without its query string."""
        path, _ = self._split_target()
        return path

    @property
    def query(self) -> str | None:
        """The query string (without the leading ``?``), or ``None``."""
        _, query = self._split_target()
        return query


@dataclass(frozen=True, kw_only=True)
class AuthLogEntry(LogEntry):
    """A parsed BSD-syslog auth.log line."""

    hostname: str | None = None
    process: str | None = None
    pid: int | None = None
    message: str = ""
    outcome: AuthOutcome = AuthOutcome.OTHER
    username: str | None = None
    source_port: int | None = None


@dataclass(frozen=True, kw_only=True)
class ParseError:
    """A structured parse failure — collected, never raised out of the engine.

    ``line_no = 0`` denotes a source-level failure (e.g. a missing file) rather
    than a single bad line.
    """

    source: str
    line_no: int
    raw: str
    reason: str
