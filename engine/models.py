"""Core data models for the log-analysis engine.

Log entries are frozen/immutable value objects (safe to share across rules).
``Finding``/``Incident`` are mutable aggregates the engine builds up during a
run, then hands off read-only to a downstream presenter.

See docs/engine-plan.md §4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .parsers import LogParser


class Severity(IntEnum):
    """Ordered severity — comparable so findings/incidents sort naturally."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        """Resolve a case-insensitive name (e.g. ``"high"``) to a member."""
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            valid = ", ".join(m.name.lower() for m in cls)
            raise ValueError(f"unknown severity {name!r}; expected one of {valid}") from exc


class AuthOutcome(Enum):
    """Single-valued classification of an auth.log message (§5)."""

    FAILURE = "failure"
    INVALID_USER = "invalid_user"
    SUCCESS = "success"
    OTHER = "other"


# --------------------------------------------------------------------------- #
# Log entries (frozen, keyword-only)
# --------------------------------------------------------------------------- #


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

    def _split_target(self) -> tuple[str, str | None]:
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


# --------------------------------------------------------------------------- #
# Aggregates
# --------------------------------------------------------------------------- #


@dataclass(kw_only=True)
class Finding:
    """A single detection result for one entity (IP), aggregated over a run."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    first_seen: datetime
    last_seen: datetime
    source_ip: str | None = None
    count: int = 1
    sources: set[str] = field(default_factory=set)
    evidence: list[LogEntry] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass(kw_only=True)
class Incident:
    """A correlated group of findings for one IP within a time window."""

    incident_id: str
    title: str
    severity: Severity
    source_ip: str | None
    first_seen: datetime
    last_seen: datetime
    findings: list[Finding] = field(default_factory=list)
    narrative: str = ""


# --------------------------------------------------------------------------- #
# Engine configuration and results
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, kw_only=True)
class LogSource:
    """A file to analyze paired with the parser that understands it."""

    path: str
    parser: LogParser


@dataclass(kw_only=True)
class AnalysisReport:
    """Plain result container handed to a downstream presenter."""

    findings: list[Finding] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    parse_errors: list[ParseError] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
