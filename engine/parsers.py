"""Log parsers.

Each parser is pure and side-effect free: ``parse_line`` turns one raw line
into a ``LogEntry`` or raises ``MalformedLineError``. ``parse_file`` wraps a
parser in a crash-proof generator that converts failures into ``ParseError``
records so a single bad line never aborts a run.

See docs/engine-plan.md §5.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    AuthLogEntry,
    AuthOutcome,
    LogEntry,
    ParseError,
    WebLogEntry,
)


class MalformedLineError(Exception):
    """Raised by a parser when a line cannot be parsed."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class LogParser(ABC):
    """Abstract parser: identifies its ``source`` and parses single lines."""

    source: str

    @abstractmethod
    def parse_line(self, line: str, line_no: int) -> LogEntry:
        """Parse one line into a ``LogEntry`` or raise ``MalformedLineError``."""


# --------------------------------------------------------------------------- #
# NCSA Combined access log
# --------------------------------------------------------------------------- #

_COMBINED_RE = re.compile(
    r"""^
    (?P<ip>\S+)\s+
    (?P<identity>\S+)\s+
    (?P<user>\S+)\s+
    \[(?P<time>[^\]]+)\]\s+
    "(?P<request>[^"]*)"\s+
    (?P<status>\d{3}|-)\s+
    (?P<size>\d+|-)
    (?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?   # Combined extras (optional)
    \s*$
    """,
    re.VERBOSE,
)

_COMBINED_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


class CombinedLogParser(LogParser):
    """Parses NCSA Common/Combined access-log lines."""

    source = "webserver"

    def __init__(self, source: str | None = None) -> None:
        if source is not None:
            self.source = source

    def parse_line(self, line: str, line_no: int) -> WebLogEntry:
        m = _COMBINED_RE.match(line.rstrip("\n"))
        if m is None:
            raise MalformedLineError("does not match Combined log format")

        try:
            timestamp = datetime.strptime(m.group("time"), _COMBINED_TIME_FMT)
        except ValueError as exc:
            raise MalformedLineError(f"bad timestamp: {exc}") from exc

        method, target, protocol = _split_request(m.group("request"))
        status_raw = m.group("status")
        size_raw = m.group("size")

        return WebLogEntry(
            timestamp=timestamp,
            source=self.source,
            raw=line.rstrip("\n"),
            line_no=line_no,
            source_ip=_dash_to_none(m.group("ip")),
            method=method,
            target=target,
            protocol=protocol,
            status=int(status_raw) if status_raw != "-" else None,
            size=int(size_raw) if size_raw != "-" else 0,
            identity=_dash_to_none(m.group("identity")),
            user=_dash_to_none(m.group("user")),
            referrer=m.group("referrer"),
            user_agent=m.group("agent"),
        )


def _split_request(request: str) -> tuple[str | None, str | None, str | None]:
    """Best-effort split of a request line into method/target/protocol.

    A garbage request inside an otherwise valid line is itself a signal, so we
    return whatever fields we can rather than failing the line.
    """
    parts = request.split()
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], None
    if len(parts) == 1:
        return parts[0], None, None
    if len(parts) > 3:
        # Unusual spacing in the target; keep method + protocol at the ends.
        return parts[0], " ".join(parts[1:-1]), parts[-1]
    return None, None, None


def _dash_to_none(value: str) -> str | None:
    return None if value == "-" else value


# --------------------------------------------------------------------------- #
# BSD syslog auth log
# --------------------------------------------------------------------------- #

_SYSLOG_RE = re.compile(
    r"""^
    (?P<month>[A-Z][a-z]{2})\s+
    (?P<day>\d{1,2})\s+
    (?P<time>\d{2}:\d{2}:\d{2})\s+
    (?P<host>\S+)\s+
    (?P<process>[^\[\s:]+)
    (?:\[(?P<pid>\d+)\])?
    :\s*
    (?P<message>.*)
    $
    """,
    re.VERBOSE,
)

_SYSLOG_TIME_FMT = "%Y %b %d %H:%M:%S"

# IP / port extraction, reused across outcome classifications.
_FROM_IP_RE = re.compile(r"\bfrom\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(?P<port>\d+))?")
_ANY_IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
_PORT_RE = re.compile(r"\bport\s+(?P<port>\d+)")
_INVALID_USER_RE = re.compile(r"invalid user\s+(?P<user>\S+)", re.IGNORECASE)
_FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user\s+)?(?P<user>\S+)\s+from", re.IGNORECASE
)
_ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+)\s+from", re.IGNORECASE
)


class SyslogAuthParser(LogParser):
    """Parses BSD-syslog auth.log lines, resolving the missing year (§5.1)."""

    source = "auth"

    def __init__(
        self,
        *,
        source: str | None = None,
        reference_time: datetime | None = None,
        default_year: int | None = None,
        tz: timezone = timezone.utc,
    ) -> None:
        if source is not None:
            self.source = source
        # BSD syslog carries no timezone; assume `tz` (UTC by default) so all
        # engine timestamps are tz-aware and comparable with web-log times.
        self._tz = tz
        ref = reference_time if reference_time is not None else datetime.now(tz)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=tz)
        self._reference_time = ref
        self._default_year = default_year

    def parse_line(self, line: str, line_no: int) -> AuthLogEntry:
        m = _SYSLOG_RE.match(line.rstrip("\n"))
        if m is None:
            raise MalformedLineError("does not match BSD syslog format")

        timestamp = self._resolve_timestamp(m.group("month"), m.group("day"), m.group("time"))
        message = m.group("message")
        outcome, username, source_ip, source_port = _classify_auth(message)
        pid_raw = m.group("pid")

        return AuthLogEntry(
            timestamp=timestamp,
            source=self.source,
            raw=line.rstrip("\n"),
            line_no=line_no,
            source_ip=source_ip,
            hostname=m.group("host"),
            process=m.group("process"),
            pid=int(pid_raw) if pid_raw else None,
            message=message,
            outcome=outcome,
            username=username,
            source_port=source_port,
        )

    def _resolve_timestamp(self, month: str, day: str, time: str) -> datetime:
        """Pick the year making ``(month, day, time)`` the most recent occurrence
        at or before ``reference_time`` (§5.1)."""
        if self._default_year is not None:
            try:
                dt = datetime.strptime(
                    f"{self._default_year} {month} {int(day):02d} {time}", _SYSLOG_TIME_FMT
                )
            except ValueError as exc:
                raise MalformedLineError(f"bad timestamp: {exc}") from exc
            return dt.replace(tzinfo=self._tz)

        ref = self._reference_time
        try:
            candidate = datetime.strptime(
                f"{ref.year} {month} {int(day):02d} {time}", _SYSLOG_TIME_FMT
            ).replace(tzinfo=self._tz)
        except ValueError as exc:
            raise MalformedLineError(f"bad timestamp: {exc}") from exc

        if candidate > ref:
            # This date hasn't happened yet this year → it's last year's log.
            try:
                candidate = candidate.replace(year=ref.year - 1)
            except ValueError:
                # Feb 29 fallback when the prior year isn't a leap year.
                candidate = candidate.replace(year=ref.year - 1, day=28)
        return candidate


def _classify_auth(
    message: str,
) -> tuple[AuthOutcome, str | None, str | None, int | None]:
    """Map an auth message to (outcome, username, source_ip, source_port)."""
    ip, port = None, None
    fm = _FROM_IP_RE.search(message)
    if fm:
        ip = fm.group("ip")
        port = int(fm.group("port")) if fm.group("port") else None
    else:
        # No "from IP" (e.g. "Connection closed by X port N [preauth]"):
        # still extract any IPv4 and a nearby port as context (§5).
        am = _ANY_IP_RE.search(message)
        if am:
            ip = am.group("ip")
            pm = _PORT_RE.search(message)
            port = int(pm.group("port")) if pm else None

    failed = _FAILED_PASSWORD_RE.search(message)
    if failed:
        if _INVALID_USER_RE.search(message):
            return AuthOutcome.INVALID_USER, failed.group("user"), ip, port
        return AuthOutcome.FAILURE, failed.group("user"), ip, port

    accepted = _ACCEPTED_RE.search(message)
    if accepted:
        return AuthOutcome.SUCCESS, accepted.group("user"), ip, port

    # "Failed ... invalid user" without the standard shape, still classify.
    invalid = _INVALID_USER_RE.search(message)
    if invalid and message.lower().startswith("failed"):
        return AuthOutcome.INVALID_USER, invalid.group("user"), ip, port

    return AuthOutcome.OTHER, None, ip, port


# --------------------------------------------------------------------------- #
# Crash-proof file iteration
# --------------------------------------------------------------------------- #


def parse_file(
    path: str | Path,
    parser: LogParser,
    *,
    counters: dict | None = None,
) -> Iterator[LogEntry | ParseError]:
    """Stream a file through ``parser``, yielding ``LogEntry`` or ``ParseError``.

    Blank lines are skipped. Any ``MalformedLineError`` becomes a ``ParseError``
    so the stream never crashes on a bad line. A missing/unreadable file yields
    a single source-level ``ParseError`` (``line_no = 0``) — callers decide
    whether that is fatal.

    If ``counters`` is supplied, ``lines_read`` and ``skipped_blank`` are
    incremented into it (the caller counts parsed/malformed from the yields).
    """
    path = Path(path)
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        yield ParseError(
            source=parser.source,
            line_no=0,
            raw=str(path),
            reason=f"{type(exc).__name__}: {exc}",
        )
        return

    with handle:
        for line_no, raw in enumerate(handle, start=1):
            if counters is not None:
                counters["lines_read"] = counters.get("lines_read", 0) + 1
            if not raw.strip():
                if counters is not None:
                    counters["skipped_blank"] = counters.get("skipped_blank", 0) + 1
                continue
            try:
                yield parser.parse_line(raw, line_no)
            except MalformedLineError as exc:
                yield ParseError(
                    source=parser.source,
                    line_no=line_no,
                    raw=raw.rstrip("\n"),
                    reason=exc.reason,
                )
