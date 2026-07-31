"""Auto-detects log format per file and builds the engine's ``LogSource`` list.

Sniffing reuses the real parsers' public ``parse_line`` rather than their
private regexes, so a sniff success guarantees the file will actually parse
(it also validates the timestamp format, not just line shape). This keeps
format detection a CLI-layer concern -- the ``engine`` package stays
format-agnostic, per its own documented boundary.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from engine import CombinedLogParser, LogSource, MalformedLineError, SyslogAuthParser

LogFormat = Literal["web", "auth"]

# Sniffing scans up to this many non-blank lines for the first that parses,
# rather than failing closed on a single bad first line: a header, comment, or
# rotation remnant at the top of an otherwise-valid file must not silently
# drop the whole file.
_SNIFF_MAX_LINES = 20

# Newest-timestamp anchoring reads only this many trailing bytes of each web
# log (they are append-only and chronological) instead of a full scan.
_TAIL_BYTES = 64 * 1024


def _nonblank_lines(path: Path, limit: int) -> Iterator[str]:
    """Yield up to ``limit`` non-blank lines from ``path`` (nothing on OSError)."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            count = 0
            for line in handle:
                if not line.strip():
                    continue
                yield line
                count += 1
                if count >= limit:
                    return
    except OSError:
        return


def detect_format(path: Path) -> LogFormat | None:
    """Sniff ``path`` against known formats, scanning its first non-blank lines.

    Returns the format of the first line (within ``_SNIFF_MAX_LINES``) that
    parses; ``None`` if the file is empty, unreadable, or no sniffed line
    matches either format -- the caller decides whether that is fatal.
    """
    web = CombinedLogParser()
    auth = SyslogAuthParser()
    for line in _nonblank_lines(path, _SNIFF_MAX_LINES):
        try:
            web.parse_line(line, 1)
        except MalformedLineError:
            pass
        else:
            return "web"
        try:
            auth.parse_line(line, 1)
        except MalformedLineError:
            pass
        else:
            return "auth"
    return None


def _last_web_timestamp(path: Path) -> datetime | None:
    """Newest parseable Combined-log timestamp in ``path``, read from its tail.

    Web access logs are append-only and chronological, so the last parseable
    line carries the newest timestamp -- reading only the trailing
    ``_TAIL_BYTES`` avoids a full end-to-end scan of a large production log.
    Falls back to the file's mtime if the tail holds no parseable line, and to
    ``None`` only when the file is unreadable.
    """
    try:
        with path.open("rb") as handle:
            size = handle.seek(0, 2)  # SEEK_END
            start = max(0, size - _TAIL_BYTES)
            handle.seek(start)
            chunk = handle.read()
    except OSError:
        return None

    lines = chunk.decode("utf-8", errors="replace").splitlines()
    if start > 0 and lines:
        # The tail almost certainly began mid-line; drop that partial fragment.
        lines = lines[1:]

    parser = CombinedLogParser()
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            return parser.parse_line(line, 0).timestamp
        except MalformedLineError:
            continue

    try:  # No parseable line in the tail; approximate with the file's mtime.
        return datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return None


def _resolve_reference_time(web_paths: Sequence[Path], override: datetime | None) -> tuple[datetime, bool]:
    """Resolve the syslog year anchor, and flag a fallback to ``now()``.

    Precedence: an explicit ``override`` (``--reference-time``) → the newest
    web-log timestamp in this run (read cheaply from each file's tail) →
    ``now()``. The returned bool is ``True`` only in that last case, letting an
    auth-only run warn that archived-log year resolution has no real anchor.
    """
    if override is not None:
        return (override if override.tzinfo is not None else override.replace(tzinfo=UTC)), False

    latest: datetime | None = None
    for path in web_paths:
        ts = _last_web_timestamp(path)
        if ts is not None and (latest is None or ts > latest):
            latest = ts
    if latest is not None:
        return latest, False

    return datetime.now(UTC), True


def build_log_sources(
    paths: Sequence[Path], *, reference_time: datetime | None = None
) -> tuple[list[LogSource], list[Path], bool]:
    """Detect each path's format and build matching ``LogSource``s.

    Returns ``(sources, skipped, anchored_to_now)``. ``skipped`` holds paths
    matching neither known format (including empty/unreadable files). Each
    source's id is the full path string, so two files sharing a basename
    (``host1/auth.log`` vs ``host2/auth.log``) stay distinct for correlation
    and parse-error attribution. ``anchored_to_now`` is ``True`` when auth
    sources exist but the syslog year anchor fell back to ``now()`` (no
    ``--reference-time`` and no web logs), so the caller can warn.
    """
    detected: dict[Path, LogFormat] = {}
    skipped: list[Path] = []
    for path in paths:
        fmt = detect_format(path)
        if fmt is None:
            skipped.append(path)
        else:
            detected[path] = fmt

    web_paths = [p for p, fmt in detected.items() if fmt == "web"]
    ref_time, fell_back_to_now = _resolve_reference_time(web_paths, reference_time)

    sources = [
        LogSource(
            path=str(path),
            parser=(
                CombinedLogParser(source=str(path))
                if fmt == "web"
                else SyslogAuthParser(source=str(path), reference_time=ref_time)
            ),
        )
        for path, fmt in detected.items()
    ]
    has_auth = any(fmt == "auth" for fmt in detected.values())
    return sources, skipped, fell_back_to_now and has_auth
