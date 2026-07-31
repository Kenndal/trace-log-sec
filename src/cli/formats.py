"""Auto-detects log format per file and builds the engine's ``LogSource`` list.

Sniffing reuses the real parsers' public ``parse_line`` rather than their
private regexes, so a sniff success guarantees the file will actually parse
(it also validates the timestamp format, not just line shape). This keeps
format detection a CLI-layer concern -- the ``engine`` package stays
format-agnostic, per its own documented boundary.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from engine import CombinedLogParser, LogSource, MalformedLineError, SyslogAuthParser, WebLogEntry, parse_file

LogFormat = Literal["web", "auth"]


def _first_nonblank_line(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip():
                    return line
    except OSError:
        return None
    return None


def detect_format(path: Path) -> LogFormat | None:
    """Sniff ``path``'s first non-blank line against known formats.

    Returns ``None`` if the file is empty, unreadable, or matches neither
    format -- the caller decides whether that is fatal.
    """
    line = _first_nonblank_line(path)
    if line is None:
        return None
    try:
        CombinedLogParser().parse_line(line, 1)
    except MalformedLineError:
        pass
    else:
        return "web"
    try:
        SyslogAuthParser().parse_line(line, 1)
    except MalformedLineError:
        return None
    return "auth"


def _reference_time(web_paths: Sequence[Path]) -> datetime:
    """Anchor auth-log year resolution to the newest timestamp among detected
    web logs in this run, falling back to "now" if there are none (generalizes
    ``scripts/run_demo.py``'s single-file helper of the same name to N files).
    """
    latest: datetime | None = None
    for path in web_paths:
        for item in parse_file(path, CombinedLogParser()):
            if isinstance(item, WebLogEntry) and (latest is None or item.timestamp > latest):
                latest = item.timestamp
    return latest if latest is not None else datetime.now(UTC)


def build_log_sources(paths: Sequence[Path]) -> tuple[list[LogSource], list[Path]]:
    """Detect each path's format and build matching ``LogSource``s.

    Returns ``(sources, skipped)``; ``skipped`` holds paths matching neither
    known format (including empty/unreadable files).
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
    reference_time = _reference_time(web_paths)

    sources = [
        LogSource(
            path=str(path),
            parser=(
                CombinedLogParser(source=path.stem)
                if fmt == "web"
                else SyslogAuthParser(source=path.stem, reference_time=reference_time)
            ),
        )
        for path, fmt in detected.items()
    ]
    return sources, skipped
