"""Continuous log following, in the style of ``tail -f``.

``follow_sources`` is the streaming counterpart to ``parse_file``: instead of
reading a file to EOF and stopping, it opens each source at its *end* and keeps
polling for appended lines, yielding the same ``LogEntry``/``ParseError`` items
so an ``AnalysisSession`` cannot tell the two producers apart.

Known limits (a deliberate scope choice, see the README):

* No rotation/truncation handling -- a rotated or truncated file stops
  producing lines until the run is restarted.
* Line numbers count from 1 at the start of the follow session, since the
  content before the starting offset is never read.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
import contextlib
from io import SEEK_END
from pathlib import Path
import time
from typing import IO

from constants import DEFAULT_FOLLOW_POLL_SECONDS, FOLLOW_READ_CHUNK_BYTES
from models import LogEntry, LogSource, ParseError
from utils.exceptions import MalformedLineError

from .parsers import LogParser

_Counters = dict[str, int]


class _Follower:
    """One open file being tailed, with its partial-line buffer."""

    def __init__(self, path: str, parser: LogParser, handle: IO[str], counters: _Counters | None) -> None:
        self.path = path
        self.parser = parser
        self.handle = handle
        self.counters = counters
        self.line_no = 0
        self._buffer = ""

    def read_lines(self) -> list[str]:
        """Return the complete lines available now, holding back a partial one.

        A writer can be caught mid-line, so anything after the last newline
        stays buffered until its newline arrives — otherwise a half-written
        entry would be reported as malformed.
        """
        chunk = self.handle.read(FOLLOW_READ_CHUNK_BYTES)
        if not chunk:
            return []
        self._buffer += chunk
        lines = self._buffer.split("\n")
        self._buffer = lines.pop()
        return lines

    def parse(self, line: str) -> LogEntry | ParseError | None:
        """Parse one complete line the way ``parse_file`` would (``None`` = blank)."""
        if self.counters is not None:
            self.counters["lines_read"] = self.counters.get("lines_read", 0) + 1
        self.line_no += 1
        if not line.strip():
            if self.counters is not None:
                self.counters["skipped_blank"] = self.counters.get("skipped_blank", 0) + 1
            return None
        try:
            return self.parser.parse_line(line, self.line_no)
        except MalformedLineError as exc:
            return ParseError(
                source=self.parser.source,
                line_no=self.line_no,
                raw=line,
                reason=exc.reason,
            )


def follow_sources(
    sources: Sequence[LogSource],
    *,
    counters: Callable[[str], _Counters] | None = None,
    poll_interval: float = DEFAULT_FOLLOW_POLL_SECONDS,
    stop: Callable[[], bool] = lambda: False,
) -> Iterator[tuple[str, LogEntry | ParseError]]:
    """Tail ``sources`` forever, yielding ``(source path, item)`` as lines arrive.

    Each file is opened at its end, so only lines appended after this call are
    analyzed. All files are polled round-robin in one loop — no threads — and
    the loop sleeps ``poll_interval`` only when every file is idle, so a busy
    stream is never throttled.

    ``counters`` supplies the per-source counter dict (``AnalysisSession.
    counters_for``) that ``lines_read``/``skipped_blank`` are tallied into.
    Iteration ends when ``stop()`` returns ``True``; an unreadable file yields
    a source-level ``ParseError`` (``line_no = 0``) and is then left out,
    exactly as ``parse_file`` reports one.
    """
    with contextlib.ExitStack() as stack:
        followers: list[_Follower] = []
        for source in sources:
            try:
                handle = open(source.path, encoding="utf-8", errors="replace")  # noqa: SIM115 (closed by ExitStack)
            except OSError as exc:
                yield (
                    source.path,
                    ParseError(
                        source=source.parser.source,
                        line_no=0,
                        raw=str(Path(source.path)),
                        reason=f"{type(exc).__name__}: {exc}",
                    ),
                )
                continue
            stack.enter_context(handle)
            handle.seek(0, SEEK_END)
            source_counters = counters(source.path) if counters is not None else None
            followers.append(_Follower(source.path, source.parser, handle, source_counters))

        if not followers:
            return

        while not stop():
            idle = True
            for follower in followers:
                for line in follower.read_lines():
                    idle = False
                    item = follower.parse(line)
                    if item is not None:
                        yield follower.path, item
            if idle:
                time.sleep(poll_interval)
