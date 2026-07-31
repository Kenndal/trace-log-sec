"""Tailer tests: ``--follow``'s line source."""

from __future__ import annotations

from collections.abc import Callable

from engine import LogSource
from engine.parsers import CombinedLogParser
from engine.tailing import follow_sources
from models import ParseError, WebLogEntry

WEB_LINE = '1.2.3.4 - - [10/Oct/2025:13:55:{sec:02d} -0700] "GET /page{sec} HTTP/1.1" 200 10\n'


def line(sec):
    return WEB_LINE.format(sec=sec)


def append(path, text):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


class Script:
    """A deterministic ``stop`` predicate that also drives the writer.

    The tail loop checks ``stop()`` once per polling pass, so each step runs
    immediately before a pass: the loop then reads exactly what that step
    wrote. Once the steps run out the loop stops — no sleeping, no threads.
    """

    def __init__(self, *steps: Callable[[], object] | None):
        self._steps = list(steps)

    def __call__(self):
        if not self._steps:
            return True
        step = self._steps.pop(0)
        if step is not None:
            step()
        return False


def source(path):
    return LogSource(path=str(path), parser=CombinedLogParser(source=str(path)))


def collect(sources, stop, counters=None):
    # poll_interval=0: the Script drives every pass, so an idle pass has
    # nothing to wait for.
    return list(follow_sources(sources, stop=stop, counters=counters, poll_interval=0))


# --------------------------------------------------------------------------- #
# Starting position and appended lines
# --------------------------------------------------------------------------- #


def test_starts_at_end_of_file_ignoring_existing_lines(tmp_path):
    f = tmp_path / "web.log"
    f.write_text(line(1) + line(2))

    items = collect([source(f)], Script(None))

    assert items == []


def test_yields_lines_appended_after_start(tmp_path):
    f = tmp_path / "web.log"
    f.write_text(line(1))

    items = collect([source(f)], Script(lambda: append(f, line(2) + line(3))))

    assert [i.target for _, i in items] == ["/page2", "/page3"]
    assert all(isinstance(i, WebLogEntry) for _, i in items)


def test_line_numbers_count_from_the_start_of_the_session(tmp_path):
    f = tmp_path / "web.log"
    f.write_text(line(1) + line(2) + line(3))

    items = collect([source(f)], Script(lambda: append(f, line(4) + line(5))))

    # The first appended line is L1: content before the starting offset is
    # never read, so its absolute line number is unknown.
    assert [i.line_no for _, i in items] == [1, 2]


def test_yields_source_path_alongside_each_item(tmp_path):
    f = tmp_path / "web.log"
    f.write_text("")

    items = collect([source(f)], Script(lambda: append(f, line(1))))

    assert [path for path, _ in items] == [str(f)]


# --------------------------------------------------------------------------- #
# Partial lines
# --------------------------------------------------------------------------- #


def test_withholds_a_partial_line_until_its_newline_arrives(tmp_path):
    f = tmp_path / "web.log"
    f.write_text("")
    half, rest = line(1)[:20], line(1)[20:]

    items = collect([source(f)], Script(lambda: append(f, half), lambda: append(f, rest)))

    # The half-written line must not be reported as malformed; it surfaces
    # once, complete, after its newline lands.
    assert len(items) == 1
    assert items[0][1].target == "/page1"


def test_does_not_count_a_partial_line_as_read(tmp_path):
    f = tmp_path / "web.log"
    f.write_text("")
    counters: dict[str, int] = {}

    collect([source(f)], Script(lambda: append(f, "1.2.3.4 - - [10/Oct")), counters=lambda _: counters)

    assert counters.get("lines_read", 0) == 0


# --------------------------------------------------------------------------- #
# Malformed input and unreadable files
# --------------------------------------------------------------------------- #


def test_malformed_line_becomes_a_parse_error_without_stopping_the_stream(tmp_path):
    f = tmp_path / "web.log"
    f.write_text("")

    items = collect([source(f)], Script(lambda: append(f, "[MALFORMED ENTRY\n" + line(2))))

    kinds = [type(item) for _, item in items]
    assert kinds == [ParseError, WebLogEntry]
    assert items[0][1].line_no == 1


def test_missing_file_yields_a_source_level_parse_error(tmp_path):
    missing = tmp_path / "gone.log"

    items = collect([source(missing)], Script(None))

    assert len(items) == 1
    _, error = items[0]
    assert isinstance(error, ParseError)
    assert error.line_no == 0


def test_missing_file_does_not_prevent_following_the_others(tmp_path):
    good = tmp_path / "web.log"
    good.write_text("")
    missing = tmp_path / "gone.log"

    items = collect([source(missing), source(good)], Script(lambda: append(good, line(1))))

    assert [type(item) for _, item in items] == [ParseError, WebLogEntry]


# --------------------------------------------------------------------------- #
# Multiple sources and counters
# --------------------------------------------------------------------------- #


def test_follows_several_files_in_one_loop(tmp_path):
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text("")
    b.write_text("")

    def write_both():
        append(a, line(1))
        append(b, line(2))

    items = collect([source(a), source(b)], Script(write_both))

    assert {path for path, _ in items} == {str(a), str(b)}


def test_counts_lines_read_and_blank_lines_per_source(tmp_path):
    f = tmp_path / "web.log"
    f.write_text("")
    counters: dict[str, int] = {}

    collect([source(f)], Script(lambda: append(f, line(1) + "\n" + line(2))), counters=lambda _: counters)

    assert counters["lines_read"] == 3
    assert counters["skipped_blank"] == 1


def test_stop_ends_the_loop(tmp_path):
    f = tmp_path / "web.log"
    f.write_text("")

    items = collect([source(f)], lambda: True)

    assert items == []
