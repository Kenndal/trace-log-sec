"""Parser tests (§9)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from engine.parsers import (
    CombinedLogParser,
    MalformedLineError,
    SyslogAuthParser,
    parse_file,
)
from models import AuthOutcome, ParseError, WebLogEntry

# --------------------------------------------------------------------------- #
# Combined access log
# --------------------------------------------------------------------------- #

COMBINED_LINE = (
    "10.0.0.50 - frank [10/Oct/2025:13:55:36 -0700] "
    '"GET /index.html HTTP/1.1" 200 2326 '
    '"http://example.com/" "Mozilla/5.0"'
)

COMMON_LINE = '10.0.0.50 - - [10/Oct/2025:13:55:36 -0700] "GET /a HTTP/1.1" 404 -'


def test_combined_full_line():
    p = CombinedLogParser()
    e = p.parse_line(COMBINED_LINE, 1)
    assert isinstance(e, WebLogEntry)
    assert e.source_ip == "10.0.0.50"
    assert e.user == "frank"
    assert e.method == "GET"
    assert e.target == "/index.html"
    assert e.protocol == "HTTP/1.1"
    assert e.status == 200
    assert e.size == 2326
    assert e.referrer == "http://example.com/"
    assert e.user_agent == "Mozilla/5.0"
    assert e.timestamp == datetime(2025, 10, 10, 13, 55, 36, tzinfo=timezone(timedelta(hours=-7)))


def test_common_line_no_referrer_agent_and_dash_size():
    p = CombinedLogParser()
    e = p.parse_line(COMMON_LINE, 2)
    assert e.status == 404
    assert e.size == 0  # "-" → 0
    assert e.referrer is None
    assert e.user_agent is None
    assert e.user is None  # "-" → None


def test_target_keeps_query_string_and_props():
    p = CombinedLogParser()
    line = '1.2.3.4 - - [10/Oct/2025:00:00:00 +0000] "GET /s?q=a&b=1 HTTP/1.1" 200 5'
    e = p.parse_line(line, 1)
    assert e.target == "/s?q=a&b=1"
    assert e.path == "/s"
    assert e.query == "q=a&b=1"


def test_garbage_request_line_is_best_effort_not_error():
    p = CombinedLogParser()
    line = '1.2.3.4 - - [10/Oct/2025:00:00:00 +0000] "GARBAGE" 400 0'
    e = p.parse_line(line, 1)
    assert e.method == "GARBAGE"
    assert e.target is None
    assert e.status == 400


def test_malformed_combined_raises():
    p = CombinedLogParser()
    with pytest.raises(MalformedLineError):
        p.parse_line("[MALFORMED ENTRY", 1)


def test_bad_timestamp_raises():
    p = CombinedLogParser()
    line = '1.2.3.4 - - [99/Zzz/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 5'
    with pytest.raises(MalformedLineError):
        p.parse_line(line, 1)


# --------------------------------------------------------------------------- #
# Syslog auth log
# --------------------------------------------------------------------------- #

REF = datetime(2026, 7, 30, 12, 0, 0)


def _auth(msg: str, host: str = "server", proc: str = "sshd[1234]") -> str:
    return f"Oct 10 13:55:36 {host} {proc}: {msg}"


def test_auth_failure_outcome_and_fields():
    p = SyslogAuthParser(reference_time=REF)
    e = p.parse_line(_auth("Failed password for frank from 10.0.0.50 port 2222 ssh2"), 1)
    assert e.outcome == AuthOutcome.FAILURE
    assert e.username == "frank"
    assert e.source_ip == "10.0.0.50"
    assert e.source_port == 2222
    assert e.process == "sshd"
    assert e.pid == 1234


def test_invalid_user_outcome():
    p = SyslogAuthParser(reference_time=REF)
    e = p.parse_line(_auth("Failed password for invalid user admin from 10.0.0.50 port 1 ssh2"), 1)
    assert e.outcome == AuthOutcome.INVALID_USER
    assert e.username == "admin"
    assert e.source_ip == "10.0.0.50"


def test_accepted_is_success():
    p = SyslogAuthParser(reference_time=REF)
    e = p.parse_line(_auth("Accepted publickey for frank from 10.0.0.50 port 5 ssh2"), 1)
    assert e.outcome == AuthOutcome.SUCCESS
    assert e.username == "frank"


def test_preauth_is_other_but_extracts_ip():
    p = SyslogAuthParser(reference_time=REF)
    e = p.parse_line(_auth("Connection closed by 10.0.0.99 port 4 [preauth]"), 1)
    assert e.outcome == AuthOutcome.OTHER
    assert e.source_ip == "10.0.0.99"
    assert e.source_port == 4


def test_year_heuristic_picks_prior_year_for_future_date():
    # Oct 10 is after Jul 30 → hasn't happened in 2026 → 2025.
    p = SyslogAuthParser(reference_time=REF)
    e = p.parse_line(_auth("Failed password for x from 1.1.1.1 port 1 ssh2"), 1)
    assert e.timestamp.year == 2025
    assert (e.timestamp.month, e.timestamp.day) == (10, 10)


def test_year_heuristic_uses_current_year_for_past_date():
    p = SyslogAuthParser(reference_time=REF)
    line = "Jan 05 01:02:03 server sshd[1]: Failed password for x from 1.1.1.1 port 1 ssh2"
    e = p.parse_line(line, 1)
    assert e.timestamp.year == 2026


def test_default_year_override():
    p = SyslogAuthParser(default_year=2020)
    e = p.parse_line(_auth("Failed password for x from 1.1.1.1 port 1 ssh2"), 1)
    assert e.timestamp.year == 2020


def test_malformed_auth_raises():
    p = SyslogAuthParser(reference_time=REF)
    with pytest.raises(MalformedLineError):
        p.parse_line("[MALFORMED ENTRY", 1)


# --------------------------------------------------------------------------- #
# parse_file (crash-proof streaming)
# --------------------------------------------------------------------------- #


def test_parse_file_mixes_entries_and_errors_and_counts(tmp_path):
    f = tmp_path / "webserver.log"
    f.write_text(
        COMBINED_LINE
        + "\n"
        + "\n"  # blank
        + "[MALFORMED ENTRY\n"
        + COMMON_LINE
        + "\n"
    )
    counters: dict[str, int] = {}
    items = list(parse_file(f, CombinedLogParser(), counters=counters))
    entries = [i for i in items if isinstance(i, WebLogEntry)]
    errors = [i for i in items if isinstance(i, ParseError)]
    assert len(entries) == 2
    assert len(errors) == 1
    assert errors[0].line_no == 3
    assert counters["lines_read"] == 4
    assert counters["skipped_blank"] == 1


def test_parse_file_missing_file_yields_source_level_error():
    items = list(parse_file("/no/such/file.log", CombinedLogParser()))
    assert len(items) == 1
    assert isinstance(items[0], ParseError)
    assert items[0].line_no == 0
