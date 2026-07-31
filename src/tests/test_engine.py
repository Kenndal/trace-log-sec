"""Engine orchestration tests (§9)."""

from __future__ import annotations

from datetime import datetime, timedelta

from config.settings import load_settings, rule_specs
from engine import Engine, LogSource
from engine.correlation import Correlator
from engine.parsers import CombinedLogParser, LogParser, SyslogAuthParser
from engine.rules import Rule, ThresholdRule, build_rules
from models import AuthLogEntry, AuthOutcome, Severity, WebLogEntry

REF = datetime(2026, 7, 30, 12, 0, 0)


def config_rules():
    """Rules as configured in config.yaml (the default rule set)."""
    return build_rules(rule_specs(load_settings()))


class ListParser(LogParser):
    """Test parser that replays a pre-built list of entries, one per line."""

    def __init__(self, source, entries):
        self.source = source
        self._entries = entries

    def parse_line(self, line, line_no):
        return self._entries[line_no - 1]


def write_lines(path, n):
    path.write_text("\n".join(f"line{i}" for i in range(n)) + "\n")


# --------------------------------------------------------------------------- #
# End-to-end with real parsers and fixture logs
# --------------------------------------------------------------------------- #


def make_auth_log(tmp_path):
    lines = [
        f"Oct 10 13:55:{i:02d} server sshd[1]: Failed password for root from 10.0.0.50 port {1000 + i} ssh2"
        for i in range(6)
    ]
    f = tmp_path / "auth.log"
    f.write_text("\n".join(lines) + "\n")
    return f


def make_web_log(tmp_path):
    # 10.0.0.50 also hammers web login (401) 10x within the same minute.
    lines = [f'10.0.0.50 - - [10/Oct/2025:13:55:{i:02d} +0000] "POST /login HTTP/1.1" 401 10' for i in range(10)]
    f = tmp_path / "webserver.log"
    f.write_text("\n".join(lines) + "\n")
    return f


def test_end_to_end_correlated_incident(tmp_path):
    auth = make_auth_log(tmp_path)
    web = make_web_log(tmp_path)
    engine = Engine(
        config_rules(),
        correlator=Correlator(window=timedelta(minutes=10)),
    )
    report = engine.analyze(
        [
            LogSource(path=str(auth), parser=SyslogAuthParser(reference_time=REF)),
            LogSource(path=str(web), parser=CombinedLogParser()),
        ]
    )
    rule_ids = {f.rule_id for f in report.findings}
    assert "ssh_brute_force" in rule_ids
    assert "web_login_brute_force" in rule_ids
    # Both fire for 10.0.0.50 within the window → one correlated incident.
    assert len(report.incidents) == 1
    inc = report.incidents[0]
    assert inc.source_ip == "10.0.0.50"
    assert inc.severity == Severity.CRITICAL


def test_stats_shape(tmp_path):
    web = make_web_log(tmp_path)
    engine = Engine(config_rules())
    report = engine.analyze([LogSource(path=str(web), parser=CombinedLogParser())])
    stats = report.stats
    assert set(stats) == {"sources", "totals", "duration_seconds"}
    src = stats["sources"][str(web)]
    assert set(src) == {"lines_read", "parsed", "malformed", "skipped_blank"}
    assert src["parsed"] == 10
    assert set(stats["totals"]) == {"lines_read", "parsed", "malformed", "skipped_blank", "findings", "incidents"}
    assert isinstance(stats["duration_seconds"], float)


def test_missing_file_captured_not_raised(tmp_path):
    engine = Engine(config_rules())
    report = engine.analyze([LogSource(path=str(tmp_path / "nope.log"), parser=CombinedLogParser())])
    assert len(report.parse_errors) == 1
    assert report.parse_errors[0].line_no == 0
    assert report.findings == []


def test_all_malformed_file_is_normal_report(tmp_path):
    f = tmp_path / "webserver.log"
    f.write_text("[MALFORMED ENTRY\nalso bad\n")
    engine = Engine(config_rules())
    report = engine.analyze([LogSource(path=str(f), parser=CombinedLogParser())])
    assert report.findings == []
    assert len(report.parse_errors) == 2
    assert report.stats["totals"]["malformed"] == 2


def test_empty_file_is_normal_report(tmp_path):
    f = tmp_path / "webserver.log"
    f.write_text("")
    engine = Engine(config_rules())
    report = engine.analyze([LogSource(path=str(f), parser=CombinedLogParser())])
    assert report.findings == []
    assert report.parse_errors == []


def test_engine_rerun_idempotent(tmp_path):
    auth = make_auth_log(tmp_path)
    engine = Engine(config_rules())
    src = [LogSource(path=str(auth), parser=SyslogAuthParser(reference_time=REF))]
    r1 = engine.analyze(src)
    r2 = engine.analyze(src)
    assert len(r1.findings) == len(r2.findings)
    assert [f.count for f in r1.findings] == [f.count for f in r2.findings]


# --------------------------------------------------------------------------- #
# Ordering invariants I1 / I2 (§8)
# --------------------------------------------------------------------------- #


def test_ordering_stateful_rule_sees_only_its_own_source_order(tmp_path):
    """I1/I2: a stateful auth rule's window reflects auth-file order only,
    regardless of the order sources are processed or interleaved web events.

    ``ListParser`` maps each physical line to a pre-built entry, so we still
    back it with real files of the right length.
    """
    t = datetime(2025, 10, 10, 12, 0, 0)

    auth_entries = [
        AuthLogEntry(
            timestamp=t + timedelta(seconds=s),
            source="auth",
            raw="",
            line_no=1,
            source_ip="9.9.9.9",
            outcome=AuthOutcome.FAILURE,
        )
        for s in range(5)
    ]
    web_entries = [
        WebLogEntry(
            timestamp=t + timedelta(seconds=s),
            source="webserver",
            raw="",
            line_no=1,
            source_ip="9.9.9.9",
            method="GET",
            target="/x",
            status=200,
        )
        for s in range(5)
    ]

    web_file = tmp_path / "web.log"
    auth_file = tmp_path / "auth.log"
    write_lines(web_file, len(web_entries))
    write_lines(auth_file, len(auth_entries))

    rule = ThresholdRule(id="bf", match="auth_failure", threshold=5, window_seconds=60, severity=Severity.HIGH)
    engine = Engine([rule], correlator=Correlator())

    # Web source processed first, then auth — web events must not disturb the
    # auth rule's window (it ignores non-auth entries), so the burst still fires.
    report = engine.analyze(
        [
            LogSource(path=str(web_file), parser=ListParser("webserver", web_entries)),
            LogSource(path=str(auth_file), parser=ListParser("auth", auth_entries)),
        ]
    )
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "bf"


# --------------------------------------------------------------------------- #
# Rule-execution failure isolation
# --------------------------------------------------------------------------- #


class RaisingRule(Rule):
    """Test double: raises on every entry it inspects."""

    id = "boom"
    severity = Severity.LOW

    def inspect(self, entry):
        raise RuntimeError("boom")


def test_rule_exception_isolated(tmp_path):
    auth = make_auth_log(tmp_path)
    engine = Engine([RaisingRule(), *config_rules()])
    report = engine.analyze([LogSource(path=str(auth), parser=SyslogAuthParser(reference_time=REF))])
    # The buggy rule's exceptions are swallowed; the well-behaved rule alongside
    # it still runs to completion and produces its finding.
    assert "ssh_brute_force" in {f.rule_id for f in report.findings}
