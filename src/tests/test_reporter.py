"""Tests for the ``reporter`` package: HTML rendering and report storage."""

from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any

import pytest

from models import AnalysisReport, Finding, Incident, LogEntry, ParseError, Severity
from reporter import list_reports, render_html, resolve_output_dir, write_report
from reporter.storage import PROJECT_ROOT
from utils.exceptions import ReportError

FIXED_TIME = datetime(2025, 11, 12, 13, 10, 0, tzinfo=UTC)
LATER_TIME = datetime(2025, 11, 12, 13, 13, 16, tzinfo=UTC)


def _finding(**overrides):
    base: dict[str, Any] = {
        "rule_id": "ssh_brute_force",
        "title": "SSH Brute Force",
        "severity": Severity.HIGH,
        "description": "Repeated SSH authentication failures from one IP.",
        "first_seen": FIXED_TIME,
        "last_seen": LATER_TIME,
        "source_ip": "203.0.113.150",
        "count": 8,
        "sources": {"auth"},
    }
    base.update(overrides)
    return Finding(**base)


def _sample_report():
    web_finding = _finding(
        rule_id="directory_traversal",
        title="Directory Traversal",
        source_ip="203.0.113.150",
        count=5,
        sources={"webserver"},
    )
    auth_finding = _finding()
    incident = Incident(
        incident_id="INC-038e68a146",
        title="Correlated activity from 203.0.113.150",
        severity=Severity.CRITICAL,
        source_ip="203.0.113.150",
        first_seen=FIXED_TIME,
        last_seen=LATER_TIME,
        findings=[web_finding, auth_finding],
        narrative="203.0.113.150 triggered 2 findings across 2 rule(s) over auth, webserver.",
    )
    return AnalysisReport(
        findings=[web_finding, auth_finding],
        incidents=[incident],
        parse_errors=[ParseError(source="webserver", line_no=844, raw="[MALFORMED]", reason="bad line")],
        stats={
            "totals": {
                "lines_read": 4167,
                "parsed": 4163,
                "malformed": 4,
                "findings": 2,
                "incidents": 1,
            },
            "duration_seconds": 0.0599,
        },
    )


# --------------------------------------------------------------------------- #
# render_html
# --------------------------------------------------------------------------- #


def test_render_html_is_a_complete_document():
    html = render_html(_sample_report(), generated_at=FIXED_TIME)
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html.strip()[-10:]
    assert "<style>" in html  # self-contained, no external assets
    assert "http://" not in html
    assert "https://" not in html


def test_render_html_contains_key_sections_and_data():
    html = render_html(_sample_report(), generated_at=FIXED_TIME)
    assert "Executive summary" in html
    assert "Correlated incidents" in html
    assert "Detected findings" in html
    assert "INC-038e68a146" in html
    assert "203.0.113.150" in html
    assert "Directory Traversal" in html
    # both correlated sources are surfaced on the incident card
    assert "auth" in html
    assert "webserver" in html


def test_render_html_shows_severity_and_stats():
    html = render_html(_sample_report(), generated_at=FIXED_TIME)
    assert "CRITICAL" in html
    assert "HIGH" in html
    assert "4167" in html  # lines_read stat tile


def test_render_html_escapes_hostile_log_content():
    payload = "<script>alert('xss')</script>"
    report = AnalysisReport(
        findings=[_finding(description=payload, source_ip=payload)],
        parse_errors=[ParseError(source="webserver", line_no=1, raw=payload, reason="bad")],
        stats={"totals": {}},
    )
    html = render_html(report, generated_at=FIXED_TIME)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_render_html_empty_report_is_clean_and_valid():
    html = render_html(AnalysisReport(), generated_at=FIXED_TIME)
    assert html.startswith("<!DOCTYPE html>")
    assert "No suspicious activity detected" in html
    assert "No correlated incidents" in html
    # no parse-errors section when there are none
    assert "Parse errors" not in html


# --------------------------------------------------------------------------- #
# Evidence toggle (raw log lines behind a finding)
# --------------------------------------------------------------------------- #


def _log_entry(**overrides):
    base: dict[str, Any] = {
        "timestamp": FIXED_TIME,
        "source": "auth",
        "raw": "Nov 12 13:10:00 server sshd[1]: Failed password for root from 203.0.113.150 port 22 ssh2",
        "line_no": 42,
        "source_ip": "203.0.113.150",
    }
    base.update(overrides)
    return LogEntry(**base)


def test_render_html_no_evidence_shows_placeholder():
    # The default `_finding()` has no evidence attached.
    html = render_html(_sample_report(), generated_at=FIXED_TIME)
    assert "no evidence captured" in html


def test_render_html_evidence_renders_collapsed_toggle_with_raw_lines():
    finding = _finding(evidence=[_log_entry(line_no=42), _log_entry(line_no=43)])
    report = AnalysisReport(findings=[finding], stats={"totals": {}})
    html = render_html(report, generated_at=FIXED_TIME)

    assert '<details class="evidence">' in html
    assert "2 raw log lines" in html
    assert "auth L42" in html
    assert "auth L43" in html
    assert "Failed password for root" in html
    # Collapsed by default: no `open` attribute on the <details> element.
    assert '<details class="evidence" open' not in html


def test_render_html_evidence_singular_label_for_one_line():
    finding = _finding(evidence=[_log_entry()])
    report = AnalysisReport(findings=[finding], stats={"totals": {}})
    html = render_html(report, generated_at=FIXED_TIME)
    assert "1 raw log line<" in html  # singular, not "1 raw log lines"


def test_render_html_escapes_hostile_evidence_raw_content():
    payload = "<script>alert('xss')</script>"
    finding = _finding(evidence=[_log_entry(raw=payload)])
    report = AnalysisReport(findings=[finding], stats={"totals": {}})
    html = render_html(report, generated_at=FIXED_TIME)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_render_html_incident_card_includes_sub_finding_evidence():
    web_finding = _finding(
        rule_id="directory_traversal",
        title="Directory Traversal",
        evidence=[_log_entry(source="webserver", raw="GET /../../etc/passwd HTTP/1.1")],
    )
    incident = Incident(
        incident_id="INC-abc123",
        title="Correlated activity",
        severity=Severity.CRITICAL,
        source_ip="203.0.113.150",
        first_seen=FIXED_TIME,
        last_seen=LATER_TIME,
        findings=[web_finding],
        narrative="narrative text",
    )
    report = AnalysisReport(findings=[web_finding], incidents=[incident], stats={"totals": {}})
    html = render_html(report, generated_at=FIXED_TIME)
    assert "GET /../../etc/passwd HTTP/1.1" in html


# --------------------------------------------------------------------------- #
# write_report
# --------------------------------------------------------------------------- #


def test_write_report_creates_missing_directory(tmp_path):
    out = tmp_path / "does" / "not" / "exist"
    assert not out.exists()
    path = write_report(_sample_report(), out, generated_at=FIXED_TIME)
    assert out.is_dir()
    assert path.is_file()


def test_write_report_returns_absolute_path_with_expected_name(tmp_path):
    path = write_report(_sample_report(), tmp_path, generated_at=FIXED_TIME)
    assert path.is_absolute()
    assert path.name == "report_2025_11_12_13_10_00.html"
    assert path.parent == tmp_path


def test_write_report_writes_rendered_html(tmp_path):
    path = write_report(_sample_report(), tmp_path, generated_at=FIXED_TIME)
    content = path.read_text(encoding="utf-8")
    assert content.startswith("<!DOCTYPE html>")
    assert "INC-038e68a146" in content


def test_write_report_empty_results_still_produces_file(tmp_path):
    path = write_report(AnalysisReport(), tmp_path, generated_at=FIXED_TIME)
    assert path.is_file()
    assert "No suspicious activity detected" in path.read_text(encoding="utf-8")


def test_write_report_defaults_generated_at_to_now(tmp_path):
    before = datetime.now(UTC)
    path = write_report(AnalysisReport(), tmp_path)
    assert re.fullmatch(r"report_\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}\.html", path.name)
    parsed = datetime.strptime(path.name, "report_%Y_%m_%d_%H_%M_%S.html").replace(tzinfo=UTC)
    # within a minute of "now" (guards against a wildly wrong default)
    assert abs((parsed - before).total_seconds()) < 60


def test_write_report_unwritable_dir_raises_report_error(tmp_path):
    # A path whose parent is a regular file can never be mkdir'd -> OSError,
    # which must surface as the project's ReportError, not a raw OSError.
    blocker = tmp_path / "afile"
    blocker.write_text("i am a file")
    with pytest.raises(ReportError):
        write_report(_sample_report(), blocker / "sub", generated_at=FIXED_TIME)


# --------------------------------------------------------------------------- #
# resolve_output_dir
# --------------------------------------------------------------------------- #


def test_resolve_output_dir_absolute_kept(tmp_path):
    assert resolve_output_dir(tmp_path) == tmp_path


def test_resolve_output_dir_relative_uses_project_root():
    assert resolve_output_dir("reports") == (PROJECT_ROOT / "reports").resolve()


# --------------------------------------------------------------------------- #
# list_reports
# --------------------------------------------------------------------------- #


def test_list_reports_missing_dir_returns_empty(tmp_path):
    assert list_reports(tmp_path / "nope") == []


def test_list_reports_finds_and_parses_timestamp(tmp_path):
    write_report(AnalysisReport(), tmp_path, generated_at=FIXED_TIME)
    reports = list_reports(tmp_path)
    assert len(reports) == 1
    assert reports[0].generated_at == FIXED_TIME
    assert reports[0].path.name == "report_2025_11_12_13_10_00.html"


def test_list_reports_sorted_newest_first(tmp_path):
    write_report(AnalysisReport(), tmp_path, generated_at=FIXED_TIME)
    write_report(AnalysisReport(), tmp_path, generated_at=LATER_TIME)
    reports = list_reports(tmp_path)
    assert [r.generated_at for r in reports] == [LATER_TIME, FIXED_TIME]


def test_list_reports_ignores_non_matching_files(tmp_path):
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / "report_not_a_date.html").write_text("x")
    write_report(AnalysisReport(), tmp_path, generated_at=FIXED_TIME)
    reports = list_reports(tmp_path)
    assert len(reports) == 1


def test_list_reports_ignores_directories_matching_glob(tmp_path):
    # A directory whose name matches the glob must not be listed as a report.
    (tmp_path / "report_2025_11_12_13_10_00.html").mkdir()
    assert list_reports(tmp_path) == []
