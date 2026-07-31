"""CLI `analyze` command tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"

COMBINED_LINE = '1.2.3.4 - - [10/Oct/2025:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326\n'
SYSLOG_LINE = "Jan 05 01:02:03 server sshd[1]: Failed password for x from 1.1.1.1 port 1 ssh2\n"


def write(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content)
    return f


def test_help_lists_analyze_subcommand():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "analyze" in result.output


def test_analyze_web_and_auth_files_succeeds(tmp_path):
    web = write(tmp_path, "webserver.log", COMBINED_LINE)
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", str(auth), str(web)])
    assert result.exit_code == 0
    assert "=== FINDINGS ===" in result.output
    assert "=== STATS ===" in result.output
    assert "lines_read=2" in result.output


def test_analyze_incidents_fixtures_correlate():
    result = runner.invoke(
        app,
        ["analyze", str(FIXTURES / "auth_incidents.log"), str(FIXTURES / "webserver_incidents.log")],
    )
    assert result.exit_code == 0
    assert "INC-" in result.output


def test_analyze_no_files_given_missing_argument():
    result = runner.invoke(app, ["analyze"])
    assert result.exit_code == 2
    assert "Missing argument" in result.output


def test_analyze_nonexistent_file_bad_parameter(tmp_path):
    result = runner.invoke(app, ["analyze", str(tmp_path / "missing.log")])
    assert result.exit_code == 2
    assert "no such file" in result.output


def test_analyze_wrong_extension_rejected(tmp_path):
    f = write(tmp_path, "notes.txt", "hello\n")
    result = runner.invoke(app, ["analyze", str(f)])
    assert result.exit_code == 2
    assert ".log" in result.output


def test_analyze_directory_rejected(tmp_path):
    d = tmp_path / "adir.log"
    d.mkdir()
    result = runner.invoke(app, ["analyze", str(d)])
    assert result.exit_code == 2
    assert "not a regular file" in result.output


def test_analyze_duplicate_paths_rejected():
    path = str(FIXTURES / "auth_incidents.log")
    result = runner.invoke(app, ["analyze", path, path])
    assert result.exit_code == 2
    assert "duplicate" in result.output


def test_analyze_multiple_bad_paths_all_reported(tmp_path):
    missing = tmp_path / "missing.log"
    wrong_ext = write(tmp_path, "notes.txt", "hello\n")
    result = runner.invoke(app, ["analyze", str(missing), str(wrong_ext)])
    assert result.exit_code == 2
    assert "no such file" in result.output
    assert ".log" in result.output


def test_analyze_unrecognized_file_skipped_with_warning(tmp_path):
    weird = write(tmp_path, "weird.log", "not a known log format\n")
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", str(weird), str(auth)])
    assert result.exit_code == 0
    assert "Warning" in result.output
    assert "weird.log" in result.output
    assert "lines_read=0" not in result.output


def test_analyze_all_files_unrecognized_exits_1(tmp_path):
    weird = write(tmp_path, "weird.log", "not a known log format\n")
    result = runner.invoke(app, ["analyze", str(weird)])
    assert result.exit_code == 1
    assert "Error" in result.output
