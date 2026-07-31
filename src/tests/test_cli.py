"""CLI `analyze` command tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cli import app
from cli.commands.analyze import _resolve
from config.settings import load_settings

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"

COMBINED_LINE = '1.2.3.4 - - [10/Oct/2025:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326\n'
SYSLOG_LINE = "Jan 05 01:02:03 server sshd[1]: Failed password for x from 1.1.1.1 port 1 ssh2\n"


def write(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content)
    return f


# --------------------------------------------------------------------------- #
# _resolve (command-line flag -> config.yaml value precedence)
# --------------------------------------------------------------------------- #


def test_resolve_returns_cli_value_when_provided():
    assert _resolve(5, 10) == 5


def test_resolve_falls_back_to_config_value_when_cli_omitted():
    assert _resolve(None, 10) == 10


def test_resolve_treats_explicit_falsy_cli_value_as_provided():
    # An explicit `--max-evidence 0` / `--window-minutes 0` must win over the
    # config value, not be coalesced away as "falsy".
    assert _resolve(0, 20) == 0
    assert _resolve(0.0, 10.0) == 0.0


# --------------------------------------------------------------------------- #
# analyze command
# --------------------------------------------------------------------------- #


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


def test_analyze_window_minutes_override_prevents_correlation():
    result = runner.invoke(
        app,
        [
            "analyze",
            "--window-minutes",
            "0",
            str(FIXTURES / "auth_incidents.log"),
            str(FIXTURES / "webserver_incidents.log"),
        ],
    )
    assert result.exit_code == 0
    assert "INC-" not in result.output


def test_analyze_uses_config_yaml_value_when_no_cli_override(monkeypatch):
    # No --window-minutes given: the effective value must come from
    # config.yaml's correlation.window_minutes, not the engine's own
    # built-in default (which would still correlate these fixtures).
    settings = load_settings()
    correlation = settings.correlation.model_copy(update={"window_minutes": 0})
    zero_window = settings.model_copy(update={"correlation": correlation})
    monkeypatch.setattr("cli.commands.analyze.load_settings", lambda: zero_window)

    result = runner.invoke(
        app,
        ["analyze", str(FIXTURES / "auth_incidents.log"), str(FIXTURES / "webserver_incidents.log")],
    )
    assert result.exit_code == 0
    assert "INC-" not in result.output


def test_analyze_max_evidence_rejects_negative(tmp_path):
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", "--max-evidence", "-1", str(auth)])
    assert result.exit_code == 2
    assert "--max-evidence" in result.output


def test_analyze_window_minutes_rejects_negative(tmp_path):
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", "--window-minutes", "-1", str(auth)])
    assert result.exit_code == 2
    assert "--window-minutes" in result.output


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
