"""CLI `analyze` command tests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from cli import app
from cli.commands.analyze import _resolve
from config.settings import load_settings
from engine import follow_sources

runner = CliRunner()

COMBINED_LINE = '1.2.3.4 - - [10/Oct/2025:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326\n'
SYSLOG_LINE = "Jan 05 01:02:03 server sshd[1]: Failed password for x from 1.1.1.1 port 1 ssh2\n"


def _auth_failures(ip, seconds, hhmm="01:02"):
    """``ssh_brute_force`` fires at 5 failures within 60s: default hhmm="01:02"."""
    return "".join(
        f"Jul 31 {hhmm}:{s:02d} server sshd[1]: Failed password for root from {ip} port 22 ssh2\n" for s in seconds
    )


def _traversal_hit(ip, time="31/Jul/2025:01:06:00 +0000"):
    """A ``directory_traversal`` signature hit (matches ``\\.\\./`` + ``/etc/passwd``)."""
    return f'{ip} - - [{time}] "GET /../../etc/passwd HTTP/1.1" 200 100\n'


@pytest.fixture(autouse=True)
def _isolate_reports(tmp_path, monkeypatch):
    """Redirect report output to a temp dir so tests never touch the real
    ``reports/`` folder. ``analyze`` resolves the configured relative dir
    against the current working directory, so chdir'ing here is enough.
    """
    monkeypatch.chdir(tmp_path)


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


def test_analyze_multi_signal_activity_correlates(tmp_path):
    # Same IP triggers ssh_brute_force (auth) and directory_traversal (web)
    # ~4 minutes apart -- 2 distinct rules within the default 10-minute
    # correlation window, so the Correlator merges them into one incident.
    ip = "203.0.113.50"
    auth = write(tmp_path, "auth.log", _auth_failures(ip, [0, 1, 2, 3, 4]))
    web = write(tmp_path, "webserver.log", _traversal_hit(ip))
    result = runner.invoke(app, ["analyze", str(auth), str(web)])
    assert result.exit_code == 0
    assert "INC-" in result.output


def test_analyze_window_minutes_override_prevents_correlation(tmp_path):
    ip = "203.0.113.50"
    auth = write(tmp_path, "auth.log", _auth_failures(ip, [0, 1, 2, 3, 4]))
    web = write(tmp_path, "webserver.log", _traversal_hit(ip))
    result = runner.invoke(app, ["analyze", "--window-minutes", "0", str(auth), str(web)])
    assert result.exit_code == 0
    assert "INC-" not in result.output


def test_analyze_uses_config_yaml_value_when_no_cli_override(monkeypatch, tmp_path):
    # No --window-minutes given: the effective value must come from
    # config.yaml's correlation.window_minutes, not the engine's own
    # built-in default (which would still correlate this activity).
    settings = load_settings()
    correlation = settings.correlation.model_copy(update={"window_minutes": 0})
    zero_window = settings.model_copy(update={"correlation": correlation})
    monkeypatch.setattr("cli.commands.analyze.load_settings", lambda *a, **k: zero_window)

    ip = "203.0.113.50"
    auth = write(tmp_path, "auth.log", _auth_failures(ip, [0, 1, 2, 3, 4]))
    web = write(tmp_path, "webserver.log", _traversal_hit(ip))
    result = runner.invoke(app, ["analyze", str(auth), str(web)])
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


def test_analyze_duplicate_paths_rejected(tmp_path):
    path = str(write(tmp_path, "auth.log", SYSLOG_LINE))
    result = runner.invoke(app, ["analyze", path, path])
    assert result.exit_code == 2
    assert "duplicate" in result.output


def test_analyze_multiple_bad_paths_all_reported(tmp_path):
    missing = tmp_path / "missing.log"
    wrong_ext = write(tmp_path, "notes.txt", "hello\n")
    result = runner.invoke(app, ["analyze", str(missing), str(wrong_ext)])
    assert result.exit_code == 2
    assert "no such file" in result.output


# --------------------------------------------------------------------------- #
# --config
# --------------------------------------------------------------------------- #

CUSTOM_CONFIG = """\
rules:
  - id: ssh_brute_force
    type: threshold
    severity: high
    enabled: false
    params:
      match: auth_failure
      threshold: 5
      window_seconds: 60
"""


def test_analyze_config_overrides_default_disables_rule(tmp_path):
    # Default config.yaml has ssh_brute_force enabled; this custom config
    # disables it, so the same failing-auth activity should produce no finding.
    config = write(tmp_path, "custom.yaml", CUSTOM_CONFIG)
    ip = "203.0.113.50"
    auth = write(tmp_path, "auth.log", _auth_failures(ip, [0, 1, 2, 3, 4]))
    result = runner.invoke(app, ["analyze", "--config", str(config), str(auth)])
    assert result.exit_code == 0
    assert "ssh_brute_force" not in result.output


def test_analyze_config_nonexistent_path_rejected(tmp_path):
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", "--config", str(tmp_path / "missing.yaml"), str(auth)])
    assert result.exit_code == 2
    assert "--config" in result.output


def test_analyze_config_malformed_yaml_reported(tmp_path):
    config = write(tmp_path, "bad.yaml", "rules: [this is not: valid: yaml\n")
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", "--config", str(config), str(auth)])
    assert result.exit_code == 1
    assert "invalid config" in result.output


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


# --------------------------------------------------------------------------- #
# Source-id uniqueness, format sniffing, and year anchoring (PR #7 review)
# --------------------------------------------------------------------------- #


def test_analyze_same_basename_files_get_distinct_sources(tmp_path):
    # Two files sharing a basename ("auth.log") in different directories must
    # not collide on source id — otherwise the >=2-distinct-sources correlation
    # can never fire. host1's file crosses ssh_brute_force (threshold 5) on its
    # own, and host2's later failure (same IP, same window) is folded into the
    # active finding — so its `sources` set spans both files only if the ids are
    # distinct, which is what makes the incident form.
    ip = "9.9.9.9"
    d1 = tmp_path / "host1"
    d1.mkdir()
    d2 = tmp_path / "host2"
    d2.mkdir()
    a1 = d1 / "auth.log"
    a1.write_text(_auth_failures(ip, [0, 1, 2, 3, 4]))
    a2 = d2 / "auth.log"
    a2.write_text(_auth_failures(ip, [5]))

    result = runner.invoke(app, ["analyze", "--reference-time", "2026-07-31T02:00:00", str(a1), str(a2)])
    assert result.exit_code == 0
    assert "INC-" in result.output
    # The incident narrative lists the sources — both full paths, not one merged "auth".
    assert "host1" in result.output
    assert "host2" in result.output


def test_analyze_detects_format_past_junk_first_line(tmp_path):
    # A header / rotation remnant on the first line must not cause the whole
    # file to be skipped when later lines parse fine.
    f = write(tmp_path, "access.log", "# rotated 2026-07-31\n" + COMBINED_LINE)
    result = runner.invoke(app, ["analyze", str(f)])
    assert result.exit_code == 0
    assert "Warning: skipping" not in result.output
    assert "lines_read=2" in result.output


def test_analyze_auth_only_warns_about_year_anchor(tmp_path):
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", str(auth)])
    assert result.exit_code == 0
    assert "no web logs or --reference-time" in result.output


def test_analyze_reference_time_override_suppresses_year_warning(tmp_path):
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", "--reference-time", "2026-01-06", str(auth)])
    assert result.exit_code == 0
    assert "no web logs or --reference-time" not in result.output


def test_analyze_web_present_does_not_trigger_year_warning(tmp_path):
    # Web logs supply the anchor, so a mixed run never emits the auth-only warning.
    web = write(tmp_path, "webserver.log", COMBINED_LINE)
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", str(auth), str(web)])
    assert result.exit_code == 0
    assert "no web logs or --reference-time" not in result.output


# --------------------------------------------------------------------------- #
# HTML report generation + list-reports command
# --------------------------------------------------------------------------- #


def test_analyze_generates_html_report_and_prints_path(tmp_path):
    # tmp_path is where reports land (see the _isolate_reports fixture).
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    result = runner.invoke(app, ["analyze", str(auth)])
    assert result.exit_code == 0
    assert "HTML report written to" in result.output
    written = list((tmp_path / "reports").glob("report_*.html"))
    assert len(written) == 1
    assert written[0].read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_list_reports_empty_reports_dir(tmp_path):
    result = runner.invoke(app, ["list-reports"])
    assert result.exit_code == 0
    assert "No reports found" in result.output


def test_list_reports_lists_generated_report(tmp_path):
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    assert runner.invoke(app, ["analyze", str(auth)]).exit_code == 0

    result = runner.invoke(app, ["list-reports"])
    assert result.exit_code == 0
    assert "report_" in result.output
    assert ".html" in result.output


def test_help_lists_list_reports_subcommand():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "list-reports" in result.output


# --------------------------------------------------------------------------- #
# --follow
# --------------------------------------------------------------------------- #


def append(path, text):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


def live_lines(ip, when=None):
    """What a live feed looks like: an SSH burst and a traversal hit from one
    IP, timestamped around ``when`` (default: a few minutes ago).

    Auth lines carry no year, so their resolution depends on the run's anchor —
    which is the point of `test_follow_anchors_syslog_years_to_now...`.
    """
    when = when or datetime.now(UTC) - timedelta(minutes=5)
    failures = "".join(
        f"{when:%b %d %H:%M}:{s:02d} server sshd[1]: Failed password for root from {ip} port 22 ssh2\n"
        for s in range(5)
    )
    return failures, _traversal_hit(ip, time=f"{when:%d/%b/%Y:%H:%M:%S} +0000")


@pytest.fixture
def follow(monkeypatch):
    """Run `--follow` over the real tailer, with a scripted stop condition.

    The tail loop checks ``stop()`` once per polling pass, so each step runs
    just before a pass and the loop reads exactly what that step wrote; when
    the steps run out the run stops, as a Ctrl+C would. That keeps the whole
    follow path under test without threads, signals, or sleeping.
    """

    def install(*steps: Callable[[], object] | None) -> None:
        remaining = list(steps)

        def stop():
            if not remaining:
                return True
            step = remaining.pop(0)
            if step is not None:
                step()
            return False

        def patched(sources, **kwargs):
            return follow_sources(sources, **{**kwargs, "stop": stop, "poll_interval": 0})

        monkeypatch.setattr("cli.commands.analyze.follow_sources", patched)

    return install


def test_follow_prints_findings_live_and_still_writes_the_report(tmp_path, follow):
    web = write(tmp_path, "webserver.log", COMBINED_LINE)
    follow(lambda: append(web, _traversal_hit("203.0.113.5")))

    result = runner.invoke(app, ["analyze", "--follow", str(web)])

    assert result.exit_code == 0
    assert "Following 1 file(s)" in result.output
    # The live alert precedes the end-of-run report.
    live, _, report = result.output.partition("=== FINDINGS ===")
    assert "directory_traversal" in live
    assert "directory_traversal" in report
    assert len(list((tmp_path / "reports").glob("report_*.html"))) == 1


def test_follow_ignores_lines_written_before_it_started(tmp_path, follow):
    web = write(tmp_path, "webserver.log", _traversal_hit("203.0.113.5"))
    follow(None)

    result = runner.invoke(app, ["analyze", "--follow", str(web)])

    assert result.exit_code == 0
    assert "lines_read=0" in result.output
    assert "directory_traversal" not in result.output


def test_follow_short_flag_is_accepted(tmp_path, follow):
    web = write(tmp_path, "webserver.log", COMBINED_LINE)
    follow(None)

    result = runner.invoke(app, ["analyze", "-f", str(web)])

    assert result.exit_code == 0
    assert "Following 1 file(s)" in result.output


def test_follow_generates_the_report_when_interrupted(tmp_path, monkeypatch):
    web = write(tmp_path, "webserver.log", COMBINED_LINE)

    def interrupt(sources, **kwargs):
        def stop():
            raise KeyboardInterrupt

        return follow_sources(sources, **{**kwargs, "stop": stop, "poll_interval": 0})

    monkeypatch.setattr("cli.commands.analyze.follow_sources", interrupt)

    result = runner.invoke(app, ["analyze", "--follow", str(web)])

    assert result.exit_code == 0
    assert "Stopped following" in result.output
    assert "HTML report written to" in result.output


def test_follow_correlates_across_files_at_the_end_of_the_run(tmp_path, follow):
    # Findings stream out per file as they fire; joining them into an incident
    # is the correlator's job and happens once the run is stopped.
    ip = "203.0.113.50"
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    web = write(tmp_path, "webserver.log", COMBINED_LINE)
    failures, traversal = live_lines(ip)
    follow(lambda: (append(auth, failures), append(web, traversal)))

    result = runner.invoke(app, ["analyze", "--follow", str(auth), str(web)])

    assert result.exit_code == 0
    live, _, report = result.output.partition("=== FINDINGS ===")
    assert "INC-" not in live
    assert "INC-" in report


def test_follow_anchors_syslog_years_to_now_not_to_stale_web_content(tmp_path, follow):
    """The syslog year anchor is read once, at startup, from the newest
    timestamp already in a web log. When tailing, that content can be
    arbitrarily old — and a stale anchor pushes live auth lines back a year,
    which would silently break correlation with the web findings they belong to.
    """
    ip = "203.0.113.77"
    # A web log that has seen no traffic since 2024 — the anchor the old
    # default would have picked.
    web = write(tmp_path, "webserver.log", '1.2.3.4 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1\n')
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    failures, traversal = live_lines(ip)
    follow(lambda: (append(auth, failures), append(web, traversal)))

    result = runner.invoke(app, ["analyze", "--follow", str(auth), str(web)])

    assert result.exit_code == 0
    # Both fired within minutes of each other, so they belong to one incident.
    assert "INC-" in result.output


def test_follow_does_not_warn_about_the_year_anchor(tmp_path, follow):
    # Anchoring live syslog to now is exactly right when tailing, so the
    # archived-log warning would be noise here.
    auth = write(tmp_path, "auth.log", SYSLOG_LINE)
    follow(None)

    result = runner.invoke(app, ["analyze", "--follow", str(auth)])

    assert result.exit_code == 0
    assert "no web logs or --reference-time" not in result.output


def test_follow_on_an_undetectable_file_explains_why(tmp_path, follow):
    empty = write(tmp_path, "webserver.log", "")
    follow(None)

    result = runner.invoke(app, ["analyze", "--follow", str(empty)])

    assert result.exit_code == 1
    assert "at least one parseable line" in result.output
