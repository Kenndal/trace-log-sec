"""The ``analyze`` command: run log analysis over one or more .log files."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
import signal
import threading
from typing import Annotated

import typer

from cli.app import app
from cli.formats import build_log_sources
from cli.render import render_live_finding, render_report
from cli.validation import validate_log_files
from config.settings import load_settings, rule_specs
from engine import AnalysisReport, Correlator, Engine, LogSource, build_rules, follow_sources
from reporter import write_report
from utils.exceptions import CliInputError, ConfigError, ReportError, RuleConfigError


def _log_files_callback(value: list[Path]) -> list[Path]:
    try:
        return validate_log_files(value)
    except CliInputError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _resolve[T](cli_value: T | None, config_value: T) -> T:
    """Command-line flag → config.yaml value (already includes its own default).

    ``None`` (never passed on the command line) is the only value that falls
    through — an explicit falsy override (``0``, ``0.0``, ``False``) must win,
    so this can't be a plain ``cli_value or config_value``.
    """
    return config_value if cli_value is None else cli_value


LogFilesArgument = Annotated[
    list[Path],
    typer.Argument(
        callback=_log_files_callback,
        help="Log files to analyze. Format (Combined access log vs BSD syslog auth log) is auto-detected per file.",
    ),
]

MaxEvidenceOption = Annotated[
    int | None,
    typer.Option(
        min=0,
        help="Max evidence lines stored per finding. Overrides config.yaml's engine.max_evidence.",
    ),
]
WindowMinutesOption = Annotated[
    float | None,
    typer.Option(
        min=0,
        help="Correlation clustering window, in minutes. Overrides config.yaml's correlation.window_minutes.",
    ),
]
ReferenceTimeOption = Annotated[
    datetime | None,
    typer.Option(
        formats=["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"],
        help=(
            "Anchor (ISO 8601) for resolving the missing year in BSD syslog auth timestamps. "
            "Defaults to the newest web-log timestamp in this run, or the current time if no "
            "web logs are given — pass this explicitly for archived/historical auth-only logs."
        ),
    ),
]
ConfigOption = Annotated[
    Path | None,
    typer.Option(
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to a YAML config file to use instead of the bundled config.yaml.",
    ),
]
FollowOption = Annotated[
    bool,
    typer.Option(
        "--follow",
        "-f",
        help=(
            "Keep following the files like 'tail -f': analyze lines as they are appended, "
            "printing findings live. Stop with Ctrl+C to get the usual report."
        ),
    ),
]


@contextmanager
def _stop_on_sigterm(stop: threading.Event) -> Iterator[None]:
    """Treat SIGTERM like Ctrl+C, so a ``docker stop`` still yields a report."""
    try:
        previous = signal.signal(signal.SIGTERM, lambda *_: stop.set())
    except ValueError:  # not the main thread (e.g. an embedding test runner)
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _run_follow(engine: Engine, sources: Sequence[LogSource]) -> AnalysisReport:
    """Tail ``sources`` until interrupted, then close the session out.

    Findings print as they fire; the accumulated session is finalized (flush →
    correlate) on the way out, so stopping produces exactly the same report a
    batch run over the same lines would.
    """
    session = engine.session()
    stop = threading.Event()

    typer.secho(
        f"Following {len(sources)} file(s) — press Ctrl+C to stop and generate the report.",
        fg=typer.colors.CYAN,
        err=True,
    )

    with _stop_on_sigterm(stop):
        try:
            for path, item in follow_sources(sources, counters=session.counters_for, stop=stop.is_set):
                for finding in session.feed(item, session.counters_for(path)):
                    render_live_finding(finding)
        except KeyboardInterrupt:
            pass

    typer.secho("\nStopped following. Generating report…", fg=typer.colors.CYAN, err=True)
    return session.finalize()


@app.command()
def analyze(
    log_files: LogFilesArgument,
    max_evidence: MaxEvidenceOption = None,
    window_minutes: WindowMinutesOption = None,
    reference_time: ReferenceTimeOption = None,
    config: ConfigOption = None,
    follow: FollowOption = False,
) -> None:
    """Analyze one or more log files for security incidents.

    Engine/correlation options default to config.yaml's ``engine``/
    ``correlation`` sections, which in turn default to the engine's own
    built-in defaults — an explicit flag here always wins. ``--config`` swaps
    out the entire config file (rules included) for this run.

    ``--follow`` switches from a one-shot pass to continuous tailing: the files
    are opened at their end, findings print as they fire, and the report is
    written when you stop the run.
    """
    # A follow run analyzes lines as they are written, so the current time is
    # the right syslog year anchor. The default (newest timestamp already in a
    # web log) would read whatever happens to be in the file at startup, which
    # for a quiet or freshly rotated log can be arbitrarily old — and a stale
    # anchor silently pushes live auth lines back a year, breaking correlation
    # with the web findings they belong to.
    anchor = datetime.now(UTC) if follow and reference_time is None else reference_time
    sources, skipped, anchored_to_now = build_log_sources(log_files, reference_time=anchor)

    for path in skipped:
        typer.secho(
            f"Warning: skipping {path} — does not match a known log format",
            fg=typer.colors.YELLOW,
            err=True,
        )

    if not sources:
        typer.secho("Error: no recognized log files to analyze.", fg=typer.colors.RED, err=True)
        if follow:
            # Format detection sniffs existing content, so a file that is still
            # empty (freshly rotated, say) can't be assigned a parser yet.
            typer.secho(
                "Hint: with --follow, each file must already hold at least one parseable "
                "line so its format can be detected.",
                fg=typer.colors.YELLOW,
                err=True,
            )
        raise typer.Exit(code=1)

    # Never true under --follow (which anchors explicitly): the warning is
    # about archived auth-only logs, where guessing the year can be wrong.
    if anchored_to_now:
        typer.secho(
            "Warning: resolving syslog years against the current time — no web logs or "
            "--reference-time to anchor to. Archived auth logs may get the wrong year "
            "(silently skewing threshold windows and correlation); pass --reference-time "
            "for historical analysis.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    try:
        settings = load_settings(config) if config is not None else load_settings()
        rules = build_rules(rule_specs(settings))
    except (ConfigError, RuleConfigError) as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    effective_max_evidence = _resolve(max_evidence, settings.engine.max_evidence)
    effective_window_minutes = _resolve(window_minutes, settings.correlation.window_minutes)

    correlator = Correlator(window=timedelta(minutes=effective_window_minutes))
    engine = Engine(
        rules,
        correlator=correlator,
        max_evidence=effective_max_evidence,
    )
    report = _run_follow(engine, sources) if follow else engine.analyze(sources)
    render_report(report)

    # Persist an HTML report. A write failure (e.g. an unwritable output dir)
    # must not lose the terminal analysis above, so it only warns.
    try:
        report_path = write_report(report, settings.reporting.output_dir)
    except ReportError as exc:
        typer.secho(f"Warning: {exc}", fg=typer.colors.YELLOW, err=True)
    else:
        typer.secho(f"\nHTML report written to {report_path}", fg=typer.colors.GREEN)
