"""The ``analyze`` command: run log analysis over one or more .log files."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer

from cli.app import app
from cli.formats import build_log_sources
from cli.render import render_report
from cli.validation import validate_log_files
from config.settings import load_settings, rule_specs
from engine import Correlator, Engine, build_rules
from utils.exceptions import CliInputError, ConfigError, RuleConfigError


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


@app.command()
def analyze(
    log_files: LogFilesArgument,
    max_evidence: MaxEvidenceOption = None,
    window_minutes: WindowMinutesOption = None,
) -> None:
    """Analyze one or more log files for security incidents.

    Engine/correlation options default to config.yaml's ``engine``/
    ``correlation`` sections, which in turn default to the engine's own
    built-in defaults — an explicit flag here always wins.
    """
    sources, skipped = build_log_sources(log_files)

    for path in skipped:
        typer.secho(
            f"Warning: skipping {path} — does not match a known log format",
            fg=typer.colors.YELLOW,
            err=True,
        )

    if not sources:
        typer.secho("Error: no recognized log files to analyze.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        settings = load_settings()
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
    report = engine.analyze(sources)
    render_report(report)
