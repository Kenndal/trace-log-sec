"""The ``analyze`` command: run log analysis over one or more .log files."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from cli.app import app
from cli.formats import build_log_sources
from cli.render import render_report
from cli.validation import validate_log_files
from config.settings import load_settings, rule_specs
from engine import Engine, build_rules
from utils.exceptions import CliInputError, ConfigError, RuleConfigError


def _log_files_callback(value: list[Path]) -> list[Path]:
    try:
        return validate_log_files(value)
    except CliInputError as exc:
        raise typer.BadParameter(str(exc)) from exc


LogFilesArgument = Annotated[
    list[Path],
    typer.Argument(
        callback=_log_files_callback,
        help="Log files to analyze. Format (Combined access log vs BSD syslog auth log) is auto-detected per file.",
    ),
]


@app.command()
def analyze(log_files: LogFilesArgument) -> None:
    """Analyze one or more log files for security incidents."""
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

    report = Engine(rules).analyze(sources)
    render_report(report)
