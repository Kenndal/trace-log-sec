"""The ``list-reports`` command: list previously generated HTML reports."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from cli.app import app
from config.settings import load_settings
from reporter import list_reports, resolve_output_dir
from utils.exceptions import ConfigError

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


@app.command(name="list-reports")
def list_reports_command(config: ConfigOption = None) -> None:
    """List generated HTML reports (newest first) with their timestamps.

    Scans the directory configured in ``config.yaml``'s ``reporting.output_dir``.
    """
    try:
        settings = load_settings(config) if config is not None else load_settings()
    except ConfigError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    output_dir = resolve_output_dir(settings.reporting.output_dir)
    reports = list_reports(output_dir)

    if not reports:
        typer.secho(f"No reports found in {output_dir}", fg=typer.colors.YELLOW)
        return

    typer.echo(f"Reports in {output_dir} ({len(reports)}):")
    for report in reports:
        timestamp = report.generated_at.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
        typer.echo(f"  {timestamp}  {report.path}")
