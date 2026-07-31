"""Renders an ``AnalysisReport`` to the terminal.

Kept separate from ``cli.commands.analyze`` so a future command can reuse it.
"""

from __future__ import annotations

import typer

from models import AnalysisReport


def render_report(report: AnalysisReport) -> None:
    typer.echo("=== FINDINGS ===")
    if not report.findings:
        typer.echo("  (none)")
    for finding in sorted(report.findings, key=lambda f: (-f.severity, f.rule_id)):
        ip = finding.source_ip or "-"
        typer.echo(
            f"  [{finding.severity.name:8}] {finding.rule_id:22} ip={ip:15} count={finding.count}  {finding.title}"
        )

    typer.echo("\n=== INCIDENTS ===")
    if not report.incidents:
        typer.echo("  (none)")
    for incident in report.incidents:
        typer.echo(f"  {incident.incident_id} [{incident.severity.name}] {incident.source_ip}")
        typer.echo(f"    {incident.narrative}")

    typer.echo("\n=== PARSE ERRORS ===")
    if not report.parse_errors:
        typer.echo("  (none)")
    for error in report.parse_errors:
        typer.echo(f"  {error.source} L{error.line_no}: {error.reason}  |  {error.raw[:50]!r}")

    totals = report.stats["totals"]
    typer.echo(
        f"\n=== STATS === lines_read={totals['lines_read']} parsed={totals['parsed']} "
        f"malformed={totals['malformed']} findings={totals['findings']} "
        f"incidents={totals['incidents']} ({report.stats['duration_seconds']:.4f}s)"
    )
