"""Renders an ``AnalysisReport`` to the terminal.

Kept separate from ``cli.commands.analyze`` so a future command can reuse it.
"""

from __future__ import annotations

from datetime import datetime

import typer

from models import AnalysisReport, Finding, Severity

_SEVERITY_COLORS = {
    Severity.INFO: typer.colors.BLUE,
    Severity.LOW: typer.colors.CYAN,
    Severity.MEDIUM: typer.colors.YELLOW,
    Severity.HIGH: typer.colors.RED,
    Severity.CRITICAL: typer.colors.BRIGHT_RED,
}


def render_live_finding(finding: Finding, *, now: datetime | None = None) -> None:
    """Print a one-line alert for a finding as it fires during a follow run.

    Prefixed with wall-clock time (when the operator saw it), while the
    finding's own timestamps stay event time — the two differ when a log is
    written with a delay, and the final report only shows the latter.
    """
    seen_at = (now or datetime.now().astimezone()).strftime("%H:%M:%S")
    ip = finding.source_ip or "-"
    typer.secho(
        f"[{seen_at}] [{finding.severity.name:8}] {finding.rule_id:22} ip={ip:15} "
        f"count={finding.count}  {finding.title}",
        fg=_SEVERITY_COLORS.get(finding.severity),
    )


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
