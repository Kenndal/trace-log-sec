"""Renders an :class:`~models.engine.AnalysisReport` to a standalone HTML string.

Pure and I/O-free (mirrors ``cli/render.py``): given a report it returns the
document text; writing to disk is :mod:`reporter.storage`'s job. Uses only the
standard library — plain string building plus :func:`html.escape` — so the
report has no framework/templating dependency (MVP-focused, per the reporting
requirements).

Every value that originates in a log line (raw text, IPs, request targets,
user-agents, narratives) is attacker-controlled, so it is passed through
:func:`html.escape` before being embedded. The report is meant to be opened in
a browser; rendering hostile log content unescaped would be a stored-XSS hole.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from html import escape

from models import AnalysisReport, Finding, Incident, ParseError, Severity

# Severity → CSS accent colour, ordered most→least severe for the legend.
_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#7c1d1d",
    Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#c2760c",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#4b5563",
}

_STYLE = """\
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #1f2937;
  background: #f3f4f6;
  line-height: 1.5;
}
.wrap { max-width: 1240px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
header.report { border-bottom: 3px solid #111827; padding-bottom: 1rem; margin-bottom: 2rem; }
header.report h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
header.report .meta { color: #6b7280; font-size: .9rem; }
h2 { font-size: 1.2rem; margin: 2.5rem 0 1rem; padding-bottom: .35rem; border-bottom: 1px solid #d1d5db; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: .75rem; }
.tile { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; }
.tile .n { font-size: 1.75rem; font-weight: 700; }
.tile .l { color: #6b7280; font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; }
.tile.alert .n { color: #b91c1c; }
.sev-legend { display: flex; flex-wrap: wrap; gap: .5rem; margin: 1rem 0 0; }
.badge {
  display: inline-block; padding: .1rem .5rem; border-radius: 999px;
  color: #fff; font-size: .75rem; font-weight: 600; letter-spacing: .02em;
}
.card {
  background: #fff; border: 1px solid #e5e7eb; border-left-width: 5px;
  border-radius: 8px; padding: 1rem 1.15rem; margin-bottom: 1rem;
}
.card h3 { margin: 0 0 .35rem; font-size: 1rem; }
.card .narrative { color: #374151; margin: .5rem 0; }
.card .sub-findings { margin: .5rem 0 0; padding-left: 1.1rem; }
.card .sub-findings li { margin: .15rem 0; }
.src { display: inline-block; background: #eef2ff; color: #3730a3; border-radius: 4px;
  padding: 0 .4rem; font-size: .75rem; margin-left: .25rem; }
table { min-width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb;
  border-radius: 8px; overflow: hidden; font-size: .88rem; }
th, td { text-align: left; padding: .55rem .65rem; border-bottom: 1px solid #eef0f3; vertical-align: top; }
th { background: #f9fafb; font-size: .78rem; text-transform: uppercase; letter-spacing: .03em; color: #4b5563; }
tr:last-child td { border-bottom: none; }
td.mono, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
td.ts { white-space: nowrap; }
.evidence-col { min-width: 240px; }
details.evidence summary {
  cursor: pointer; color: #2563eb; font-size: .78rem; font-weight: 600; white-space: nowrap;
}
details.evidence summary:hover { text-decoration: underline; }
details.evidence pre {
  margin: .5rem 0 0; padding: .6rem .7rem; background: #111827; color: #e5e7eb;
  border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .74rem; line-height: 1.5; max-height: 260px;
  overflow: auto; white-space: pre-wrap; overflow-wrap: break-word;
}
details.evidence pre .line-no { color: #9ca3af; }
.no-evidence { color: #9ca3af; }
.empty { color: #6b7280; font-style: italic; background: #fff; border: 1px dashed #d1d5db;
  border-radius: 8px; padding: 1rem; }
.table-scroll { overflow-x: auto; }
footer { margin-top: 3rem; color: #9ca3af; font-size: .8rem; text-align: center; }
"""


def _fmt_dt(value: datetime) -> str:
    """Human-readable UTC-ish timestamp; falls back to str() defensively."""
    try:
        return value.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    except (ValueError, AttributeError):  # pragma: no cover - defensive
        return escape(str(value))


def _badge(severity: Severity) -> str:
    color = _SEVERITY_COLORS.get(severity, "#4b5563")
    return f'<span class="badge" style="background:{color}">{escape(severity.name)}</span>'


def _tile(label: str, value: object, *, alert: bool = False) -> str:
    cls = "tile alert" if alert else "tile"
    return f'<div class="{cls}"><div class="n">{escape(str(value))}</div><div class="l">{escape(label)}</div></div>'


def _evidence_block(finding: Finding) -> str:
    """A click-to-expand ``<details>`` disclosure listing a finding's raw log lines.

    Native HTML, no JavaScript — collapsed by default so the table stays
    scannable; expanding it shows the exact source/line/raw text behind the
    finding, saving a manual grep through the original log file. Evidence is
    already capped per-finding by the engine's ``max_evidence`` (see
    ``constants.DEFAULT_MAX_EVIDENCE`` / config.yaml's ``engine.max_evidence``).
    """
    if not finding.evidence:
        return '<span class="no-evidence">no evidence captured</span>'
    lines = "\n".join(
        f'<span class="line-no">[{escape(e.source)} L{e.line_no}]</span> {escape(e.raw)}' for e in finding.evidence
    )
    count = len(finding.evidence)
    label = f"{count} raw log line{'s' if count != 1 else ''}"
    return f'<details class="evidence"><summary>{escape(label)}</summary><pre>{lines}</pre></details>'


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1
    return counts


def _executive_summary(report: AnalysisReport) -> str:
    totals = report.stats.get("totals", {})
    duration = report.stats.get("duration_seconds")
    duration_str = f"{duration:.3f}s" if isinstance(duration, (int, float)) else "-"

    tiles = [
        _tile("Findings", totals.get("findings", len(report.findings)), alert=bool(report.findings)),
        _tile("Incidents", totals.get("incidents", len(report.incidents)), alert=bool(report.incidents)),
        _tile("Lines read", totals.get("lines_read", "-")),
        _tile("Parsed", totals.get("parsed", "-")),
        _tile("Malformed", totals.get("malformed", "-"), alert=bool(totals.get("malformed"))),
        _tile("Duration", duration_str),
    ]

    counts = _severity_counts(report.findings)
    legend = "".join(
        f'<span class="badge" style="background:{_SEVERITY_COLORS[sev]}">{escape(sev.name)}: {counts[sev]}</span>'
        for sev in sorted(_SEVERITY_COLORS, reverse=True)
        if counts.get(sev)
    )
    legend_html = f'<div class="sev-legend">{legend}</div>' if legend else ""

    return f'<h2>Executive summary</h2>\n<div class="tiles">{"".join(tiles)}</div>\n{legend_html}'


def _incident_card(incident: Incident) -> str:
    color = _SEVERITY_COLORS.get(incident.severity, "#4b5563")
    span = incident.last_seen - incident.first_seen
    ip = escape(incident.source_ip or "-")

    items = []
    for finding in sorted(incident.findings, key=lambda f: (-f.severity, f.rule_id)):
        srcs = "".join(f'<span class="src">{escape(s)}</span>' for s in sorted(finding.sources))
        items.append(
            f"<li>{_badge(finding.severity)} <strong>{escape(finding.title)}</strong> "
            f"&times;{finding.count}{srcs}{_evidence_block(finding)}</li>"
        )
    sub = f'<ul class="sub-findings">{"".join(items)}</ul>' if items else ""

    return (
        f'<div class="card" style="border-left-color:{color}">'
        f"<h3>{_badge(incident.severity)} {escape(incident.incident_id)} "
        f'<span class="mono">{ip}</span></h3>'
        f'<div class="meta mono">{escape(_fmt_dt(incident.first_seen))} &rarr; '
        f"{escape(_fmt_dt(incident.last_seen))} (span {escape(str(span))})</div>"
        f'<p class="narrative">{escape(incident.narrative)}</p>'
        f"{sub}</div>"
    )


def _incidents_section(incidents: list[Incident]) -> str:
    body = (
        "".join(_incident_card(i) for i in incidents)
        if incidents
        else '<div class="empty">No correlated incidents — no IP triggered multiple '
        "rules or sources within the correlation window.</div>"
    )
    return f"<h2>Correlated incidents ({len(incidents)})</h2>\n{body}"


def _findings_section(findings: list[Finding]) -> str:
    if not findings:
        return (
            "<h2>Detected findings (0)</h2>\n"
            '<div class="empty">No suspicious activity detected — the analyzed logs are clean.</div>'
        )
    rows = []
    for f in sorted(findings, key=lambda f: (-f.severity, f.rule_id)):
        srcs = ", ".join(sorted(f.sources)) or "-"
        rows.append(
            "<tr>"
            f"<td>{_badge(f.severity)}</td>"
            f"<td>{escape(f.title)}<br><span class='mono' style='color:#6b7280'>{escape(f.rule_id)}</span></td>"
            f"<td class='mono'>{escape(f.source_ip or '-')}</td>"
            f"<td>{f.count}</td>"
            f"<td>{escape(srcs)}</td>"
            f"<td class='mono ts'>{escape(_fmt_dt(f.first_seen))}<br>{escape(_fmt_dt(f.last_seen))}</td>"
            f"<td>{escape(f.description)}</td>"
            f"<td class='evidence-col'>{_evidence_block(f)}</td>"
            "</tr>"
        )
    return (
        f"<h2>Detected findings ({len(findings)})</h2>\n"
        '<div class="table-scroll"><table><thead><tr>'
        "<th>Severity</th><th>Type</th><th>Source IP</th><th>Count</th>"
        "<th>Log source</th><th>First / last seen</th><th>Description</th>"
        "<th class='evidence-col'>Evidence</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _parse_errors_section(errors: list[ParseError]) -> str:
    if not errors:
        return ""
    rows = "".join(
        "<tr>"
        f"<td class='mono'>{escape(e.source)}</td>"
        f"<td>{e.line_no}</td>"
        f"<td>{escape(e.reason)}</td>"
        f"<td class='mono'>{escape(e.raw[:120])}</td>"
        "</tr>"
        for e in errors
    )
    return (
        f"<h2>Parse errors ({len(errors)})</h2>\n"
        '<div class="table-scroll"><table><thead><tr>'
        "<th>Source</th><th>Line</th><th>Reason</th><th>Raw</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def render_html(report: AnalysisReport, *, generated_at: datetime) -> str:
    """Render ``report`` into a complete, self-contained HTML document.

    ``generated_at`` is the report's stated generation time (shown in the
    header). The returned string embeds all CSS inline and references no
    external assets, so it opens correctly straight from disk.
    """
    title = "TraceLogSec Security Analysis Report"
    body = "\n".join(
        [
            _executive_summary(report),
            _incidents_section(report.incidents),
            _findings_section(report.findings),
            _parse_errors_section(report.parse_errors),
        ]
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{escape(title)}</title>\n<style>{_STYLE}</style>\n</head>\n<body>\n"
        '<div class="wrap">\n'
        f'<header class="report"><h1>{escape(title)}</h1>'
        f'<div class="meta">Generated {escape(_fmt_dt(generated_at))}</div></header>\n'
        f"{body}\n"
        "<footer>Generated by TraceLogSec.</footer>\n"
        "</div>\n</body>\n</html>\n"
    )
