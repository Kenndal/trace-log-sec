"""HTML reporting for trace-log-sec.

Compiles an :class:`~models.engine.AnalysisReport` into a standalone HTML file
and lists previously generated reports. Kept out of the ``engine`` package so
the detection core stays presentation-free (mirrors the ``cli.render`` split).
"""

from __future__ import annotations

from .html import render_html
from .storage import ReportInfo, list_reports, resolve_output_dir, write_report

__all__ = [
    "render_html",
    "write_report",
    "list_reports",
    "resolve_output_dir",
    "ReportInfo",
]
