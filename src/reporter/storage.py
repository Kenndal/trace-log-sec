"""Filesystem side of reporting: writing reports and listing existing ones.

Kept apart from :mod:`reporter.html` (which is pure) so rendering stays
I/O-free and unit-testable. Callers pass an explicit output directory; config
resolution lives in the CLI layer, keeping this module free of any config
dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from constants import REPORT_FILENAME_FORMAT, REPORT_GLOB
from models import AnalysisReport
from utils.exceptions import ReportError

from .html import render_html

# reporter/storage.py -> reporter -> src -> project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, kw_only=True)
class ReportInfo:
    """A generated report file on disk, with the time parsed from its name."""

    path: Path
    generated_at: datetime


def resolve_output_dir(output_dir: str | Path) -> Path:
    """Resolve a configured output dir to an absolute path.

    Absolute paths are returned unchanged; a relative path is resolved against
    the project root, so reports land in the same place regardless of the
    caller's working directory.
    """
    path = Path(output_dir)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def write_report(
    report: AnalysisReport,
    output_dir: str | Path,
    *,
    generated_at: datetime | None = None,
) -> Path:
    """Render ``report`` and write it to ``output_dir``, returning its path.

    Creates ``output_dir`` (and parents) if missing. The filename follows the
    ``report_YYYY_MM_DD_HH_MM_SS.html`` convention, timestamped with
    ``generated_at`` (defaulting to now, UTC). Any filesystem failure — an
    unwritable directory, a permission error — is raised as ``ReportError``.
    """
    when = generated_at if generated_at is not None else datetime.now(UTC)
    target_dir = resolve_output_dir(output_dir)
    destination = target_dir / when.strftime(REPORT_FILENAME_FORMAT)
    html = render_html(report, generated_at=when)
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        destination.write_text(html, encoding="utf-8")
    except OSError as exc:
        raise ReportError(destination, str(exc)) from exc
    return destination


def list_reports(output_dir: str | Path) -> list[ReportInfo]:
    """List generated reports in ``output_dir``, newest first.

    A missing directory yields an empty list (not an error). Files whose names
    don't match the ``report_YYYY_MM_DD_HH_MM_SS.html`` convention are ignored.
    """
    target_dir = resolve_output_dir(output_dir)
    if not target_dir.is_dir():
        return []

    reports: list[ReportInfo] = []
    for path in target_dir.glob(REPORT_GLOB):
        if not path.is_file():
            continue
        try:
            generated_at = datetime.strptime(path.name, REPORT_FILENAME_FORMAT).replace(tzinfo=UTC)
        except ValueError:
            continue  # not one of ours despite the glob match
        reports.append(ReportInfo(path=path, generated_at=generated_at))

    reports.sort(key=lambda r: r.generated_at, reverse=True)
    return reports
