#!/usr/bin/env python3
"""Developer smoke-test / demo runner for the detection engine.

Not the CLI (that layer is intentionally out of scope) — a thin harness that
runs the default rule set over two log files and prints the analysis report.

Usage:
    python3 scripts/run_demo.py                       # uses tests/fixtures/*
    python3 scripts/run_demo.py AUTH_LOG WEBSERVER_LOG

Run from the repo root so the ``engine`` package is importable.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running as `python3 scripts/run_demo.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import (  # noqa: E402
    CombinedLogParser,
    Engine,
    LogSource,
    SyslogAuthParser,
    WebLogEntry,
    default_rules,
    parse_file,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTH = REPO_ROOT / "tests" / "fixtures" / "auth.log"
DEFAULT_WEB = REPO_ROOT / "tests" / "fixtures" / "webserver.log"


def _reference_time(web_path: str) -> datetime:
    """Anchor auth-log year resolution (§5.1) to the web log's own dates.

    The auth log carries no year. Anchoring to "now" would silently pick the
    wrong year whenever the log data itself isn't from today (e.g. sample or
    archived logs), which breaks cross-file correlation by putting each file
    in a different year. The web log's newest timestamp is a same-run source
    of truth, so use that instead — falling back to "now" only if the web log
    has no parseable timestamp at all.
    """
    latest: datetime | None = None
    for item in parse_file(web_path, CombinedLogParser()):
        if isinstance(item, WebLogEntry) and (latest is None or item.timestamp > latest):
            latest = item.timestamp
    return latest if latest is not None else datetime.now(timezone.utc)


def main(argv: list[str]) -> int:
    if len(argv) == 3:
        auth_path, web_path = argv[1], argv[2]
    elif len(argv) == 1:
        auth_path, web_path = str(DEFAULT_AUTH), str(DEFAULT_WEB)
    else:
        print(__doc__)
        return 2

    engine = Engine(default_rules())
    report = engine.analyze(
        [
            LogSource(
                path=auth_path,
                parser=SyslogAuthParser(reference_time=_reference_time(web_path)),
            ),
            LogSource(path=web_path, parser=CombinedLogParser()),
        ]
    )

    print("=== FINDINGS ===")
    if not report.findings:
        print("  (none)")
    for f in sorted(report.findings, key=lambda f: (-f.severity, f.rule_id)):
        ip = f.source_ip or "-"
        print(f"  [{f.severity.name:8}] {f.rule_id:22} ip={ip:15} count={f.count}  {f.title}")

    print("\n=== INCIDENTS ===")
    if not report.incidents:
        print("  (none)")
    for i in report.incidents:
        print(f"  {i.incident_id} [{i.severity.name}] {i.source_ip}")
        print(f"    {i.narrative}")

    print("\n=== PARSE ERRORS ===")
    if not report.parse_errors:
        print("  (none)")
    for e in report.parse_errors:
        print(f"  {e.source} L{e.line_no}: {e.reason}  |  {e.raw[:50]!r}")

    t = report.stats["totals"]
    print(
        f"\n=== STATS === lines_read={t['lines_read']} parsed={t['parsed']} "
        f"malformed={t['malformed']} findings={t['findings']} incidents={t['incidents']} "
        f"({report.stats['duration_seconds']:.4f}s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
