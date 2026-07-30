"""Engine orchestration.

Feeds parsed entries through every rule, flushes end-of-stream aggregates, and
runs the correlator. Never crashes on bad input: parse failures (including a
missing file) are captured as ``ParseError`` unless ``strict=True``.

See docs/engine-plan.md §8.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Sequence

from .correlation import Correlator
from .models import AnalysisReport, Finding, Incident, LogEntry, LogSource, ParseError
from .parsers import parse_file
from .rules import Rule


class Engine:
    """Orchestrates parsing → detection → correlation over a set of sources."""

    def __init__(
        self,
        rules: Sequence[Rule],
        *,
        correlator: Correlator | None = None,
        logger: logging.Logger | None = None,
        max_evidence: int = 20,
        strict: bool = False,
    ) -> None:
        self.rules = list(rules)
        self.correlator = correlator if correlator is not None else Correlator()
        self.logger = logger or logging.getLogger("trace_log_sec.engine")
        self.max_evidence = max_evidence
        self.strict = strict

    def analyze(self, sources: Iterable[LogSource]) -> AnalysisReport:
        started = time.monotonic()

        # 0. Reset every rule so a single Engine is safely re-runnable.
        for rule in self.rules:
            rule.reset()

        findings: list[Finding] = []
        parse_errors: list[ParseError] = []
        per_source: dict[str, dict[str, int]] = {}

        for source in sources:
            stats = per_source.setdefault(
                source.path,
                {"lines_read": 0, "parsed": 0, "malformed": 0, "skipped_blank": 0},
            )
            for item in parse_file(source.path, source.parser, counters=stats):
                if isinstance(item, ParseError):
                    if item.line_no == 0 and self.strict:
                        raise FileNotFoundError(item.reason)
                    parse_errors.append(item)
                    self.logger.warning(
                        "parse error in %s line %d: %s",
                        item.source,
                        item.line_no,
                        item.reason,
                    )
                    if item.line_no > 0:
                        stats["malformed"] += 1
                    continue

                stats["parsed"] += 1
                for rule in self.rules:
                    findings.extend(rule.inspect(item))

        # 4. Flush end-of-stream aggregates.
        for rule in self.rules:
            findings.extend(rule.flush())

        # Cap evidence to the engine-wide ceiling. A rule's own max_evidence
        # (if lower) already wins during collection; this only trims further.
        for f in findings:
            if len(f.evidence) > self.max_evidence:
                del f.evidence[self.max_evidence :]

        # 5. Correlate.
        incidents = self.correlator.correlate(findings)

        stats = self._build_stats(per_source, findings, incidents, started)
        return AnalysisReport(
            findings=findings,
            incidents=incidents,
            parse_errors=parse_errors,
            stats=stats,
        )

    @staticmethod
    def _build_stats(
        per_source: dict[str, dict[str, int]],
        findings: list[Finding],
        incidents: list[Incident],
        started: float,
    ) -> dict:
        totals = {
            "lines_read": 0,
            "parsed": 0,
            "malformed": 0,
            "skipped_blank": 0,
            "findings": len(findings),
            "incidents": len(incidents),
        }
        for s in per_source.values():
            for key in ("lines_read", "parsed", "malformed", "skipped_blank"):
                totals[key] += s[key]
        return {
            "sources": per_source,
            "totals": totals,
            "duration_seconds": time.monotonic() - started,
        }
