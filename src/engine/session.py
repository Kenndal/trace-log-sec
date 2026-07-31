"""Incremental analysis state shared by batch and follow runs.

A session owns everything a run accumulates -- findings, parse errors, and
per-source counters -- so the caller only has to supply entries. ``feed``
handles one item at a time and returns whatever findings that item newly
emitted, which is what a live (``--follow``) run prints as it goes;
``finalize`` closes the run out into an ``AnalysisReport``.

Splitting this out of ``Engine.analyze`` keeps a single implementation of the
detection pipeline: a batch run drives the session from ``parse_file``, a
follow run drives it from the tailer, and both get identical semantics.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from constants import DEFAULT_MAX_EVIDENCE
from models import AnalysisReport, Finding, Incident, LogEntry, ParseError

from .correlation import Correlator
from .rules import Rule

_COUNTER_KEYS = ("lines_read", "parsed", "malformed", "skipped_blank")


class AnalysisSession:
    """One analysis run in progress: fed entries, finalized into a report."""

    def __init__(
        self,
        rules: list[Rule],
        *,
        correlator: Correlator | None = None,
        logger: logging.Logger | None = None,
        max_evidence: int = DEFAULT_MAX_EVIDENCE,
    ) -> None:
        self.rules = rules
        self.correlator = correlator if correlator is not None else Correlator()
        self.logger = logger or logging.getLogger("trace_log_sec.engine")
        self.max_evidence = max_evidence

        self.findings: list[Finding] = []
        self.parse_errors: list[ParseError] = []
        self.per_source: dict[str, dict[str, int]] = {}
        self._started = time.monotonic()

        # Reset every rule so a single Engine is safely re-runnable.
        for rule in self.rules:
            rule.reset()

    def counters_for(self, path: str) -> dict[str, int]:
        """Return (creating if needed) the mutable counter dict for ``path``."""
        return self.per_source.setdefault(path, dict.fromkeys(_COUNTER_KEYS, 0))

    def feed(self, item: LogEntry | ParseError, counters: dict[str, int]) -> list[Finding]:
        """Process one parsed item, returning the findings it newly emitted.

        ``counters`` is the dict from ``counters_for`` for the item's source --
        the producer (``parse_file`` or the tailer) already counted the raw
        line, so only ``parsed``/``malformed`` are tracked here.
        """
        if isinstance(item, ParseError):
            self.parse_errors.append(item)
            self.logger.warning(
                "parse error in %s line %d: %s",
                item.source,
                item.line_no,
                item.reason,
            )
            if item.line_no > 0:
                counters["malformed"] += 1
            return []

        counters["parsed"] += 1
        emitted: list[Finding] = []
        for rule in self.rules:
            try:
                emitted.extend(rule.inspect(item))
            except Exception as e:  # noqa: BLE001 (never crash on a buggy rule)
                self.logger.warning("rule %s raised on entry: %s", rule.id, e)
        self.findings.extend(emitted)
        return emitted

    def finalize(self) -> AnalysisReport:
        """Flush end-of-stream aggregates, correlate, and build the report."""
        for rule in self.rules:
            try:
                self.findings.extend(rule.flush())
            except Exception as e:  # noqa: BLE001 (never crash on a buggy rule)
                self.logger.warning("rule %s raised on flush: %s", rule.id, e)

        # Cap evidence to the engine-wide ceiling. A rule's own max_evidence
        # (if lower) already wins during collection; this only trims further.
        for f in self.findings:
            if len(f.evidence) > self.max_evidence:
                del f.evidence[self.max_evidence :]

        incidents = self.correlator.correlate(self.findings)

        return AnalysisReport(
            findings=self.findings,
            incidents=incidents,
            parse_errors=self.parse_errors,
            stats=self._build_stats(self.per_source, self.findings, incidents, self._started),
        )

    @staticmethod
    def _build_stats(
        per_source: dict[str, dict[str, int]],
        findings: list[Finding],
        incidents: list[Incident],
        started: float,
    ) -> dict[str, Any]:
        totals = {
            "lines_read": 0,
            "parsed": 0,
            "malformed": 0,
            "skipped_blank": 0,
            "findings": len(findings),
            "incidents": len(incidents),
        }
        for s in per_source.values():
            for key in _COUNTER_KEYS:
                totals[key] += s[key]
        return {
            "sources": per_source,
            "totals": totals,
            "duration_seconds": time.monotonic() - started,
        }
