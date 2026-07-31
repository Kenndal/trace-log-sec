"""Engine orchestration.

Feeds parsed entries through every rule, flushes end-of-stream aggregates, and
runs the correlator. Never crashes on bad input: parse failures (including a
missing file) are captured as ``ParseError``.

The per-entry work lives in :class:`engine.session.AnalysisSession`; this class
just drives it over a fixed set of files. A ``--follow`` run drives the same
session from the tailer instead.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
import logging

from constants import DEFAULT_MAX_EVIDENCE
from models import AnalysisReport, LogSource

from .correlation import Correlator
from .parsers import parse_file
from .rules import Rule
from .session import AnalysisSession


class Engine:
    """Orchestrates parsing → detection → correlation over a set of sources."""

    def __init__(
        self,
        rules: Sequence[Rule],
        *,
        correlator: Correlator | None = None,
        logger: logging.Logger | None = None,
        max_evidence: int = DEFAULT_MAX_EVIDENCE,
    ) -> None:
        self.rules = list(rules)
        self.correlator = correlator if correlator is not None else Correlator()
        self.logger = logger or logging.getLogger("trace_log_sec.engine")
        self.max_evidence = max_evidence

    def session(self) -> AnalysisSession:
        """Start an empty session over this engine's rules and correlator."""
        return AnalysisSession(
            self.rules,
            correlator=self.correlator,
            logger=self.logger,
            max_evidence=self.max_evidence,
        )

    def analyze(self, sources: Iterable[LogSource]) -> AnalysisReport:
        session = self.session()
        for source in sources:
            counters = session.counters_for(source.path)
            for item in parse_file(source.path, source.parser, counters=counters):
                session.feed(item, counters)
        return session.finalize()
