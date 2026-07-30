"""Core data models for the log-analysis engine.

Split into one module per consumer in ``engine``: :mod:`models.parsers`,
:mod:`models.rules`, :mod:`models.correlation`, :mod:`models.engine`. This
package re-exports the full public surface so callers can keep writing
``from models import X``.

See docs/engine-plan.md §4.
"""

from __future__ import annotations

from models.correlation import Incident
from models.engine import AnalysisReport, LogSource
from models.parsers import AuthLogEntry, AuthOutcome, LogEntry, ParseError, WebLogEntry
from models.rules import Finding, Severity

__all__ = [
    # parsers
    "AuthOutcome",
    "LogEntry",
    "WebLogEntry",
    "AuthLogEntry",
    "ParseError",
    # rules
    "Severity",
    "Finding",
    # correlation
    "Incident",
    # engine
    "LogSource",
    "AnalysisReport",
]
