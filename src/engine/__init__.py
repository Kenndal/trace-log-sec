"""trace-log-sec detection engine.

Public surface: data models, parsers, rules, correlation, and the ``Engine``
orchestrator. No CLI/presentation lives here.
"""

from __future__ import annotations

from models import (
    AnalysisReport,
    AuthLogEntry,
    AuthOutcome,
    Finding,
    Incident,
    LogEntry,
    LogSource,
    ParseError,
    Severity,
    WebLogEntry,
)

from .correlation import Correlator
from .engine import Engine
from .parsers import (
    CombinedLogParser,
    LogParser,
    MalformedLineError,
    SyslogAuthParser,
    parse_file,
)
from .rules import (
    RULE_TYPES,
    PatternSignatureRule,
    Rule,
    ThresholdRule,
    build_rules,
    register,
)

__all__ = [
    # models
    "Severity",
    "AuthOutcome",
    "LogEntry",
    "WebLogEntry",
    "AuthLogEntry",
    "ParseError",
    "Finding",
    "Incident",
    # parsers
    "LogParser",
    "CombinedLogParser",
    "SyslogAuthParser",
    "MalformedLineError",
    "parse_file",
    # rules
    "Rule",
    "PatternSignatureRule",
    "ThresholdRule",
    "RULE_TYPES",
    "register",
    "build_rules",
    # correlation
    "Correlator",
    # engine
    "Engine",
    "LogSource",
    "AnalysisReport",
]
