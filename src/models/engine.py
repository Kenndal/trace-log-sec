"""Data models dedicated to :mod:`engine.engine`."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from models.correlation import Incident
from models.parsers import ParseError
from models.rules import Finding

if TYPE_CHECKING:
    from engine.parsers import LogParser


@dataclass(frozen=True, kw_only=True)
class LogSource:
    """A file to analyze paired with the parser that understands it."""

    path: str
    parser: LogParser


@dataclass(kw_only=True)
class AnalysisReport:
    """Plain result container handed to a downstream presenter."""

    findings: list[Finding] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    parse_errors: list[ParseError] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
