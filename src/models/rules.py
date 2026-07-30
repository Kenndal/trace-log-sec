"""Data models dedicated to :mod:`engine.rules`.

``Finding`` is a mutable aggregate the engine builds up during a run, then
hands off read-only to a downstream presenter.

See docs/engine-plan.md §4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any

from models.parsers import LogEntry


class Severity(IntEnum):
    """Ordered severity — comparable so findings/incidents sort naturally."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def from_name(cls, name: str) -> Severity:
        """Resolve a case-insensitive name (e.g. ``"high"``) to a member."""
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            valid = ", ".join(m.name.lower() for m in cls)
            raise ValueError(f"unknown severity {name!r}; expected one of {valid}") from exc


@dataclass(kw_only=True)
class Finding:
    """A single detection result for one entity (IP), aggregated over a run."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    first_seen: datetime
    last_seen: datetime
    source_ip: str | None = None
    count: int = 1
    sources: set[str] = field(default_factory=set)
    evidence: list[LogEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
