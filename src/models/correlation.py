"""Data models dedicated to :mod:`engine.correlation`.

``Incident`` is a mutable aggregate the engine builds up during a run, then
hands off read-only to a downstream presenter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from models.rules import Finding, Severity


@dataclass(kw_only=True)
class Incident:
    """A correlated group of findings for one IP within a time window."""

    incident_id: str
    title: str
    severity: Severity
    source_ip: str | None
    first_seen: datetime
    last_seen: datetime
    findings: list[Finding] = field(default_factory=list)
    narrative: str = ""
