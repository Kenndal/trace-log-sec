"""Threshold rule: stateful per-IP sliding window (brute force, scanning, ...).

Fires one finding per burst that crosses the configured threshold.
See docs/engine-plan.md §6.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from datetime import datetime, timedelta

from constants import DEFAULT_MAX_EVIDENCE
from engine.rules.base import Rule
from engine.rules.registry import register
from engine.rules.utils import FieldExtractor, Predicate, add_evidence, resolve_preset
from models import AuthLogEntry, AuthOutcome, Finding, LogEntry, Severity, WebLogEntry
from utils.exceptions import RuleConfigError

# Named predicates (the config-safe "match" presets).


def _auth_failure(entry: LogEntry) -> bool:
    return isinstance(entry, AuthLogEntry) and entry.outcome in (AuthOutcome.FAILURE, AuthOutcome.INVALID_USER)


def _web_login_failure(entry: LogEntry) -> bool:
    # A failed request (401/403) to a login-shaped endpoint — deliberately
    # narrower than "any 401/403", which would also catch admin-path probing
    # (a different signal, not login brute force).
    if not isinstance(entry, WebLogEntry) or entry.status not in (401, 403):
        return False
    path = entry.path
    return path is not None and "login" in path.lower()


def _web_404(entry: LogEntry) -> bool:
    return isinstance(entry, WebLogEntry) and entry.status == 404


MATCH_PREDICATES: dict[str, Predicate] = {
    "auth_failure": _auth_failure,
    "web_login_failure": _web_login_failure,
    "web_404": _web_404,
}


# Named field extractors for `distinct_by` — also a config-safe preset set.


def _distinct_path(entry: LogEntry) -> str | None:
    """Normalized path key: no query, trailing slash trimmed (except root)."""
    if not isinstance(entry, WebLogEntry) or entry.path is None:
        return None
    path = entry.path
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return path


def _distinct_username(entry: LogEntry) -> str | None:
    return entry.username if isinstance(entry, AuthLogEntry) else None


DISTINCT_EXTRACTORS: dict[str, FieldExtractor] = {
    "path": _distinct_path,
    "username": _distinct_username,
}


@register("threshold")
class ThresholdRule(Rule):
    """Per-IP sliding window; fires one finding per burst that crosses threshold."""

    def __init__(
        self,
        *,
        id: str,
        match: str,
        threshold: int,
        window_seconds: float,
        severity: Severity = Severity.MEDIUM,
        distinct_by: str | None = None,
        title: str | None = None,
        description: str = "",
        max_evidence: int = DEFAULT_MAX_EVIDENCE,
    ) -> None:
        if threshold < 1:
            raise RuleConfigError(f"threshold must be >= 1, got {threshold!r}")
        if window_seconds <= 0:
            raise RuleConfigError(f"window_seconds must be > 0, got {window_seconds!r}")
        self.id = id
        self.title = title or id
        self.severity = severity
        self.description = description
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.max_evidence = max_evidence
        self._match_name = match
        self._match = resolve_preset(match, MATCH_PREDICATES, "match preset")
        self._distinct_name = distinct_by
        self._distinct = resolve_preset(distinct_by, DISTINCT_EXTRACTORS, "distinct_by field") if distinct_by else None
        # Per-IP window state.
        self._events: dict[str | None, deque[LogEntry]] = {}
        self._active: dict[str | None, Finding] = {}
        self._max_seen: dict[str | None, datetime] = {}

    def reset(self) -> None:
        self._events = {}
        self._active = {}
        self._max_seen = {}

    def inspect(self, entry: LogEntry) -> Iterable[Finding]:
        if not self._match(entry):
            return ()

        ip = entry.source_ip
        window = self._events.setdefault(ip, deque())
        window.append(entry)

        # Evict events older than `window` relative to the right edge, which is
        # the max timestamp seen for this IP so far — not necessarily this
        # entry's own timestamp, since a single IP's events aren't guaranteed
        # to arrive in order (§6.3 out-of-order tolerance).
        right_edge = self._max_seen.get(ip)
        if right_edge is None or entry.timestamp > right_edge:
            right_edge = entry.timestamp
        self._max_seen[ip] = right_edge
        cutoff = right_edge - self.window
        while window and window[0].timestamp < cutoff:
            window.popleft()

        count = self._count(window)
        if count < self.threshold:
            # Burst has subsided (or not yet begun): clear any active finding so
            # a later crossing starts a fresh one — one finding per burst.
            self._active.pop(ip, None)
            return ()

        emitted = self._update_finding(ip, window, count, entry)
        return (emitted,) if emitted is not None else ()

    def _count(self, window: deque[LogEntry]) -> int:
        if self._distinct is None:
            return len(window)
        values = {self._distinct(e) for e in window}
        values.discard(None)
        return len(values)

    def _update_finding(self, ip: str | None, window: deque[LogEntry], count: int, entry: LogEntry) -> Finding | None:
        finding = self._active.get(ip)
        newly_emitted = finding is None
        if finding is None:
            finding = Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                description=self.description,
                first_seen=window[0].timestamp,
                last_seen=entry.timestamp,
                source_ip=ip,
                count=count,
                sources={entry.source},
                evidence=[],
                metadata={
                    "match": self._match_name,
                    "distinct_by": self._distinct_name,
                    "threshold": self.threshold,
                    "window_seconds": self.window.total_seconds(),
                },
            )
            self._active[ip] = finding

        finding.count = count
        finding.last_seen = max(finding.last_seen, entry.timestamp)
        finding.sources.add(entry.source)
        add_evidence(finding, entry, self.max_evidence)

        return finding if newly_emitted else None

    def flush(self) -> Iterable[Finding]:
        # Findings are emitted eagerly on the crossing event; nothing buffered.
        return ()
