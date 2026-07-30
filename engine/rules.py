"""Detection rules.

Two algorithm classes cover every shipped detection:

* ``PatternSignatureRule`` — stateless per-line regex matching (SQLi, traversal),
  aggregated per IP into one finding.
* ``ThresholdRule`` — stateful per-IP sliding window (brute force, scanning).

Behavior lives in these classes; parameters (thresholds, patterns, severities)
are data supplied via config specs. A registry + ``build_rules`` factory turns
structured specs into rule instances.

See docs/engine-plan.md §6.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from urllib.parse import unquote

from .models import (
    AuthLogEntry,
    AuthOutcome,
    Finding,
    LogEntry,
    Severity,
    WebLogEntry,
)

# --------------------------------------------------------------------------- #
# Rule interface
# --------------------------------------------------------------------------- #


class Rule(ABC):
    """A detection rule. Rules ignore entry types they don't care about."""

    id: str

    @abstractmethod
    def inspect(self, entry: LogEntry) -> Iterable[Finding]:
        """Examine one entry; yield findings emitted eagerly (may be empty)."""

    def flush(self) -> Iterable[Finding]:
        """Emit end-of-stream aggregates. Default: nothing."""
        return ()

    def reset(self) -> None:
        """Clear internal state so the rule is reusable across runs."""


# --------------------------------------------------------------------------- #
# Named predicates (the config-safe "match" presets)
# --------------------------------------------------------------------------- #

Predicate = Callable[[LogEntry], bool]


def _auth_failure(entry: LogEntry) -> bool:
    return (
        isinstance(entry, AuthLogEntry)
        and entry.outcome in (AuthOutcome.FAILURE, AuthOutcome.INVALID_USER)
    )


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


# Named field extractors for ``distinct_by`` — also a config-safe preset set.
FieldExtractor = Callable[[LogEntry], str | None]


def _distinct_path(entry: LogEntry) -> str | None:
    """Normalized path key: no query, trailing slash trimmed (except root)."""
    if not isinstance(entry, WebLogEntry) or entry.path is None:
        return None
    path = entry.path
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return path


def _distinct_username(entry: LogEntry) -> str | None:
    return getattr(entry, "username", None)


DISTINCT_EXTRACTORS: dict[str, FieldExtractor] = {
    "path": _distinct_path,
    "username": _distinct_username,
}


# --------------------------------------------------------------------------- #
# Registry + factory
# --------------------------------------------------------------------------- #

RULE_TYPES: dict[str, type[Rule]] = {}


def register(type_name: str) -> Callable[[type[Rule]], type[Rule]]:
    """Class decorator registering a Rule subclass under a config ``type`` name."""

    def _decorator(cls: type[Rule]) -> type[Rule]:
        RULE_TYPES[type_name] = cls
        return cls

    return _decorator


# --------------------------------------------------------------------------- #
# Signature rule (stateless per line, aggregated per IP)
# --------------------------------------------------------------------------- #

# Named match targets for signature rules (also config-safe presets).
TARGET_EXTRACTORS: dict[str, FieldExtractor] = {
    "request_target": lambda e: getattr(e, "target", None),
    "path": lambda e: getattr(e, "path", None) if isinstance(e, WebLogEntry) else None,
    "query": lambda e: getattr(e, "query", None) if isinstance(e, WebLogEntry) else None,
    "user_agent": lambda e: getattr(e, "user_agent", None),
    "referrer": lambda e: getattr(e, "referrer", None),
}

_MAX_DECODE_PASSES = 2


def _decode_variants(value: str) -> list[str]:
    """Return {raw, bounded-recursively-decoded} forms (fail-soft)."""
    variants = [value]
    current = value
    for _ in range(_MAX_DECODE_PASSES):
        decoded = unquote(current, errors="replace")
        if decoded == current:
            break
        variants.append(decoded)
        current = decoded
    # Dedupe while preserving order.
    seen: dict[str, None] = {}
    for v in variants:
        seen.setdefault(v, None)
    return list(seen)


@register("signature")
class PatternSignatureRule(Rule):
    """Stateless regex matcher; aggregates hits per IP into one Finding."""

    def __init__(
        self,
        *,
        id: str,
        patterns: list[str],
        severity: Severity = Severity.HIGH,
        target: str = "request_target",
        title: str | None = None,
        description: str = "",
        case_sensitive: bool = False,
        min_hits: int = 1,
        max_evidence: int = 20,
    ) -> None:
        self.id = id
        self.title = title or id
        self.severity = severity
        self.description = description
        self.min_hits = min_hits
        self.max_evidence = max_evidence
        if target not in TARGET_EXTRACTORS:
            raise ValueError(f"unknown signature target {target!r}")
        self._target_name = target
        self._extract = TARGET_EXTRACTORS[target]
        flags = 0 if case_sensitive else re.IGNORECASE
        self._patterns = [(p, re.compile(p, flags)) for p in patterns]
        self._by_ip: dict[str | None, Finding] = {}

    def reset(self) -> None:
        self._by_ip = {}

    def inspect(self, entry: LogEntry) -> Iterable[Finding]:
        value = self._extract(entry)
        if not value:
            return ()

        hit_pattern = None
        hit_snippet = None
        for variant in _decode_variants(value):
            for source, compiled in self._patterns:
                m = compiled.search(variant)
                if m:
                    hit_pattern = source
                    hit_snippet = m.group(0)
                    break
            if hit_pattern is not None:
                break

        if hit_pattern is None:
            return ()

        self._record(entry, hit_pattern, hit_snippet, value)
        return ()

    def _record(self, entry: LogEntry, pattern: str, snippet: str, value: str) -> None:
        ip = entry.source_ip
        finding = self._by_ip.get(ip)
        if finding is None:
            finding = Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                description=self.description,
                first_seen=entry.timestamp,
                last_seen=entry.timestamp,
                source_ip=ip,
                count=0,
                sources={entry.source},
                evidence=[],
                metadata={"target": self._target_name, "matches": []},
            )
            self._by_ip[ip] = finding

        finding.count += 1
        finding.last_seen = max(finding.last_seen, entry.timestamp)
        finding.first_seen = min(finding.first_seen, entry.timestamp)
        finding.sources.add(entry.source)
        if len(finding.evidence) < self.max_evidence:
            finding.evidence.append(entry)
        matches = finding.metadata["matches"]
        if len(matches) < self.max_evidence:
            matches.append({"pattern": pattern, "snippet": snippet, "value": value})

    def flush(self) -> Iterable[Finding]:
        emitted = [f for f in self._by_ip.values() if f.count >= self.min_hits]
        return emitted


# --------------------------------------------------------------------------- #
# Threshold rule (stateful per-IP sliding window)
# --------------------------------------------------------------------------- #


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
        max_evidence: int = 20,
    ) -> None:
        self.id = id
        self.title = title or id
        self.severity = severity
        self.description = description
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.max_evidence = max_evidence
        if match not in MATCH_PREDICATES:
            raise ValueError(f"unknown match preset {match!r}")
        self._match_name = match
        self._match = MATCH_PREDICATES[match]
        if distinct_by is not None and distinct_by not in DISTINCT_EXTRACTORS:
            raise ValueError(f"unknown distinct_by field {distinct_by!r}")
        self._distinct_name = distinct_by
        self._distinct = DISTINCT_EXTRACTORS[distinct_by] if distinct_by else None
        # Per-IP window state.
        self._events: dict[str | None, deque] = {}
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

    def _count(self, window: deque) -> int:
        if self._distinct is None:
            return len(window)
        values = {self._distinct(e) for e in window}
        values.discard(None)
        return len(values)

    def _update_finding(
        self, ip: str | None, window: deque, count: int, entry: LogEntry
    ) -> Finding | None:
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
        if len(finding.evidence) < self.max_evidence:
            finding.evidence.append(entry)

        return finding if newly_emitted else None

    def flush(self) -> Iterable[Finding]:
        # Findings are emitted eagerly on the crossing event; nothing buffered.
        return ()


# --------------------------------------------------------------------------- #
# Factory + defaults
# --------------------------------------------------------------------------- #


def build_rules(specs: Iterable[dict]) -> list[Rule]:
    """Instantiate rules from structured specs (list of dicts).

    Each spec: ``{id, type, enabled?, severity?, params?}``. ``severity`` (top
    level) and everything in ``params`` are merged into the rule constructor.
    Disabled specs are skipped. Format loading (YAML/TOML) lives outside core.
    """
    rules: list[Rule] = []
    for spec in specs:
        if not spec.get("enabled", True):
            continue
        type_name = spec.get("type")
        if type_name not in RULE_TYPES:
            raise ValueError(f"unknown rule type {type_name!r} for id {spec.get('id')!r}")
        cls = RULE_TYPES[type_name]

        kwargs: dict = {"id": spec["id"]}
        if "severity" in spec:
            kwargs["severity"] = _coerce_severity(spec["severity"])
        for key, value in spec.get("params", {}).items():
            kwargs[key] = _coerce_severity(value) if key == "severity" else value
        rules.append(cls(**kwargs))
    return rules


def _coerce_severity(value) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        return Severity.from_name(value)
    return Severity(value)


def default_rules() -> list[Rule]:
    """A working baseline rule set with the agreed defaults (§11)."""
    return build_rules(
        [
            {
                "id": "ssh_brute_force",
                "type": "threshold",
                "severity": "high",
                "params": {
                    "match": "auth_failure",
                    "threshold": 5,
                    "window_seconds": 60,
                    "title": "SSH Brute Force",
                    "description": "Repeated SSH authentication failures from one IP.",
                },
            },
            {
                "id": "web_login_brute_force",
                "type": "threshold",
                "severity": "medium",
                "params": {
                    "match": "web_login_failure",
                    "threshold": 10,
                    "window_seconds": 60,
                    "title": "Web Login Brute Force",
                    "description": "Repeated failed web logins (401/403) from one IP.",
                },
            },
            {
                "id": "web_scanning",
                "type": "threshold",
                "severity": "medium",
                "params": {
                    "match": "web_404",
                    "distinct_by": "path",
                    "threshold": 15,
                    "window_seconds": 120,
                    "title": "Web Scanning",
                    "description": "Many distinct 404 paths from one IP (enumeration).",
                },
            },
            {
                "id": "directory_traversal",
                "type": "signature",
                "severity": "high",
                "params": {
                    "target": "request_target",
                    "title": "Directory Traversal",
                    "description": "Path traversal sequences in the request target.",
                    "patterns": [
                        r"\.\./",
                        r"\.\.\\",
                        r"/etc/passwd",
                        r"/etc/shadow",
                        r"\bboot\.ini\b",
                        r"%2e%2e",
                    ],
                },
            },
            {
                "id": "sql_injection",
                "type": "signature",
                "severity": "high",
                "params": {
                    "target": "request_target",
                    "title": "SQL Injection",
                    "description": "SQL-injection syntax in the request target.",
                    "patterns": [
                        r"union\s+select",
                        r"\bor\s+1\s*=\s*1\b",
                        r"'\s*or\s*'1'\s*=\s*'1",
                        r'"\s*or\s*"1"\s*=\s*"1',
                        r"'\s*or\s+\w",
                        r"'\s*--",
                        r"'\s*#",
                        r"\bsleep\s*\(",
                        r"\bbenchmark\s*\(",
                        r"information_schema",
                        r"xp_cmdshell",
                        r"\bdrop\s+table\b",
                        r";\s*(?:drop|delete|update|insert|alter|truncate)\b",
                    ],
                },
            },
        ]
    )
