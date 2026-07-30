"""Signature rule: stateless per-line regex matching (SQLi, traversal, ...).

Aggregates hits per IP into one Finding. See docs/engine-plan.md §6.
"""

from __future__ import annotations

from collections.abc import Iterable
import re
from urllib.parse import unquote

from constants import DEFAULT_MAX_EVIDENCE, MAX_DECODE_PASSES
from engine.rules.base import Rule
from engine.rules.registry import register
from engine.rules.utils import FieldExtractor, add_evidence, resolve_preset
from models import AuthLogEntry, Finding, LogEntry, Severity, WebLogEntry

# Named match targets for signature rules (config-safe presets).
TARGET_EXTRACTORS: dict[str, FieldExtractor] = {
    "request_target": lambda e: getattr(e, "target", None),
    "path": lambda e: getattr(e, "path", None) if isinstance(e, WebLogEntry) else None,
    "query": lambda e: getattr(e, "query", None) if isinstance(e, WebLogEntry) else None,
    "user_agent": lambda e: getattr(e, "user_agent", None),
    "referrer": lambda e: getattr(e, "referrer", None),
    "auth_message": lambda e: getattr(e, "message", None) if isinstance(e, AuthLogEntry) else None,
}


def _decode_variants(value: str) -> list[str]:
    """Return {raw, bounded-recursively-decoded} forms (fail-soft)."""
    variants = [value]
    current = value
    for _ in range(MAX_DECODE_PASSES):
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
        max_evidence: int = DEFAULT_MAX_EVIDENCE,
    ) -> None:
        self.id = id
        self.title = title or id
        self.severity = severity
        self.description = description
        self.min_hits = min_hits
        self.max_evidence = max_evidence
        self._target_name = target
        self._extract = resolve_preset(target, TARGET_EXTRACTORS, "signature target")
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

        if hit_pattern is None or hit_snippet is None:
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
        add_evidence(finding, entry, self.max_evidence)
        matches = finding.metadata["matches"]
        if len(matches) < self.max_evidence:
            matches.append({"pattern": pattern, "snippet": snippet, "value": value})

    def flush(self) -> Iterable[Finding]:
        emitted = [f for f in self._by_ip.values() if f.count >= self.min_hits]
        return emitted
