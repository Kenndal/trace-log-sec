"""Helpers shared by more than one rule implementation."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from models import Finding, LogEntry

Predicate = Callable[[LogEntry], bool]
FieldExtractor = Callable[[LogEntry], str | None]


def resolve_preset[T](name: str, presets: Mapping[str, T], kind: str) -> T:
    """Look up a config-safe preset by name, raising a uniform error if unknown."""
    try:
        return presets[name]
    except KeyError:
        raise ValueError(f"unknown {kind} {name!r}") from None


def add_evidence(finding: Finding, entry: LogEntry, max_evidence: int) -> None:
    """Append ``entry`` to ``finding.evidence``, capped at ``max_evidence``."""
    if len(finding.evidence) < max_evidence:
        finding.evidence.append(entry)
