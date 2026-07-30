"""The ``Rule`` interface shared by every detection rule."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from models import Finding, LogEntry, Severity


class Rule(ABC):
    """A detection rule. Rules ignore entry types they don't care about."""

    id: str
    severity: Severity

    @abstractmethod
    def inspect(self, entry: LogEntry) -> Iterable[Finding]:
        """Examine one entry; yield findings emitted eagerly (may be empty)."""

    def flush(self) -> Iterable[Finding]:
        """Emit end-of-stream aggregates. Default: nothing."""
        return ()

    def reset(self) -> None:  # noqa: B027 (intentionally optional, not every rule holds state)
        """Clear internal state so the rule is reusable across runs."""
