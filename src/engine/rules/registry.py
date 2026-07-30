"""Config ``type`` name → ``Rule`` subclass registry."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from engine.rules.base import Rule

RULE_TYPES: dict[str, type[Rule]] = {}

RuleT = TypeVar("RuleT", bound=type[Rule])


def register(type_name: str) -> Callable[[RuleT], RuleT]:
    """Class decorator registering a Rule subclass under a config ``type`` name."""

    def _decorator(cls: RuleT) -> RuleT:
        RULE_TYPES[type_name] = cls
        return cls

    return _decorator
