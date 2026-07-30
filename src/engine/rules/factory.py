"""Factory that turns structured config specs into ``Rule`` instances."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from engine.rules.base import Rule
from engine.rules.registry import RULE_TYPES
from models import Severity


def build_rules(specs: Iterable[dict[str, Any]]) -> list[Rule]:
    """Instantiate rules from structured specs (list of dicts).

    Each spec: ``{id, type, enabled?, severity?, params?}``. ``severity`` (top
    level) and everything in ``params`` are merged into the rule constructor.
    Disabled specs are skipped. Format loading (YAML/TOML) lives outside core.
    """
    rules: list[Rule] = []
    for spec in specs:
        if not spec.get("enabled", True):
            continue
        if "id" not in spec:
            raise ValueError(f"rule spec missing required 'id' field: {spec!r}")
        rule_id = spec["id"]
        type_name = spec.get("type")
        if type_name not in RULE_TYPES:
            raise ValueError(f"unknown rule type {type_name!r} for id {rule_id!r}")
        cls = RULE_TYPES[type_name]

        try:
            kwargs: dict[str, Any] = {"id": rule_id}
            if "severity" in spec:
                kwargs["severity"] = _coerce_severity(spec["severity"])
            for key, value in spec.get("params", {}).items():
                kwargs[key] = _coerce_severity(value) if key == "severity" else value
            rules.append(cls(**kwargs))
        except Exception as e:
            raise ValueError(f"failed to build rule {rule_id!r} (type={type_name!r}): {e}") from e
    return rules


def _coerce_severity(value: Any) -> Severity:  # noqa: ANN401 (genuinely dynamic: parsed config data)
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        return Severity.from_name(value)
    return Severity(value)
