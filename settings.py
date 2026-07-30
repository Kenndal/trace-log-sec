"""Loads and validates the YAML rule configuration.

Kept outside the ``engine`` package so the core detection engine stays
format-agnostic (it only ever sees structured specs — plain dicts — never a
file path or a YAML/pydantic dependency). See docs/rule-config-plan.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "config.yaml"


class RuleSpec(BaseModel):
    id: str
    type: str
    enabled: bool = True
    severity: str | None = None
    params: dict[str, Any] = {}


class EngineSettings(BaseModel):
    rules: list[RuleSpec]


def load_settings(path: str | Path = DEFAULT_CONFIG_PATH) -> EngineSettings:
    """Read and validate the YAML config at ``path``."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return EngineSettings.model_validate(data)


def rule_specs(settings: EngineSettings) -> list[dict]:
    """Convert validated rule specs into the plain dicts ``build_rules`` expects."""
    return [r.model_dump(exclude_none=True) for r in settings.rules]
