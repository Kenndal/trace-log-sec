"""Loads and validates the YAML rule configuration.

Kept outside the ``engine`` package so the core detection engine stays
format-agnostic (it only ever sees structured specs — plain dicts — never a
file path or a YAML/pydantic dependency). See docs/rule-config-plan.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError
import yaml

from constants import (
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_CORRELATION_WINDOW_MINUTES,
    DEFAULT_MAX_EVIDENCE,
    DEFAULT_REPORTS_DIR,
)
from utils.exceptions import ConfigError

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PACKAGE_DIR / DEFAULT_CONFIG_FILENAME


class RuleSpec(BaseModel):
    id: str
    type: str
    enabled: bool = True
    severity: str | None = None
    params: dict[str, Any] = {}


class EngineConfig(BaseModel):
    """Top-level ``Engine`` behavior, independent of any single rule."""

    max_evidence: int = DEFAULT_MAX_EVIDENCE


class CorrelationConfig(BaseModel):
    """``Correlator`` behavior: how findings are clustered into incidents."""

    window_minutes: float = DEFAULT_CORRELATION_WINDOW_MINUTES


class ReportingConfig(BaseModel):
    """HTML report output behavior (see :mod:`reporter`)."""

    output_dir: str = DEFAULT_REPORTS_DIR


class EngineSettings(BaseModel):
    rules: list[RuleSpec]
    engine: EngineConfig = Field(default_factory=EngineConfig)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


def load_settings(path: str | Path = DEFAULT_CONFIG_PATH) -> EngineSettings:
    """Read and validate the YAML config at ``path``.

    Raises ``ConfigError`` (never a raw ``OSError``/``yaml.YAMLError``/
    ``pydantic.ValidationError``) so callers get one consistent, informative
    failure type for every way a hand-authored config file can be broken.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except OSError as e:
        raise ConfigError(path, str(e)) from e
    except yaml.YAMLError as e:
        raise ConfigError(path, f"malformed YAML: {e}") from e

    try:
        return EngineSettings.model_validate(data)
    except ValidationError as e:
        raise ConfigError(path, str(e)) from e


def rule_specs(settings: EngineSettings) -> list[dict[str, Any]]:
    """Convert validated rule specs into the plain dicts ``build_rules`` expects.

    A later rule with the same ``id`` overrides an earlier one (per the
    ``config.yaml`` header comment), keeping the first-seen position.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for r in settings.rules:
        by_id[r.id] = r.model_dump(exclude_none=True)
    return list(by_id.values())
