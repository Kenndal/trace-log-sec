"""Config loading failure-scenario tests (§9)."""

from __future__ import annotations

import pytest

from config.settings import load_settings, rule_specs
from utils.exceptions import ConfigError

VALID_RULE = """\
rules:
  - id: a
    type: threshold
    params:
      match: auth_failure
      threshold: 1
      window_seconds: 1
"""


def write(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content)
    return f


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "nope.yaml")


def test_malformed_yaml_syntax_raises_config_error(tmp_path):
    f = write(tmp_path, "bad.yaml", "rules: [this is not: valid: yaml\n")
    with pytest.raises(ConfigError, match="malformed YAML"):
        load_settings(f)


def test_empty_file_raises_config_error(tmp_path):
    f = write(tmp_path, "empty.yaml", "")
    with pytest.raises(ConfigError):
        load_settings(f)


def test_non_mapping_yaml_raises_config_error(tmp_path):
    f = write(tmp_path, "list.yaml", "- 1\n- 2\n")
    with pytest.raises(ConfigError):
        load_settings(f)


def test_rule_missing_required_key_raises_config_error(tmp_path):
    f = write(tmp_path, "missing_type.yaml", "rules:\n  - id: a\n    params: {}\n")
    with pytest.raises(ConfigError):
        load_settings(f)


def test_valid_config_loads(tmp_path):
    f = write(tmp_path, "ok.yaml", VALID_RULE)
    settings = load_settings(f)
    assert [r.id for r in settings.rules] == ["a"]


def test_engine_and_correlation_default_when_omitted(tmp_path):
    f = write(tmp_path, "ok.yaml", VALID_RULE)
    settings = load_settings(f)
    assert settings.engine.max_evidence == 20
    assert settings.correlation.window_minutes == 10


def test_engine_and_correlation_overrides_applied(tmp_path):
    content = (
        VALID_RULE
        + """\
engine:
  max_evidence: 5
correlation:
  window_minutes: 30
"""
    )
    f = write(tmp_path, "ok.yaml", content)
    settings = load_settings(f)
    assert settings.engine.max_evidence == 5
    assert settings.correlation.window_minutes == 30


def test_duplicate_id_overrides_keeping_first_position(tmp_path):
    content = """\
rules:
  - id: a
    type: threshold
    severity: low
    params:
      match: auth_failure
      threshold: 1
      window_seconds: 1
  - id: b
    type: threshold
    params:
      match: auth_failure
      threshold: 2
      window_seconds: 2
  - id: a
    type: threshold
    severity: high
    params:
      match: auth_failure
      threshold: 9
      window_seconds: 9
"""
    f = write(tmp_path, "dup.yaml", content)
    specs = rule_specs(load_settings(f))
    assert [s["id"] for s in specs] == ["a", "b"]
    a_spec = next(s for s in specs if s["id"] == "a")
    assert a_spec["severity"] == "high"
    assert a_spec["params"]["threshold"] == 9
