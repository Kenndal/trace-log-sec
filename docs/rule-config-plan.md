# Rule Configuration — Externalization Plan

## Goal

Rule definitions currently live hardcoded in `engine/rules.py::default_rules()`.
Extract them into a user-editable YAML file, loaded and validated via a
dedicated `settings.py` module (Pydantic `BaseModel`), so operators can
retune thresholds/severities/patterns and add rules without touching code.

## Scope decisions

- **`settings.py` location: repo root**, not `engine/`. Keeps the core engine
  package free of a pydantic/YAML dependency, consistent with the
  "format-agnostic core" principle already stated in `docs/engine-plan.md`
  §6.1 (core accepts structured specs — dicts — not file paths or formats).
- **Config covers `rules` only.** Correlation tuning is out of scope for this
  configuration and will be handled at a different level in the future.
- **Unit tests keep their own hardcoded configuration.** `default_rules()` in
  `engine/rules.py` stays exactly as-is and becomes, in effect, the test
  fixture baseline. No new YAML test fixtures, no test-file edits required.

## New files

### 1. `requirements.txt` (repo root)

No dependency manifest exists in the repo today — pydantic and PyYAML are only
ambiently installed. Add:

```
PyYAML==6.0.3
pydantic==2.12.4
```

### 2. `config.yaml` (repo root)

Direct YAML transcription of the 8 rules currently hardcoded in
`default_rules()`: `ssh_brute_force`, `web_login_brute_force`, `web_scanning`,
`directory_traversal`, `sql_injection`, `sensitive_file_exposure`,
`scanner_user_agent`, `sudo_privilege_escalation` — same ids, types,
severities, and params, byte-for-byte equivalent in behavior.

### 3. `settings.py` (repo root, beside `scripts/run_demo.py`)

```python
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
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return EngineSettings.model_validate(data)


def rule_specs(settings: EngineSettings) -> list[dict]:
    return [r.model_dump(exclude_none=True) for r in settings.rules]
```

Notes:

- Plain `BaseModel`, not `BaseSettings` — there's no need for env-var/`.env`
  loading right now, and `BaseModel` still guarantees the loaded file is
  validated at startup (fail-fast on missing/malformed fields), which is the
  actual requirement. Revisit `BaseSettings` if env-var overrides become a
  real need later.
- `load_settings(path)` takes an explicit path so it isn't hardwired to
  `config.yaml` (reusable for alternate configs later).
- `severity`/`type` validity is **not** re-validated here — that stays the
  job of `build_rules()` / `Severity.from_name` in `engine/rules.py`, so
  there remains exactly one source of truth for "what's a valid rule type or
  severity name."
- Pydantic gives fail-fast, field-level errors for a missing/malformed
  `config.yaml` (missing `id`, wrong types, etc.) before anything reaches the
  engine.

## Files to modify

- **`scripts/run_demo.py`** — replace `Engine(default_rules())` with:
  ```python
  settings = load_settings()
  engine = Engine(build_rules(rule_specs(settings)))
  ```
- **`engine/rules.py`** — no behavior change; `default_rules()` remains as
  the hardcoded test baseline.
- **`engine/__init__.py`**, **`tests/*`** — untouched.

## Verification

1. `python3 scripts/run_demo.py` must produce output identical to the
   pre-change run (same findings/incidents/counts) — confirms `config.yaml`
   faithfully reproduces `default_rules()`.
2. Full `pytest` run — expect no failures, since nothing under `engine/` or
   `tests/` changes.

## Explicitly out of scope (unless requested later)

- A `--config` CLI flag on `run_demo.py` (its signature is currently fixed:
  0 or 2 positional args).
- Env-var/`.env` overrides (would require switching `EngineSettings` to
  `BaseSettings`).
- Any change to `engine/correlation.py` or `engine/engine.py` beyond how
  `run_demo.py` wires them together.

## Implementation order

1. Add `requirements.txt`.
2. Write `config.yaml` (transcribe `default_rules()`).
3. Write `settings.py` (`RuleSpec`, `EngineSettings`, `load_settings`,
   `rule_specs`).
4. Update `scripts/run_demo.py` to load `config.yaml` via `settings.py`.
5. Verify demo output is unchanged; run full test suite.
6. (Optional) Update `docs/engine-plan.md` §6.1 to point at the real
   `config.yaml` instead of the illustrative example.
