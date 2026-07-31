# TraceLogSec — Improvement Suggestions

> Ideas for improving the tool: usability, clearer errors/warnings, new
> detections, coverage gaps, or documentation/manifest drift. These are **not**
> bugs — a passing test can still inspire a suggestion. One row per idea.

| Area | Suggestion | Rationale |
|------|------------|-----------|
| CLI / shell completion | Wrap `shellingham` / Typer's `_get_shell_name()` in `try/except` inside `_detect_shell_with_env_fallback` so a raised `PermissionError` / other failure falls through to `$SHELL`. | `src/cli/app.py` already intends an env fallback when process-tree detection fails, but the fallback only runs when detection returns a falsy name. In restricted environments (sandboxes, some CI) `ps` raises `PermissionError` and `--show-completion` crashes with a traceback instead of using `$SHELL=/bin/zsh`. A7 still passes in a normal interactive shell. |
| Output formats | Add a `--json` / machine-readable output mode on `analyze` (and optionally `list-reports`). | Only terminal + HTML exist today — confirmed via A2 help and the full suite. Scriptable CI/SOC pipelines need structured output without scraping the human sections. |
| Docs drift | Update `samples/incidents_manifest.md`: SQL-injection scenario is detected 6/6, not 5/6. | The unquoted `; DROP TABLE orders--` payload is caught by `\bdrop\s+table\b`. Verified again via D1 (`sql_injection count=6`) and B3. |
| CLI / errors | Distinguish missing vs empty `reporting.output_dir` in `list-reports`. | I3 prints `No reports found in …/sandbox/reports` and exits 0 whether the directory is absent or empty — fine and non-crashing, but a typo'd `output_dir` looks the same as "no runs yet." |
| Config fixtures | `custom_output_dir.yaml` yields `directory_traversal count=4` on the same fixture that default config scores as count=5 (D2). | F9 still passes (it only asserts the custom report path), but the fixture name suggests it only redirects output — a trimmed pattern set can surprise anyone reusing it for detection checks. |
