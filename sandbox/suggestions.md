# TraceLogSec — Improvement Suggestions

> Ideas for improving the tool: usability, clearer errors/warnings, new
> detections, coverage gaps, or documentation/manifest drift. These are **not**
> bugs — a passing test can still inspire a suggestion. One row per idea.

| Area | Suggestion | Rationale |
|------|------------|-----------|
| Docs / test fixtures | Update `tests.md`'s H6 Expected Outcome. | It documents exit 1 + "does not match a known log format" for an unreadable file, but the current build actually fails earlier and more precisely: exit 2 with `Invalid value for 'log_files': Path '...' is not readable.` (Typer's `readable=True` check). The doc is stale and the seeded suggestion below about H6 is already resolved by this behavior. |
| CLI / shell completion | Make `--show-completion` degrade gracefully (or accept an explicit shell name reliably) when `shellingham`'s process-tree detection fails. | In this run, `--show-completion` (and `--show-completion zsh`) produced `Shell  not supported.` and exited 1 even though `$SHELL=/bin/zsh` — the empty shell name in the message suggests the explicit argument isn't being honored as a fallback when detection fails. A clearer error (naming the detection failure) or honoring an explicit argument would help users in containers/CI/non-interactive shells where process-tree walking is unreliable. |
| Output formats | Only terminal + HTML output exist. A `--json` / machine-readable output mode would make the tool scriptable in CI/SOC pipelines. | Confirmed still true after full test pass — no `--json`/`--format` flag exists on `analyze` or `list-reports`. |
| Docs drift | `samples/incidents_manifest.md` states the SQL-injection scenario is detected 5/6 (the unquoted `'; DROP TABLE orders--` "slips past every current pattern"). | Confirmed stale: the current config's `\bdrop\s+table\b` pattern catches it, so the real count is 6/6 (verified directly via B3 and D1, both showing `sql_injection count=6`). |
| CLI / errors | `list-reports` on a missing/empty output directory prints a plain "No reports found in `<dir>`" message and exits 0 — good, non-crashing behavior (confirmed via I3), but consider clarifying in the message whether the directory itself is missing vs. present-but-empty, for operators debugging a misconfigured `reporting.output_dir`. | Currently both cases (dir absent vs. dir empty) would presumably print the same message; a `reporting.output_dir` typo could be confused with "no runs yet." |

## Candidate observations (seeded during test design — confirm & expand)

- **CLI / errors — RESOLVED:** The original concern that an unreadable file
  (H6) is reported identically to a genuinely-unrecognized file no longer
  applies to the current build. Testing on 2026-07-31 shows the CLI now
  raises a distinct, specific error ("Path '...' is not readable.") at
  argument-validation time (exit 2), before ever reaching the sniff/format
  logic. See the corresponding row in `bugs.md` (Test ID H6) and the new
  suggestion above about updating `tests.md`.
- **Docs drift — RESOLVED / merged above:** `samples/incidents_manifest.md`'s
  5/6 SQL-injection claim is stale; current behavior is 6/6. Merged into the
  table above.
- **Output formats — confirmed / merged above:** Only terminal + HTML output
  exist. Merged into the table above.
