# TraceLogSec — Manual / CLI Test Suite

Comprehensive, manually-executable test scenarios covering 100% of the
`trace-log-sec` CLI surface: both commands (`analyze`, `list-reports`), every
flag, every detection rule, correlation, and the parsing/validation/config
failure modes.

Every **Expected Outcome** below was captured by running the fixture against the
current build on 2026-07-31; they are observed behavior, not guesses.

---

## How to run

All commands are run **from the repository root**
(`/Users/jakubprzybylo/projects/trace-log-sec`). Make the CLI available first:

```bash
# either activate the project venv…
source .venv/bin/activate      # then invoke:  trace-log-sec ...
# …or prefix every command with uv:
uv run trace-log-sec ...
```

This suite writes `trace-log-sec ...` for brevity — substitute `uv run
trace-log-sec ...` if you did not activate the venv.

### Conventions & gotchas

- **Terminal output** has four sections: `=== FINDINGS ===`, `=== INCIDENTS ===`,
  `=== PARSE ERRORS ===`, `=== STATS ===`. Each finding prints as
  `[SEVERITY] <rule_id> ip=<ip> count=<N> <Title>`. The STATS line is
  `=== STATS === lines_read=… parsed=… malformed=… findings=… incidents=… (…s)`.
- Warnings/errors print to **stderr**; a successful `analyze` also prints a green
  `HTML report written to …` line and exits `0`. `analyze` exits `1` on a config
  error or when no file is recognizable; Typer argument/option validation errors
  exit `2`.
- **Syslog year anchoring:** BSD auth logs carry no year. When a run has **no web
  log** and **no `--reference-time`**, the year is resolved against *now* (a
  warning is printed) — for auth-only fixtures this suite passes
  `--reference-time 2025-11-12T23:59:59` so results are deterministic. All
  fixtures are dated 12 Nov 2025.
- **HTML reports are a side effect.** Every successful `analyze` writes a
  `report_YYYY_MM_DD_HH_MM_SS.html` into the config's `reporting.output_dir`
  (default `reports/`). The cleanup step in the execution prompt removes the ones
  this suite generates.
- `REF` below is shorthand for `--reference-time 2025-11-12T23:59:59`.

---

## A. CLI Surface / Help

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| A1 | Root help | — | `trace-log-sec --help` | Exit 0. Shows usage, the description line, global `--install-completion` / `--show-completion` / `--help`, and a Commands list containing `analyze` and `list-reports`. |
| A2 | analyze help | — | `trace-log-sec analyze --help` | Exit 0. Shows the `log_files` argument (required) and options `--max-evidence`, `--window-minutes`, `--reference-time`, `--config`, `--help` with their help text. |
| A3 | list-reports help | — | `trace-log-sec list-reports --help` | Exit 0. Shows only `--config` and `--help`; mentions scanning `reporting.output_dir`. |
| A4 | No subcommand | — | `trace-log-sec` | Non-zero exit. Prints usage / "Missing command." (Typer requires a subcommand.) |
| A5 | Unknown subcommand | — | `trace-log-sec bogus` | Exit 2. Error: "No such command 'bogus'." |
| A6 | Unknown option | single_line_web.log | `trace-log-sec analyze --bogus sandbox/samples/single_line_web.log` | Exit 2. Error: "No such option: --bogus". |
| A7 | Show completion | — | `trace-log-sec --show-completion` | Exit 0. Prints a shell completion script to stdout (no side effects). |

## B. Happy Paths

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| B1 | Clean web log, no findings | webserver_clean.log | `trace-log-sec analyze sandbox/samples/webserver_clean.log` | Exit 0. FINDINGS empty; INCIDENTS empty; STATS `lines_read=9 parsed=9 malformed=0 findings=0 incidents=0`. Green "HTML report written". |
| B2 | Clean auth log, no findings | auth_clean.log | `trace-log-sec analyze REF sandbox/samples/auth_clean.log` | Exit 0. No findings; STATS `lines_read=8 parsed=8 malformed=0 findings=0`. No anchored-to-now warning (REF supplied). |
| B3 | Bundled full run (baseline) | repo `samples/` | `trace-log-sec analyze samples/auth_incidents.log samples/webserver_incidents.log` | Exit 0. 15 findings across all 8 rules; exactly 1 incident (`203.0.113.150`, Directory Traversal + SSH Brute Force). 4 benign parse errors. STATS `lines_read=4167 parsed=4163 malformed=4 findings=15 incidents=1`. |
| B4 | Single valid web line | single_line_web.log | `trace-log-sec analyze sandbox/samples/single_line_web.log` | Exit 0. 0 findings; STATS `lines_read=1 parsed=1 malformed=0`. |
| B5 | Single valid auth line | single_line_auth.log | `trace-log-sec analyze REF sandbox/samples/single_line_auth.log` | Exit 0. 0 findings; STATS `lines_read=1 parsed=1 malformed=0`. |
| B6 | Two files, mixed formats | clean web + auth | `trace-log-sec analyze sandbox/samples/webserver_clean.log sandbox/samples/auth_clean.log` | Exit 0. Both auto-detected (web + auth); 0 findings; STATS `lines_read=17 parsed=17`. No anchored-to-now warning (web log present anchors the year). |

## C. Threshold Detections

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| C1 | SSH brute force fires (≥5/60s) | ssh_brute_force.log | `trace-log-sec analyze REF sandbox/samples/ssh_brute_force.log` | Exit 0. `[HIGH] ssh_brute_force ip=45.10.20.30 count=5`. findings=1. |
| C2 | SSH brute force boundary negative (4) | ssh_brute_force_negative.log | `trace-log-sec analyze REF sandbox/samples/ssh_brute_force_negative.log` | Exit 0. **0 findings** (4 < threshold 5). STATS `findings=0`. |
| C3 | Web login brute force (≥10/60s) | web_login_brute_force.log | `trace-log-sec analyze sandbox/samples/web_login_brute_force.log` | Exit 0. `[MEDIUM] web_login_brute_force ip=203.0.113.55 count=10`. findings=1. (The trailing 200 and the other IP do not fire.) |
| C4 | Web scanning (≥15 distinct 404 paths) | web_scanning.log | `trace-log-sec analyze sandbox/samples/web_scanning.log` | Exit 0. `[MEDIUM] web_scanning ip=198.51.100.201 count=17`. count reflects **distinct** paths (20 lines, 3 duplicates → 17 distinct). findings=1. |

## D. Signature Detections

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| D1 | SQL injection | sql_injection.log | `trace-log-sec analyze sandbox/samples/sql_injection.log` | Exit 0. `[HIGH] sql_injection ip=198.51.100.90 count=6` (all 6 payloads match, incl. the `; DROP TABLE` stacked query, caught by the `drop table` pattern). findings=1. |
| D2 | Directory traversal (+ URL-decode + backslash) | directory_traversal.log | `trace-log-sec analyze sandbox/samples/directory_traversal.log` | Exit 0. `[HIGH] directory_traversal ip=203.0.113.160 count=5` (incl. `%2e%2e` encoded and `..\` backslash variants). findings=1. |
| D3 | Sensitive file / credential exposure | sensitive_file_exposure.log | `trace-log-sec analyze sandbox/samples/sensitive_file_exposure.log` | Exit 0. `[HIGH] sensitive_file_exposure ip=198.51.100.250 count=7` (`.git/`, `.env`, `.aws/credentials`, `id_rsa`, `wp-config.php`, `.sql`, `.bak`). findings=1. |
| D4 | Scanner / attack-tool user agents | scanner_user_agent.log | `trace-log-sec analyze sandbox/samples/scanner_user_agent.log` | Exit 0. **4** findings, one per attacking IP, each `[MEDIUM] scanner_user_agent … count=1`: sqlmap (203.0.113.99), Nikto (198.51.100.66), gobuster (192.0.2.150), and the **blank `-` UA** (192.0.2.77). The real-browser line does not fire. |
| D5 | Sudo privilege escalation | sudo_privilege_escalation.log | `trace-log-sec analyze REF sandbox/samples/sudo_privilege_escalation.log` | Exit 0. `[CRITICAL] sudo_privilege_escalation ip=- count=5` (cat shadow, .aws/credentials, id_rsa/.ssh, useradd, usermod…sudo). `ip=-` because sudo lines carry no source IP. findings=1. |

## E. Correlation & Time Windows

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| E1 | Multi-source incident (2 rules, 2 files) | correlation_web.log + correlation_auth.log | `trace-log-sec analyze sandbox/samples/correlation_web.log sandbox/samples/correlation_auth.log` | Exit 0. Two findings for `203.0.113.150` (directory_traversal count=5, ssh_brute_force count=5) **plus 1 incident** `[CRITICAL] 203.0.113.150 … 2 rule(s) (Directory Traversal, SSH Brute Force)`. STATS `findings=2 incidents=1`. |
| E2 | Single-file, two-rule incident | correlation_single_file.log | `trace-log-sec analyze sandbox/samples/correlation_single_file.log` | Exit 0. sql_injection count=2 + directory_traversal count=2 for `198.51.100.91`, **1 incident** (2 rules, 1 source). STATS `findings=2 incidents=1`. |
| E3 | Window 0 suppresses incident | correlation pair | `trace-log-sec analyze --window-minutes 0 sandbox/samples/correlation_web.log sandbox/samples/correlation_auth.log` | Exit 0. Same 2 findings but **incidents=0** (findings ~3.5 min apart, 0-min window can't cluster). |
| E4 | Wider window keeps incident | correlation pair | `trace-log-sec analyze --window-minutes 30 sandbox/samples/correlation_web.log sandbox/samples/correlation_auth.log` | Exit 0. 1 incident (still clustered). STATS `incidents=1`. |
| E5 | Sudo findings never correlate | sudo_privilege_escalation.log | `trace-log-sec analyze REF sandbox/samples/sudo_privilege_escalation.log` | Exit 0. Critical finding present but **incidents=0** — `ip=-` (None) is excluded from correlation. |

## F. Flag Behavior

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| F1 | `--max-evidence 0` (falsy override wins) | sql_injection.log | `trace-log-sec analyze --max-evidence 0 sandbox/samples/sql_injection.log` | Exit 0. Still fires `sql_injection count=6` (count is hit count); evidence lines stored are trimmed to 0. Confirms an explicit `0` overrides the config default 20, rather than being ignored. |
| F2 | `--max-evidence -1` rejected | single_line_web.log | `trace-log-sec analyze --max-evidence -1 sandbox/samples/single_line_web.log` | Exit 2. Error "Invalid value for '--max-evidence': -1 is not in the range x>=0." |
| F3 | `--reference-time` valid ISO | single_line_auth.log | `trace-log-sec analyze --reference-time 2025-11-12T23:59:59 sandbox/samples/single_line_auth.log` | Exit 0. No anchored-to-now warning; auth year resolves to 2025. |
| F4 | `--reference-time` alt formats | single_line_auth.log | `trace-log-sec analyze --reference-time "2025-11-12" sandbox/samples/single_line_auth.log` | Exit 0 (date-only format accepted). No warning. |
| F5 | `--reference-time` invalid | single_line_auth.log | `trace-log-sec analyze --reference-time "not-a-date" sandbox/samples/single_line_auth.log` | Exit 2. Error "Invalid value for '--reference-time': 'not-a-date' does not match the formats …". |
| F6 | Auth-only, no anchor → warning | single_line_auth.log | `trace-log-sec analyze sandbox/samples/single_line_auth.log` | Exit 0 but **yellow warning** on stderr: "resolving syslog years against the current time — no web logs or --reference-time to anchor to …". |
| F7 | `--config` swap + in-file override | custom_lower_threshold.yaml, ssh_brute_force_negative.log | `trace-log-sec analyze --config sandbox/samples/custom_lower_threshold.yaml REF sandbox/samples/ssh_brute_force_negative.log` | Exit 0. Now `[HIGH] ssh_brute_force ip=45.10.20.31 count=4` **fires** (custom threshold 3). Proves `--config` replaces the whole rule set and the in-file threshold wins. |
| F8 | `--config` disables a rule | custom_disable_rule.yaml, correlation_single_file.log | `trace-log-sec analyze --config sandbox/samples/custom_disable_rule.yaml sandbox/samples/correlation_single_file.log` | Exit 0. Only `directory_traversal count=2` fires; **no sql_injection** (`enabled: false`); incidents=0 (only 1 rule left). |
| F9 | `--config` custom output dir | custom_output_dir.yaml, directory_traversal.log | `trace-log-sec analyze --config sandbox/samples/custom_output_dir.yaml sandbox/samples/directory_traversal.log` | Exit 0. "HTML report written to …/sandbox/reports/report_*.html" (not the default `reports/`). Directory `sandbox/reports/` is created. |
| F10 | `--window-minutes` override vs config | correlation pair | (covered by E3/E4) | Explicit flag overrides `correlation.window_minutes`. |

## G. Edge & Boundary

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| G1 | Empty file, sole input | empty.log | `trace-log-sec analyze sandbox/samples/empty.log` | **Exit 1.** Yellow "skipping … does not match a known log format" + red "Error: no recognized log files to analyze." No report written. |
| G2 | Blank-lines-only file | blank_lines.log | `trace-log-sec analyze sandbox/samples/blank_lines.log` | Exit 1. Same skip + "no recognized log files" (all lines blank → unrecognized). |
| G3 | Fully corrupted file | corrupted_format.log | `trace-log-sec analyze sandbox/samples/corrupted_format.log` | Exit 1. Skipped as unrecognized; "no recognized log files". |
| G4 | Valid line after 20 junk lines | unrecognized_after_20.log | `trace-log-sec analyze sandbox/samples/unrecognized_after_20.log` | Exit 1. **Skipped** — sniffing only scans the first 20 non-blank lines; the valid line at line 22 is never reached. Boundary test of the 20-line sniff limit. |
| G5 | Header/comment then valid | header_then_valid.log | `trace-log-sec analyze sandbox/samples/header_then_valid.log` | Exit 0. Format **still detected** (sniff scans past the 2 comment lines). STATS `lines_read=4 parsed=2 malformed=2` — the 2 comment lines become parse errors, the 2 web lines parse. 0 findings. |
| G6 | Mixed valid + malformed lines | mixed_valid_malformed.log | `trace-log-sec analyze sandbox/samples/mixed_valid_malformed.log` | Exit 0. PARSE ERRORS lists lines 2/4/6 ("does not match Combined log format"); STATS `lines_read=7 parsed=4 malformed=3`. Run never crashes. |
| G7 | Bad timestamps | bad_timestamp_web.log | `trace-log-sec analyze sandbox/samples/bad_timestamp_web.log` | Exit 0. Line 2 (missing `+0000` offset) and line 3 (nonsense date) → "bad timestamp" parse errors; STATS `lines_read=4 parsed=2 malformed=2`. |
| G8 | Recognized + unrecognized mix | webserver_clean.log + corrupted_format.log | `trace-log-sec analyze sandbox/samples/webserver_clean.log sandbox/samples/corrupted_format.log` | Exit 0. Warning skips `corrupted_format.log`; the web log still analyzes (STATS `lines_read=9`). Non-fatal because ≥1 file recognized. |
| G9 | Large log performance | large_webserver.log | `trace-log-sec analyze sandbox/samples/large_webserver.log` | Exit 0. STATS `lines_read=50006 parsed=50006 malformed=0 findings=1` with `[HIGH] sql_injection ip=203.0.113.201 count=6`. Completes in ~1s. |

## H. Negative / Failure

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| H1 | Missing required argument | — | `trace-log-sec analyze` | Exit 2. Error "Missing argument 'log_files'." |
| H2 | Non-existent file | — | `trace-log-sec analyze sandbox/samples/does_not_exist.log` | Exit 2. "Invalid value for 'log_files': …does_not_exist.log: no such file". |
| H3 | Wrong extension (.txt) | not_a_log.txt | `trace-log-sec analyze sandbox/samples/not_a_log.txt` | Exit 2. "Invalid value for 'log_files': …not_a_log.txt: expected a '.log' file, got .txt". |
| H4 | Directory as argument | — | `trace-log-sec analyze sandbox/samples` | Exit 2. "Invalid value for 'log_files': sandbox/samples: not a regular file". |
| H5 | Duplicate paths | single_line_web.log | `trace-log-sec analyze sandbox/samples/single_line_web.log sandbox/samples/single_line_web.log` | Exit 2. "Invalid value for 'log_files': duplicate log file path(s): …". |
| H6 | Unreadable file (permissions) | single_line_web.log | `chmod 000 sandbox/samples/single_line_web.log && trace-log-sec analyze sandbox/samples/single_line_web.log ; chmod 644 sandbox/samples/single_line_web.log` | Exit 2. "Invalid value for 'log_files': Path '…/single_line_web.log' is not readable." Typer's `Path` argument type validation (which defaults `readable=True`) rejects the file up front, before the sniff/analyze logic ever runs — a distinct, actionable error instead of the old generic "unrecognized format" path. **Restore perms afterward** (the `&& … ; chmod 644` does this). |
| H7 | `--config` file missing | single_line_web.log | `trace-log-sec analyze --config sandbox/samples/nope.yaml sandbox/samples/single_line_web.log` | Exit 2. "Invalid value for '--config': File 'sandbox/samples/nope.yaml' does not exist." (Typer `exists=True`, fails before the command body.) |
| H8 | Malformed YAML config | bad_yaml.yaml, single_line_web.log | `trace-log-sec analyze --config sandbox/samples/bad_yaml.yaml sandbox/samples/single_line_web.log` | Exit 1. Red "Error: invalid config at …bad_yaml.yaml: malformed YAML: …". |
| H9 | Empty config file | empty_config.yaml, single_line_web.log | `trace-log-sec analyze --config sandbox/samples/empty_config.yaml sandbox/samples/single_line_web.log` | Exit 1. "Error: invalid config at …empty_config.yaml: 1 validation error for EngineSettings …" (None is not a valid mapping). |
| H10 | Config missing required `rules` | missing_rules.yaml, single_line_web.log | `trace-log-sec analyze --config sandbox/samples/missing_rules.yaml sandbox/samples/single_line_web.log` | Exit 1. "Error: invalid config … 1 validation error for EngineSettings / rules / Field required". |
| H11 | Unknown rule type | unknown_rule_type.yaml, single_line_web.log | `trace-log-sec analyze --config sandbox/samples/unknown_rule_type.yaml sandbox/samples/single_line_web.log` | Exit 1. "Error: unknown rule type 'bogus' for id 'my_broken_rule'". (Raised at rule-build, after format detection — so a valid log file is required to reach it.) |

## I. list-reports

| ID | Title | Prereq | Command | Expected Outcome |
|----|-------|--------|---------|------------------|
| I1 | List default reports dir | at least one prior run | `trace-log-sec list-reports` | Exit 0. "Reports in …/reports (N):" newest-first, each line `YYYY-MM-DD HH:MM:SS UTC  <path>`. |
| I2 | List custom reports dir | run F9 first | `trace-log-sec list-reports --config sandbox/samples/custom_output_dir.yaml` | Exit 0. "Reports in …/sandbox/reports (1):" listing the report F9 wrote. |
| I3 | Empty / absent reports dir | fresh custom_output_dir before any F9 run | `trace-log-sec list-reports --config sandbox/samples/custom_output_dir.yaml` (before running F9) | Exit 0. Reports a "no reports" / empty listing for the (missing) directory — **observe and record the exact message and that it does not crash.** |
| I4 | list-reports with bad config | bad_yaml.yaml | `trace-log-sec list-reports --config sandbox/samples/bad_yaml.yaml` | Exit 1. Red "Error: invalid config … malformed YAML". |
| I5 | list-reports with missing config | — | `trace-log-sec list-reports --config sandbox/samples/nope.yaml` | Exit 2. "Invalid value for '--config': File … does not exist." |

---

## Fixture ↔ scenario reference

| Fixture (`sandbox/samples/`) | Triggers |
|------------------------------|----------|
| `webserver_clean.log`, `auth_clean.log` | clean baselines (0 findings) |
| `ssh_brute_force.log` / `_negative.log` | ssh_brute_force positive (count 5) / boundary negative (4) |
| `web_login_brute_force.log` | web_login_brute_force (count 10) |
| `web_scanning.log` | web_scanning (17 distinct 404s) |
| `sql_injection.log` | sql_injection (count 6) |
| `directory_traversal.log` | directory_traversal (count 5) |
| `sensitive_file_exposure.log` | sensitive_file_exposure (count 7) |
| `scanner_user_agent.log` | scanner_user_agent (4 IPs incl. blank UA) |
| `sudo_privilege_escalation.log` | sudo_privilege_escalation (critical, ip=-) |
| `correlation_web.log` + `correlation_auth.log` | multi-source incident |
| `correlation_single_file.log` | single-file two-rule incident |
| `single_line_web.log` / `single_line_auth.log` | single-line inputs |
| `empty.log`, `blank_lines.log`, `corrupted_format.log` | unrecognized → exit 1 |
| `unrecognized_after_20.log` | 20-line sniff boundary |
| `header_then_valid.log` | header/comment tolerance |
| `mixed_valid_malformed.log` | parse-error resilience |
| `bad_timestamp_web.log` | bad-timestamp parse errors |
| `large_webserver.log` | 50k-line performance + embedded SQLi |
| `not_a_log.txt` | `.log` extension rejection |
| `custom_lower_threshold.yaml` | rule-set swap + threshold override |
| `custom_disable_rule.yaml` | `enabled: false` |
| `custom_output_dir.yaml` | reporting output redirect |
| `bad_yaml.yaml`, `empty_config.yaml`, `missing_rules.yaml`, `unknown_rule_type.yaml` | config failure modes |

---

## Prompt for the Execution Agent

> **You are a QA Execution Agent for the TraceLogSec CLI.** Your job is to
> execute every test case in this file exactly as written, verify each observed
> result against its **Expected Outcome**, and record the results. You are
> validating the software — **do not modify product source code, the fixtures in
> `sandbox/samples/`, or this `tests.md`.** Treat the tool's real behavior as
> ground truth; when it diverges from an Expected Outcome, that is a finding to
> log, not something to "fix".
>
> **Setup**
> 1. Work from the repository root (`/Users/jakubprzybylo/projects/trace-log-sec`).
> 2. Make the CLI available: `source .venv/bin/activate` (then use `trace-log-sec`),
>    or prefix each command with `uv run`. Confirm with `trace-log-sec --help`.
> 3. Note the current contents of `reports/` (`ls reports/`) so you can identify
>    and remove the HTML reports this run generates during cleanup.
> 4. Wherever a command shows the literal `REF`, expand it to
>    `--reference-time 2025-11-12T23:59:59`.
>
> **Execution**
> 5. Run **every** test A1 through I5, in order. For each: capture stdout, stderr,
>    and the exit code (`echo "exit=$?"` immediately after the command).
> 6. Compare the observed FINDINGS lines, INCIDENTS, STATS counts, warnings/error
>    text, and exit code against the Expected Outcome. A test **passes** only if
>    all stated expectations hold. Minor cosmetic differences (timestamps, report
>    filenames, absolute paths, ordering within the same severity) are not
>    failures — focus on rule ids, counts, exit codes, and error/warning text.
> 7. Some cases have ordering dependencies: run **F9 before I2**; run **I3 before
>    any F9 run** (or against a freshly-removed `sandbox/reports/`) so the
>    directory is empty/absent. For **H6**, the command restores permissions
>    itself — verify `sandbox/samples/single_line_web.log` is readable again
>    afterward (`ls -l`), and if the run was interrupted, run
>    `chmod 644 sandbox/samples/single_line_web.log`.
>
> **Recording**
> 8. For every case that does **not** match its Expected Outcome, append a row to
>    `sandbox/bugs.md` using the existing table schema: Test ID, exact command,
>    Expected, Actual (paste the relevant output), Severity (Critical/High/
>    Medium/Low — your judgment of user impact), and Notes. Include false
>    positives/negatives in detections, wrong counts, wrong exit codes, crashes/
>    tracebacks, or misleading messages.
> 9. Independently, record **improvement ideas** (usability, clearer errors,
>    missing features, coverage gaps, docs/manifest drift) in
>    `sandbox/suggestions.md` using its schema (Area, Suggestion, Rationale).
>    Suggestions are not bugs — a test can pass and still inspire a suggestion
>    (e.g. H6's message conflating "unreadable" with "unrecognized format").
> 10. At the top of `sandbox/bugs.md`, write a one-line run summary:
>     `Executed N tests: P passed, F failed` with the date.
>
> **Cleanup**
> 11. Delete every `report_*.html` this run created (in `reports/` and, if F9 ran,
>     `sandbox/reports/`) so the repository is left as you found it. Do not delete
>     reports that pre-existed step 3.
> 12. Verify `git status` shows only the intended edits to `sandbox/bugs.md` and
>     `sandbox/suggestions.md` (plus any pre-existing untracked files) — no
>     stray reports, no permission changes, no modified source.
>
> Be precise and literal. If a command errors in a way not described here, that
> itself is a finding — capture the full output.
