# trace-log-sec

A security log analysis CLI that parses webserver and authentication logs, detects suspicious activity with configurable rules, and correlates related findings into incidents.

It processes NCSA Combined access logs and BSD syslog auth logs, runs signature and threshold detectors, groups multi-signal activity by IP into correlated incidents, and writes both a terminal summary and a standalone HTML report.

---

## Requirements

- **Python** 3.12 or 3.13
- **[uv](https://docs.astral.sh/uv/)** (recommended) — installs the project and its dependencies from the lockfile

---

## Installation

Clone the repository and install into a local virtual environment:

```bash
git clone https://github.com/Kenndal/trace-log-sec.git
cd trace-log-sec
uv sync
```

That creates `.venv/`, editable-installs the package, and registers the `trace-log-sec` console script.

To include the test tooling as well:

```bash
uv sync --group test
```

For linting / typing / pre-commit hooks:

```bash
uv sync --group dev --group test
```

Verify the install:

```bash
uv run trace-log-sec --help
```

### Alternative: pip

If you prefer pip over uv (still requires Python ≥ 3.12):

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
trace-log-sec --help
```

---

## CLI usage

The tool exposes two commands: `analyze` and `list-reports`.

```bash
uv run trace-log-sec --help
uv run trace-log-sec analyze --help
uv run trace-log-sec list-reports --help
```

### Analyze logs

```bash
uv run trace-log-sec analyze AUTH.log WEBSERVER.log
```

`analyze` accepts one or more `*.log` files as positional arguments. Format — NCSA Combined access log vs BSD syslog auth log — is **auto-detected per file** from content (first parseable non-blank line within the first 20 lines), so files can be given in any order or mix. The shipped default rule set (`config.yaml` at the repo root) is used, and findings are correlated across files by source IP.

Quick start against the bundled sample logs:

```bash
uv run trace-log-sec analyze \
  samples/auth_incidents.log \
  samples/webserver_incidents.log
```

#### Options

| Option | Overrides | Default |
|---|---|---|
| `--max-evidence N` | `engine.max_evidence` | from `config.yaml` (built-in default: `20`) |
| `--window-minutes N` | `correlation.window_minutes` | from `config.yaml` (built-in default: `10`) |
| `--reference-time DATETIME` | syslog year anchor | newest web-log timestamp in this run, else current UTC time |
| `--config PATH` | the entire config file (rules included) | bundled `config.yaml` at the repo root |
| `--follow` / `-f` | one-shot pass → continuous tailing | off |

Precedence is always **command-line flag → `config.yaml` → built-in default**: an option only takes effect if explicitly passed.

```bash
uv run trace-log-sec analyze \
  --max-evidence 5 \
  --window-minutes 30 \
  --reference-time 2025-11-12T12:00:00 \
  auth.log webserver.log
```

`--reference-time` accepts `%Y-%m-%dT%H:%M:%S`, `%Y-%m-%d %H:%M:%S`, or `%Y-%m-%d`.

Use `--config` to swap out the whole config file — rules, `engine`, `correlation`, and `reporting` sections — for a single run, without touching the bundled `config.yaml`:

```bash
uv run trace-log-sec analyze --config custom-config.yaml auth.log webserver.log
```

`--config` must point to an existing, readable file; `--max-evidence`/`--window-minutes` still override whatever that file (or its defaults) sets. `list-reports` also accepts `--config`, so a run's HTML reports can be listed from the same custom `reporting.output_dir`.

#### Continuous following (`--follow`)

For live logs, `--follow` turns the one-shot pass into a `tail -f`-style session:

```bash
uv run trace-log-sec analyze --follow /var/log/auth.log /var/log/nginx/access.log
```

Each file is opened at its **end**, so only lines appended after the command starts are analyzed. Findings print as one-line alerts the moment they fire:

```
Following 2 file(s) — press Ctrl+C to stop and generate the report.
[14:07:31] [HIGH    ] ssh_brute_force        ip=10.0.0.50    count=5  SSH Brute Force
[14:09:02] [HIGH    ] directory_traversal    ip=203.0.113.5  count=1  Directory Traversal
```

Stop the session with **Ctrl+C** (or `SIGTERM`, so a `docker stop` behaves the same). The run then finishes exactly like a batch one: rules flush, findings are correlated into incidents, and the full terminal summary plus the HTML report are written. Detection is identical to batch mode — the same session code processes both — so tailing 5 lines gives the same findings as analyzing a file containing those 5 lines.

Two details worth knowing:

- Alerts are per finding, not per line. A finding is announced once, when it first crosses its threshold; later matching lines keep updating it silently, and the final report carries the complete count. Incidents appear only at the end, since correlation is a whole-run view.
- Windows still use **event time** from the log line, never the wall clock, so a delayed writer or a backfilled batch is evaluated on its own timestamps. The bracketed time on an alert is when the operator saw it.

**Limitations** (deliberate scope choices for this build):

- **No log rotation or truncation handling.** If a followed file is rotated or truncated, the run keeps holding the old handle and stops seeing new lines — restart it after a rotation.
- **State grows with the stream.** Rules keep per-IP state and the report keeps every finding, so memory grows with distinct IPs over a long session. Fine for hours of a normal feed; a permanently resident deployment would want per-IP expiry and periodic report checkpoints.
- **Format detection still reads existing content.** A file that is empty when the run starts has no detectable format and is rejected with a hint.
- **Line numbers are relative to the session**, counting from 1 at the first appended line, since content before the starting offset is never read.
- **The syslog year anchor is fixed at startup.** A session running across New Year's Eve keeps resolving auth timestamps against the year it started in; restart it (or pass `--reference-time`) after the rollover.

A scripted demo lives in `sandbox/demo/`: `./sandbox/demo/follow-demo.sh` replays the bundled sample logs into a pair of live files and tails them, so you can watch alerts appear and then stop the run to get the report.

#### Input validation

Before analysis starts, every path is checked. Problems are collected and reported together:

- file must exist and be a regular file
- extension must be `.log`
- paths must be unique (duplicates rejected)
- at least one file is required

Unrecognized formats are skipped with a warning (non-fatal), unless *every* given file is unrecognized — that is treated as an error.

#### Auth-log year anchoring

BSD syslog lines have **no year**. The CLI resolves the year as follows:

1. Explicit `--reference-time` if passed
2. Else the newest Combined-log timestamp among web logs in this run (read cheaply from each file’s tail)
3. Else the current UTC time — and a warning is printed, because archived auth-only logs can get the wrong year (which silently skews threshold windows and correlation)

When analyzing both web and auth logs together, you usually do **not** need `--reference-time`. Pass it for historical auth-only runs.

Under `--follow` step 2 is skipped: unless `--reference-time` is passed, live runs anchor to the **current time**, since lines are analyzed as they are written. The newest timestamp already sitting in a web log would be an unreliable anchor there — a quiet or freshly rotated file can be arbitrarily stale, and a stale anchor silently pushes live auth lines back a year, so they no longer correlate with the web findings they belong to. No warning is printed, because for a live stream this is the right answer rather than a guess.

#### Terminal output

```
=== FINDINGS ===
  [HIGH    ] ssh_brute_force        ip=198.51.100.23  count=8   SSH Brute Force
  ...

=== INCIDENTS ===
  INC-a1b2c3d4e5 [HIGH] 203.0.113.150
    ...narrative...

=== PARSE ERRORS ===
  (none)

=== STATS === lines_read=4167 parsed=4160 malformed=7 findings=12 incidents=3 (0.0421s)

HTML report written to reports/report_2026_07_31_12_00_00.html
```

Findings are sorted by severity (highest first), then rule id. Parse errors show source, line number, reason, and a raw snippet.

#### HTML report

Every successful `analyze` also writes a standalone HTML report under the directory configured in `config.yaml` (`reporting.output_dir`, default `reports/`). The directory is created automatically if missing. Filename format:

```
report_YYYY_MM_DD_HH_MM_SS.html
```

Relative paths resolve against the **current working directory**. A write failure (e.g. unwritable directory) only warns — the terminal analysis is never discarded.

The HTML report includes:

- executive summary tiles (findings, incidents, lines read/parsed/malformed, duration)
- correlated incident cards with nested findings and expandable evidence
- findings table (severity, IP, count, sources, time span, description, evidence)
- parse-error table when any malformed lines were seen

All log-derived values are HTML-escaped before embedding (attacker-controlled content must not become stored XSS when the report is opened in a browser).

### List previous reports

```bash
uv run trace-log-sec list-reports
```

Scans `reporting.output_dir` and prints generated reports newest-first with their timestamps. Files that do not match the `report_YYYY_MM_DD_HH_MM_SS.html` naming convention are ignored. A missing directory yields an empty result, not an error.

Accepts `--config PATH` as well, to list reports from a custom config's `reporting.output_dir` instead of the bundled `config.yaml`'s.

---

## Configuration

All runtime knobs live in `config.yaml` at the repo root (shipped with the package):

```yaml
engine:
  max_evidence: 20          # ceiling on evidence lines stored per finding

correlation:
  window_minutes: 10        # IP clustering window for incidents

reporting:
  output_dir: reports       # HTML report directory (cwd-relative or absolute)

rules:
  - id: ssh_brute_force
    type: threshold
    severity: high
    params: { ... }
```

Sections `engine`, `correlation`, and `reporting` are optional — omitted keys fall back to the built-in defaults above. Rules are described in [Shipped rules](#shipped-rules-configyaml) and [Adding a new rule](#adding-a-new-rule).

Pass `--config PATH` to `analyze` (or `list-reports`) to use a different config file entirely for a single run, instead of editing the bundled `config.yaml`.

---

## How it works

The pipeline is a crash-proof, streaming, single-pass flow:

```
LogSource(s)  →  parse_file      ↘
                                   AnalysisSession  →  Correlator  →  AnalysisReport
                 follow_sources  ↗  (rule.inspect / flush)          ↘ terminal + HTML
```

A batch run reads each file to EOF through `parse_file`; a `--follow` run keeps tailing them through `follow_sources`. Both feed the same session, so the two modes differ only in where the lines come from and when the report is produced.

### 1. Parsing (`engine/parsers.py`)

Every parser implements `LogParser`: a `source` label plus `parse_line(line, line_no) → LogEntry`. Parsers are pure — they raise `MalformedLineError` on bad input and never touch the filesystem themselves.

`parse_file(path, parser)` wraps a parser in a crash-proof generator:

- Opens with `encoding="utf-8", errors="replace"`.
- Skips blank lines.
- Yields `LogEntry` on success, or `ParseError` on `MalformedLineError`.
- A missing/unreadable file yields a single source-level `ParseError` with `line_no = 0` (callers decide if that is fatal).

#### CombinedLogParser (webserver)

Parses NCSA Common/Combined access-log lines:

```
IP identity user [dd/Mon/yyyy:HH:MM:SS +zzzz] "METHOD target proto" status size ["referrer" "user-agent"]
```

- Referrer/user-agent are optional (Common vs Combined).
- Timestamp uses `%d/%b/%Y:%H:%M:%S %z` (timezone-aware).
- Produces `WebLogEntry` with `method`, `target` (path **and** query), `status`, etc.
- Convenience properties: `path` (no query), `query` (no leading `?`).
- A garbage request inside an otherwise valid line is best-effort split (still a signal, not a parse error).

#### SyslogAuthParser (auth)

Parses BSD syslog:

```
Mon DD HH:MM:SS host process[pid]: message
```

BSD syslog has **no year** and **no timezone**. The parser resolves these as follows:

- **Year:** pick the year that makes `(month, day, time)` the most recent occurrence at or before `reference_time` (default: now). If the candidate is in the future relative to the reference, subtract one year. An explicit `default_year` can force a fixed year. The CLI supplies `reference_time` automatically (see [Auth-log year anchoring](#auth-log-year-anchoring)).
- **Timezone:** attach `tz` (default UTC) so every engine timestamp is tz-aware and comparable with web-log times.

Message semantics map to `AuthOutcome`:

| Message shape | Outcome |
|---|---|
| `Failed password for invalid user X from …` | `INVALID_USER` |
| `Failed password for X from …` | `FAILURE` |
| `Accepted password/publickey for X from …` | `SUCCESS` |
| `Connection closed by … [preauth]`, etc. | `OTHER` (IP/port still extracted) |

Produces `AuthLogEntry` with `hostname`, `process`, `pid`, `message`, `outcome`, `username`, `source_ip`, `source_port`.

---

### 2. Detection rules (`engine/rules/`)

Every rule implements the same small interface:

```python
class Rule(ABC):
    id: str
    severity: Severity

    def inspect(self, entry: LogEntry) -> Iterable[Finding]: ...
    def flush(self) -> Iterable[Finding]: ...  # end-of-stream aggregates
    def reset(self) -> None: ...  # clear state between runs
```

Rules ignore entry types they don't care about (`isinstance` checks), so the engine feeds **every** entry to **every** rule with no special casing.

There are **two algorithm classes**. All shipped detections are instances of one of these — parameters are data, algorithms are code.

#### PatternSignatureRule (`type: signature`)

Stateless per-line regex matching, aggregated per IP into one `Finding`.

| Param | Role |
|---|---|
| `patterns` | List of regexes |
| `target` | Named field extractor (see presets below) |
| `case_sensitive` | Default `false` → `re.IGNORECASE` |
| `min_hits` | Minimum matches before emit (default 1) |
| `max_evidence` | Cap on stored evidence lines |
| `max_decode_passes` | Nested URL-decode attempts (default 2) |

**Target presets:** `request_target`, `path`, `query`, `user_agent`, `referrer`, `auth_message`.

**URL decoding:** matching runs against the union of `{raw, decoded}` forms, with up to 2 recursive `unquote` passes (catches double-encoding like `%252e`). Invalid `%` sequences are left as-is (fail-soft).

**Aggregation:** hits for the same IP fold into one finding; `metadata["matches"]` records which pattern/snippet fired. Findings with no IP (e.g. some sudo lines) still aggregate, but the correlator cannot join them across sources.

**Emission:** like `ThresholdRule`, the finding is emitted from `inspect` the moment that IP reaches `min_hits`, then updated in place — so a `--follow` run alerts on a signature hit as it happens instead of waiting for end of stream.

#### ThresholdRule (`type: threshold`)

Stateful per-IP sliding window. Fires **one finding per burst** that crosses the threshold.

| Param | Role |
|---|---|
| `match` | Named predicate selecting which events count |
| `threshold` | Count that must be reached |
| `window_seconds` | Sliding window length |
| `distinct_by` | Optional: count distinct field values instead of events |

**Match presets:**

| Name | Matches |
|---|---|
| `auth_failure` | Auth `FAILURE` or `INVALID_USER` |
| `web_login_failure` | Web 401/403 to a path containing `login` |
| `web_404` | Web status 404 |

**Distinct-by presets:** `path` (normalized: no query, trailing slash trimmed), `username`.

**Burst semantics:**

1. On each matching event, append to a per-IP deque.
2. Evict events older than `window` relative to the **max timestamp seen for that IP** (tolerates minor out-of-order arrival).
3. When count first reaches `threshold`, emit one `Finding`; later events in the same burst update it in place.
4. When count drops back below threshold (events age out), the active finding is cleared — a later re-crossing starts a **new** finding.

Windows use event timestamps only (never wall-clock / processing time).

#### Shipped rules (`config.yaml`)

| ID | Type | What it detects | Defaults |
|---|---|---|---|
| `ssh_brute_force` | threshold | Repeated SSH auth failures from one IP | ≥5 `auth_failure` / 60s → HIGH |
| `web_login_brute_force` | threshold | Repeated failed web logins | ≥10 `web_login_failure` / 60s → MEDIUM |
| `web_scanning` | threshold | Path enumeration via distinct 404s | ≥15 distinct paths / 120s → MEDIUM |
| `directory_traversal` | signature | `../`, `/etc/passwd`, `%2e%2e`, … | any hit → HIGH |
| `sql_injection` | signature | `union select`, tautologies, `drop table`, … | any hit → HIGH |
| `sensitive_file_exposure` | signature | `.env`, `.git/`, `id_rsa`, `wp-config.php`, … | any hit → HIGH |
| `scanner_user_agent` | signature | sqlmap, nikto, nmap, gobuster, … | any hit → MEDIUM |
| `sudo_privilege_escalation` | signature | sudo reading shadow/passwd/keys, useradd, … | any hit → CRITICAL |

SQL-injection patterns deliberately match SQL *syntax*, never lone metacharacters — a benign `O'Brien` produces zero hits.

#### Config → instances

```
config.yaml  →  load_settings()  →  rule_specs()  →  build_rules()  →  list[Rule]
```

`build_rules` looks up each `type` in `RULE_TYPES` (populated by `@register`), merges top-level `severity` with `params`, skips `enabled: false`, and instantiates. A later rule with the same `id` overrides an earlier one.

---

### 3. Correlation (`engine/correlation.py`)

After all rules have flushed, `Correlator` groups findings into multi-signal `Incident`s:

1. Group findings by `source_ip` (findings with no IP are skipped).
2. Sort each IP's findings by `first_seen`.
3. Greedily cluster findings whose gap from the running span is ≤ `window` (default **10 minutes**).
4. A cluster becomes an incident **only if** it spans ≥2 distinct `rule_id`s **or** ≥2 distinct log sources. A single rule's repeated findings never form an incident — even if far apart.
5. Incident severity = one level above the max child severity, capped at CRITICAL.
6. `incident_id` is deterministic: `INC-` + `sha1(ip|first_seen|sorted_rule_ids)[:10]`.
7. `narrative` summarizes which rules/sources fired and over what span.

Correlation is the **only** place cross-source relationships are formed. Stateful rules themselves are single-source (their `match` predicate selects one log type), so the engine does not merge-sort streams across files.

**Known limit:** sudo lines often carry no source IP, so `sudo_privilege_escalation` findings cannot be joined into an IP-keyed incident with SSH/web activity from the same attacker.

---

### 4. Orchestration (`engine/engine.py`, `engine/session.py`)

`Engine.analyze(sources) → AnalysisReport` runs the full pipeline:

```
0. reset() every rule          # safe re-runs on the same Engine instance
1. for each LogSource:
     parse_file(...)
       ParseError  → collect + log warning
       LogEntry    → feed to every rule.inspect(); collect eager findings
2. flush() every rule          # any aggregate not already emitted
3. cap evidence                # engine-wide max_evidence ceiling
4. correlator.correlate(...)   # findings → incidents
5. build stats                 # per-source + totals + duration_seconds
```

Steps 1–5 live in `AnalysisSession`, not in `Engine`: `session.feed(item, counters)` does the per-entry work and returns the findings that item newly emitted, and `session.finalize()` does the closing steps. `Engine.analyze` is just the batch driver over that session — the follow loop drives the same session from the tailer instead, which is why both modes detect identically.

### 5. Following (`engine/tailing.py`)

`follow_sources(sources, ...)` is the streaming counterpart to `parse_file`. It opens each file at its end, polls them round-robin in a single loop (no threads), holds back a trailing partial line until its newline arrives, and yields the same `LogEntry`/`ParseError` items — so the session cannot tell which producer it is being fed by. It runs until its `stop` predicate returns true, which the CLI wires to Ctrl+C and `SIGTERM`. See [`--follow`](#continuous-following---follow) for the operator-facing behavior and limitations.

**Ordering invariants:**

- Sources are consumed **sequentially** (file A fully, then file B) — not merge-sorted by timestamp.
- Stateful rules only ever see one source type, so per-file order is enough.
- Cross-file relationships are the correlator's job (post-hoc, timestamp-based).

**Failure policy:** never crash on bad input. Malformed lines and missing files become `ParseError`s in the report; rule exceptions are logged and skipped.

**Report shape:**

```python
AnalysisReport(
    findings: list[Finding],      # per-rule detections
    incidents: list[Incident],    # correlated multi-signal groups
    parse_errors: list[ParseError],
    stats: {
        "sources": { "<path>": {lines_read, parsed, malformed, skipped_blank} },
        "totals":  { ..., findings, incidents },
        "duration_seconds": float,
    },
)
```

The CLI then renders the report to the terminal (`cli/render.py`) and persists HTML (`reporter/`).

---

## File structure

```
trace-log-sec/
├── config.yaml                 # Shipped rules + engine/correlation/reporting (edit this)
├── samples/                    # Sample logs with embedded incidents (see incidents_manifest.md)
├── src/
│   ├── engine/                 # Detection core (format-agnostic)
│   │   ├── engine.py           # Orchestrator: parse → detect → correlate
│   │   ├── session.py          # Incremental run state (feed / finalize)
│   │   ├── parsers.py          # Combined + syslog parsers, parse_file()
│   │   ├── tailing.py          # tail -f style following for --follow
│   │   ├── correlation.py      # IP-based finding correlator
│   │   └── rules/
│   │       ├── base.py         # Rule ABC (inspect / flush / reset)
│   │       ├── signature.py    # PatternSignatureRule
│   │       ├── threshold.py    # ThresholdRule
│   │       ├── registry.py     # @register("type") → RULE_TYPES
│   │       ├── factory.py      # build_rules(specs) → Rule instances
│   │       └── utils.py        # Shared helpers (presets, evidence)
│   ├── models/                 # Dataclasses (parsers, rules, correlation, engine)
│   ├── config/
│   │   └── settings.py         # YAML → validated settings
│   ├── constants/              # Shared literals (windows, formats, defaults)
│   ├── cli/                    # Typer CLI
│   │   ├── app.py              # Shared Typer app
│   │   ├── commands/           # analyze, list-reports
│   │   ├── formats.py          # Format sniffing + LogSource construction
│   │   ├── validation.py       # Path / .log / uniqueness checks
│   │   └── render.py           # Terminal report rendering
│   ├── reporter/               # Standalone HTML reports
│   │   ├── html.py             # Pure HTML renderer (XSS-safe)
│   │   └── storage.py          # write / list / resolve output dir
│   ├── utils/                  # Exceptions (MalformedLineError, ConfigError, …)
│   └── tests/                  # Unit tests
├── docs/                       # Design plans (engine, rules, config)
├── task.md                     # Original assignment brief
└── pyproject.toml
```

**Separation of concerns:** the `engine` package is format-agnostic — it accepts structured rule specs (plain dicts), never a YAML path. Config loading lives in `config/`. Format sniffing and presentation (terminal + HTML) live in `cli/` and `reporter/`. Models are split by consumer so each package owns the types it produces.

---

## Adding a new rule

There are three tiers of extensibility. Prefer the cheapest one that fits.

### Tier 1 — Retune an existing rule (config only)

Edit `config.yaml` (repo root): change `threshold`, `window_seconds`, `severity`, `patterns`, or set `enabled: false`.

```yaml
- id: ssh_brute_force
  type: threshold
  severity: critical        # was: high
  params:
    match: auth_failure
    threshold: 3            # was: 5
    window_seconds: 30      # was: 60
    title: SSH Brute Force
```

No code changes required.

### Tier 2 — New detection using an existing class (config only)

Add a new entry with a unique `id` and an existing `type` (`threshold` or `signature`).

**Example — credential stuffing** (many distinct usernames failing from one IP):

```yaml
- id: credential_stuffing
  type: threshold
  severity: high
  params:
    match: auth_failure
    distinct_by: username
    threshold: 20
    window_seconds: 300
    title: Credential Stuffing
    description: Many distinct usernames failing auth from one IP.
```

**Example — new signature** (XSS probing in the query string):

```yaml
- id: xss_probe
  type: signature
  severity: medium
  params:
    target: query
    title: XSS Probe
    description: Script-injection syntax in the query string.
    patterns:
      - "<script\\b"
      - "javascript:"
      - "onerror\\s*="
```

Available presets (must already exist in code):

| Kind | Names |
|---|---|
| `match` (threshold) | `auth_failure`, `web_login_failure`, `web_404` |
| `distinct_by` (threshold) | `path`, `username` |
| `target` (signature) | `request_target`, `path`, `query`, `user_agent`, `referrer`, `auth_message` |

If you need a new match predicate or target field, that is Tier 3 (a small code change to the preset dicts in `threshold.py` / `signature.py`) — still cheaper than a whole new algorithm class.

### Tier 3 — New algorithm class (code + config)

Use this when neither signature nor threshold captures the detection logic (e.g. sequence detection, rate-of-change, cross-field conditions).

**Step 1 — Implement the class**

Create a module under `src/engine/rules/` (or add to an existing one) and subclass `Rule`:

```python
# src/engine/rules/sequence.py
from __future__ import annotations

from collections.abc import Iterable

from engine.rules.base import Rule
from engine.rules.registry import register
from models import Finding, LogEntry, Severity


@register("sequence")  # ← makes type: sequence available in config
class SequenceRule(Rule):
    """Example: fire when event A is followed by event B within a gap."""

    def __init__(
        self,
        *,
        id: str,
        severity: Severity = Severity.HIGH,
        title: str | None = None,
        description: str = "",
        # …your params…
    ) -> None:
        self.id = id
        self.title = title or id
        self.severity = severity
        self.description = description
        # hold any per-IP state here

    def reset(self) -> None:
        # clear state so Engine can re-run safely
        ...

    def inspect(self, entry: LogEntry) -> Iterable[Finding]:
        # examine one entry; yield each finding once, when it first qualifies,
        # then keep updating it in place. Ignore entry types you don't care
        # about. Only what you yield here can appear in a --follow run's live
        # output, so prefer emitting here over buffering for flush().
        ...

    def flush(self) -> Iterable[Finding]:
        # emit anything that can only be decided at end of stream
        return ()
```

**Step 2 — Export it**

Import the module so `@register` runs at package load. In `src/engine/rules/__init__.py`:

```python
from engine.rules.sequence import SequenceRule  # noqa: F401  (side-effect: register)

__all__ = [..., "SequenceRule"]
```

Also re-export from `src/engine/__init__.py` if it should be part of the public API.

**Step 3 — Wire it in config**

```yaml
- id: my_sequence_rule
  type: sequence
  severity: high
  params:
    title: My Sequence Rule
    description: ...
    # params map 1:1 to constructor kwargs (except id / severity / type)
```

**Step 4 — Escape hatch (tests / ad-hoc)**

You can also bypass config entirely and pass instances straight to the engine:

```python
from engine import Engine, SequenceRule
from models import Severity

engine = Engine(
    rules=[
        SequenceRule(id="my_sequence_rule", severity=Severity.HIGH, title="…"),
    ]
)
```

This is what unit tests typically do.

### Checklist for a new rule

1. Can you express it with existing `type` + presets? → edit `config.yaml` only.
2. Need a new `match` / `target` / `distinct_by` preset? → add a named function to the preset dict in `threshold.py` or `signature.py`, then reference it from config.
3. Need a new algorithm? → subclass `Rule`, `@register("name")`, export, add a config entry.
4. Add a unit test under `src/tests/test_rules.py` covering the boundary cases (threshold N−1 vs N, pattern hit/miss, flush aggregation, `reset` idempotency).

---

## Development

```bash
# Install with test + lint tooling
uv sync --group dev --group test

# Run the full suite
uv run pytest

# Lint / format
uv run ruff check .
uv run ruff format .

# Type-check
uv run mypy
```

Sample logs used for end-to-end demos live under `samples/`; see `incidents_manifest.md` there for the embedded attack scenarios.
