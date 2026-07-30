# trace-log-sec

A security log analysis engine that parses webserver and authentication logs, detects suspicious activity with configurable rules, and correlates related findings into incidents.

It processes NCSA Combined access logs (`webserver.log`) and BSD syslog auth logs (`auth.log`), runs signature and threshold detectors, then groups multi-signal activity by IP into correlated incidents. The design goal is a crash-proof, streaming, single-pass pipeline that stays memory-efficient and easy to extend.

> **Note:** This is a preliminary README covering project structure and engine logic. Installation, CLI usage, and packaging details will be added later.

---

## File structure

```
trace-log-sec/
├── src/
│   ├── engine/                 # Detection core
│   │   ├── engine.py           # Orchestrator: parse → detect → correlate
│   │   ├── parsers.py          # Combined + syslog parsers, parse_file()
│   │   ├── correlation.py      # IP-based finding correlator
│   │   └── rules/
│   │       ├── base.py         # Rule ABC (inspect / flush / reset)
│   │       ├── signature.py    # PatternSignatureRule
│   │       ├── threshold.py    # ThresholdRule
│   │       ├── registry.py     # @register("type") → RULE_TYPES
│   │       ├── factory.py      # build_rules(specs) → Rule instances
│   │       └── utils.py        # Shared helpers (presets, evidence)
│   ├── models/                 # Frozen/mutable dataclasses
│   │   ├── parsers.py          # LogEntry, WebLogEntry, AuthLogEntry, ParseError
│   │   ├── rules.py            # Finding, Severity
│   │   ├── correlation.py      # Incident
│   │   └── engine.py           # LogSource, AnalysisReport
│   ├── config/
│   │   ├── config.yaml         # Shipped rule definitions
│   │   └── settings.py         # YAML → validated RuleSpec dicts
│   ├── constants/              # Shared literals (windows, formats, defaults)
│   ├── cli/                    # CLI surface (WIP)
│   ├── utils/                  # Exceptions (MalformedLineError, ConfigError, …)
│   └── tests/                  # Unit + fixture logs
├── scripts/run_demo.py         # End-to-end smoke demo
├── docs/                       # Design plans (engine, rules, config)
├── task.md                     # Original assignment brief
└── pyproject.toml
```

**Separation of concerns:** the `engine` package is format-agnostic — it accepts structured rule specs (plain dicts), never a YAML path. Config loading lives in `config/`. Models are split by consumer so each package owns the types it produces.

---

## Engine logic

The pipeline is:

```
LogSource(s)  →  parse_file  →  Rule.inspect / flush  →  Correlator  →  AnalysisReport
```

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

- **Year:** pick the year that makes `(month, day, time)` the most recent occurrence at or before `reference_time` (default: now). If the candidate is in the future relative to the reference, subtract one year. An explicit `default_year` can force a fixed year.
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
    def flush(self) -> Iterable[Finding]: ...   # end-of-stream aggregates
    def reset(self) -> None: ...                # clear state between runs
```

Rules ignore entry types they don't care about (`isinstance` checks), so the engine feeds **every** entry to **every** rule with no special casing.

There are **two algorithm classes**. All shipped detections are instances of one of these — parameters are data, algorithms are code.

#### PatternSignatureRule (`type: signature`)

Stateless per-line regex matching, aggregated per IP into one `Finding` (emitted on `flush`).

| Param | Role |
|---|---|
| `patterns` | List of regexes |
| `target` | Named field extractor (see presets below) |
| `case_sensitive` | Default `false` → `re.IGNORECASE` |
| `min_hits` | Minimum matches before emit (default 1) |
| `max_evidence` | Cap on stored evidence lines |

**Target presets:** `request_target`, `path`, `query`, `user_agent`, `referrer`, `auth_message`.

**URL decoding:** matching runs against the union of `{raw, decoded}` forms, with up to 2 recursive `unquote` passes (catches double-encoding like `%252e`). Invalid `%` sequences are left as-is (fail-soft).

**Aggregation:** hits for the same IP fold into one finding; `metadata["matches"]` records which pattern/snippet fired.

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

#### Shipped rules (`config/config.yaml`)

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

---

### 4. Orchestration (`engine/engine.py`)

`Engine.analyze(sources) → AnalysisReport` runs the full pipeline:

```
0. reset() every rule          # safe re-runs on the same Engine instance
1. for each LogSource:
     parse_file(...)
       ParseError  → collect + log warning
                     (strict=True + missing file → raise FileNotFoundError)
       LogEntry    → feed to every rule.inspect(); collect eager findings
2. flush() every rule          # signature aggregates land here
3. cap evidence                # engine-wide max_evidence ceiling
4. correlator.correlate(...)   # findings → incidents
5. build stats                 # per-source + totals + duration_seconds
```

**Ordering invariants:**

- Sources are consumed **sequentially** (file A fully, then file B) — not merge-sorted by timestamp.
- Stateful rules only ever see one source type, so per-file order is enough.
- Cross-file relationships are the correlator's job (post-hoc, timestamp-based).

**Failure policy:** never crash on bad input by default. Malformed lines and missing files become `ParseError`s in the report. Rule exceptions are logged and skipped unless `strict=True`.

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

---

## Adding a new rule

There are three tiers of extensibility. Prefer the cheapest one that fits.

### Tier 1 — Retune an existing rule (config only)

Edit `src/config/config.yaml`: change `threshold`, `window_seconds`, `severity`, `patterns`, or set `enabled: false`.

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


@register("sequence")          # ← makes type: sequence available in config
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
        # examine one entry; yield findings eagerly, or return () and
        # buffer for flush(). Ignore entry types you don't care about.
        ...

    def flush(self) -> Iterable[Finding]:
        # emit end-of-stream aggregates (like PatternSignatureRule does)
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

engine = Engine(rules=[
    SequenceRule(id="my_sequence_rule", severity=Severity.HIGH, title="…"),
])
```

This is what unit tests typically do.

---

### Checklist for a new rule

1. Can you express it with existing `type` + presets? → edit `config.yaml` only.
2. Need a new `match` / `target` / `distinct_by` preset? → add a named function to the preset dict in `threshold.py` or `signature.py`, then reference it from config.
3. Need a new algorithm? → subclass `Rule`, `@register("name")`, export, add a config entry.
4. Add a unit test under `src/tests/test_rules.py` covering the boundary cases (threshold N−1 vs N, pattern hit/miss, flush aggregation, `reset` idempotency).
