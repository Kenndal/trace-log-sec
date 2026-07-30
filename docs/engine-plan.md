# Core Engine — Design Plan

Scope: **only** the log-processing/detection engine. No CLI, no output
formatting, no packaging/project scaffolding. This document is the plan to
review before any code is written.

---

## 1. Goals & non-goals

**Goals**
- Parse `webserver.log` (NCSA Combined Log Format) and `auth.log` (BSD syslog).
- Never crash on malformed/corrupted lines — capture them as structured errors.
- Rule-based detection: Brute Force, Directory Traversal, SQL Injection, Web Scanning.
- Cross-file correlation by entity (IP) within a configurable time window.
- Clean, typed, immutable data models ready for a later CLI/presenter.
- Memory-efficient (streaming/generators) and highly unit-testable.

**Non-goals (this module)**
- No `argparse`/click CLI, no colored/table output, no file discovery.
- No persistence/DB, no threading — single-pass, in-process.

---

## 2. Assumptions (RESOLVED)

1. `webserver.log` is **Combined** format:
   `IP identity user [dd/Mon/yyyy:HH:MM:SS +zzzz] "METHOD target proto" status size "referrer" "user-agent"`. — **confirmed.**
2. `auth.log` is **BSD syslog**: `Mon DD HH:MM:SS host process[pid]: message`.
   BSD syslog carries **no year** → resolved by a reference-time heuristic, see §5.1.
3. Log lines within a single file are **roughly chronological**. Sliding-window
   rules tolerate minor disorder (see §6.3); extreme reordering is out of scope.
4. Detection is **signature/heuristic** based (no ML, no threat-intel feeds).
5. Correlation entity is the **IP address only** for now (user-based correlation
   deferred). See §6.2 — shipped rules always **group by IP**, so every `Finding`
   has one meaningful `source_ip`; `distinct_by: username` is only *evidence*, not
   a correlation key. `group_by: username` (password spraying across many IPs) is
   the same deferral as user-based correlation.
6. Default thresholds/windows are provided but **must be configurable** (§6.1).

---

## 3. Module layout (engine-internal only)

```
engine/
  __init__.py        # public exports (models, parsers, rules, Engine)
  models.py          # LogEntry hierarchy, ParseError, Finding, Incident, enums
  parsers.py         # LogParser ABC, CombinedLogParser, SyslogAuthParser, parse_file()
  rules.py           # Rule ABC, PatternSignatureRule, ThresholdRule, registry, build_rules
  correlation.py     # Correlator (group findings by IP within a time window)
  engine.py          # Engine orchestration + AnalysisReport + LogSource
```

---

## 4. Data models (`models.py`)

Frozen, `kw_only` dataclasses (Python 3.10+).

- `LogEntry` (base): `timestamp`, `source`, `raw`, `line_no`, `source_ip`.
  Every rule/correlator relies only on the normalized `timestamp` + `source_ip`.
- `WebLogEntry(LogEntry)`: `method, target, protocol, status, size, identity,
  user, referrer, user_agent`.
  **`target` = the request target exactly as sent, path *and* query string**
  (e.g. `/search?q=' OR 1=1`). Convenience props: `path` (target without query),
  `query` (query only).
- `AuthLogEntry(LogEntry)`: `hostname, process, pid, message, outcome
  (AuthOutcome enum), username, source_port`.
- `ParseError` (frozen): `source, line_no, raw, reason` — collected, never raised.
  Also used for source-level failures (missing file) with `line_no = 0`.
- `Severity(IntEnum)`: INFO/LOW/MEDIUM/HIGH/CRITICAL — ordered for sorting.
- `Finding`: `rule_id, title, severity, description, first_seen, last_seen,
  source_ip, count, sources:set, evidence:list[LogEntry], metadata:dict`.
- `Incident`: `incident_id, title, severity, source_ip, first_seen, last_seen,
  findings:list[Finding], narrative`.

Rationale: immutable entries are safe to share across rules; `Finding`/`Incident`
are mutable aggregates the engine builds up then hands off read-only downstream.

---

## 5. Parsing (`parsers.py`)

- `LogParser` ABC: attribute `source` + `parse_line(line, line_no) -> LogEntry`.
  Pure and side-effect free → trivially unit-testable.
- `MalformedLineError(reason)`: raised by a parser when a line can't be parsed.
- `parse_file(path, parser) -> Iterator[LogEntry | ParseError]`: **generator**
  that opens with `errors="replace"`, skips blank lines, and converts any
  `MalformedLineError` into a `ParseError` so the stream is crash-proof.

**CombinedLogParser**
- Single anchored regex; referrer/user-agent optional (Common vs Combined).
- Timestamp via `%d/%b/%Y:%H:%M:%S %z`.
- Request line split into method / **target** / protocol; a **garbage request
  inside an otherwise valid line** yields best-effort fields (not a `ParseError` —
  the line is structurally valid and is itself a signal). `size` of `-` → 0.

**SyslogAuthParser**
- Regex for `timestamp host proc[pid]: msg`; year resolved per §5.1.
- Message semantics → `AuthOutcome` (single-valued):
  - `Failed password for invalid user X from IP …` → **`INVALID_USER`**
  - `Failed password for X from IP …` → `FAILURE`
  - `Accepted password/publickey for X from IP …` → `SUCCESS`
  - `Connection closed by IP … [preauth]`, `Received disconnect …` → `OTHER`
    **with IP/port still extracted** (kept as context/evidence, not a failure)
  - anything else → `OTHER`
  - extracts `username`, `source_ip`, `source_port` whenever present.
- Lines like `[MALFORMED ENTRY` fail the regex → `ParseError`.

### 5.1 Year resolution for syslog (no year in BSD format)

- `reference_time` param (default: `datetime.now`, injectable); `default_year`
  may also be passed to force a fixed year.
- Heuristic: choose the year that makes each `(month, day, time)` the most recent
  occurrence **at or before** `reference_time` — i.e. start from the reference
  year, and if the resulting datetime is in the future, subtract one year.
- Why: with `reference_time = 2026-07-30`, "Oct 10" resolves to **2025**,
  automatically aligning `auth.log` with a 2025 `webserver.log` so correlation
  works with zero config.
- Known limitation: a single file spanning a New-Year boundary is imperfect;
  pass an explicit `default_year`/`reference_time` for those.
- **Timezone (implementation note):** BSD syslog has no offset, so the parser
  attaches one (`tz` param, **default UTC**) → every engine timestamp is
  tz-aware and directly comparable with web-log times (which carry an explicit
  offset). This is required for cross-file correlation to compare timestamps.

---

## 6. Detection rules (`rules.py`)

One small interface, two behavioral shapes:

```python
class Rule(ABC):
    id: str
    def inspect(self, entry: LogEntry) -> Iterable[Finding]: ...
    def flush(self) -> Iterable[Finding]: return ()   # emit end-of-stream aggregates
    def reset(self) -> None: ...                       # clear state; called by analyze()
```

Rules **ignore entry types they don't care about** (isinstance check), so the
engine feeds every entry to every rule with no special casing.

- **`PatternSignatureRule` (stateless per line, aggregated per IP)** — data-driven
  (list of regexes, `severity`, `target`). Matches on the chosen `target`
  (default = request target incl. query string; also `path`, `query`,
  `user_agent`, `referrer`). Patterns are `IGNORECASE` by default (per-rule
  `case_sensitive` override). Matching runs against **raw ∪ URL-decoded** forms
  (see §6.3). Aggregates matches per IP into one `Finding` (bounded evidence),
  emitted on `flush`. Presets: directory traversal, SQL injection.

- **`ThresholdRule` (stateful sliding window)** — single primitive for
  volume/breadth anomalies. Per-IP `deque` over a `window`; fires when a count
  crosses `threshold`. Parameters:
  - `match` — named predicate for which events count (`auth_failure`,
    `web_login_failure`, `web_404`, …). `auth_failure` **includes**
    `FAILURE` *and* `INVALID_USER`.
  - `distinct_by` — optional field extractor. **Absent → count events (volume =
    brute force). Present → count distinct field values (breadth = scanning).**
  - `threshold`, `window`, `severity`.
  Firing/burst/ordering semantics: see §6.3. Examples:
  - SSH brute force: `match=auth_failure, threshold=5, window=60`
  - Web scanning: `match=web_404, distinct_by=path, threshold=15, window=120`
  - Credential stuffing: `match=auth_failure, distinct_by=username, threshold=20, window=300`

**Net: two algorithm classes total** — `PatternSignatureRule` (stateless regex)
and `ThresholdRule` (stateful window). Instance `id`/`title` carry the
human-readable name (e.g. "Web Scanning"), independent of the underlying type.

### 6.1 Configuration model (data vs. behavior)

Guiding principle: **parameters are data (config); algorithms are code.** No
config mini-language for control flow — that path leads to a bad, unsafe DSL.

- **In code (behavior):** the algorithm classes `PatternSignatureRule` and
  `ThresholdRule`. These are *behavior*, not settings.
- **In config (data):** thresholds, windows, severities, regex pattern lists,
  match target, case sensitivity, enable/disable, and the named `match` preset.

**Registry + factory.** Each Rule class registers under a `type` name via a
`@register("...")` decorator into `RULE_TYPES: dict[str, type[Rule]]`.
`build_rules(specs)` reads a list of rule specs, looks up each `type`, validates
`params`, and instantiates. The engine core accepts **structured specs (list of
dicts / typed `RuleSpec`)**, NOT a file path — YAML/TOML/JSON loading is a thin
adapter at the CLI edge later, keeping the core format-agnostic and testable.

Example config (illustrative — parsed outside core into specs):

```yaml
rules:
  - id: ssh_brute_force
    type: threshold                # volume: count events
    enabled: true
    severity: high
    params: { match: auth_failure, threshold: 5, window_seconds: 60 }
  - id: web_login_brute_force      # same type, different params — no code
    type: threshold
    params: { match: web_login_failure, threshold: 10, window_seconds: 60 }
  - id: web_scanning               # breadth: count DISTINCT paths
    type: threshold
    severity: medium
    params: { match: web_404, distinct_by: path, threshold: 15, window_seconds: 120 }
  - id: sql_injection
    type: signature
    severity: high
    params:
      target: request_target       # path + query
      patterns: ["union\\s+select", "'\\s*or\\s*'1'='1", "xp_cmdshell"]
correlation:
  window_seconds: 600
```

**Three tiers of extensibility:**
1. **Re-tune** any threshold/window/severity/on-off — config only.
2. **Add a new detection of an existing shape** — a new SQLi/traversal signature,
   or another threshold rule — config only, pure regex/params.
3. **Add a new algorithm** — a new `Rule` subclass with `@register("type")`; a
   few lines, and the parse loop/engine never change.
Plus an **escape hatch**: instantiate any `Rule` and pass it straight to
`Engine(rules=[...])` (this is what unit tests do).

**Defaults are a baseline, not a cage.** `default_rules()` ships a working set
(SSH brute force, traversal, SQLi, web scan) with the agreed defaults. Supplying
config **overrides by `id`**: same `id` replaces params, `enabled: false`
disables a default, new `id`s add rules.

**Safety boundary.** The `match` value is a **named preset** resolved from a small
in-code registry of predicates — the config never executes arbitrary Python (no
`eval`, no injection surface). A genuinely novel predicate is a Tier-3 code addition.

### 6.2 Three entities — keep them distinct (consistency with §2.5 IP-only)

`ThresholdRule` involves three *different* notions of "entity"; conflating them
is what would break the IP-only correlation decision:

| Concept | Role | Value now |
|---|---|---|
| `group_by` | key the sliding window is bucketed by | **IP** |
| `distinct_by` | field we count distinct values of within a bucket | any field (path, username) — **metadata/evidence, not a key** |
| correlation key | how `Correlator` joins findings across rules | **IP** (§2.5) |

**Invariant:** every shipped rule **groups by IP**, so every `Finding` has one
meaningful `source_ip` the correlator can join on. `distinct_by: username`
(credential stuffing) is fine — still IP-grouped. `group_by: username` (password
spraying) is deferred (same deferral as user-based correlation). `group_by` may
exist as an internal extension point but defaults to IP and all presets use IP.

### 6.3 Detection semantics (precise)

**URL-decoding (signature rules).** Bounded **recursive** decode: up to 2 passes,
stopping when stable (catches double-encoding like `%252e`). Invalid `%`
sequences are **left as-is (fail-soft, never raise)**. Patterns are matched
against the **union of {raw target, decoded target}**, so a decode quirk can
never hide a hit. Decoding uses `urllib.parse.unquote(..., errors="replace")`.

**Threshold firing — one finding per burst.** Window is measured on **event
timestamps only** (never wall/processing time). On each matching event: append to
the per-IP deque, evict events older than `window` relative to the **max
timestamp seen for that IP** (the deque's right edge). When the count first
reaches `threshold`, create **one** `Finding` for that IP; subsequent qualifying
events fold into the same finding (update `last_seen`, `count`, capped evidence).
**When the count drops back below `threshold`** (the burst subsides as events age
out — this generalizes "the deque empties"), the active finding is cleared, so a
later re-crossing starts a **new** finding. Result: one finding per (rule, IP,
burst), no per-event spam.

**Out-of-order tolerance.** No sorting. The right edge is the max timestamp seen;
an event within `window` of it still counts even if slightly out of order; an
event older than `max_seen - window` is ignored for threshold purposes. Extreme
reordering is out of scope (§2.3).

**`distinct_by = path` key.** Distinct key = **path without query string, trailing
slash trimmed (except root `/`), case preserved** (Linux paths are case-sensitive;
preserving case avoids under-counting real enumeration). Deliberately different
from signature matching, which retains the query string.

**SQL-injection false-positive policy (benign apostrophes, e.g. `O'Brien`).**
Signatures match SQL **syntax, never lone metacharacters** — a bare `'`, a stray
`--`, or a lone `;` is *never* a pattern on its own, so `?name=O'Brien` produces
**zero hits**. A signature must be one of:
1. a SQL keyword construct — `union\s+select`, `\bor\s+1=1\b`, `sleep\(`,
   `benchmark\(`, `information_schema`, `xp_cmdshell`, …;
2. a tautology — `'\s*or\s*'1'='1`, `"\s*or\s*"1"="1`;
3. a quote/comment *terminator* combo — `'\s*--`, `'\s*#`, `'\s*or\s`.
Two layered safety valves: aggregation is per-IP (one benign hit can't flood),
and an optional per-rule `min_hits` (default 1) requires N corroborating
signatures before emitting — raise it to trade recall for precision. Each match
records the pattern that fired and the offending snippet in `Finding.metadata` /
evidence for triage.

---

## 7. Correlation (`correlation.py`)

- `Correlator(window=timedelta(minutes=10))` — stateless; `correlate(findings)`.
- Group findings by `source_ip`, sort by `first_seen`, greedily cluster findings
  whose time gap `<= window`.
- A cluster becomes an `Incident` **only when it spans ≥2 distinct `rule_id`s OR
  ≥2 distinct sources** for the same IP (e.g. `10.0.0.50` brute-forcing SSH *and*
  hitting web endpoints). **A single rule's repeated findings for one IP — even
  two far apart — never form an incident.** (Confirmed.)
- **Incident severity = one level above the max child severity, capped at
  CRITICAL** (HIGH+HIGH→CRITICAL, MEDIUM+HIGH→CRITICAL, MEDIUM+MEDIUM→HIGH). Valid
  because an incident always represents genuine multi-signal correlation.
- **`incident_id`** = `"INC-" + sha1(f"{ip}|{first_seen.isoformat()}|" +
  ",".join(sorted(rule_ids)))[:10]` — deterministic and reproducible across runs
  (uuid4 would break test idempotency).
- `narrative` summarizes the chain (which rules/sources, time span).

---

## 8. Orchestration (`engine.py`)

- `LogSource(path, parser)` value object.
- `Engine(rules, correlator=None, logger=None, max_evidence=20, strict=False)`.
- `analyze(sources) -> AnalysisReport`:
  0. **`reset()` every rule** so one `Engine` is safely re-runnable (idempotent
     across calls; stateful rules start clean each run).
  1. For each source, iterate `parse_file(...)`.
     - Missing/unreadable file → **captured** as `ParseError(line_no=0,
       reason="FileNotFoundError: …")` and analysis continues, unless
       `strict=True`, which re-raises. (Matches the "never crash" goal.)
  2. `ParseError` → collect + `logger.warning`.
  3. `LogEntry` → feed to every rule's `inspect`; bump stats.
  4. After all sources: `flush` every rule; gather findings.
  5. Run correlator → incidents.
- `AnalysisReport(findings, incidents, parse_errors, stats)` — plain container.
- Empty file / all-malformed file → **normal report** (empty findings,
  `parse_errors` populated, zeroed stats), not an exception.

**Ordering invariants (explicit).**
- **I1 — sequential-by-file, NOT merge-sorted.** The engine consumes each source
  fully before the next and does **not** globally time-sort across files. Input
  order across files is undefined; only *within* a file is order assumed
  (roughly chronological, §2.3).
- **I2 — single-source stateful rules.** Every stateful rule's `match` predicate
  selects exactly one source type, so a given sliding-window rule only ever sees
  one file's events, in that file's order. I1 is sound *because of* I2.
- **Cross-source relationships** are the **Correlator's** job (post-hoc,
  timestamp-based), never a sliding window.
- **Upgrade path (not active):** if a future rule ever needs a genuine
  cross-source detection window, and only then, the engine switches to a
  `heapq.merge` of per-file streams keyed on timestamp. Until such a rule exists,
  I1 holds.

**Stats shape (exact):**
```python
stats = {
  "sources": {
     "<path>": {"lines_read": int, "parsed": int, "malformed": int, "skipped_blank": int},
     ...
  },
  "totals": {"lines_read", "parsed", "malformed", "skipped_blank", "findings", "incidents"},
  "duration_seconds": float,   # wall time of analyze(); the only perf counter for now
}
```

---

## 9. Testing strategy (pytest)

- **Parsers**: table-driven incl. `[MALFORMED ENTRY` → `ParseError`; Common vs
  Combined; garbage request line; `-` size; timezone parsing; §5.1 year heuristic
  (Oct→2025 under a 2026 reference); invalid-user vs failure outcome; `[preauth]`
  → OTHER with IP.
- **Rules**: threshold boundary (N-1 vs N in/out of window); burst re-fire after
  window empties; `distinct_by` volume-vs-breadth; URL-decode incl. `%252e` and
  invalid `%`; case-insensitive match; target = query string catches `?q=` SQLi;
  **`?name=O'Brien` (and lone `--`) produces zero SQLi hits**; `min_hits`
  corroboration gate.
- **Ordering**: I1/I2 — two sources processed sequentially; a stateful rule's
  window reflects only its own source's order regardless of source ordering.
- **Correlator**: multi-rule same-IP cluster → Incident; single-rule repeats →
  none; severity escalation cap; deterministic `incident_id`.
- **Engine**: fixture logs end-to-end → report shape/stats; re-run idempotency;
  missing file captured (and `strict=True` raises); empty/all-malformed file.
- No filesystem needed for logic tests (parsers take strings; `parse_file`
  covered with `tmp_path`).

---

## 10. Build order

1. `models.py`
2. `parsers.py` (+ tests)
3. `rules.py` (+ tests)
4. `correlation.py` (+ tests)
5. `engine.py` (+ end-to-end test)
6. Smoke-test on sample logs, report results.

---

## 11. Default thresholds (all overridable via config)

| Rule | Default |
|---|---|
| SSH brute force | ≥ 5 `auth_failure` (incl. invalid-user) within 60s → HIGH |
| Web login brute force | ≥ 10 failures within 60s → MEDIUM |
| Web scanning | ≥ 15 distinct 404 paths within 120s → MEDIUM |
| Directory traversal | any signature match → HIGH |
| SQL injection | any signature match → HIGH |
| Correlation window | 600s (10 min) |
