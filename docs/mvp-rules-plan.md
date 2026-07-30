# MVP rules plan — sensitive-file exposure, scanner UA, sudo escalation

Implementation plan for the three "trivial" items from `new-incidents-rules.md`
(#4 sensitive file/credential exposure, #5 scanner User-Agent fingerprinting,
#1 privileged escalation via sudo). All three reuse `PatternSignatureRule`
as-is — no new `Rule` subclass, no changes to `ThresholdRule`, no changes to
`correlation.py`. Two of the three are pure config additions to
`default_rules()`; the third needs one new line in `TARGET_EXTRACTORS`.

Verification fixtures for all three already exist in
`tests/fixtures/webserver_incidents.log` and `tests/fixtures/auth_incidents.log`
(see `tests/fixtures/incidents_manifest.md`) — no new fixture data needed.

---

## 1. Summary

| # | Rule id | Type | Code change | Config-only? |
|---|---|---|---|---|
| 4 | `sensitive_file_exposure` | signature | none | yes |
| 5 | `scanner_user_agent` | signature | none | yes |
| 1 | `sudo_privilege_escalation` | signature | +1 line in `TARGET_EXTRACTORS` | after that, yes |

All three slot into `default_rules()` in `engine/rules.py` (§404-487) as
additional dict specs, same shape as the existing `directory_traversal` /
`sql_injection` entries.

---

## 2. #4 — Sensitive file / credential exposure

**Target:** `request_target` (existing preset — path + query, already
URL-decoded per §6.3 of `engine-plan.md`).

**Proposed spec:**

```python
{
    "id": "sensitive_file_exposure",
    "type": "signature",
    "severity": "high",
    "params": {
        "target": "request_target",
        "title": "Sensitive File / Credential Exposure Probing",
        "description": "Request for source control, environment, backup, or key material.",
        "patterns": [
            r"\.git/",
            r"\.env(\.|$|\?)",
            r"\.aws/credentials",
            r"id_rsa",
            r"\.ssh/",
            r"\.htpasswd",
            r"\.pem$",
            r"wp-config\.php",
            r"config\.php",
            r"\.bak$",
            r"\.sql$",
            r"\.tar\.gz$",
            r"docker-compose\.ya?ml",
        ],
    },
},
```

**Validation:** `tests/fixtures/webserver_incidents.log` lines ~15:00 UTC,
source `198.51.100.250`, 13 requests (`incidents_manifest.md` §"Sensitive file
/ credential exposure probing"). Expect `count=13` (or fewer if some paths
don't match every pattern — check exact `path` strings in the fixture and
tighten/loosen the list so all 13 hit, since the fixture was written before
this rule existed and patterns should match reality, not the other way
around).

**Known limitation (accept for MVP, don't fix now):** `PatternSignatureRule`
matches on the request target only — it has no notion of `status`. Two of the
13 fixture requests return `200` (an actual exposed secret, not just a probe)
but the rule can't distinguish that from the eleven `403`/`404` probes; all 13
fold into one `HIGH` finding. The `200` hits are still visible in
`Finding.evidence` (each evidence entry is the full `WebLogEntry`, `status`
included) for manual triage. Making status drive severity is a real
enhancement (e.g. bump to `CRITICAL` when `min_hits`-worth of matches include
a `2xx`) but requires new logic in `_record`/`flush`, not just data — treat as
a follow-up, not part of this trivial pass.

---

## 3. #5 — Scanner / attack-tool User-Agent fingerprinting

**Target:** `user_agent` — already a working preset in `TARGET_EXTRACTORS`
(§132-138), unused by any current rule.

**Proposed spec:**

```python
{
    "id": "scanner_user_agent",
    "type": "signature",
    "severity": "medium",
    "params": {
        "target": "user_agent",
        "title": "Known Scanner / Attack-Tool User-Agent",
        "description": "Request identifies itself as a known scanning or exploitation tool.",
        "patterns": [
            r"sqlmap",
            r"\bnikto\b",
            r"\bnessus\b",
            r"\bmasscan\b",
            r"\bnmap\b",
            r"acunetix",
            r"netsparker",
            r"\bw3af\b",
            r"dirbuster",
            r"gobuster",
            r"feroxbuster",
            r"\bzgrab\b",
            r"^-$",
        ],
    },
},
```

**Validation:** `tests/fixtures/webserver_incidents.log` ~15:30 UTC, 5 source
IPs (sqlmap, Nikto, Nessus, masscan UAs + one blank `"-"` UA) per the manifest.
Expect 5 separate findings (one per attacking IP, since `PatternSignatureRule`
aggregates per IP), lower severity than the others (recon signal, not
confirmed exploitation).

**Watch for false positives:** the existing `webserver.log` fixture already
contains legitimate `curl/8.0` traffic and the generated background traffic
includes `Googlebot`. Neither `curl` nor generic `bot`/`crawler` substrings are
in the pattern list above — keep it that way; don't widen to loose terms like
`bot` without re-checking both fixtures for false hits (`Googlebot`,
potential future monitoring UAs, etc.).

---

## 4. #1 — Privileged escalation via sudo

**Target:** new preset, `auth_message` — `AuthLogEntry.message` already holds
the full text after `hostname process[pid]:` (§109-118 `models.py`), which for
a sudo line includes the `COMMAND=...` field verbatim. `_classify_auth` never
touches it (sudo lines fall through to `AuthOutcome.OTHER`), so nothing about
parsing needs to change — the data is already there, just not exposed to
signature rules.

**Code change — `engine/rules.py`, `TARGET_EXTRACTORS` (§132-138):**

```python
TARGET_EXTRACTORS: dict[str, FieldExtractor] = {
    "request_target": lambda e: getattr(e, "target", None),
    "path": lambda e: getattr(e, "path", None) if isinstance(e, WebLogEntry) else None,
    "query": lambda e: getattr(e, "query", None) if isinstance(e, WebLogEntry) else None,
    "user_agent": lambda e: getattr(e, "user_agent", None),
    "referrer": lambda e: getattr(e, "referrer", None),
    "auth_message": lambda e: getattr(e, "message", None) if isinstance(e, AuthLogEntry) else None,
}
```

(`AuthLogEntry` is already imported in this module — no new import needed.)

**Proposed spec:**

```python
{
    "id": "sudo_privilege_escalation",
    "type": "signature",
    "severity": "critical",
    "params": {
        "target": "auth_message",
        "title": "Sudo Access to Sensitive Files / Credentials",
        "description": "A sudo command read or copied credential material.",
        "patterns": [
            r"COMMAND=.*\bcat\b.*shadow",
            r"COMMAND=.*\bcat\b.*passwd\b",
            r"COMMAND=.*id_rsa",
            r"COMMAND=.*\.ssh/",
            r"COMMAND=.*\.aws/credentials",
            r"COMMAND=.*\buseradd\b",
            r"COMMAND=.*\busermod\b.*sudo",
        ],
    },
},
```

**Validation:** two scenarios in `tests/fixtures/auth_incidents.log`
(`incidents_manifest.md`):
- `carol`, ~02:15 UTC — `cat /etc/shadow`, copy `.aws/credentials`, `useradd
  backdoor`, `usermod -aG sudo backdoor` → 4 matches.
- `admin`, ~09:41 UTC (flagship chain) — `cat /etc/shadow`, `cat
  ~/.ssh/id_rsa` → 2 matches.

**Known limitation — this finding will NOT correlate with the matching SSH
finding for the same attacker, and that's expected for this pass.** Sudo audit
lines carry no `from IP` (confirmed against the fixture — every `sudo:` line
has `source_ip = None`), so `PatternSignatureRule._record` (keyed by
`entry.source_ip`) buckets every sudo-escalation hit from every user under one
`ip=None` Finding. Two consequences to flag to the user, not silently fix:
1. `Correlator` groups by IP (§7 `engine-plan.md`), so this new finding cannot
   join the `ssh_brute_force` finding for `203.0.113.77` into one `Incident` —
   the flagship "brute force → success → credential theft" chain will surface
   as two separate top-level findings, not one incident, even after this rule
   ships.
2. Because aggregation is per-IP and every sudo line is `ip=None`, hits from
   unrelated users (`dave`, `alice`, `deploy` running ordinary sudo commands
   that happen to *not* match the patterns above are fine and won't appear —
   but if two different real incidents both used sudo the same day, they'd
   fold into the same single `None`-keyed Finding rather than staying
   separate). `Finding.evidence` still lists each raw line individually
   (including `username` on `AuthLogEntry`), so triage isn't blocked, just not
   auto-separated.

Both are acceptable for a first pass (the goal here is *detecting* the
behavior at all, which today is zero) but are worth calling out before this
ships as "done" — fixing them for real is the sequence-detection work
(shortlist item #2) and/or a `key_by=username` style generalization, not part
of this trivial pattern-only pass.

---

## 5. Rollout order & testing

1. Add the `TARGET_EXTRACTORS["auth_message"]` line (§4) — no behavior change
   until a rule uses it.
2. Add the three specs to `default_rules()`, in this order: #4, #5, #1 (cheapest/most
   isolated first).
3. Re-run `python3 scripts/run_demo.py tests/fixtures/auth_incidents.log
   tests/fixtures/webserver_incidents.log` after each addition and diff the
   finding counts against the expectations in §2-4 above and
   `incidents_manifest.md`.
4. Add unit tests in the existing `tests/` rule-test style: one table-driven
   case per new rule id, covering a true positive from the fixtures and at
   least one benign near-miss (e.g. `.env` as a substring of a legitimate path,
   `curl` UA, an ordinary `sudo systemctl restart nginx` line) to guard against
   false positives.
5. Update `incidents_manifest.md` statuses from "NOT DETECTED" /
   "PARTIALLY DETECTED" to "DETECTED" for the three scenarios once verified,
   and update `docs/engine-plan.md` §11 (default thresholds table) and §6.1
   example config with the three new entries.

## 6. Out of scope for this pass

- Status-aware severity for `sensitive_file_exposure` (§2 limitation).
- Correlating `sudo_privilege_escalation` findings back to the originating
  SSH IP (§4 limitation) — needs either a `key_by`/session-aware generalization
  or the brute-force→success sequence work (shortlist #2).
- Shortlist #2 (brute-force → success) and #3 (password spraying,
  `key_by` generalization of `ThresholdRule`) — separate, larger plan.
