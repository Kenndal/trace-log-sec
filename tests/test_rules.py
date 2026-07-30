"""Rule tests (§9)."""

from __future__ import annotations

from datetime import datetime, timedelta

from engine.models import AuthLogEntry, AuthOutcome, Severity, WebLogEntry
from engine.rules import (
    PatternSignatureRule,
    ThresholdRule,
    build_rules,
    default_rules,
)

T0 = datetime(2025, 10, 10, 12, 0, 0)


def auth_fail(ip, seconds, outcome=AuthOutcome.FAILURE, user="x"):
    return AuthLogEntry(
        timestamp=T0 + timedelta(seconds=seconds),
        source="auth",
        raw="",
        line_no=1,
        source_ip=ip,
        message="Failed password",
        outcome=outcome,
        username=user,
    )


def web(ip, seconds, target="/a", status=200):
    return WebLogEntry(
        timestamp=T0 + timedelta(seconds=seconds),
        source="webserver",
        raw="",
        line_no=1,
        source_ip=ip,
        method="GET",
        target=target,
        status=status,
    )


def run(rule, entries):
    findings = []
    for e in entries:
        findings.extend(rule.inspect(e))
    findings.extend(rule.flush())
    return findings


# --------------------------------------------------------------------------- #
# ThresholdRule — volume (brute force)
# --------------------------------------------------------------------------- #


def test_threshold_boundary_n_minus_1_no_fire():
    r = ThresholdRule(id="bf", match="auth_failure", threshold=5, window_seconds=60)
    findings = run(r, [auth_fail("1.1.1.1", s) for s in range(4)])  # 4 events
    assert findings == []


def test_threshold_fires_at_n_once_per_burst():
    r = ThresholdRule(id="bf", match="auth_failure", threshold=5, window_seconds=60)
    # 6 events within window → crosses at 5th, folds the 6th into same finding.
    findings = run(r, [auth_fail("1.1.1.1", s) for s in range(6)])
    assert len(findings) == 1
    assert findings[0].count == 6
    assert findings[0].source_ip == "1.1.1.1"


def test_threshold_window_eviction_prevents_fire():
    r = ThresholdRule(id="bf", match="auth_failure", threshold=5, window_seconds=60)
    # Spread 5 events over 200s so never 5 within any 60s window.
    findings = run(r, [auth_fail("1.1.1.1", s * 50) for s in range(5)])
    assert findings == []


def test_threshold_invalid_user_counts_as_auth_failure():
    r = ThresholdRule(id="bf", match="auth_failure", threshold=3, window_seconds=60)
    entries = [auth_fail("1.1.1.1", s, outcome=AuthOutcome.INVALID_USER) for s in range(3)]
    findings = run(r, entries)
    assert len(findings) == 1


def test_threshold_burst_refires_after_window_empties():
    r = ThresholdRule(id="bf", match="auth_failure", threshold=3, window_seconds=60)
    burst1 = [auth_fail("1.1.1.1", s) for s in (0, 1, 2)]
    # Gap large enough to age out the whole first burst.
    burst2 = [auth_fail("1.1.1.1", s) for s in (500, 501, 502)]
    findings = run(r, burst1 + burst2)
    assert len(findings) == 2


def test_threshold_per_ip_isolation():
    r = ThresholdRule(id="bf", match="auth_failure", threshold=3, window_seconds=60)
    a = [auth_fail("1.1.1.1", s) for s in (0, 1)]
    b = [auth_fail("2.2.2.2", s) for s in (0, 1)]
    findings = run(r, a + b)  # neither IP reaches 3
    assert findings == []


# --------------------------------------------------------------------------- #
# ThresholdRule — breadth (scanning) via distinct_by
# --------------------------------------------------------------------------- #


def test_distinct_by_path_counts_breadth_not_volume():
    r = ThresholdRule(
        id="scan", match="web_404", distinct_by="path", threshold=3, window_seconds=120
    )
    # 5 hits but only 2 distinct paths → no fire.
    entries = [web("1.1.1.1", s, target="/a", status=404) for s in range(3)]
    entries += [web("1.1.1.1", s + 3, target="/b", status=404) for s in range(2)]
    assert run(r, entries) == []


def test_distinct_by_path_fires_on_enough_distinct():
    r = ThresholdRule(
        id="scan", match="web_404", distinct_by="path", threshold=3, window_seconds=120
    )
    entries = [web("1.1.1.1", i, target=f"/p{i}", status=404) for i in range(3)]
    findings = run(r, entries)
    assert len(findings) == 1
    assert findings[0].count == 3


def test_distinct_by_path_normalizes_trailing_slash_and_query():
    r = ThresholdRule(
        id="scan", match="web_404", distinct_by="path", threshold=2, window_seconds=120
    )
    # "/a", "/a/", "/a?x=1" all normalize to the same key → 1 distinct → no fire.
    entries = [
        web("1.1.1.1", 0, target="/a", status=404),
        web("1.1.1.1", 1, target="/a/", status=404),
        web("1.1.1.1", 2, target="/a?x=1", status=404),
    ]
    assert run(r, entries) == []


# --------------------------------------------------------------------------- #
# PatternSignatureRule
# --------------------------------------------------------------------------- #


def sqli_rule(**kw):
    return PatternSignatureRule(
        id="sqli",
        severity=Severity.HIGH,
        patterns=[r"union\s+select", r"'\s*or\s+\w", r"'\s*--", r"\bor\s+1\s*=\s*1\b"],
        **kw,
    )


def test_signature_matches_query_string():
    r = sqli_rule()
    findings = run(r, [web("1.1.1.1", 0, target="/s?q=1 UNION SELECT password")])
    assert len(findings) == 1
    assert findings[0].source_ip == "1.1.1.1"


def test_signature_benign_apostrophe_zero_hits():
    r = sqli_rule()
    findings = run(r, [web("1.1.1.1", 0, target="/s?name=O'Brien")])
    assert findings == []


def test_signature_lone_dashes_zero_hits():
    r = sqli_rule()
    findings = run(r, [web("1.1.1.1", 0, target="/s?note=a--b")])
    assert findings == []


def test_signature_case_insensitive_by_default():
    r = sqli_rule()
    findings = run(r, [web("1.1.1.1", 0, target="/s?q=UnIoN   SeLeCt 1")])
    assert len(findings) == 1


def test_signature_url_decoded_double_encoding():
    r = PatternSignatureRule(
        id="trav", patterns=[r"\.\./", r"%2e%2e"], target="request_target"
    )
    # %252e%252e%252f decodes twice to ../ — caught via decoded variant.
    findings = run(r, [web("1.1.1.1", 0, target="/x?f=%252e%252e%252fetc")])
    assert len(findings) == 1


def test_signature_invalid_percent_is_fail_soft():
    r = sqli_rule()
    # A stray % must not raise; benign content → no hit.
    findings = run(r, [web("1.1.1.1", 0, target="/s?q=100%discount")])
    assert findings == []


def test_signature_aggregates_per_ip():
    r = sqli_rule()
    entries = [
        web("1.1.1.1", 0, target="/s?q=1 union select a"),
        web("1.1.1.1", 1, target="/s?q=2 union select b"),
    ]
    findings = run(r, entries)
    assert len(findings) == 1
    assert findings[0].count == 2


def test_signature_min_hits_gate():
    r = sqli_rule(min_hits=2)
    findings = run(r, [web("1.1.1.1", 0, target="/s?q=1 union select a")])
    assert findings == []  # only one hit, needs 2


def test_signature_records_match_metadata():
    r = sqli_rule()
    findings = run(r, [web("1.1.1.1", 0, target="/s?q=1 union select pw")])
    assert findings[0].metadata["matches"][0]["pattern"] == r"union\s+select"


# --------------------------------------------------------------------------- #
# build_rules / default_rules
# --------------------------------------------------------------------------- #


def test_build_rules_disabled_skipped():
    rules = build_rules(
        [
            {"id": "a", "type": "threshold", "enabled": False,
             "params": {"match": "auth_failure", "threshold": 1, "window_seconds": 1}},
            {"id": "b", "type": "threshold",
             "params": {"match": "auth_failure", "threshold": 1, "window_seconds": 1}},
        ]
    )
    assert [r.id for r in rules] == ["b"]


def test_build_rules_severity_coercion():
    rules = build_rules(
        [{"id": "s", "type": "signature", "severity": "high", "params": {"patterns": [r"x"]}}]
    )
    assert rules[0].severity == Severity.HIGH


def test_default_rules_present():
    ids = {r.id for r in default_rules()}
    assert {"ssh_brute_force", "web_scanning", "directory_traversal", "sql_injection"} <= ids


# --------------------------------------------------------------------------- #
# sensitive_file_exposure / scanner_user_agent / sudo_privilege_escalation
# --------------------------------------------------------------------------- #


def _rule_from_defaults(rule_id):
    return next(r for r in default_rules() if r.id == rule_id)


def auth_msg(message, ip=None, seconds=0, user=None):
    return AuthLogEntry(
        timestamp=T0 + timedelta(seconds=seconds),
        source="auth",
        raw="",
        line_no=1,
        source_ip=ip,
        message=message,
        outcome=AuthOutcome.OTHER,
        username=user,
    )


def web_ua(ip, seconds, user_agent, status=200):
    return WebLogEntry(
        timestamp=T0 + timedelta(seconds=seconds),
        source="webserver",
        raw="",
        line_no=1,
        source_ip=ip,
        method="GET",
        target="/",
        status=status,
        user_agent=user_agent,
    )


def test_sensitive_file_exposure_matches_git_config():
    r = _rule_from_defaults("sensitive_file_exposure")
    findings = run(r, [web("1.1.1.1", 0, target="/.git/config")])
    assert len(findings) == 1


def test_sensitive_file_exposure_ignores_ordinary_path():
    r = _rule_from_defaults("sensitive_file_exposure")
    findings = run(r, [web("1.1.1.1", 0, target="/products/environment-friendly-mug")])
    assert findings == []


def test_scanner_user_agent_matches_sqlmap():
    r = _rule_from_defaults("scanner_user_agent")
    findings = run(r, [web_ua("1.1.1.1", 0, "sqlmap/1.7.2#stable (http://sqlmap.org)")])
    assert len(findings) == 1


def test_scanner_user_agent_matches_blank_dash():
    r = _rule_from_defaults("scanner_user_agent")
    findings = run(r, [web_ua("1.1.1.1", 0, "-")])
    assert len(findings) == 1


def test_scanner_user_agent_ignores_curl_and_browsers():
    r = _rule_from_defaults("scanner_user_agent")
    entries = [
        web_ua("1.1.1.1", 0, "curl/8.0"),
        web_ua("1.1.1.1", 1, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ]
    assert run(r, entries) == []


def test_sudo_privilege_escalation_matches_shadow_read():
    r = _rule_from_defaults("sudo_privilege_escalation")
    line = (
        "carol : TTY=pts/7 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    )
    findings = run(r, [auth_msg(line, user="carol")])
    assert len(findings) == 1


def test_sudo_privilege_escalation_ignores_ordinary_sudo():
    r = _rule_from_defaults("sudo_privilege_escalation")
    line = (
        "dave : TTY=pts/2 ; PWD=/home/dave ; USER=root ; COMMAND=/bin/systemctl restart nginx"
    )
    findings = run(r, [auth_msg(line, user="dave")])
    assert findings == []


def test_sudo_privilege_escalation_aggregates_under_no_ip():
    # Sudo audit lines carry no source IP — all hits fold into one ip=None
    # finding regardless of username (documented limitation, docs/mvp-rules-plan.md §4).
    r = _rule_from_defaults("sudo_privilege_escalation")
    entries = [
        auth_msg("carol : ... COMMAND=/usr/bin/cat /etc/shadow", user="carol"),
        auth_msg("admin : ... COMMAND=/bin/cat /etc/shadow", seconds=1, user="admin"),
    ]
    findings = run(r, entries)
    assert len(findings) == 1
    assert findings[0].source_ip is None
    assert findings[0].count == 2
