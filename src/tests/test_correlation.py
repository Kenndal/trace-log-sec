"""Correlator tests."""

from __future__ import annotations

from datetime import datetime, timedelta

from engine.correlation import Correlator
from models import Finding, Severity

T0 = datetime(2025, 10, 10, 12, 0, 0)


def finding(rule_id, ip, seconds, severity=Severity.HIGH, sources=None):
    ts = T0 + timedelta(seconds=seconds)
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        description="",
        first_seen=ts,
        last_seen=ts,
        source_ip=ip,
        sources=sources or {"auth"},
    )


def test_two_rules_same_ip_form_incident():
    c = Correlator(window=timedelta(minutes=10))
    findings = [
        finding("ssh_brute_force", "10.0.0.50", 0, sources={"auth"}),
        finding("web_login_brute_force", "10.0.0.50", 30, sources={"webserver"}),
    ]
    incidents = c.correlate(findings)
    assert len(incidents) == 1
    assert incidents[0].source_ip == "10.0.0.50"
    assert len(incidents[0].findings) == 2


def test_single_rule_repeats_never_form_incident():
    c = Correlator(window=timedelta(minutes=10))
    findings = [
        finding("ssh_brute_force", "10.0.0.50", 0),
        finding("ssh_brute_force", "10.0.0.50", 60),
    ]
    assert c.correlate(findings) == []


def test_two_sources_same_rule_form_incident():
    c = Correlator(window=timedelta(minutes=10))
    findings = [
        finding("probe", "10.0.0.50", 0, sources={"auth"}),
        finding("probe", "10.0.0.50", 30, sources={"webserver"}),
    ]
    incidents = c.correlate(findings)
    assert len(incidents) == 1


def test_findings_outside_window_do_not_cluster():
    c = Correlator(window=timedelta(minutes=10))
    findings = [
        finding("ssh_brute_force", "10.0.0.50", 0),
        finding("web_login_brute_force", "10.0.0.50", 3600),  # 1h later
    ]
    assert c.correlate(findings) == []


def test_severity_escalation_cap():
    c = Correlator()
    findings = [
        finding("a", "10.0.0.50", 0, severity=Severity.HIGH),
        finding("b", "10.0.0.50", 10, severity=Severity.HIGH),
    ]
    incidents = c.correlate(findings)
    assert incidents[0].severity == Severity.CRITICAL  # HIGH → one above, capped


def test_severity_escalation_medium_to_high():
    c = Correlator()
    findings = [
        finding("a", "10.0.0.50", 0, severity=Severity.MEDIUM),
        finding("b", "10.0.0.50", 10, severity=Severity.MEDIUM),
    ]
    incidents = c.correlate(findings)
    assert incidents[0].severity == Severity.HIGH


def test_incident_id_deterministic():
    c = Correlator()
    findings = [
        finding("a", "10.0.0.50", 0),
        finding("b", "10.0.0.50", 10),
    ]
    id1 = c.correlate(findings)[0].incident_id
    id2 = c.correlate(findings)[0].incident_id
    assert id1 == id2
    assert id1.startswith("INC-")


def test_findings_without_ip_are_ignored():
    c = Correlator()
    findings = [
        finding("a", None, 0),
        finding("b", None, 10),
    ]
    assert c.correlate(findings) == []
