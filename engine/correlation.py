"""Cross-rule correlation.

Groups findings by IP and clusters those close in time into ``Incident``s. An
incident forms only for genuine multi-signal activity (≥2 distinct rules OR ≥2
sources for the same IP) — a single rule's repeated findings never do.

See docs/engine-plan.md §7.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from .models import Finding, Incident, Severity


class Correlator:
    """Stateless correlator; clusters findings per IP within a time window."""

    def __init__(self, window: timedelta = timedelta(minutes=10)) -> None:
        self.window = window

    def correlate(self, findings: Iterable[Finding]) -> list[Incident]:
        by_ip: dict[str | None, list[Finding]] = defaultdict(list)
        for f in findings:
            by_ip[f.source_ip].append(f)

        incidents: list[Incident] = []
        for ip, ip_findings in by_ip.items():
            if ip is None:
                continue  # can't meaningfully correlate findings with no IP
            ip_findings.sort(key=lambda f: f.first_seen)
            for cluster in self._cluster(ip_findings):
                incident = self._build_incident(ip, cluster)
                if incident is not None:
                    incidents.append(incident)

        incidents.sort(key=lambda i: (i.first_seen, i.source_ip or ""))
        return incidents

    def _cluster(self, findings: list[Finding]) -> list[list[Finding]]:
        """Greedily group findings whose gap from the running span <= window."""
        clusters: list[list[Finding]] = []
        current: list[Finding] = []
        current_end = None
        for f in findings:
            if current and f.first_seen - current_end <= self.window:
                current.append(f)
                current_end = max(current_end, f.last_seen)
            else:
                if current:
                    clusters.append(current)
                current = [f]
                current_end = f.last_seen
        if current:
            clusters.append(current)
        return clusters

    def _build_incident(self, ip: str, cluster: list[Finding]) -> Incident | None:
        rule_ids = {f.rule_id for f in cluster}
        sources = {s for f in cluster for s in f.sources}
        if len(rule_ids) < 2 and len(sources) < 2:
            return None

        first_seen = min(f.first_seen for f in cluster)
        last_seen = max(f.last_seen for f in cluster)
        severity = self._escalate(max(f.severity for f in cluster))

        incident_id = "INC-" + hashlib.sha1(
            (f"{ip}|{first_seen.isoformat()}|" + ",".join(sorted(rule_ids))).encode()
        ).hexdigest()[:10]

        return Incident(
            incident_id=incident_id,
            title=f"Correlated activity from {ip}",
            severity=severity,
            source_ip=ip,
            first_seen=first_seen,
            last_seen=last_seen,
            findings=list(cluster),
            narrative=self._narrative(ip, cluster, rule_ids, sources, first_seen, last_seen),
        )

    @staticmethod
    def _escalate(max_severity: Severity) -> Severity:
        """One level above the max child severity, capped at CRITICAL."""
        members = sorted(Severity)
        idx = members.index(max_severity)
        return members[min(idx + 1, len(members) - 1)]

    @staticmethod
    def _narrative(
        ip: str,
        cluster: list[Finding],
        rule_ids: set[str],
        sources: set[str],
        first_seen,
        last_seen,
    ) -> str:
        span = last_seen - first_seen
        titles = sorted({f.title for f in cluster})
        return (
            f"{ip} triggered {len(cluster)} findings across {len(rule_ids)} rule(s) "
            f"({', '.join(titles)}) over {', '.join(sorted(sources))} "
            f"within {span} ({first_seen.isoformat()} → {last_seen.isoformat()})."
        )
