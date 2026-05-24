"""
report.py
---------
Aggregates parsed entries and findings into a Report object
consumed by the UI.
"""

from collections import Counter, defaultdict
from datetime import datetime
from core.geo import bulk_lookup, geo_summary


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#f85149",
    "HIGH":     "#d29922",
    "MEDIUM":   "#58a6ff",
    "LOW":      "#7ee787",
    "INFO":     "#8b949e",
}
TYPE_LABELS = {
    "BRUTE_FORCE": "Brute Force",
    "PRIVESC":     "Privilege Escalation",
    "PORT_SCAN":   "Port / Dir Scan",
    "ODD_HOURS":   "Off-Hours Access",
    "HTTP_ATTACK": "HTTP Attack",
    "GEO_ANOMALY": "Geo Anomaly",
}


class Report:
    def __init__(self, filepath: str, entries: list[dict],
                 findings: list[dict], log_format: str):
        self.filepath    = filepath
        self.entries     = entries
        self.findings    = findings
        self.log_format  = log_format
        self.generated   = datetime.now()

        # Geo-enrich findings
        self._enrich_geo()

        # Pre-computed summaries
        self.total_lines    = len(entries)
        self.total_findings = len(findings)
        self.severity_counts = Counter(f["severity"] for f in findings)
        self.type_counts     = Counter(f["type"] for f in findings)
        self.top_ips         = Counter(
            f["source_ip"] for f in findings if f["source_ip"]
        ).most_common(10)
        self.top_users       = Counter(
            f["user"] for f in findings if f["user"]
        ).most_common(10)

    def _enrich_geo(self):
        ips = [f["source_ip"] for f in self.findings if f["source_ip"]]
        geo_map = bulk_lookup(ips)
        for f in self.findings:
            if f["source_ip"]:
                geo = geo_map.get(f["source_ip"])
                if geo:
                    f["extra"]["geo"] = geo
                    f["extra"]["geo_summary"] = geo_summary(geo)

    def findings_by_severity(self) -> list[dict]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    def findings_for_timeline(self) -> list[dict]:
        """Return only findings with a valid timestamp, sorted chronologically."""
        return [f for f in self.findings if f["timestamp"]]

    def risk_score(self) -> int:
        """Simple weighted risk score 0–100."""
        weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        raw = sum(weights.get(sev, 0) * cnt for sev, cnt in self.severity_counts.items())
        return min(raw, 100)

    def risk_label(self) -> str:
        score = self.risk_score()
        if score >= 60: return "CRITICAL"
        if score >= 35: return "HIGH"
        if score >= 15: return "MEDIUM"
        if score > 0:   return "LOW"
        return "CLEAN"