"""Unit tests for automated incident reporting."""

import unittest
from sectoolkit.reporting import (
    generate_incident_summary,
    render_html_report,
    render_markdown_report,
)


class TestReporting(unittest.TestCase):

    def setUp(self):
        self.sample_alerts = [
            {
                "alert_id": "SEC-01",
                "severity": "critical",
                "rule": "Cobalt Strike Beacon",
                "hostname": "domain-ctrl-01",
                "source_ip": "185.220.101.5",
                "priority_score": 4.0,
                "count": 5,
            },
            {
                "alert_id": "SEC-02",
                "severity": "low",
                "rule": "Port Scan",
                "hostname": "domain-ctrl-01",
                "source_ip": "185.220.101.5",
                "priority_score": 1.25,
                "count": 1,
            },
        ]
        self.sample_iocs = {
            "ips": ["185.220.101.5"],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        }

    def test_generate_incident_summary(self):
        summary = generate_incident_summary(
            self.sample_alerts,
            extracted_iocs=self.sample_iocs,
            case_id="INC-2026-99",
        )
        self.assertEqual(summary["case_id"], "INC-2026-99")
        self.assertEqual(summary["metrics"]["unique_alerts"], 2)
        self.assertEqual(summary["metrics"]["total_event_occurrences"], 6)
        self.assertEqual(summary["metrics"]["critical_alerts"], 1)
        self.assertEqual(summary["metrics"]["top_target_host"], "domain-ctrl-01")

    def test_render_markdown_report(self):
        summary = generate_incident_summary(self.sample_alerts, extracted_iocs=self.sample_iocs)
        md = render_markdown_report(summary)
        self.assertIn("# Incident Triage & Forensic Case Report", md)
        self.assertIn("Cobalt Strike Beacon", md)
        self.assertIn("185.220.101.5", md)
        self.assertIn("Remediation & Containment Recommendations", md)

    def test_render_html_report(self):
        summary = generate_incident_summary(self.sample_alerts, extracted_iocs=self.sample_iocs)
        html = render_html_report(summary, dark_mode=True)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("#0d1117", html)  # Dark mode canvas
        self.assertIn("Cobalt Strike Beacon", html)

    def test_render_report_with_purple_team_coverage(self):
        coverage = {
            "total_scenarios": 2,
            "detected_count": 1,
            "missed_count": 1,
            "coverage_percent": 50.0,
            "results": [
                {
                    "case_id": "PT-01",
                    "technique_id": "T1071",
                    "tactic": "Command and Control",
                    "target_host": "domain-ctrl-01",
                    "status": "detected",
                    "matched_rule": "Cobalt Strike Beacon",
                },
                {
                    "case_id": "PT-02",
                    "technique_id": "T1059.001",
                    "tactic": "Execution",
                    "target_host": "ws-02",
                    "status": "missed",
                    "matched_rule": None,
                },
            ],
        }
        summary = generate_incident_summary(
            self.sample_alerts,
            extracted_iocs=self.sample_iocs,
            coverage=coverage,
        )
        md = render_markdown_report(summary)
        self.assertIn("Purple Team Detection Coverage", md)
        self.assertIn("50.0%", md)
        self.assertIn("PT-01", md)
        self.assertIn("**MISSED**", md)


if __name__ == "__main__":
    unittest.main()
