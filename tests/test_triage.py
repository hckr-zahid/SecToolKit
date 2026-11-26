"""Unit tests for SOC triage and alert normalization."""

import unittest
from sectoolkit.triage import (
    fingerprint,
    normalize_alert,
    priority_score,
    triage_alerts,
)


class TestTriage(unittest.TestCase):

    def test_normalize_alert_standard(self):
        raw = {
            "id": "SEC-1001",
            "severity": "HIGH",
            "src_ip": "192.168.1.100",
            "host": "web-srv-01",
            "time": "2026-11-23T10:00:00Z",
            "rule_name": "SQL Injection Attempt",
        }
        normalized = normalize_alert(raw)
        self.assertEqual(normalized["alert_id"], "SEC-1001")
        self.assertEqual(normalized["severity"], "high")
        self.assertEqual(normalized["source_ip"], "192.168.1.100")
        self.assertEqual(normalized["hostname"], "web-srv-01")
        self.assertEqual(normalized["timestamp"], "2026-11-23T10:00:00Z")
        self.assertEqual(normalized["rule"], "SQL Injection Attempt")

    def test_normalize_alert_alternate_fields(self):
        raw = {
            "alert_id": "ALT-99",
            "source_ip": "10.0.0.5",
            "hostname": "db-prod",
            "@timestamp": "2026-11-23T10:15:30Z",
            "signature": "Port Scan Detected",
        }
        normalized = normalize_alert(raw)
        self.assertEqual(normalized["alert_id"], "ALT-99")
        self.assertEqual(normalized["severity"], "unknown")
        self.assertEqual(normalized["source_ip"], "10.0.0.5")
        self.assertEqual(normalized["hostname"], "db-prod")
        self.assertEqual(normalized["timestamp"], "2026-11-23T10:15:30Z")
        self.assertEqual(normalized["rule"], "Port Scan Detected")

    def test_normalize_alert_invalid_type(self):
        with self.assertRaises(TypeError):
            normalize_alert("not a dictionary")

    def test_fingerprint_deterministic(self):
        alert_a = {
            "rule": "Brute Force Login",
            "hostname": "auth-01",
            "source_ip": "203.0.113.10",
            "timestamp": "2026-11-23T10:00:15.123Z",
        }
        alert_b = {
            "rule": "Brute Force Login",
            "hostname": "auth-01",
            "source_ip": "203.0.113.10",
            "timestamp": "2026-11-23T10:00:59.999Z",  # Same minute bucket
        }
        alert_diff = {
            "rule": "Brute Force Login",
            "hostname": "auth-01",
            "source_ip": "203.0.113.10",
            "timestamp": "2026-11-23T10:05:00.000Z",  # Different minute bucket
        }
        fp_a = fingerprint(alert_a)
        fp_b = fingerprint(alert_b)
        fp_diff = fingerprint(alert_diff)

        self.assertEqual(fp_a, fp_b)
        self.assertNotEqual(fp_a, fp_diff)
        self.assertEqual(len(fp_a), 64)

    def test_priority_score_valid(self):
        # Critical severity (4 * 0.45 = 1.80) + conf (4 * 0.30 = 1.20) + crit (4 * 0.25 = 1.00) = 4.00
        score_crit = priority_score("critical", confidence=4, asset_criticality=4)
        self.assertEqual(score_crit, 4.0)

        # Low severity (1 * 0.45 = 0.45) + conf (1 * 0.30 = 0.30) + crit (1 * 0.25 = 0.25) = 1.00
        score_low = priority_score("low", confidence=1, asset_criticality=1)
        self.assertEqual(score_low, 1.0)

        # High severity (3 * 0.45 = 1.35) + conf (3 * 0.30 = 0.90) + crit (2 * 0.25 = 0.50) = 2.75
        score_med = priority_score("high", confidence=3, asset_criticality=2)
        self.assertEqual(score_med, 2.75)

    def test_priority_score_invalid_ranges(self):
        with self.assertRaises(ValueError):
            priority_score("high", confidence=0, asset_criticality=3)
        with self.assertRaises(ValueError):
            priority_score("high", confidence=5, asset_criticality=3)
        with self.assertRaises(ValueError):
            priority_score("high", confidence=2, asset_criticality=0)
        with self.assertRaises(ValueError):
            priority_score("high", confidence=2, asset_criticality=5)

    def test_priority_score_invalid_types(self):
        with self.assertRaises(TypeError):
            priority_score("high", confidence="high", asset_criticality=2)
        with self.assertRaises(TypeError):
            priority_score("high", confidence=2, asset_criticality=True)

    def test_triage_alerts_pipeline(self):
        raw_alerts = [
            # High priority alert (2 occurrences within same minute)
            {
                "id": "A1",
                "severity": "critical",
                "src_ip": "198.51.100.5",
                "host": "payment-api",
                "time": "2026-11-23T11:00:10Z",
                "rule_name": "Ransomware Activity",
                "confidence": 4,
                "asset_criticality": 4,
            },
            {
                "id": "A2",
                "severity": "critical",
                "src_ip": "198.51.100.5",
                "host": "payment-api",
                "time": "2026-11-23T11:00:45Z",
                "rule_name": "Ransomware Activity",
                "confidence": 4,
                "asset_criticality": 4,
            },
            # Low priority alert
            {
                "id": "A3",
                "severity": "low",
                "src_ip": "10.0.0.2",
                "host": "dev-station",
                "time": "2026-11-23T11:00:20Z",
                "rule_name": "Unusual DNS Query",
                "confidence": 1,
                "asset_criticality": 1,
            },
        ]

        triaged = triage_alerts(raw_alerts)
        self.assertEqual(len(triaged), 2)  # Deduplicated from 3 down to 2
        self.assertEqual(triaged[0]["rule"], "Ransomware Activity")
        self.assertEqual(triaged[0]["count"], 2)
        self.assertEqual(triaged[0]["priority_score"], 4.0)

        self.assertEqual(triaged[1]["rule"], "Unusual DNS Query")
        self.assertEqual(triaged[1]["count"], 1)
        self.assertEqual(triaged[1]["priority_score"], 1.0)

        # Test filtering by min_priority
        filtered = triage_alerts(raw_alerts, min_priority=2.0)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["rule"], "Ransomware Activity")


if __name__ == "__main__":
    unittest.main()
