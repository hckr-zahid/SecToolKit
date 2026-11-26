"""Unit tests for Purple Team timeline correlation and coverage scoring."""

import unittest
from sectoolkit.purple_team import correlate_timeline, score_detection_coverage


class TestPurpleTeam(unittest.TestCase):

    def test_correlate_timeline_matches_and_misses(self):
        scenarios = [
            {
                "case_id": "PT-01",
                "name": "SSH Brute Force Test",
                "technique_id": "T1110",
                "tactic": "Credential Access",
                "target_host": "web-01",
                "timestamp": "2026-11-26T10:00:00Z",
            },
            {
                "case_id": "PT-02",
                "name": "PowerShell Encoded Execution",
                "technique_id": "T1059.001",
                "tactic": "Execution",
                "target_host": "win-01",
                "timestamp": "2026-11-26T10:05:00Z",
            },
            {
                "case_id": "PT-03",
                "name": "Out-of-window Exfiltration",
                "technique_id": "T1041",
                "tactic": "Exfiltration",
                "target_host": "db-01",
                "timestamp": "2026-11-26T10:10:00Z",
            },
        ]
        observed = [
            {
                "alert_id": "AL-101",
                "rule": "SSH Brute Force",
                "hostname": "web-01",
                "time": "2026-11-26T10:01:30Z",
            },
            {
                "alert_id": "AL-102",
                "rule": "Data Exfiltration",
                "hostname": "db-01",
                "time": "2026-11-26T12:00:00Z",  # Outside 300s window
            },
        ]

        results = correlate_timeline(scenarios, observed, time_window_seconds=300)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["status"], "detected")
        self.assertEqual(results[0]["matched_alert_id"], "AL-101")
        self.assertEqual(results[0]["time_delta_seconds"], 90.0)
        self.assertEqual(results[1]["status"], "missed")
        self.assertEqual(results[2]["status"], "missed")

        coverage = score_detection_coverage(results)
        self.assertEqual(coverage["total_scenarios"], 3)
        self.assertEqual(coverage["detected_count"], 1)
        self.assertEqual(coverage["missed_count"], 2)
        self.assertEqual(coverage["coverage_percent"], 33.33)
        self.assertEqual(coverage["by_tactic"]["Credential Access"]["detected"], 1)
        self.assertEqual(coverage["by_tactic"]["Execution"]["missed"], 1)

    def test_correlate_negative_window_raises(self):
        with self.assertRaises(ValueError):
            correlate_timeline([], [], time_window_seconds=-1)


if __name__ == "__main__":
    unittest.main()
