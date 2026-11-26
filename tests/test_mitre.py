"""Unit tests for MITRE ATT&CK alert tagging."""

import unittest
from sectoolkit.mitre import tag_alert_mitre, tag_alerts_mitre


class TestMitre(unittest.TestCase):

    def test_tag_known_rules(self):
        ssh_alert = {"rule": "SSH Brute Force Attempt", "severity": "high"}
        tagged = tag_alert_mitre(ssh_alert)
        self.assertEqual(tagged["mitre"]["technique_id"], "T1110")
        self.assertEqual(tagged["mitre"]["tactic"], "Credential Access")
        # Original dict must not be mutated
        self.assertNotIn("mitre", ssh_alert)

        webshell_alert = {"rule": "Suspicious_Webshell", "severity": "critical"}
        self.assertEqual(tag_alert_mitre(webshell_alert)["mitre"]["technique_id"], "T1505.003")

    def test_preserves_existing_mitre_tag(self):
        custom = {
            "rule": "Custom Rule",
            "mitre": {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Defense Evasion"},
        }
        tagged = tag_alert_mitre(custom)
        self.assertEqual(tagged["mitre"]["technique_id"], "T1055")
        self.assertEqual(tagged["mitre"]["tactic"], "Defense Evasion")

    def test_unmapped_fallback_and_type_error(self):
        unknown = {"rule": "Benign Heartbeat", "severity": "low"}
        tagged = tag_alert_mitre(unknown)
        self.assertEqual(tagged["mitre"]["technique_id"], "UNMAPPED")

        with self.assertRaises(TypeError):
            tag_alert_mitre("not a dict")  # type: ignore[arg-type]

    def test_tag_alerts_batch(self):
        alerts = [
            {"rule": "Log4j JNDI Exploit"},
            {"rule": "Nmap Port Scan"},
        ]
        tagged = tag_alerts_mitre(alerts)
        self.assertEqual([a["mitre"]["technique_id"] for a in tagged], ["T1190", "T1046"])


if __name__ == "__main__":
    unittest.main()
