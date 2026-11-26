"""Unit tests for network telemetry and auditing."""

from pathlib import Path
import tempfile
import unittest
from sectoolkit.net_audit import (
    check_tcp,
    parse_suricata_eve,
    subnet_hosts,
    summarize_top_talkers,
)


class TestNetAudit(unittest.TestCase):

    def test_subnet_hosts(self):
        hosts = subnet_hosts("192.168.1.0/29")
        # /29 has 8 total addresses, 6 usable hosts (192.168.1.1 to 192.168.1.6)
        self.assertEqual(len(hosts), 6)
        self.assertEqual(hosts[0], "192.168.1.1")
        self.assertEqual(hosts[-1], "192.168.1.6")

    def test_subnet_hosts_invalid(self):
        with self.assertRaises(ValueError):
            subnet_hosts("invalid-subnet")
        with self.assertRaises(TypeError):
            subnet_hosts(12345)

    def test_check_tcp_closed(self):
        # Port 1 on 127.0.0.1 should not connect
        result = check_tcp("127.0.0.1", 1, timeout=0.1)
        self.assertFalse(result)

    def test_check_tcp_invalid_port(self):
        with self.assertRaises(ValueError):
            check_tcp("127.0.0.1", 70000)

    def test_parse_suricata_eve_and_top_talkers(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f:
            f.write(
                '{"event_type": "alert", "src_ip": "10.0.0.5", "alert": {"signature": "ET SCAN"}}\n'
                '{"event_type": "dns", "src_ip": "10.0.0.5"}\n'
                '{"event_type": "alert", "src_ip": "10.0.0.5", "alert": {"signature": "ET SCAN"}}\n'
                '{"event_type": "alert", "src_ip": "192.168.1.20", "alert": {"signature": "SQLi"}}\n'
            )
            temp_path = Path(f.name)

        try:
            alerts = list(parse_suricata_eve(temp_path, event_type="alert"))
            self.assertEqual(len(alerts), 3)

            top = summarize_top_talkers(alerts, key="src_ip")
            self.assertEqual(top, [("10.0.0.5", 2), ("192.168.1.20", 1)])
        finally:
            temp_path.unlink()


if __name__ == "__main__":
    unittest.main()
