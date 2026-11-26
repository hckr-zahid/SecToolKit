"""Unit tests for Central CLI."""

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from sectoolkit.cli import main


class TestCLI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_ioc_inline(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["ioc", "Traffic to 192.168.1.50 and md5 098f6bcd4621d373cade4e832627b4f6"])
        self.assertEqual(code, 0)
        output = json.loads(buf.getvalue())
        self.assertIn("192.168.1.50", output["ips"])
        self.assertIn("098f6bcd4621d373cade4e832627b4f6", output["md5"])

    def test_cli_manifest(self):
        sample = self.root / "sample.txt"
        sample.write_text("forensic evidence content", encoding="utf-8")
        out_file = self.root / "manifest.json"

        code = main(["manifest", str(self.root), "-o", str(out_file)])
        self.assertEqual(code, 0)
        self.assertTrue(out_file.exists())
        manifest = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest), 1)
        self.assertEqual(manifest[0]["path"], "sample.txt")

    def test_cli_triage(self):
        alerts = [
            {"id": "A1", "severity": "high", "rule": "XSS", "time": "2026-11-23T12:00:00Z"},
            {"id": "A2", "severity": "low", "rule": "Ping", "time": "2026-11-23T12:00:00Z"},
        ]
        alerts_file = self.root / "alerts.json"
        alerts_file.write_text(json.dumps(alerts), encoding="utf-8")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["triage", str(alerts_file), "--min-score", "2.0"])
        self.assertEqual(code, 0)
        triaged = json.loads(buf.getvalue())
        self.assertEqual(len(triaged), 1)
        self.assertEqual(triaged[0]["rule"], "XSS")

    def test_cli_enrich(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["enrich", "10.10.5.1"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["is_private"])
        self.assertEqual(data["scope"], "internal")

    def test_cli_scan(self):
        test_file = self.root / "test.php"
        test_file.write_text("eval($_POST['x']);", encoding="utf-8")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["scan", str(test_file)])
        # code 2 indicates matches detected
        self.assertEqual(code, 2)
        matches = json.loads(buf.getvalue())
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule"], "Suspicious_Keywords")

    def test_cli_audit_port(self):
        with patch("sectoolkit.cli.check_tcp", return_value=True):
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                code = main(["audit-port", "127.0.0.1", "443"])
            self.assertEqual(code, 0)
            self.assertIn("OPEN", buf.getvalue())

        with patch("sectoolkit.cli.check_tcp", return_value=False):
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                code = main(["audit-port", "127.0.0.1", "65432"])
            self.assertEqual(code, 2)
            self.assertIn("CLOSED/FILTERED", buf.getvalue())

    def test_cli_report_markdown_and_html(self):
        alerts = [
            {"id": "A1", "severity": "critical", "rule": "RCE", "time": "2026-11-23T12:00:00Z"},
        ]
        alerts_file = self.root / "alerts.json"
        alerts_file.write_text(json.dumps(alerts), encoding="utf-8")

        md_buf = io.StringIO()
        with patch("sys.stdout", md_buf):
            code_md = main(["report", str(alerts_file), "--format", "md"])
        self.assertEqual(code_md, 0)
        self.assertIn("RCE", md_buf.getvalue())

        html_out = self.root / "report.html"
        code_html = main(["report", str(alerts_file), "--format", "html", "-o", str(html_out)])
        self.assertEqual(code_html, 0)
        self.assertTrue(html_out.exists())
        self.assertIn("<html", html_out.read_text(encoding="utf-8").lower())

    def test_cli_coverage(self):
        scenarios = [
            {
                "case_id": "PT-01",
                "technique_id": "T1190",
                "tactic": "Initial Access",
                "target_host": "web-01",
                "timestamp": "2026-11-23T12:00:00Z",
            }
        ]
        alerts = [
            {
                "id": "A1",
                "severity": "high",
                "rule": "XSS Exploit",
                "hostname": "web-01",
                "time": "2026-11-23T12:01:00Z",
            }
        ]
        scenarios_file = self.root / "scenarios.json"
        alerts_file = self.root / "alerts.json"
        scenarios_file.write_text(json.dumps(scenarios), encoding="utf-8")
        alerts_file.write_text(json.dumps(alerts), encoding="utf-8")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["coverage", str(scenarios_file), str(alerts_file)])
        self.assertEqual(code, 0)
        cov = json.loads(buf.getvalue())
        self.assertEqual(cov["detected_count"], 1)
        self.assertEqual(cov["coverage_percent"], 100.0)


if __name__ == "__main__":
    unittest.main()
