"""
Integration test: full_pipeline_demo flow executed programmatically.

Validates that all 7 pipeline stages complete without error and that
expected output artefacts are produced, using real sample fixtures.

API notes (verified against source):
  - stream_lines()         → yields (int, str) tuples
  - EnrichmentCache.set()  → (indicator, kind, data)  — 3 args
  - YaraScanner()          → YaraScanner(rule_file=path) kwarg
  - EvidenceStore          → add_alert(dict), add_indicator(str, str, str),
                             get_alerts(min_priority=), get_indicators()
  - generate_incident_summary() → (triaged, extracted_iocs=dict, manifest=list)
  - render_markdown_report()    → returns str
  - render_html_report()        → returns str
"""

import json
import os
import pathlib
import sys
import tempfile
import unittest

# Ensure src/ is on path when run directly
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from sectoolkit.log_stream import stream_lines
from sectoolkit.ioc import extract_iocs, defang_indicator
from sectoolkit.enrichment import EnrichmentCache
from sectoolkit.triage import triage_alerts
from sectoolkit.scanner import YaraScanner, calculate_entropy
from sectoolkit.storage import EvidenceStore
from sectoolkit.reporting import (
    generate_incident_summary,
    render_markdown_report,
    render_html_report,
)

DATA_DIR = pathlib.Path(__file__).resolve().parents[1] / "data"
AUTH_LOG = DATA_DIR / "sample_auth.log"
ALERTS_JSON = DATA_DIR / "sample_alerts.json"
YARA_RULES = DATA_DIR / "sample_rules.yar"


class TestPipelineIntegration(unittest.TestCase):
    """End-to-end pipeline integration tests."""

    # ------------------------------------------------------------------
    # Stage 1 — Log Streaming
    # stream_lines yields (lineno: int, text: str) tuples
    # ------------------------------------------------------------------
    def test_stage1_log_streaming(self):
        """stream_lines must yield (lineno, text) tuples from sample_auth.log."""
        pairs = list(stream_lines(str(AUTH_LOG)))
        self.assertGreater(len(pairs), 0, "No lines streamed from auth log")
        lines = [text for _lineno, text in pairs]
        failures = [l for l in lines if "Failed password" in l]
        self.assertGreater(len(failures), 0, "Expected SSH failure lines in fixture")

    # ------------------------------------------------------------------
    # Stage 2 — IOC Extraction & Defanging
    # ------------------------------------------------------------------
    def test_stage2_ioc_extraction(self):
        """extract_iocs must find IPs from auth log lines."""
        pairs = list(stream_lines(str(AUTH_LOG)))
        all_text = "\n".join(text for _lineno, text in pairs)
        iocs = extract_iocs(all_text)
        self.assertIn("ips", iocs)
        self.assertGreater(len(iocs["ips"]), 0, "No IPs extracted from auth log")

    def test_stage2_defanging(self):
        """defang_indicator must bracket dots in IP addresses."""
        defanged = defang_indicator("185.220.101.5")
        self.assertIn("[.]", defanged)
        self.assertNotIn("185.220.101.5", defanged)

    # ------------------------------------------------------------------
    # Stage 3 — IP Enrichment with SQLite cache
    # EnrichmentCache.set(indicator: str, kind: str, data: dict)
    # ------------------------------------------------------------------
    def test_stage3_enrichment_cache(self):
        """EnrichmentCache must store and retrieve enrichment records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "enrich.db")
            fake = {"ip": "10.0.0.1", "scope": "internal", "tags": ["trusted"]}
            with EnrichmentCache(db_path) as cache:
                cache.set("10.0.0.1", "ip", fake)
                result = cache.get("10.0.0.1")
            self.assertIsNotNone(result, "Cached record not found")
            self.assertEqual(result["scope"], "internal")

    # ------------------------------------------------------------------
    # Stage 4 — SIEM Triage
    # ------------------------------------------------------------------
    def test_stage4_triage(self):
        """triage_alerts must deduplicate and score alerts from fixture."""
        with open(ALERTS_JSON) as f:
            raw_alerts = json.load(f)
        triaged = triage_alerts(raw_alerts)
        self.assertGreater(len(triaged), 0, "Triage returned no alerts")
        for alert in triaged:
            self.assertIn("priority_score", alert)
            self.assertIsInstance(alert["priority_score"], (int, float))

    def test_stage4_triage_ordered_descending(self):
        """Triaged results must be sorted highest score first."""
        with open(ALERTS_JSON) as f:
            raw_alerts = json.load(f)
        triaged = triage_alerts(raw_alerts)
        scores = [a["priority_score"] for a in triaged]
        self.assertEqual(scores, sorted(scores, reverse=True))

    # ------------------------------------------------------------------
    # Stage 5 — YARA + Entropy
    # YaraScanner(rule_file=str) — use keyword argument
    # ------------------------------------------------------------------
    def test_stage5_entropy_zero_bytes(self):
        """calculate_entropy of all-zero bytes must be 0.0."""
        h = calculate_entropy(b"\x00" * 256)
        self.assertEqual(h, 0.0)

    def test_stage5_entropy_random_data(self):
        """calculate_entropy of random bytes must be > 5.0."""
        h = calculate_entropy(os.urandom(256))
        self.assertGreater(h, 5.0, "Random data entropy should be > 5.0")

    @unittest.skipUnless(YARA_RULES.exists(), "sample_rules.yar not found")
    def test_stage5_yara_webshell_detection(self):
        """YaraScanner must flag webshell payload with Suspicious_Webshell rule."""
        scanner = YaraScanner(rule_file=str(YARA_RULES))
        payload = b"<?php eval($_POST['cmd']); ?>"
        matches = scanner.scan_data(payload)
        rule_names = [m["rule"] for m in matches]
        self.assertIn("Suspicious_Webshell", rule_names)

    # ------------------------------------------------------------------
    # Stage 6 — EvidenceStore persistence
    # add_alert(alert: dict) — alert must have "fingerprint" key
    # add_indicator(indicator: str, kind: str, source: str)
    # get_alerts(min_priority: float) / get_indicators(kind: str | None)
    # ------------------------------------------------------------------
    def test_stage6_evidence_store_roundtrip(self):
        """EvidenceStore must persist and query alert + indicator rows."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "evidence.db")
            test_alert = {
                "alert_id": "INT-001",
                "severity": "HIGH",
                "rule": "Integration Test Alert",
                "source_ip": "185.220.101.5",
                "hostname": "test-host-01",
                "timestamp": "2026-01-01T00:00:00Z",
                "priority_score": 3.5,
                "fingerprint": "deadbeef01",
            }
            with EvidenceStore(db_path) as store:
                store.add_alert(test_alert)
                store.add_indicator("10.0.0.99", "ip", "ssh_bruteforce")
                alerts = store.get_alerts(min_priority=3.0)
                indicators = store.get_indicators()

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["hostname"], "test-host-01")
            self.assertAlmostEqual(alerts[0]["priority_score"], 3.5)
            self.assertEqual(len(indicators), 1)
            self.assertEqual(indicators[0]["indicator"], "10.0.0.99")

    # ------------------------------------------------------------------
    # Stage 7 — Report generation
    # render_markdown_report / render_html_report return str (not write files)
    # generate_incident_summary(triaged, extracted_iocs=dict, manifest=list)
    # ------------------------------------------------------------------
    def test_stage7_report_strings_returned(self):
        """render_markdown_report and render_html_report must return non-empty strings."""
        with open(ALERTS_JSON) as f:
            raw_alerts = json.load(f)
        triaged = triage_alerts(raw_alerts)
        summary = generate_incident_summary(
            triaged,
            extracted_iocs={"ips": ["185.220.101.5"]},
        )
        md_content = render_markdown_report(summary)
        html_content = render_html_report(summary)

        self.assertIsInstance(md_content, str)
        self.assertIsInstance(html_content, str)
        self.assertGreater(len(md_content), 100)
        self.assertGreater(len(html_content), 100)
        self.assertIn("<html", html_content.lower())
        self.assertIn("background", html_content)
        self.assertIn("INC-001", md_content)

    def test_stage7_report_write_to_file(self):
        """Report strings can be written to disk and produce valid files."""
        with open(ALERTS_JSON) as f:
            raw_alerts = json.load(f)
        triaged = triage_alerts(raw_alerts)
        summary = generate_incident_summary(triaged)

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = os.path.join(tmpdir, "report.md")
            html_path = os.path.join(tmpdir, "report.html")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(render_markdown_report(summary))
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(render_html_report(summary))
            self.assertTrue(os.path.exists(md_path))
            self.assertTrue(os.path.exists(html_path))
            self.assertGreater(os.path.getsize(md_path), 0)
            self.assertGreater(os.path.getsize(html_path), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
