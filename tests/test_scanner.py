"""Unit tests for YARA scanning and binary triage."""

from pathlib import Path
import tempfile
import unittest
from sectoolkit.scanner import YaraScanner, calculate_entropy, extract_strings


class TestScanner(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_calculate_entropy(self):
        # Uniform zero bytes = 0 entropy
        self.assertEqual(calculate_entropy(b"\x00" * 100), 0.0)

        # High entropy random payload
        import os
        random_bytes = os.urandom(1000)
        entropy = calculate_entropy(random_bytes)
        self.assertTrue(entropy > 7.0)

    def test_extract_strings(self):
        test_file = self.dir / "sample.bin"
        test_file.write_bytes(b"\x00\x00\x00MALWARE_C2_SERVER\x00\x00\x01\x02cmd.exe /c calc\x00")

        strings = list(extract_strings(test_file, min_length=5))
        self.assertIn("MALWARE_C2_SERVER", strings)
        self.assertIn("cmd.exe /c calc", strings)

    def test_yara_scanner_memory_and_file(self):
        rule_source = """
        rule Detect_Webshell {
            meta:
                description = "Detects simple webshell signature"
            strings:
                $shell = "eval(base64_decode"
                $cmd = "passthru"
            condition:
                $shell or $cmd
        }
        """
        scanner = YaraScanner(rule_source=rule_source)

        # Test scan bytes
        matches = scanner.scan_data(b"<?php eval(base64_decode($_POST['c'])); ?>")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule"], "Detect_Webshell")

        # Test clean file
        clean_file = self.dir / "clean.txt"
        clean_file.write_text("Normal application log without keywords", encoding="utf-8")
        clean_matches = scanner.scan_file(clean_file)
        self.assertEqual(len(clean_matches), 0)

        # Test infected file
        bad_file = self.dir / "webshell.php"
        bad_file.write_text("system(passthru($_GET['x']));", encoding="utf-8")
        bad_matches = scanner.scan_file(bad_file)
        self.assertEqual(len(bad_matches), 1)
        self.assertEqual(bad_matches[0]["rule"], "Detect_Webshell")


if __name__ == "__main__":
    unittest.main()
