"""Unit tests for digital forensics and safe execution."""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from sectoolkit.forensics import (
    generate_manifest,
    parse_iso_timestamp,
    safe_exec,
    verify_manifest,
)


class TestForensics(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_and_verify_manifest(self):
        # Create test files
        sub = self.root / "cases"
        sub.mkdir()
        f1 = self.root / "file1.txt"
        f1.write_text("evidence data 1", encoding="utf-8")
        f2 = sub / "file2.txt"
        f2.write_text("evidence data 2", encoding="utf-8")

        manifest = generate_manifest(self.root)
        self.assertEqual(len(manifest), 2)
        self.assertEqual(manifest[0]["path"], "cases/file2.txt")
        self.assertEqual(manifest[1]["path"], "file1.txt")

        # Verify integrity
        verify = verify_manifest(manifest, self.root)
        self.assertEqual(len(verify["matched"]), 2)
        self.assertEqual(len(verify["modified"]), 0)
        self.assertEqual(len(verify["missing"]), 0)

        # Modify one file and delete another
        f1.write_text("tampered data", encoding="utf-8")
        f2.unlink()

        verify_tampered = verify_manifest(manifest, self.root)
        self.assertIn("file1.txt", verify_tampered["modified"])
        self.assertIn("cases/file2.txt", verify_tampered["missing"])

    def test_parse_iso_timestamp(self):
        ts = "2026-11-23T15:30:00Z"
        dt = parse_iso_timestamp(ts)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.tzinfo, timezone.utc)

        ts_offset = "2026-11-23T20:30:00+05:00"
        dt_offset = parse_iso_timestamp(ts_offset)
        self.assertEqual(dt_offset, dt)

    def test_parse_iso_timestamp_invalid(self):
        with self.assertRaises(ValueError):
            parse_iso_timestamp("2026-11-23 15:30:00")  # missing timezone
        with self.assertRaises(ValueError):
            parse_iso_timestamp("not-a-timestamp")
        with self.assertRaises(TypeError):
            parse_iso_timestamp(12345)

    def test_safe_exec(self):
        ret, stdout, stderr = safe_exec(["echo", "hello forensic world"])
        self.assertEqual(ret, 0)
        self.assertEqual(stdout.strip(), "hello forensic world")

    def test_safe_exec_invalid_args(self):
        with self.assertRaises(TypeError):
            safe_exec("echo hello")  # Must be list, not string


if __name__ == "__main__":
    unittest.main()
