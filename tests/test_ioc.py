import hashlib
from pathlib import Path
import tempfile
import unittest
from sectoolkit.ioc import defang_indicator, extract_iocs, sha256_file


class TestIOC(unittest.TestCase):

    def test_sha256_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"malware analysis test payload")
            temp_path = Path(f.name)
        try:
            expected = hashlib.sha256(b"malware analysis test payload").hexdigest()
            self.assertEqual(sha256_file(temp_path), expected)
        finally:
            temp_path.unlink()

    def test_sha256_file_missing(self):
        with self.assertRaises(FileNotFoundError):
            sha256_file(Path("non_existent_file.bin"))

    def test_extract_iocs(self):
        text = (
            "Suspicious connections to 192.168.1.1 and 10.0.0.5, plus invalid 999.999.999.999. "
            "Hash detected: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 "
            "and legacy md5: 098f6bcd4621d373cade4e832627b4f6."
        )
        iocs = extract_iocs(text)
        self.assertEqual(iocs["ips"], ["10.0.0.5", "192.168.1.1"])
        self.assertIn("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", iocs["sha256"])
        self.assertIn("098f6bcd4621d373cade4e832627b4f6", iocs["md5"])

    def test_defang_indicator(self):
        self.assertEqual(defang_indicator("https://evil.com/malware"), "hxxps://evil[.]com/malware")
        self.assertEqual(defang_indicator("http://192.168.1.100"), "hxxp://192[.]168[.]1[.]100")
        self.assertEqual(defang_indicator("c2.attacker.net"), "c2[.]attacker[.]net")


if __name__ == "__main__":
    unittest.main()
