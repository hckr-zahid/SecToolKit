import tempfile
import unittest
from pathlib import Path
from sectoolkit.security import safe_child, redact_secrets


class TestSecurity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_safe_child_valid(self):
        child = safe_child(self.root, "subfolder/file.txt")
        self.assertTrue(str(child).startswith(str(self.root.resolve())))

    def test_safe_child_traversal_blocked(self):
        with self.assertRaises(ValueError):
            safe_child(self.root, "../evil.txt")
        with self.assertRaises(ValueError):
            safe_child(self.root, "../../etc/passwd")

    def test_safe_child_same_dir(self):
        child = safe_child(self.root, ".")
        self.assertEqual(child, self.root.resolve())

    def test_redact_secrets_simple(self):
        data = {"user": "analyst", "password": "supersecret123"}
        result = redact_secrets(data)
        self.assertEqual(result["user"], "analyst")
        self.assertEqual(result["password"], "[REDACTED]")

    def test_redact_secrets_nested(self):
        data = {
            "session": {
                "token": "xyz987",
                "info": {"api_key": "abc12345", "ip": "10.0.0.1"}
            },
            "items": [{"cookie": "sess=123"}, {"name": "sample"}]
        }
        result = redact_secrets(data)
        self.assertEqual(result["session"]["token"], "[REDACTED]")
        self.assertEqual(result["session"]["info"]["api_key"], "[REDACTED]")
        self.assertEqual(result["session"]["info"]["ip"], "10.0.0.1")
        self.assertEqual(result["items"][0]["cookie"], "[REDACTED]")
        self.assertEqual(result["items"][1]["name"], "sample")


if __name__ == "__main__":
    unittest.main()
