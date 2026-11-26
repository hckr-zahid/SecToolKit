"""Unit tests for boundary validators."""

import unittest
from sectoolkit.validators import parse_port, normalize_username, is_private_ip


class TestValidators(unittest.TestCase):

    def test_parse_port_valid(self):
        self.assertEqual(parse_port(80), 80)
        self.assertEqual(parse_port("443"), 443)
        self.assertEqual(parse_port(1), 1)
        self.assertEqual(parse_port(65535), 65535)

    def test_parse_port_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_port(0)
        with self.assertRaises(ValueError):
            parse_port(65536)
        with self.assertRaises(ValueError):
            parse_port(-1)

    def test_parse_port_invalid_type(self):
        with self.assertRaises(ValueError):
            parse_port("ssh")
        with self.assertRaises(ValueError):
            parse_port(None)

    def test_normalize_username(self):
        self.assertEqual(normalize_username("  Admin "), "admin")
        self.assertEqual(normalize_username("ALICE"), "alice")
        self.assertEqual(normalize_username(""), "")

    def test_normalize_username_invalid_type(self):
        with self.assertRaises(TypeError):
            normalize_username(12345)

    def test_is_private_ip(self):
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.50"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))

    def test_is_private_ip_invalid(self):
        with self.assertRaises(ValueError):
            is_private_ip("999.999.999.999")
        with self.assertRaises(ValueError):
            is_private_ip("not-an-ip")


if __name__ == "__main__":
    unittest.main()
