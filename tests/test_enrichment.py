"""Unit tests for threat intelligence enrichment and caching."""

from pathlib import Path
import tempfile
import unittest
from sectoolkit.enrichment import EnrichmentCache, enrich_ip


class TestEnrichment(unittest.TestCase):

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = Path(self.temp_file.name)
        self.temp_file.close()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_enrich_private_ip(self):
        result = enrich_ip("10.0.0.15")
        self.assertEqual(result["scope"], "internal")
        self.assertTrue(result["is_private"])
        self.assertEqual(result["reputation"], "trusted_internal")
        self.assertFalse(result["cached"])

    def test_enrich_public_ip_with_cache(self):
        with EnrichmentCache(self.db_path) as cache:
            # First lookup (uncached) - 93.184.216.34 is public
            res1 = enrich_ip("93.184.216.34", cache=cache, mock_reputation="suspicious_c2")
            self.assertEqual(res1["scope"], "public")
            self.assertFalse(res1["is_private"])
            self.assertEqual(res1["reputation"], "suspicious_c2")
            self.assertFalse(res1["cached"])

            # Second lookup (should hit cache)
            res2 = enrich_ip("93.184.216.34", cache=cache)
            self.assertEqual(res2["reputation"], "suspicious_c2")
            self.assertTrue(res2["cached"])

    def test_cache_miss_and_hit(self):
        with EnrichmentCache(":memory:") as cache:
            self.assertIsNone(cache.get("8.8.8.8"))
            cache.set("8.8.8.8", "ipv4", {"status": "ok"})
            self.assertEqual(cache.get("8.8.8.8"), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
