"""Unit tests for parameterized storage and concurrency."""

import tempfile
import unittest
from pathlib import Path
from sectoolkit.storage import EvidenceStore, bounded_worker_pool


class TestStorage(unittest.TestCase):

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = Path(self.temp_file.name)
        self.temp_file.close()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_indicator_storage(self):
        with EvidenceStore(self.db_path) as store:
            id1 = store.add_indicator("192.168.1.10", "ip", source="threat-feed")
            id2 = store.add_indicator("evil.exe", "file", source="edr")
            self.assertTrue(id1 > 0)
            self.assertTrue(id2 > 0)

            all_inds = store.get_indicators()
            self.assertEqual(len(all_inds), 2)

            ip_inds = store.get_indicators(kind="ip")
            self.assertEqual(len(ip_inds), 1)
            self.assertEqual(ip_inds[0]["indicator"], "192.168.1.10")

    def test_indicator_validation(self):
        with EvidenceStore(":memory:") as store:
            with self.assertRaises(ValueError):
                store.add_indicator("", "ip")
            with self.assertRaises(ValueError):
                store.add_indicator("10.0.0.1", "")

    def test_alert_storage_and_deduplication(self):
        with EvidenceStore(self.db_path) as store:
            alert = {
                "alert_id": "SEC-01",
                "severity": "high",
                "rule": "Command Injection",
                "source_ip": "10.0.0.5",
                "priority_score": 3.45,
                "fingerprint": "abc123hash",
            }
            store.add_alert(alert)

            # Insert duplicate fingerprint
            store.add_alert(alert)

            # Query results
            stored = store.get_alerts()
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]["fingerprint"], "abc123hash")
            self.assertEqual(stored[0]["priority_score"], 3.45)

            # Filter by threshold
            high_only = store.get_alerts(min_priority=4.0)
            self.assertEqual(len(high_only), 0)

    def test_bounded_worker_pool(self):
        def square(x: int) -> int:
            if x == 5:
                raise ValueError("error on 5")
            return x * x

        inputs = [1, 2, 3, 5]
        results = bounded_worker_pool(square, inputs, max_workers=2)
        self.assertEqual(len(results), 4)

        result_dict = dict(results)
        self.assertEqual(result_dict[1], 1)
        self.assertEqual(result_dict[2], 4)
        self.assertEqual(result_dict[3], 9)
        self.assertIsInstance(result_dict[5], ValueError)


if __name__ == "__main__":
    unittest.main()
