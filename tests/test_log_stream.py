"""Unit tests for log streaming and batching."""

from pathlib import Path
import tempfile
import unittest
from sectoolkit.log_stream import batch_stream, stream_json_lines, stream_lines


class TestLogStream(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_stream_lines_all(self):
        test_file = self.dir_path / "sample.log"
        test_file.write_text("line 1\nline 2\nline 3\n", encoding="utf-8")

        lines = list(stream_lines(test_file))
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], (1, "line 1"))
        self.assertEqual(lines[1], (2, "line 2"))
        self.assertEqual(lines[2], (3, "line 3"))

    def test_stream_lines_filter(self):
        test_file = self.dir_path / "auth.log"
        content = (
            "Nov 23 10:00:01 sshd[123]: Accepted publickey for analyst\n"
            "Nov 23 10:00:15 sshd[124]: Failed password for invalid user admin\n"
            "Nov 23 10:00:22 sshd[125]: Failed password for root\n"
        )
        test_file.write_text(content, encoding="utf-8")

        failures = list(stream_lines(test_file, needle="Failed password"))
        self.assertEqual(len(failures), 2)
        self.assertEqual(failures[0][0], 2)
        self.assertIn("invalid user admin", failures[0][1])
        self.assertEqual(failures[1][0], 3)
        self.assertIn("root", failures[1][1])

    def test_stream_lines_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            list(stream_lines(self.dir_path / "does_not_exist.log"))

    def test_stream_json_lines(self):
        ndjson_file = self.dir_path / "events.json"
        content = (
            '{"event_id": 1, "status": "ok"}\n'
            'not valid json\n'
            '\n'
            '{"event_id": 2, "status": "alert"}\n'
        )
        ndjson_file.write_text(content, encoding="utf-8")

        records = list(stream_json_lines(ndjson_file))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0], (1, {"event_id": 1, "status": "ok"}))
        self.assertEqual(records[1], (4, {"event_id": 2, "status": "alert"}))

    def test_batch_stream(self):
        items = iter(range(10))
        batches = list(batch_stream(items, batch_size=4))
        self.assertEqual(batches, [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9]])

    def test_batch_stream_invalid_size(self):
        with self.assertRaises(ValueError):
            list(batch_stream([1, 2, 3], batch_size=0))


if __name__ == "__main__":
    unittest.main()
