"""Parameterized SQLite storage and bounded concurrency for security tooling."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


class EvidenceStore:
    """Thread-safe, parameterized SQLite store for forensic evidence and threat data."""

    def __init__(self, db_path: Path | str = ":memory:"):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    source TEXT,
                    observed_utc TEXT NOT NULL
                );
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT,
                    severity TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    source_ip TEXT,
                    hostname TEXT,
                    timestamp TEXT,
                    priority_score REAL,
                    fingerprint TEXT UNIQUE NOT NULL
                );
            """)

    def add_indicator(
        self,
        indicator: str,
        kind: str,
        source: str = "internal",
    ) -> int:
        """Insert an indicator using strictly parameterized SQL."""
        if not indicator or not kind:
            raise ValueError("Indicator and kind cannot be empty")

        now_utc = datetime.now(timezone.utc).isoformat()
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO indicators (indicator, kind, source, observed_utc)
                VALUES (?, ?, ?, ?);
                """,
                (indicator.strip(), kind.strip().lower(), source.strip(), now_utc),
            )
            return cur.lastrowid or 0

    def get_indicators(self, kind: str | None = None) -> list[dict[str, Any]]:
        """Query indicators safely using parameterized filtering."""
        with self.conn:
            if kind:
                cur = self.conn.execute(
                    "SELECT id, indicator, kind, source, observed_utc FROM indicators WHERE kind = ?;",
                    (kind.strip().lower(),),
                )
            else:
                cur = self.conn.execute(
                    "SELECT id, indicator, kind, source, observed_utc FROM indicators ORDER BY id ASC;"
                )
            return [dict(row) for row in cur.fetchall()]

    def add_alert(self, alert: dict[str, Any]) -> int:
        """Insert or ignore a triaged alert using its unique fingerprint."""
        fp = alert.get("fingerprint")
        if not fp:
            raise ValueError("Alert must have a unique fingerprint")

        with self.conn:
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    alert_id, severity, rule, source_ip, hostname, timestamp, priority_score, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(alert.get("alert_id", "unknown")),
                    str(alert.get("severity", "unknown")),
                    str(alert.get("rule", "unknown")),
                    alert.get("source_ip"),
                    alert.get("hostname"),
                    str(alert.get("timestamp", "")),
                    float(alert.get("priority_score", 0.0)),
                    str(fp),
                ),
            )
            return cur.lastrowid or 0

    def get_alerts(self, min_priority: float = 0.0) -> list[dict[str, Any]]:
        """Retrieve alerts meeting or exceeding a minimum priority threshold."""
        with self.conn:
            cur = self.conn.execute(
                """
                SELECT id, alert_id, severity, rule, source_ip, hostname, timestamp, priority_score, fingerprint
                FROM alerts
                WHERE priority_score >= ?
                ORDER BY priority_score DESC;
                """,
                (min_priority,),
            )
            return [dict(row) for row in cur.fetchall()]

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def bounded_worker_pool(
    func: Callable[[T], R],
    items: Iterable[T],
    max_workers: int = 4,
) -> list[tuple[T, R | Exception]]:
    """Execute independent I/O tasks across a bounded worker pool safely.

    Args:
        func: Worker function to execute on each item.
        items: Iterable of items to process.
        max_workers: Maximum concurrent thread workers.

    Returns:
        list[tuple[T, R | Exception]]: Processed pairs of (input, result_or_exception).
    """
    results: list[tuple[T, R | Exception]] = []
    item_list = list(items)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_item = {executor.submit(func, item): item for item in item_list}
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            try:
                out = future.result()
                results.append((item, out))
            except Exception as exc:
                results.append((item, exc))

    return results
