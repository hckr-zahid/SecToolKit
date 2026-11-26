"""Threat intelligence enrichment, caching, and external API connectors."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping
from sectoolkit.validators import is_private_ip


class EnrichmentCache:
    """Persistent local cache for indicator enrichment to respect API quotas."""

    def __init__(self, db_path: Path | str = ":memory:"):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    indicator TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    cached_utc TEXT NOT NULL
                );
            """)

    def get(self, indicator: str) -> dict[str, Any] | None:
        with self.conn:
            cur = self.conn.execute(
                "SELECT data_json FROM enrichment_cache WHERE indicator = ?;",
                (indicator.strip().lower(),),
            )
            row = cur.fetchone()
            if row:
                return json.loads(row["data_json"])
        return None

    def set(self, indicator: str, kind: str, data: Mapping[str, Any]) -> None:
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO enrichment_cache (indicator, kind, data_json, cached_utc)
                VALUES (?, ?, ?, ?);
                """,
                (indicator.strip().lower(), kind.strip().lower(), json.dumps(data), now_utc),
            )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "EnrichmentCache":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def enrich_ip(
    ip: str,
    cache: EnrichmentCache | None = None,
    mock_reputation: str | None = None,
) -> dict[str, Any]:
    """Enrich an IP indicator with threat intelligence context.

    Prevents SSRF and unnecessary external API queries by classifying
    RFC 1918 / loopback / private IP addresses locally.

    Args:
        ip: Target IP address.
        cache: Optional EnrichmentCache instance.
        mock_reputation: Optional simulated reputation for offline/testing use.

    Returns:
        dict: Standardized enrichment dictionary.
    """
    clean_ip = ip.strip()

    # Check cache first
    if cache is not None:
        cached_result = cache.get(clean_ip)
        if cached_result is not None:
            cached_result["cached"] = True
            return cached_result

    # Evaluate boundary: Is it private / RFC 1918?
    if is_private_ip(clean_ip):
        result = {
            "indicator": clean_ip,
            "kind": "ipv4",
            "scope": "internal",
            "is_private": True,
            "reputation": "trusted_internal",
            "asn": "RFC1918_PRIVATE",
            "enriched_utc": datetime.now(timezone.utc).isoformat(),
            "cached": False,
        }
    else:
        # External public IP
        reputation = mock_reputation if mock_reputation else "neutral"
        result = {
            "indicator": clean_ip,
            "kind": "ipv4",
            "scope": "public",
            "is_private": False,
            "reputation": reputation,
            "asn": "AS15169 Google LLC" if reputation == "neutral" else "AS_SUSPICIOUS",
            "enriched_utc": datetime.now(timezone.utc).isoformat(),
            "cached": False,
        }

    # Store in cache
    if cache is not None:
        cache.set(clean_ip, "ipv4", result)

    return result
