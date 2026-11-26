"""SOC triage, alert normalization, deduplication, and priority scoring."""

import hashlib
import json
from typing import Any, Mapping, Sequence

SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def normalize_alert(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize raw alert data from SIEM or security sensors into a standard schema.

    Args:
        raw: Mapping containing raw alert fields.

    Returns:
        dict: Normalized alert dictionary with standard keys:
            alert_id, severity, source_ip, hostname, timestamp, rule.

    Raises:
        TypeError: If raw is not a Mapping.
    """
    if not isinstance(raw, Mapping):
        raise TypeError(f"Raw alert must be a dict-like mapping, got: {type(raw).__name__}")

    alert_id = raw.get("alert_id") or raw.get("id") or "unknown"
    severity = str(raw.get("severity", "unknown")).strip().lower()
    source_ip = raw.get("source_ip") or raw.get("src_ip")
    hostname = raw.get("hostname") or raw.get("host")
    timestamp = str(raw.get("timestamp") or raw.get("@timestamp") or raw.get("time") or "")
    rule = raw.get("rule") or raw.get("rule_name") or raw.get("signature") or "unknown"

    return {
        "alert_id": str(alert_id),
        "severity": severity,
        "source_ip": str(source_ip).strip() if source_ip else None,
        "hostname": str(hostname).strip() if hostname else None,
        "timestamp": timestamp,
        "rule": str(rule).strip(),
    }


def fingerprint(alert: Mapping[str, Any]) -> str:
    """Compute a deterministic SHA-256 fingerprint for alert deduplication.

    Args:
        alert: Normalized alert dictionary.

    Returns:
        str: 64-character hexadecimal SHA-256 string.

    Raises:
        TypeError: If alert is not a Mapping.
    """
    if not isinstance(alert, Mapping):
        raise TypeError(f"Alert must be a dict-like mapping, got: {type(alert).__name__}")

    timestamp_str = str(alert.get("timestamp", ""))
    stable = {
        "rule": alert.get("rule"),
        "host": alert.get("hostname"),
        "src": alert.get("source_ip"),
        "time_bucket": timestamp_str[:16],
    }
    raw = json.dumps(stable, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def priority_score(
    severity: str,
    confidence: float | int,
    asset_criticality: float | int,
) -> float:
    """Calculate a transparent priority score for an alert.

    Formula: (severity_weight * 0.45) + (confidence * 0.30) + (asset_criticality * 0.25)
    Weights: low=1, medium=2, high=3, critical=4 (default=1 for unknown).

    Args:
        severity: Severity string ("low", "medium", "high", "critical").
        confidence: Numeric confidence rating between 1 and 4.
        asset_criticality: Numeric asset criticality rating between 1 and 4.

    Returns:
        float: Priority score rounded to 2 decimal places.

    Raises:
        TypeError: If confidence or asset_criticality is not numeric.
        ValueError: If confidence or asset_criticality is out of range [1, 4].
    """
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        raise TypeError(f"Confidence must be an integer or float, got: {type(confidence).__name__}")
    if not isinstance(asset_criticality, (int, float)) or isinstance(asset_criticality, bool):
        raise TypeError(
            f"Asset criticality must be an integer or float, got: {type(asset_criticality).__name__}"
        )

    if not (1 <= confidence <= 4):
        raise ValueError(f"Confidence must be between 1 and 4, got: {confidence}")
    if not (1 <= asset_criticality <= 4):
        raise ValueError(f"Asset criticality must be between 1 and 4, got: {asset_criticality}")

    sev_key = str(severity).strip().lower()
    sev_weight = SEVERITY_WEIGHTS.get(sev_key, 1)

    score = (sev_weight * 0.45) + (confidence * 0.30) + (asset_criticality * 0.25)
    return round(score, 2)


def triage_alerts(
    raw_alerts: Sequence[Mapping[str, Any]],
    default_confidence: float | int = 2,
    default_criticality: float | int = 2,
    min_priority: float = 0.0,
) -> list[dict[str, Any]]:
    """Normalize, deduplicate, score, and rank raw alerts.

    Args:
        raw_alerts: Sequence of raw alert mappings.
        default_confidence: Fallback confidence if not specified per alert (1-4).
        default_criticality: Fallback asset criticality if not specified per alert (1-4).
        min_priority: Minimum score threshold; alerts below this score are filtered out.

    Returns:
        list[dict]: Deduplicated and prioritized alerts sorted descending by priority score.
    """
    deduped: dict[str, dict[str, Any]] = {}

    for raw in raw_alerts:
        norm = normalize_alert(raw)
        fp = fingerprint(norm)

        if fp in deduped:
            deduped[fp]["count"] += 1
        else:
            conf = raw.get("confidence", default_confidence)
            crit = raw.get("asset_criticality", default_criticality)
            score = priority_score(norm["severity"], conf, crit)
            norm["fingerprint"] = fp
            norm["priority_score"] = score
            norm["confidence"] = conf
            norm["asset_criticality"] = crit
            norm["count"] = 1
            deduped[fp] = norm

    results = [alert for alert in deduped.values() if alert["priority_score"] >= min_priority]
    results.sort(key=lambda a: a["priority_score"], reverse=True)
    return results
