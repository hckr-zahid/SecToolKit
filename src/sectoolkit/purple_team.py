"""Purple Team timeline correlation and detection coverage scoring."""

from collections import defaultdict
from typing import Any, Mapping, Sequence

from sectoolkit.forensics import parse_iso_timestamp
from sectoolkit.mitre import tag_alert_mitre


def _extract_technique_id(record: Mapping[str, Any]) -> str | None:
    """Extract a normalized MITRE technique ID from an event or alert."""
    mitre = record.get("mitre")
    if isinstance(mitre, Mapping) and mitre.get("technique_id"):
        tid = str(mitre["technique_id"]).strip().upper()
        return tid if tid != "UNMAPPED" else None
    if record.get("technique_id"):
        return str(record["technique_id"]).strip().upper()
    return None


def _extract_timestamp(record: Mapping[str, Any]) -> str | None:
    """Extract an ISO timestamp string from common timestamp field names."""
    for field in ("timestamp", "time", "created_at", "@timestamp"):
        val = record.get(field)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def correlate_timeline(
    expected_scenarios: Sequence[Mapping[str, Any]],
    observed_alerts: Sequence[Mapping[str, Any]],
    time_window_seconds: float = 300.0,
) -> list[dict[str, Any]]:
    """Correlate expected Purple Team test scenarios against observed defensive alerts.

    A scenario matches an alert when:
      1. Both share the same MITRE ``technique_id`` (parent technique prefix match
         is also accepted, e.g., ``T1059.001`` matches ``T1059``).
      2. If both specify a host (``target_host`` / ``hostname``), they match
         case-insensitively.
      3. Both have valid ISO timestamps within ``time_window_seconds`` (or if
         either lacks a timestamp, technique + host match is used).

    Args:
        expected_scenarios: Planned Purple Team test-case scenarios.
        observed_alerts: Observed SIEM/Suricata/YARA alerts.
        time_window_seconds: Maximum allowed time difference in seconds (>= 0).

    Returns:
        list[dict]: Per-scenario correlation records with ``status``
            (``"detected"`` or ``"missed"``).

    Raises:
        ValueError: If ``time_window_seconds`` is negative.
    """
    if time_window_seconds < 0:
        raise ValueError("time_window_seconds must be non-negative")

    tagged_alerts = [tag_alert_mitre(a) for a in observed_alerts]
    results: list[dict[str, Any]] = []

    for idx, scenario in enumerate(expected_scenarios, start=1):
        case_id = str(scenario.get("case_id", f"PT-{idx:02d}"))
        tech_id = _extract_technique_id(scenario) or "UNMAPPED"
        tactic = str(scenario.get("tactic", "Unknown"))
        scenario_host = str(scenario.get("target_host") or scenario.get("hostname") or "").strip().lower()
        scenario_ts_raw = _extract_timestamp(scenario)
        scenario_dt = parse_iso_timestamp(scenario_ts_raw) if scenario_ts_raw else None

        matched_alert: Mapping[str, Any] | None = None
        best_delta: float | None = None

        for alert in tagged_alerts:
            alert_tid = _extract_technique_id(alert)
            if not alert_tid or tech_id == "UNMAPPED":
                continue

            # Exact match or sub-technique match (e.g., T1059.001 vs T1059)
            if alert_tid != tech_id and not alert_tid.startswith(f"{tech_id}.") and not tech_id.startswith(f"{alert_tid}."):
                continue

            alert_host = str(alert.get("hostname") or alert.get("target_host") or "").strip().lower()
            if scenario_host and alert_host and scenario_host != alert_host:
                continue

            alert_ts_raw = _extract_timestamp(alert)
            delta_seconds: float | None = None
            if scenario_dt is not None and alert_ts_raw is not None:
                alert_dt = parse_iso_timestamp(alert_ts_raw)
                delta_seconds = abs((alert_dt - scenario_dt).total_seconds())
                if delta_seconds > time_window_seconds:
                    continue

            if matched_alert is None or (
                delta_seconds is not None and (best_delta is None or delta_seconds < best_delta)
            ):
                matched_alert = alert
                best_delta = delta_seconds

        results.append({
            "case_id": case_id,
            "name": str(scenario.get("name", case_id)),
            "technique_id": tech_id,
            "tactic": tactic,
            "target_host": scenario.get("target_host") or scenario.get("hostname") or "N/A",
            "status": "detected" if matched_alert is not None else "missed",
            "matched_rule": matched_alert.get("rule") if matched_alert else None,
            "matched_alert_id": matched_alert.get("alert_id") or matched_alert.get("id") if matched_alert else None,
            "time_delta_seconds": round(best_delta, 2) if best_delta is not None else None,
        })

    return results


def score_detection_coverage(correlation_results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Compute overall and per-tactic detection coverage metrics.

    Args:
        correlation_results: Output list from :func:`correlate_timeline`.

    Returns:
        dict: Summary containing ``total_scenarios``, ``detected_count``,
            ``missed_count``, ``coverage_percent``, ``by_tactic``, and ``results``.
    """
    total = len(correlation_results)
    detected = sum(1 for r in correlation_results if r.get("status") == "detected")
    missed = total - detected
    coverage_pct = round((detected / total) * 100.0, 2) if total > 0 else 0.0

    by_tactic: dict[str, dict[str, int]] = defaultdict(lambda: {"detected": 0, "missed": 0})
    for item in correlation_results:
        tactic = str(item.get("tactic", "Unknown"))
        if item.get("status") == "detected":
            by_tactic[tactic]["detected"] += 1
        else:
            by_tactic[tactic]["missed"] += 1

    return {
        "total_scenarios": total,
        "detected_count": detected,
        "missed_count": missed,
        "coverage_percent": coverage_pct,
        "by_tactic": dict(by_tactic),
        "results": [dict(r) for r in correlation_results],
    }
