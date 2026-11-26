"""Automated incident report generation in Markdown and HTML formats."""

from collections import Counter
from datetime import datetime, timezone
import json
from typing import Any, Mapping, Sequence


def generate_incident_summary(
    triaged_alerts: Sequence[Mapping[str, Any]],
    extracted_iocs: Mapping[str, Sequence[str]] | None = None,
    manifest: Sequence[Mapping[str, Any]] | None = None,
    case_id: str = "INC-001",
    coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate triaged alerts, IOCs, and evidence files into a structured incident summary.

    Args:
        triaged_alerts: List of triaged and scored alert dictionaries.
        extracted_iocs: Optional dictionary of extracted IOC lists.
        manifest: Optional list of evidence manifest records.
        case_id: Unique case identifier.
        coverage: Optional Purple Team detection coverage dictionary from
            :func:`sectoolkit.purple_team.score_detection_coverage`.

    Returns:
        dict: Complete incident summary data.
    """
    total_alerts = len(triaged_alerts)
    total_events = sum(a.get("count", 1) for a in triaged_alerts)

    # Count by severity
    severity_counter = Counter(a.get("severity", "unknown").lower() for a in triaged_alerts)
    critical_count = severity_counter.get("critical", 0)
    high_count = severity_counter.get("high", 0)

    # Top targeted hosts
    host_counter = Counter(a.get("hostname") for a in triaged_alerts if a.get("hostname"))
    top_target = host_counter.most_common(1)[0][0] if host_counter else "None"

    # Average priority score
    scores = [float(a.get("priority_score", 0.0)) for a in triaged_alerts]
    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0

    return {
        "case_id": case_id,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "unique_alerts": total_alerts,
            "total_event_occurrences": total_events,
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "avg_priority_score": avg_score,
            "top_target_host": top_target,
        },
        "alerts": list(triaged_alerts),
        "iocs": dict(extracted_iocs) if extracted_iocs else {},
        "evidence_files_count": len(manifest) if manifest else 0,
        "coverage": dict(coverage) if coverage else None,
    }


def render_markdown_report(summary: Mapping[str, Any]) -> str:
    """Render a structured incident report in standard Markdown.

    Args:
        summary: Output dictionary from generate_incident_summary.

    Returns:
        str: Markdown formatted report.
    """
    metrics = summary["metrics"]
    case_id = summary["case_id"]
    gen_time = summary["generated_utc"]

    lines = [
        f"# Incident Triage & Forensic Case Report: {case_id}",
        f"**Generated:** `{gen_time}`",
        "",
        "## Executive Summary",
        f"- **Unique Triaged Incidents:** {metrics['unique_alerts']} ({metrics['total_event_occurrences']} raw events)",
        f"- **Critical Severity Count:** {metrics['critical_alerts']}",
        f"- **High Severity Count:** {metrics['high_alerts']}",
        f"- **Average Priority Score:** `{metrics['avg_priority_score']} / 4.00`",
        f"- **Primary Target Host:** `{metrics['top_target_host']}`",
        f"- **Evidence Files Collected:** {summary['evidence_files_count']}",
        "",
        "## Prioritized Incidents",
        "| Score | Severity | MITRE ATT&CK | Rule / Signature | Host | Attacking IP | Event Count |",
        "| :---: | :---: | :---: | :--- | :--- | :--- | :---: |",
    ]

    for a in summary.get("alerts", []):
        mitre = a.get("mitre") if isinstance(a.get("mitre"), Mapping) else {}
        mitre_tid = mitre.get("technique_id") or a.get("technique_id") or "N/A"
        lines.append(
            f"| `{a.get('priority_score', 0.0)}` | **{a.get('severity', '').upper()}** | `{mitre_tid}` | "
            f"{a.get('rule', 'unknown')} | `{a.get('hostname', 'N/A')}` | `{a.get('source_ip', 'N/A')}` | {a.get('count', 1)} |"
        )

    coverage = summary.get("coverage")
    if isinstance(coverage, Mapping) and coverage.get("total_scenarios", 0) > 0:
        lines.extend([
            "",
            "## Purple Team Detection Coverage",
            f"- **Coverage Score:** `{coverage.get('coverage_percent', 0.0)}%` "
            f"({coverage.get('detected_count', 0)}/{coverage.get('total_scenarios', 0)} detected, "
            f"{coverage.get('missed_count', 0)} missed)",
            "",
            "| Case ID | Technique | Tactic | Target Host | Status | Matched Rule |",
            "| :--- | :---: | :--- | :--- | :---: | :--- |",
        ])
        for row in coverage.get("results", []):
            status_badge = "**DETECTED**" if row.get("status") == "detected" else "**MISSED**"
            lines.append(
                f"| `{row.get('case_id', 'N/A')}` | `{row.get('technique_id', 'N/A')}` | "
                f"{row.get('tactic', 'Unknown')} | `{row.get('target_host', 'N/A')}` | "
                f"{status_badge} | {row.get('matched_rule') or '—'} |"
            )

    iocs = summary.get("iocs", {})
    if any(iocs.values()):
        lines.extend([
            "",
            "## Associated Indicators of Compromise (IOCs)",
        ])
        for kind, values in iocs.items():
            if values:
                lines.append(f"### {kind.upper()}")
                for val in values:
                    lines.append(f"- `{val}`")

    lines.extend([
        "",
        "## Remediation & Containment Recommendations",
        "1. **Isolate Primary Target:** Disconnect compromised host from subnet if critical malware detected.",
        "2. **Block Malicious Indicators:** Add discovered source IPs to perimeter firewall drop lists.",
        "3. **Revoke Exposed Credentials:** Force credential rotation for accounts associated with breached hosts.",
    ])

    return "\n".join(lines)


def render_html_report(summary: Mapping[str, Any], dark_mode: bool = True) -> str:
    """Render a standalone, styled HTML incident report.

    Args:
        summary: Output dictionary from generate_incident_summary.
        dark_mode: Whether to apply a dark theme (default: True).

    Returns:
        str: Complete HTML report document.
    """
    import markdown
    md_content = render_markdown_report(summary)
    body_html = markdown.markdown(md_content, extensions=["tables"])

    bg_canvas = "#0d1117" if dark_mode else "#f6f8fa"
    bg_surface = "#161b22" if dark_mode else "#ffffff"
    text_color = "#e6edf3" if dark_mode else "#24292f"
    border_color = "#30363d" if dark_mode else "#d0d7de"
    header_color = "#58a6ff" if dark_mode else "#0969da"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Incident Report - {summary.get('case_id')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: {bg_canvas};
            color: {text_color};
            line-height: 1.6;
            padding: 24px;
        }}
        .report-card {{
            max-width: 900px;
            margin: 0 auto;
            background-color: {bg_surface};
            border: 1px solid {border_color};
            border-radius: 8px;
            padding: 35px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        h1, h2, h3 {{ color: {header_color}; border-bottom: 1px solid {border_color}; padding-bottom: 6px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid {border_color}; padding: 10px; text-align: left; }}
        th {{ background-color: rgba(255,255,255,0.05); }}
        code {{ background-color: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="report-card">
        {body_html}
    </div>
</body>
</html>"""
