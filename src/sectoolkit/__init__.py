"""Security Engineering & SOC Automation Toolkit (`sectoolkit`)."""

from sectoolkit.validators import parse_port, normalize_username, is_private_ip
from sectoolkit.security import safe_child, redact_secrets
from sectoolkit.ioc import sha256_file, extract_iocs, defang_indicator
from sectoolkit.triage import normalize_alert, fingerprint, priority_score, triage_alerts
from sectoolkit.log_stream import stream_lines, stream_json_lines, batch_stream
from sectoolkit.net_audit import check_tcp, subnet_hosts, parse_suricata_eve, summarize_top_talkers
from sectoolkit.forensics import generate_manifest, verify_manifest, parse_iso_timestamp, safe_exec
from sectoolkit.storage import EvidenceStore, bounded_worker_pool
from sectoolkit.enrichment import EnrichmentCache, enrich_ip
from sectoolkit.scanner import YaraScanner, calculate_entropy, extract_strings
from sectoolkit.reporting import generate_incident_summary, render_markdown_report, render_html_report
from sectoolkit.mitre import tag_alert_mitre, tag_alerts_mitre
from sectoolkit.purple_team import correlate_timeline, score_detection_coverage

__all__ = [
    "parse_port",
    "normalize_username",
    "is_private_ip",
    "safe_child",
    "redact_secrets",
    "sha256_file",
    "extract_iocs",
    "defang_indicator",
    "normalize_alert",
    "fingerprint",
    "priority_score",
    "triage_alerts",
    "stream_lines",
    "stream_json_lines",
    "batch_stream",
    "check_tcp",
    "subnet_hosts",
    "parse_suricata_eve",
    "summarize_top_talkers",
    "generate_manifest",
    "verify_manifest",
    "parse_iso_timestamp",
    "safe_exec",
    "EvidenceStore",
    "bounded_worker_pool",
    "EnrichmentCache",
    "enrich_ip",
    "YaraScanner",
    "calculate_entropy",
    "extract_strings",
    "generate_incident_summary",
    "render_markdown_report",
    "render_html_report",
    "tag_alert_mitre",
    "tag_alerts_mitre",
    "correlate_timeline",
    "score_detection_coverage",
]
