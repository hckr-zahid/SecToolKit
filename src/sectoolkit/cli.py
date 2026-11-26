"""Command-line interface for sectoolkit security automation."""

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from sectoolkit.enrichment import enrich_ip
from sectoolkit.forensics import generate_manifest
from sectoolkit.ioc import extract_iocs
from sectoolkit.net_audit import check_tcp
from sectoolkit.reporting import generate_incident_summary, render_html_report, render_markdown_report
from sectoolkit.mitre import tag_alerts_mitre
from sectoolkit.purple_team import correlate_timeline, score_detection_coverage
from sectoolkit.scanner import YaraScanner
from sectoolkit.triage import triage_alerts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sectoolkit",
        description="Modular Security Engineering and SOC Automation Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # triage command
    triage_cmd = subparsers.add_parser("triage", help="Triage, deduplicate, and score SIEM alerts")
    triage_cmd.add_argument("file", help="Path to JSON file containing raw alerts list")
    triage_cmd.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum priority score threshold (default: 0.0)",
    )

    # manifest command
    manifest_cmd = subparsers.add_parser("manifest", help="Generate forensic SHA-256 evidence manifest")
    manifest_cmd.add_argument("directory", help="Target evidence directory")
    manifest_cmd.add_argument("-o", "--output", help="Optional path to write JSON manifest to")

    # ioc command
    ioc_cmd = subparsers.add_parser("ioc", help="Extract and categorize IOCs (IPs, SHA256, MD5)")
    ioc_cmd.add_argument("input", help="Raw text string or path to text file")

    # audit-port command
    port_cmd = subparsers.add_parser("audit-port", help="Audit TCP port connectivity on authorized target")
    port_cmd.add_argument("host", help="Target hostname or IP")
    port_cmd.add_argument("port", type=int, help="Target port number (1-65535)")
    port_cmd.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds")

    # enrich command
    enrich_cmd = subparsers.add_parser("enrich", help="Enrich IP with threat intelligence and ASN scope")
    enrich_cmd.add_argument("ip", help="Target IP address")

    # scan command
    scan_cmd = subparsers.add_parser("scan", help="Scan file with YARA signature rule")
    scan_cmd.add_argument("target", help="File path to scan")
    scan_cmd.add_argument("--rule-source", help="Inline YARA rule string")

    # report command
    report_cmd = subparsers.add_parser("report", help="Generate Markdown or HTML incident case report")
    report_cmd.add_argument("alerts_file", help="Path to JSON file containing triaged alerts")
    report_cmd.add_argument("--format", choices=["md", "html"], default="md", help="Output format (default: md)")
    report_cmd.add_argument("-o", "--output", help="Path to write generated report to")

    # coverage command
    cov_cmd = subparsers.add_parser(
        "coverage",
        help="Correlate Purple Team scenarios against alerts and score MITRE ATT&CK coverage",
    )
    cov_cmd.add_argument("scenarios_file", help="Path to JSON file containing expected scenarios")
    cov_cmd.add_argument("alerts_file", help="Path to JSON file containing observed alerts")
    cov_cmd.add_argument("--window", type=float, default=300.0, help="Correlation time window in seconds (default: 300)")
    cov_cmd.add_argument("--format", choices=["json", "md", "html"], default="json", help="Output format (default: json)")
    cov_cmd.add_argument("-o", "--output", help="Optional path to write output to")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "triage":
        path = Path(args.file)
        if not path.is_file():
            print(f"Error: File not found: {path}", file=sys.stderr)
            return 1
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                print("Error: Alerts JSON must contain a list of alert objects", file=sys.stderr)
                return 1
            results = triage_alerts(data, min_priority=args.min_score)
            print(json.dumps(results, indent=2))
            return 0
        except Exception as exc:
            print(f"Error triaging alerts: {exc}", file=sys.stderr)
            return 1

    elif args.command == "manifest":
        try:
            manifest = generate_manifest(args.directory)
            manifest_json = json.dumps(manifest, indent=2)
            if args.output:
                Path(args.output).write_text(manifest_json, encoding="utf-8")
                print(f"Manifest written to {args.output} ({len(manifest)} files)")
            else:
                print(manifest_json)
            return 0
        except Exception as exc:
            print(f"Error generating manifest: {exc}", file=sys.stderr)
            return 1

    elif args.command == "ioc":
        candidate_path = Path(args.input)
        if candidate_path.is_file():
            text = candidate_path.read_text(encoding="utf-8", errors="replace")
        else:
            text = args.input
        iocs = extract_iocs(text)
        print(json.dumps(iocs, indent=2))
        return 0

    elif args.command == "audit-port":
        try:
            is_open = check_tcp(args.host, args.port, timeout=args.timeout)
            status = "OPEN" if is_open else "CLOSED/FILTERED"
            print(f"Target: {args.host}:{args.port} -> {status}")
            return 0 if is_open else 2
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    elif args.command == "enrich":
        try:
            enriched = enrich_ip(args.ip)
            print(json.dumps(enriched, indent=2))
            return 0
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    elif args.command == "scan":
        target_path = Path(args.target)
        if not target_path.is_file():
            print(f"Error: Target file not found: {target_path}", file=sys.stderr)
            return 1
        rule = args.rule_source or """
            rule Suspicious_Keywords {
                strings:
                    $s1 = "malware" nocase
                    $s2 = "eval(" nocase
                    $s3 = "passthru" nocase
                condition:
                    any of them
            }
        """
        try:
            scanner = YaraScanner(rule_source=rule)
            matches = scanner.scan_file(target_path)
            print(json.dumps(matches, indent=2))
            return 0 if len(matches) == 0 else 2
        except Exception as exc:
            print(f"Scan error: {exc}", file=sys.stderr)
            return 1

    elif args.command == "report":
        path = Path(args.alerts_file)
        if not path.is_file():
            print(f"Error: File not found: {path}", file=sys.stderr)
            return 1
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            alerts = triage_alerts(raw)
            summary = generate_incident_summary(alerts)
            if args.format == "html":
                report_text = render_html_report(summary, dark_mode=True)
            else:
                report_text = render_markdown_report(summary)

            if args.output:
                Path(args.output).write_text(report_text, encoding="utf-8")
                print(f"Report written to {args.output}")
            else:
                print(report_text)
            return 0
        except Exception as exc:
            print(f"Report error: {exc}", file=sys.stderr)
            return 1

    elif args.command == "coverage":
        scenarios_path = Path(args.scenarios_file)
        alerts_path = Path(args.alerts_file)
        if not scenarios_path.is_file():
            print(f"Error: Scenarios file not found: {scenarios_path}", file=sys.stderr)
            return 1
        if not alerts_path.is_file():
            print(f"Error: Alerts file not found: {alerts_path}", file=sys.stderr)
            return 1
        try:
            scenarios = json.loads(scenarios_path.read_text(encoding="utf-8"))
            raw_alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
            triaged = tag_alerts_mitre(triage_alerts(raw_alerts))
            correlation = correlate_timeline(scenarios, triaged, time_window_seconds=args.window)
            coverage = score_detection_coverage(correlation)

            if args.format == "json":
                out_text = json.dumps(coverage, indent=2)
            else:
                summary = generate_incident_summary(triaged, case_id="PT-COVERAGE", coverage=coverage)
                out_text = (
                    render_html_report(summary, dark_mode=True)
                    if args.format == "html"
                    else render_markdown_report(summary)
                )

            if args.output:
                Path(args.output).write_text(out_text, encoding="utf-8")
                print(f"Coverage output written to {args.output}")
            else:
                print(out_text)
            return 0
        except Exception as exc:
            print(f"Coverage error: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
