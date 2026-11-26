"""End-to-End Demonstration Pipeline for sectoolkit.

Demonstrates:
1. Memory-safe log streaming from data/
2. IOC extraction and defanging
3. IP enrichment and SSRF boundary defense
4. SIEM alert triage, deduplication, and risk scoring
5. YARA static scanning and Shannon entropy calculation
6. Parameterized SQLite evidence database persistence
7. Automated generation of dark-theme HTML and Markdown incident reports
"""

import json
from pathlib import Path
import sys

# Ensure src/ is on python path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from sectoolkit.enrichment import EnrichmentCache, enrich_ip
from sectoolkit.forensics import generate_manifest
from sectoolkit.ioc import defang_indicator, extract_iocs
from sectoolkit.log_stream import stream_json_lines, stream_lines
from sectoolkit.reporting import generate_incident_summary, render_html_report, render_markdown_report
from sectoolkit.scanner import YaraScanner, calculate_entropy
from sectoolkit.storage import EvidenceStore
from sectoolkit.triage import triage_alerts


def main():
    print("=================================================================")
    print("   SECTOOLKIT — Production Security Automation Pipeline Demo    ")
    print("=================================================================\n")

    data_dir = BASE_DIR / "data"
    output_dir = BASE_DIR / "output"
    output_dir.mkdir(exist_ok=True)

    # 1. Log Streaming & Pattern Filtering
    print("[1] Streaming authentication logs (Memory-Safe Generator)...")
    auth_log = data_dir / "sample_auth.log"
    failed_attempts = list(stream_lines(auth_log, needle="Failed password"))
    print(f"    -> Found {len(failed_attempts)} failed authentication attempts in {auth_log.name}")

    # 2. IOC Extraction & Defanging
    print("\n[2] Extracting & defanging Indicators of Compromise (IOCs)...")
    combined_log_text = "\n".join(text for _, text in failed_attempts)
    extracted = extract_iocs(combined_log_text)
    defanged_ips = [defang_indicator(ip) for ip in extracted["ips"]]
    print(f"    -> Raw Extracted IPs: {extracted['ips']}")
    print(f"    -> Defanged Indicators: {defanged_ips}")

    # 3. Threat Intelligence Enrichment with Cache & SSRF Defense
    print("\n[3] Enriching discovered indicators (with local SQLite cache)...")
    cache_path = output_dir / "enrichment_cache.db"
    with EnrichmentCache(cache_path) as cache:
        for ip in extracted["ips"]:
            res = enrich_ip(ip, cache=cache, mock_reputation="malicious_bruteforce")
            status = "CACHED" if res["cached"] else "FRESH LOOKUP"
            print(f"    -> {res['indicator']} [{res['scope'].upper()}] - {res['reputation']} ({status})")

    # 4. SOC Triage, Deduplication & Priority Scoring
    print("\n[4] Ingesting and Triaging SIEM Alerts...")
    alerts_file = data_dir / "sample_alerts.json"
    raw_alerts = json.loads(alerts_file.read_text(encoding="utf-8"))
    triaged = triage_alerts(raw_alerts, min_priority=1.5)
    print(f"    -> Ingested {len(raw_alerts)} raw alerts. Deduplicated to {len(triaged)} distinct incidents:")
    for incident in triaged:
        print(f"       * [Score: {incident['priority_score']:.2f}] {incident['rule']} on {incident['hostname']} (Burst Count: {incident['count']})")

    # 5. YARA Signature Matching & Entropy Analysis
    print("\n[5] YARA Signature Detection & Shannon Entropy Analysis...")
    yara_rules_file = data_dir / "sample_rules.yar"
    scanner = YaraScanner(rule_file=yara_rules_file)
    test_payload = b"<?php system($_GET['cmd']); ?>"
    matches = scanner.scan_data(test_payload)
    entropy = calculate_entropy(test_payload)
    print(f"    -> Simulated Payload Entropy: {entropy:.4f} (Under 7.0 = uncompressed)")
    print(f"    -> YARA Matches: {[m['rule'] for m in matches]}")

    # 6. Parameterized SQLite Evidence Store
    print("\n[6] Storing incidents & indicators in Parameterized EvidenceStore...")
    db_path = output_dir / "evidence_store.db"
    with EvidenceStore(db_path) as store:
        for inc in triaged:
            store.add_alert(inc)
        for ip in extracted["ips"]:
            store.add_indicator(ip, "ipv4", source="sample_auth.log")
        stored_alerts = store.get_alerts(min_priority=2.0)
        stored_indicators = store.get_indicators()
        print(f"    -> Database verified: {len(stored_alerts)} high-priority alerts, {len(stored_indicators)} indicators persisted.")

    # 7. Forensic Manifest & Case Reporting
    print("\n[7] Generating Executive Case Reports...")
    manifest = generate_manifest(data_dir)
    summary = generate_incident_summary(triaged, extracted_iocs=extracted, manifest=manifest, case_id="CASE-2026-ALPHA")

    md_report_path = output_dir / "INCIDENT_REPORT.md"
    html_report_path = output_dir / "INCIDENT_REPORT.html"

    md_report_path.write_text(render_markdown_report(summary), encoding="utf-8")
    html_report_path.write_text(render_html_report(summary, dark_mode=True), encoding="utf-8")

    print(f"    -> Executive Markdown Report: {md_report_path}")
    print(f"    -> Interactive Dark HTML Report: {html_report_path}")

    print("\n=================================================================")
    print("   [+] DEMO COMPLETE: All sectoolkit pipelines executed 100%     ")
    print("=================================================================\n")


if __name__ == "__main__":
    main()
