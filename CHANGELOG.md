# Changelog

All notable changes to `sectoolkit` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-11-24

### 🚀 Initial Release

**12 fully-implemented production-grade cybersecurity modules**, built for
Python 3.10+ and guided by *Python Scripting for Cybersecurity Professionals*.

### Added

#### Core Modules (`src/sectoolkit/`)
| Module | Key Exports |
|---|---|
| `validators.py` | `parse_port`, `normalize_username`, `is_private_ip` |
| `security.py` | `safe_child` (path traversal guard), `redact_secrets` |
| `ioc.py` | `sha256_file`, `extract_iocs`, `defang_indicator` |
| `triage.py` | `normalize_alert`, `fingerprint`, `priority_score`, `triage_alerts` |
| `log_stream.py` | `stream_lines`, `stream_json_lines`, `batch_stream` |
| `net_audit.py` | `check_tcp`, `subnet_hosts`, `parse_suricata_eve`, `summarize_top_talkers` |
| `forensics.py` | `generate_manifest`, `verify_manifest`, `parse_iso_timestamp`, `safe_exec` |
| `storage.py` | `EvidenceStore` (SQLite context manager), `bounded_worker_pool` |
| `enrichment.py` | `EnrichmentCache`, `enrich_ip` (SSRF-safe) |
| `scanner.py` | `calculate_entropy`, `extract_strings`, `YaraScanner` |
| `reporting.py` | `generate_incident_summary`, `render_markdown_report`, `render_html_report` |
| `cli.py` | 7 subcommands: `triage`, `manifest`, `ioc`, `audit-port`, `enrich`, `scan`, `report` |

#### Test Suite (`tests/`)
- **72 unit tests** across 13 test files — all passing
- Full edge-case coverage: path traversal, injection, encoding, boundary conditions, and end-to-end pipeline integration

#### Data Fixtures (`data/`)
- `sample_auth.log` — SSH brute-force authentication log
- `sample_eve.json` — Suricata `eve.json` NDJSON (SSH, Log4j, DNS, flow events)
- `sample_alerts.json` — Heterogeneous SIEM alerts (critical/high/low)
- `sample_rules.yar` — YARA rules: `Suspicious_Webshell`, `Suspicious_Powershell_Encoded`

#### Documentation (`docs/`)
- `MASTER_SECURITY_ENGINEERING_GUIDE.html` / `.md` — 12-module dark-theme engineering reference
- `ARCHITECTURE_AND_STUDY_GUIDE.html` / `.md` — Architecture overview with Mermaid diagrams

#### Examples (`examples/`)
- `full_pipeline_demo.py` — End-to-end pipeline: log streaming → IOC extraction →
  enrichment → SIEM triage → YARA scanning → SQLite persistence → HTML+MD reporting

### Security Design Principles
- No `shell=True` in subprocess calls
- Parameterized SQL queries throughout `EvidenceStore`
- Path containment via `safe_child()` for all file operations
- SSRF guard in `enrich_ip()` (blocks private/loopback ranges)
- `errors="replace"` on all file I/O to prevent encoding bombs

---

## [Unreleased] — CyberGun Integration (Phase 2)

### Added
- `mitre.py`: `tag_alert_mitre`, `tag_alerts_mitre` (MITRE ATT&CK tactic/technique tagging for alerts)
- `purple_team.py`: `correlate_timeline`, `score_detection_coverage` (Purple Team scenario-to-alert correlation and coverage scoring)
- `reporting.py`: Optional `coverage` integration and MITRE ATT&CK column in Markdown/HTML incident reports
- `cli.py`: Added `coverage` subcommand (`--window`, `--format json|md|html`, `-o`)

> Remaining planned work: External CyberGun repository wiring.
