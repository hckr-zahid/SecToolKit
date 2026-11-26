# Security Toolkit (`sectoolkit`)

A modular, production-grade security engineering and automation toolkit built following defensive Python principles from *Python Scripting for Cybersecurity Professionals*.

## Directory Structure
- `src/sectoolkit/`: Core modules, security domains, and utilities.
- `tests/`: Automated test suite (`unittest`).
- `data/`: Sanitized sample logs and test fixtures.
- `output/`: Generated reports, manifests, and database artifacts.
- `docs/`: Master security engineering documentation, architecture guides, and bug bounty playbooks (`MASTER_SECURITY_ENGINEERING_GUIDE`, `ARCHITECTURE_AND_STUDY_GUIDE`, `WEB_BUG_BOUNTY_PENTEST_GUIDE`, `COMPASS_BUG_BOUNTY_PLAYBOOK`).

## Completed Modules

- [x] **Module 1: Boundary Validators & Normalization** (`src/sectoolkit/validators.py`)
- [x] **Module 2: Path Traversal & Secret Redaction** (`src/sectoolkit/security.py`)
- [x] **Module 3: Threat Intel & IOC Processing** (`src/sectoolkit/ioc.py`)
- [x] **Module 4: SOC Triage & Alert Normalization** (`src/sectoolkit/triage.py`)
- [x] **Module 5: Large Datasets & Log Streaming** (`src/sectoolkit/log_stream.py`)
- [x] **Module 6: Network & Web Telemetry** (`src/sectoolkit/net_audit.py`)
- [x] **Module 7: Digital Forensics & Safe Execution** (`src/sectoolkit/forensics.py`)
- [x] **Module 8: Parameterized SQLite & Concurrency** (`src/sectoolkit/storage.py`)
- [x] **Module 9: Central CLI & Packaging** (`src/sectoolkit/cli.py` & `pyproject.toml`)
- [x] **Module 10: Threat Intel Enrichment & Caching** (`src/sectoolkit/enrichment.py`)
- [x] **Module 11: YARA & File Pattern Scanning** (`src/sectoolkit/scanner.py`)
- [x] **Module 12: Automated Case Report Generator** (`src/sectoolkit/reporting.py`)
- [x] **Module 13: MITRE ATT&CK Alert Tagging** (`src/sectoolkit/mitre.py`)
- [x] **Module 14: Purple Team Timeline & Coverage Scoring** (`src/sectoolkit/purple_team.py`)

## Running Tests
```bash
PYTHONPATH=src .venv/bin/python3 -m unittest discover -s tests -p "test_*.py" -v
```

## CLI Usage
Install locally in editable mode:
```bash
.venv/bin/pip install --no-build-isolation -e .
```
Commands:
```bash
sectoolkit triage sample_alerts.json --min-score 2.0
sectoolkit manifest /path/to/evidence -o manifest.json
sectoolkit ioc "Suspicious connection to 192.168.1.100"
sectoolkit audit-port 192.168.1.1 443
sectoolkit enrich 10.0.0.1
sectoolkit scan suspicious_file.bin
sectoolkit report sample_alerts.json --format html -o case_report.html
sectoolkit coverage scenarios.json sample_alerts.json --format md -o coverage.md
```
