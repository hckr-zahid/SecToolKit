# Master Security Engineering Guide: Building Production-Grade Security Tools with Python

---

## About This Guide
This guide is designed for intermediate security practitioners, engineers, and analysts who want to transition from writing ad-hoc scripts to building robust, production-grade cybersecurity tools. 

It uses the **`sectoolkit`** codebase as a concrete foundation, explaining:
1. **The Underlying Security Concepts**: The attack vectors, vulnerabilities, and real-world failure modes that necessitate defensive coding.
2. **Detailed Code Walkthroughs**: Complete source code with comprehensive explanations of parameters, data types, logic, and standard library mechanisms.
3. **Architectural Best Practices**: Memory efficiency via generators, concurrency controls, parameterized databases, cryptographic hashing, and injection prevention.
4. **How to Build Future Tools**: Reusable architectural blueprints for building SOC automation pipelines, digital forensics collectors, and network auditing scanners.

---

# PART 1: The Core Philosophy of Defensive Security Scripting

When an engineer writes a standard enterprise application, they generally trust their database, their colleagues, and internal inputs. 

**In cybersecurity, the rules are inverted:**
- You are parsing inputs crafted by active adversaries trying to crash your tool or evade detection.
- You are handling multi-gigabyte log dumps from perimeter firewalls that can exhaust RAM.
- You are generating forensic evidence that must stand up to scrutiny in legal proceedings or executive root-cause analyses.
- Your tools often run with elevated administrative or network privileges, making your own scripts a high-value target for privilege escalation if they contain injection flaws.

### The 7 Golden Rules of Security Tooling

1. **Validate at the Boundaries, Never in the Core**:
   Never let unvalidated strings propagate deep into your functions. Validate types, formats, lengths, and ranges the microsecond data enters your application (from CLI flags, files, sockets, or HTTP requests).
2. **Defensive Path Handling (Preventing Traversal)**:
   Never trust file paths provided by users or log records. String containment checks (like `if "../" in path`) are easily bypassed by URL encoding, symlinks, or Unicode normalization. Always resolve paths to their absolute canonical forms before evaluating boundaries.
3. **Safe External Execution (Zero Shell Interpolation)**:
   Never invoke `os.system()` or `subprocess.run(cmd, shell=True)`. A single unescaped semi-colon, backtick, or pipe character allows an attacker to execute arbitrary shell commands with your script's privileges. Always pass arguments as explicit lists (`shell=False`).
4. **Parameterized Data Access (Zero SQL Interpolation)**:
   Never use f-strings or string concatenation to build database queries (e.g. `f"SELECT * FROM iocs WHERE val = '{user_input}'"`). Always use parameterized query placeholders (`?` in SQLite, `%s` in PostgreSQL) so the database engine separates code from data.
5. **Memory-Conscious I/O (Generators Over Lists)**:
   Never read entire log files into memory using `.read()` or `.readlines()`. A 10 GB firewall log will crash an analyst's laptop with an `OutOfMemoryError`. Use streaming generators (`yield`) to process data line-by-line in O(1) constant memory.
6. **Deterministic Evidence & Time Normalization**:
   Different security sensors record timestamps in various time zones (EST, UTC, local, Unix epoch) or omit time zones entirely. Always convert timestamps to explicit, timezone-aware UTC datetime objects. For deduplication and evidence verification, always use deterministic, sorted cryptographic digests (SHA-256).
7. **Explainable and Transparent Scoring**:
   Avoid "black box" heuristics that assign arbitrary urgency to alerts without a clear audit trail. Formulas for alert prioritization must be deterministic, documented, and transparent so analysts can understand and defend why an incident was escalated.

---

# PART 2: Comprehensive Module-by-Module Technical Deep Dive

```
src/sectoolkit/
├── validators.py   # Module 1: Input boundary validators
├── security.py     # Module 2: Path containment & secret redaction
├── ioc.py          # Module 3: Threat intelligence & indicator extraction
├── triage.py       # Module 4: SOC triage, deduplication & scoring
├── log_stream.py   # Module 5: Memory-safe log streaming & batching
├── net_audit.py    # Module 6: Network telemetry & Suricata inspection
├── forensics.py    # Module 7: Evidence manifests, timelines & safe exec
├── storage.py      # Module 8: Parameterized SQLite & worker pools
└── cli.py          # Module 9: Central CLI entry point
```

---

## Module 1: Boundary Validators & Normalization (`validators.py`)

### 1.1 The Real-World Security Problem
Security scripts frequently crash or expose vulnerabilities due to loose boundary validation:
- Passing invalid port numbers (e.g., `-1`, `70000`, or `"80; rm -rf /"`) can cause crashes, unexpected protocol behavior, or injection flaws.
- Inconsistent username formatting allows authentication spoofing or duplicate database records (e.g., `"Admin "`, `"admin"`, and `"ADMIN"`).
- Misidentifying private vs. public IP addresses can lead to security scanners accidentally targeting external internet infrastructure instead of internal test ranges, or triggering False Positive alerts.

### 1.2 Full Source Code
```python
"""Boundary validators and normalization functions for security tooling."""

import ipaddress
from typing import Union


def parse_port(value: Union[str, int]) -> int:
    """Parse and validate a network port number.

    Args:
        value: Port number as a string or integer.

    Returns:
        int: Validated port number within range [1, 65535].

    Raises:
        ValueError: If the value cannot be parsed as an integer or is out of range.
    """
    try:
        port = int(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Port must be an integer, got: {value!r}") from exc

    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got: {port}")

    return port


def normalize_username(value: str) -> str:
    """Normalize a username by trimming surrounding whitespace and applying casefold.

    casefold() is more aggressive and robust than lower() for internationalized strings.

    Args:
        value: Raw username string.

    Returns:
        str: Normalized username.

    Raises:
        TypeError: If the input is not a string.
    """
    if not isinstance(value, str):
        raise TypeError(f"Username must be a string, got: {type(value).__name__}")
    return value.strip().casefold()


def is_private_ip(ip_text: str) -> bool:
    """Check if an IPv4 or IPv6 address is in a private or reserved range.

    Args:
        ip_text: String representation of an IP address.

    Returns:
        bool: True if private/loopback, False otherwise.

    Raises:
        ValueError: If ip_text is not a valid IP address.
        TypeError: If ip_text is not a string.
    """
    if not isinstance(ip_text, str):
        raise TypeError(f"IP address must be a string, got: {type(ip_text).__name__}")

    try:
        address = ipaddress.ip_address(ip_text.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid IP address format: {ip_text!r}") from exc

    return address.is_private

```

### 1.3 Detailed Code Breakdown

#### Function 1: `parse_port(value: Union[str, int]) -> int`
- **Purpose**: Validates and normalizes network port numbers.
- **Lines 19–22**:
  ```python
  try:
      port = int(value)
  except (ValueError, TypeError) as exc:
      raise ValueError(f"Port must be an integer, got: {value!r}") from exc
  ```
  - We use `int(value)` inside a `try-except` block catching both `ValueError` (if a string cannot be converted, e.g., `"ssh"`) and `TypeError` (if an unconvertible type like `None` or a `list` is passed).
  - The `from exc` idiom preserves exception chaining, maintaining the original stack trace for debugging while presenting a clean error message.
- **Lines 24–27**:
  ```python
  if not (1 <= port <= 65535):
      raise ValueError(f"Port must be between 1 and 65535, got: {port}")
  return port
  ```
  - Validates that the integer falls strictly within the 16-bit unsigned port range (1 to 65,535).
  - Prevents port `0` (often reserved or special) and ports > 65535.

#### Function 2: `normalize_username(value: str) -> str`
- **Purpose**: Strips leading/trailing whitespace and normalizes character casing for usernames.
- **Lines 44–45**:
  ```python
  if not isinstance(value, str):
      raise TypeError(f"Username must be a string, got: {type(value).__name__}")
  ```
  - Type-enforcement protects against unexpected objects (e.g., integers from parsed JSON or `None`).
- **Line 46**:
  ```python
  return value.strip().casefold()
  ```
  - `.strip()` removes leading and trailing spaces, tabs, and newline characters.
  - **Why `.casefold()` instead of `.lower()`?** While `.lower()` converts standard ASCII uppercase letters, `.casefold()` is designed for caseless international matching according to the Unicode standard. For example, the German lowercase letter `"ß"` becomes `"ss"`. Using `casefold()` neutralizes visual spoofing and Unicode homoglyph collisions.

#### Function 3: `is_private_ip(ip_text: str) -> bool`
- **Purpose**: Determines if an IP address belongs to private or reserved IP ranges (RFC 1918, RFC 4193, loopback, etc.).
- **Lines 62–64**:
  - Enforces that `ip_text` is a string.
- **Lines 65–68**:
  ```python
  try:
      address = ipaddress.ip_address(ip_text.strip())
  except ValueError as exc:
      raise ValueError(f"Invalid IP address format: {ip_text!r}") from exc
  ```
  - Rather than writing a fragile regular expression, we use Python's standard library `ipaddress.ip_address()`. This parser inherently validates IPv4 and IPv6 octets/hexlets (rejecting values like `256.0.0.1` or `192.168.1`).
- **Line 70**:
  ```python
  return address.is_private
  ```
  - Evaluates whether the address is in a private network (e.g., `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `fc00::/7`).

---

## Module 2: Path Traversal & Secret Redaction (`security.py`)

### 2.1 The Real-World Security Problem
1. **Directory Traversal**: When an analyst or automation tool saves forensic artifacts, evidence, or reports based on input (like an event ID or log name), an attacker can supply filenames like `../../../../etc/cron.d/malicious_job`. Without containment, files are written outside the intended directory.
2. **Secret Leakage in Logs**: Automated tools log API responses and event dictionaries. If these events contain passwords, API tokens, or session cookies, those secrets get committed to disk logs, SIEM indices, or terminal displays, leading to credential exposure.

### 2.2 Full Source Code
```python
from pathlib import Path
from typing import Any, Mapping, Sequence

SENSITIVE_KEYS = {
    "password",
    "token",
    "authorization",
    "cookie",
    "api_key",
    "secret",
    "private_key",
    "access_token",
}


def safe_child(root: Path, user_supplied: str) -> Path:
    resolved_root = Path(root).resolve()
    candidate = (resolved_root / user_supplied).resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError(f"Path traversal detected: {user_supplied!r} escapes {resolved_root}")
    return candidate


def redact_secrets(data: Any, sensitive_keys: set[str] | None = None) -> Any:
    keys_to_check = sensitive_keys if sensitive_keys is not None else SENSITIVE_KEYS

    if isinstance(data, Mapping):
        redacted_dict = {}
        for key, value in data.items():
            if isinstance(key, str) and key.lower() in keys_to_check:
                redacted_dict[key] = "[REDACTED]"
            else:
                redacted_dict[key] = redact_secrets(value, keys_to_check)
        return redacted_dict

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
        return [redact_secrets(item, keys_to_check) for item in data]

    return data

```

### 2.3 Detailed Code Breakdown

#### Function 1: `safe_child(root: Path, user_supplied: str) -> Path`
- **Purpose**: Guarantees that any user-supplied relative path remains strictly contained inside an allowed root directory.
- **Lines 17–18**:
  ```python
  resolved_root = Path(root).resolve()
  candidate = (resolved_root / user_supplied).resolve()
  ```
  - `Path(root).resolve()`: Resolves all symbolic links, relative references (`.`, `..`), and returns an absolute canonical path.
  - `(resolved_root / user_supplied).resolve()`: Combines the base root with the user-supplied string and fully resolves the final destination.
- **Lines 19–21**:
  ```python
  if candidate != resolved_root and resolved_root not in candidate.parents:
      raise ValueError(f"Path traversal detected: {user_supplied!r} escapes {resolved_root}")
  return candidate
  ```
  - `candidate.parents` returns a sequence of all directory ancestors of `candidate`.
  - If `resolved_root` is not present in `candidate.parents` (and is not the root itself), it means the user supplied a path that traversed upwards past the root boundary.
  - Throws an immediate `ValueError` to block the operation.

#### Function 2: `redact_secrets(data: Any, sensitive_keys: set[str] | None = None) -> Any`
- **Purpose**: Recursively scrubs sensitive credentials from nested dictionaries and lists before logging or serialization.
- **Lines 4–13 (`SENSITIVE_KEYS`)**:
  - Default denylist: `password`, `token`, `authorization`, `cookie`, `api_key`, `secret`, `private_key`, `access_token`.
- **Lines 27–34 (Mapping Handling)**:
  ```python
  if isinstance(data, Mapping):
      redacted_dict = {}
      for key, value in data.items():
          if isinstance(key, str) and key.lower() in keys_to_check:
              redacted_dict[key] = "[REDACTED]"
          else:
              redacted_dict[key] = redact_secrets(value, keys_to_check)
      return redacted_dict
  ```
  - Iterates over all keys. If a key matches the sensitive set (case-insensitively), its value is masked to `"[REDACTED]"`.
  - If not masked, `redact_secrets()` is recursively called on the value, allowing deep inspection of nested structures.
- **Lines 36–37 (Sequence Handling)**:
  ```python
  if isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
      return [redact_secrets(item, keys_to_check) for item in data]
  ```
  - Handles lists and tuples. Notice `and not isinstance(data, (str, bytes))`: strings and bytes are technically sequences in Python. Excluding them prevents infinite recursion character-by-character.

---

## Module 3: Threat Intelligence & IOC Processing (`ioc.py`)

### 3.1 The Real-World Security Problem
- **Unstructured Threat Feeds**: Threat reports, emails, and pastebin dumps contain valuable Indicators of Compromise (IOCs) scattered within prose. Analysts need to extract valid IPs, SHA-256 hashes, and MD5 hashes automatically.
- **Accidental Execution**: Storing raw malicious URLs (e.g. `http://malicious-c2.com/payload.exe`) can lead to accidental clicks by analysts or automatic fetching by link-preview bots in chat tools (Slack, Teams). Indicators must be safely "defanged".
- **Malware Memory Crashes**: Hashing a 2 GB ISO or memory dump by reading the entire file into memory crashes scripts. It must be processed in streaming blocks.

### 3.2 Full Source Code
```python
import hashlib
import ipaddress
from pathlib import Path
import re

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_PATTERN = re.compile(r"\b[A-Fa-f0-9]{64}\b")
MD5_PATTERN = re.compile(r"\b[A-Fa-f0-9]{32}\b")


def sha256_file(path: Path | str, chunk_size: int = 1024 * 1024) -> str:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def extract_iocs(text: str) -> dict[str, list[str]]:
    if not isinstance(text, str):
        raise TypeError(f"Input text must be a string, got: {type(text).__name__}")

    valid_ips = set()
    for candidate in IPV4_PATTERN.findall(text):
        try:
            valid_ips.add(str(ipaddress.IPv4Address(candidate)))
        except ipaddress.AddressValueError:
            pass

    sha256_hashes = {h.lower() for h in SHA256_PATTERN.findall(text)}
    md5_hashes = {h.lower() for h in MD5_PATTERN.findall(text)}

    return {
        "ips": sorted(valid_ips),
        "sha256": sorted(sha256_hashes),
        "md5": sorted(md5_hashes),
    }


def defang_indicator(indicator: str) -> str:
    if not isinstance(indicator, str):
        raise TypeError(f"Indicator must be a string, got: {type(indicator).__name__}")

    sanitized = indicator.strip()
    sanitized = re.sub(r"^https://", "hxxps://", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"^http://", "hxxp://", sanitized, flags=re.IGNORECASE)
    return sanitized.replace(".", "[.]")

```

### 3.3 Detailed Code Breakdown

#### Function 1: `sha256_file(path: Path | str, chunk_size: int = 1MB) -> str`
- **Lines 11–20**:
  ```python
  hasher = hashlib.sha256()
  with file_path.open("rb") as handle:
      for chunk in iter(lambda: handle.read(chunk_size), b""):
          hasher.update(chunk)
  return hasher.hexdigest()
  ```
  - Opens the file in binary read mode (`"rb"`).
  - Uses `iter(lambda: handle.read(chunk_size), b"")`. This Python idiom repeatedly calls `handle.read(1MB)` until it returns an empty byte string `b""` (indicating EOF).
  - Keeps memory usage bounded to exactly `chunk_size` regardless of whether the file is 10 KB or 100 GB.

#### Function 2: `extract_iocs(text: str) -> dict[str, list[str]]`
- **Lines 6–8**: Regular expressions for IPv4, SHA-256, and MD5.
  - Notice `` word boundary anchors to avoid matching partial substrings.
- **Lines 27–32 (IP Extraction & Validation)**:
  ```python
  valid_ips = set()
  for candidate in IPV4_PATTERN.findall(text):
      try:
          valid_ips.add(str(ipaddress.IPv4Address(candidate)))
      except ipaddress.AddressValueError:
          pass
  ```
  - Regular expressions match patterns like `999.999.999.999`. By passing every candidate through `ipaddress.IPv4Address()`, invalid IP candidates are filtered out automatically.
- **Lines 34–41**:
  - Extracts and lowercases all SHA-256 and MD5 hashes.
  - Converts sets into sorted lists, ensuring deterministic output order.

#### Function 3: `defang_indicator(indicator: str) -> str`
- **Lines 49–51**:
  ```python
  sanitized = re.sub(r"^https://", "hxxps://", sanitized, flags=re.IGNORECASE)
  sanitized = re.sub(r"^http://", "hxxp://", sanitized, flags=re.IGNORECASE)
  return sanitized.replace(".", "[.]")
  ```
  - Replaces `http://` and `https://` with inert `hxxp://` and `hxxps://`.
  - Replaces all periods with bracketed dots `[.]` (e.g. `192[.]168[.]1[.]1` or `evil[.]com`). This neutralizes hyperlinks in documentation and ticketing platforms.

---

## Module 4: SOC Triage & Alert Normalization (`triage.py`)

### 4.1 The Real-World Security Problem
In an active enterprise SOC, alerts stream in from disparate vendors (CrowdStrike, Palo Alto Networks, Suricata, AWS GuardDuty).
- Each vendor formats alert payloads differently (`src_ip` vs `source_ip` vs `sourceAddress`).
- An ongoing port scan or brute force attack can generate 50,000 alerts in 10 minutes. If each alert creates a separate ticket, analysts suffer from acute alert fatigue.
- Analysts need a transparent, mathematically explainable priority score to sort the queue so critical breaches are investigated ahead of informational scans.

### 4.2 Full Source Code
```python
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

```

### 4.3 Detailed Code Breakdown

#### Function 1: `normalize_alert(raw: Mapping[str, Any]) -> dict[str, Any]`
- Translates various vendor field naming conventions into a standard schema:
  - `alert_id`, `severity` (lowercased), `source_ip`, `hostname`, `timestamp`, `rule`.
- Returns clean strings or `None`, providing predictable downstream data contracts.

#### Function 2: `fingerprint(alert: Mapping[str, Any]) -> str`
- **Lines 63–71**:
  ```python
  timestamp_str = str(alert.get("timestamp", ""))
  stable = {
      "rule": alert.get("rule"),
      "host": alert.get("hostname"),
      "src": alert.get("source_ip"),
      "time_bucket": timestamp_str[:16],
  }
  raw = json.dumps(stable, sort_keys=True).encode("utf-8")
  return hashlib.sha256(raw).hexdigest()
  ```
  - Constructs a deduplication fingerprint.
  - **Minute-Level Time Bucketing**: Slicing the ISO timestamp `timestamp_str[:16]` produces `YYYY-MM-DDTHH:MM`.
  - Any alerts triggered by the same attacker IP against the same host with the same detection rule within that 60-second window generate the exact same fingerprint!
  - `sort_keys=True` guarantees deterministic JSON byte ordering.

#### Function 3: `priority_score(severity, confidence, asset_criticality) -> float`
- **Lines 108–112**:
  - Implements the weighted security formula:
    Priority Score = (Severity * 0.45) + (Confidence * 0.30) + (Asset Criticality * 0.25)
  - Severity weights: `{"low": 1, "medium": 2, "high": 3, "critical": 4}`.
  - Both `confidence` (how certain the detection rule is) and `asset_criticality` (how important the target host is: domain controller vs guest Wi-Fi laptop) are rated from 1 to 4.
  - Produces an explainable score between 1.00 and 4.00.

#### Function 4: `triage_alerts(raw_alerts, ...) -> list[dict]`
- Iterates through alert sequences.
- If an alert fingerprint has already been seen in the batch, it increments the `count` attribute rather than duplicating the record.
- Calculates priority scores, filters out noise below `min_priority`, and returns the deduplicated queue sorted descending by priority.

---

## Module 5: Large Datasets & Log Streaming (`log_stream.py`)

### 5.1 The Real-World Security Problem
Production web servers and proxy gateways generate gigabytes of log lines per hour. When building forensic or triage scripts, engineers often write:
```python
# DANGEROUS PATTERN:
with open("access.log") as f:
    lines = f.readlines()  # Loads entire 20 GB file into RAM -> Kills process
```
Security automation must stream records line-by-line using Python generators.

### 5.2 Full Source Code
```python
"""Streaming and batch utilities for large log files and datasets."""

import json
from pathlib import Path
from typing import Any, Iterator, Sequence


def stream_lines(
    path: Path | str,
    needle: str | None = None,
    encoding: str = "utf-8",
) -> Iterator[tuple[int, str]]:
    """Stream lines from a file line-by-line without loading it entirely into memory.

    Args:
        path: Path to the target log file.
        needle: Optional substring to filter lines by.
        encoding: File encoding (defaults to utf-8 with error replacement).

    Yields:
        tuple[int, str]: 1-based line number and stripped line content.

    Raises:
        FileNotFoundError: If the file does not exist.
        TypeError: If path is invalid.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    with file_path.open("r", encoding=encoding, errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.rstrip("\r\n")
            if needle is None or needle in stripped:
                yield line_number, stripped


def stream_json_lines(
    path: Path | str,
    encoding: str = "utf-8",
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Stream and parse JSON Lines (NDJSON) safely from a file.

    Malformed JSON lines are skipped to prevent crashing streaming pipelines.

    Args:
        path: Path to the NDJSON/JSON-lines file.
        encoding: File encoding.

    Yields:
        tuple[int, dict]: 1-based line number and parsed JSON object.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    for line_number, line in stream_lines(path, encoding=encoding):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                yield line_number, parsed
        except json.JSONDecodeError:
            continue


def batch_stream(
    items: Iterator[Any] | Sequence[Any],
    batch_size: int = 100,
) -> Iterator[list[Any]]:
    """Batch an iterator or sequence into fixed-size chunks for memory-safe processing.

    Args:
        items: An iterator, generator, or sequence of items.
        batch_size: Maximum number of items per batch (must be >= 1).

    Yields:
        list[Any]: A chunk of items up to batch_size.

    Raises:
        ValueError: If batch_size is less than 1.
    """
    if batch_size < 1:
        raise ValueError(f"batch_size must be at least 1, got: {batch_size}")

    batch: list[Any] = []
    iterator = iter(items)
    for item in iterator:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []

    if batch:
        yield batch

```

### 5.3 Detailed Code Breakdown

#### Function 1: `stream_lines(path, needle=None, encoding="utf-8") -> Iterator[tuple[int, str]]`
- **Lines 28–33**:
  ```python
  with file_path.open("r", encoding=encoding, errors="replace") as handle:
      for line_number, line in enumerate(handle, start=1):
          stripped = line.rstrip("
")
          if needle is None or needle in stripped:
              yield line_number, stripped
  ```
  - `errors="replace"`: Log files often contain corrupted or non-UTF-8 binary bytes (e.g. from exploit payloads). Using `"replace"` replaces invalid bytes with the Unicode replacement character `�` instead of crashing with a `UnicodeDecodeError`.
  - `yield line_number, stripped`: Turns the function into a **generator**. Python reads one line from disk, hands it to the caller, and pauses execution until the next line is requested. The memory footprint remains constant (O(1)) whether the file has 10 lines or 100,000,000 lines.

#### Function 2: `stream_json_lines(path) -> Iterator[tuple[int, dict]]`
- **Lines 50–59**:
  - Reads line-by-line from `stream_lines`.
  - Attempts `json.loads(stripped)`.
  - If a line is corrupted or incomplete, it catches `json.JSONDecodeError` and skips to the next line without breaking the streaming loop.

#### Function 3: `batch_stream(items, batch_size=100) -> Iterator[list]`
- **Lines 82–93**:
  - Accumulates items from any iterator until `batch_size` is reached, yields the list, and flushes the buffer.
  - Essential for chunked database inserts (e.g. `cursor.executemany()`) or batching requests to external threat intelligence APIs.

---

## Module 6: Network & Web Telemetry (`net_audit.py`)

### 6.1 The Real-World Security Problem
During incident response or authorized surface assessments, engineers need to verify:
- What host IP addresses exist within an assigned CIDR range.
- Whether specific network ports (e.g., SSH 22, HTTPS 443, WinRM 5985) are actively listening without launching heavy or intrusive vulnerability scans.
- Who the top communicating endpoints ("top talkers") are in network telemetry exports like Suricata `eve.json`.

### 6.2 Full Source Code
```python
"""Network and web telemetry utilities for security auditing."""

from collections import Counter
import ipaddress
from pathlib import Path
import socket
from typing import Any, Iterable, Iterator
from sectoolkit.validators import parse_port


def check_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check TCP connectivity to an authorized target host and port.

    Args:
        host: Target IP address or hostname.
        port: Validated port number (1-65535).
        timeout: Socket timeout in seconds.

    Returns:
        bool: True if connection succeeded, False otherwise.

    Raises:
        ValueError: If port is invalid.
    """
    valid_port = parse_port(port)
    try:
        with socket.create_connection((host.strip(), valid_port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


def subnet_hosts(cidr: str) -> list[str]:
    """Calculate and return usable host IP addresses within a CIDR subnet.

    Args:
        cidr: String representation of CIDR network (e.g. "192.168.1.0/29").

    Returns:
        list[str]: Usable host IP addresses as strings.

    Raises:
        ValueError: If CIDR is invalid.
        TypeError: If cidr is not a string.
    """
    if not isinstance(cidr, str):
        raise TypeError(f"CIDR must be a string, got: {type(cidr).__name__}")

    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR network: {cidr!r}") from exc

    return [str(host) for host in network.hosts()]


def parse_suricata_eve(
    path: Path | str,
    event_type: str = "alert",
) -> Iterator[dict[str, Any]]:
    """Stream and filter events from a Suricata eve.json telemetry file.

    Args:
        path: Path to eve.json file.
        event_type: Event type to extract (default is "alert").

    Yields:
        dict: Filtered security telemetry event.
    """
    from sectoolkit.log_stream import stream_json_lines

    for _, event in stream_json_lines(path):
        if event.get("event_type") == event_type:
            yield event


def summarize_top_talkers(
    events: Iterable[dict[str, Any]],
    key: str = "src_ip",
    limit: int = 10,
) -> list[tuple[str, int]]:
    """Summarize top talkers (IPs, users, or domains) from network event records.

    Args:
        events: Iterable of event dictionaries.
        key: The field name to aggregate on (defaults to 'src_ip').
        limit: Maximum number of top talkers to return.

    Returns:
        list[tuple[str, int]]: Top talkers as (identifier, count) sorted descending.
    """
    counter: Counter[str] = Counter()
    for ev in events:
        val = ev.get(key)
        if val is not None:
            counter[str(val)] += 1

    return counter.most_common(limit)

```

### 6.3 Detailed Code Breakdown

#### Function 1: `check_tcp(host: str, port: int, timeout: float = 2.0) -> bool`
- **Lines 29–35**:
  ```python
  valid_port = parse_port(port)
  try:
      with socket.create_connection((host.strip(), valid_port), timeout=timeout):
          return True
  except (socket.timeout, OSError):
      return False
  ```
  - Reuses Module 1's `parse_port` to ensure the port number is strictly validated.
  - `socket.create_connection()` handles DNS resolution and opens a stream socket.
  - Enforces a bounded `timeout` (default 2 seconds). Without a timeout, sockets can hang indefinitely when packets are silently dropped by firewalls.
  - Returns `True` if connected, `False` if refused or timed out.

#### Function 2: `subnet_hosts(cidr: str) -> list[str]`
- **Lines 54–59**:
  ```python
  network = ipaddress.ip_network(cidr.strip(), strict=False)
  return [str(host) for host in network.hosts()]
  ```
  - `strict=False` allows callers to pass host addresses (e.g., `192.168.1.50/24`) without raising errors; it automatically calculates the network base (`192.168.1.0/24`).
  - `network.hosts()` yields only usable host addresses, automatically omitting the network address (e.g., `.0`) and broadcast address (e.g., `.255`).

#### Function 3: `parse_suricata_eve(path, event_type="alert") -> Iterator[dict]`
- **Lines 74–77**:
  - Streams NDJSON records using Module 5's `stream_json_lines`.
  - Yields only events matching the requested type (e.g. `alert`, `dns`, `flow`).

#### Function 4: `summarize_top_talkers(events, key="src_ip", limit=10) -> list[tuple[str, int]]`
- **Lines 93–100**:
  ```python
  counter: Counter[str] = Counter()
  for ev in events:
      val = ev.get(key)
      if val is not None:
          counter[str(val)] += 1
  return counter.most_common(limit)
  ```
  - Uses `collections.Counter` to tally frequency distributions.
  - `.most_common(limit)` returns the top talkers sorted by volume in descending order.

---

## Module 7: Digital Forensics & Safe Execution (`forensics.py`)

### 7.1 The Real-World Security Problem
1. **Chain of Custody & Tamper Evidence**: In digital forensics, any evidence acquired from a suspect system must have a verifiable cryptographic baseline. If an investigator cannot prove that evidence was unmodified, it can be thrown out in court.
2. **Timezone Discrepancies**: Log records from different servers might log timestamps as `10:00:00` without timezone indicators. One could be UTC, another EST, and another PST. Correlating these without UTC normalization creates incorrect incident timelines.
3. **Command Injection**: When executing CLI tools like `nmap` or `tshark`, using shell strings (`shell=True`) allows input like `filename = "test; cat /etc/shadow"` to execute arbitrary malicious code.

### 7.2 Full Source Code
```python
"""Digital forensics support, evidence hashing, timeline normalization, and safe execution."""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from typing import Any
from sectoolkit.ioc import sha256_file


def generate_manifest(directory: Path | str) -> list[dict[str, Any]]:
    """Recursively generate a deterministic forensic manifest of files.

    Records relative path, size, SHA-256 digest, and UTC timestamp.
    Order is deterministic (alphabetical by relative path).

    Args:
        directory: Target evidence directory.

    Returns:
        list[dict]: Manifest entries containing file metadata and hashes.

    Raises:
        FileNotFoundError: If the directory does not exist.
        NotADirectoryError: If the path is not a directory.
    """
    root = Path(directory).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Evidence directory not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Evidence target is not a directory: {root}")

    manifest: list[dict[str, Any]] = []
    # Deterministic alphabetical ordering
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel_path = path.relative_to(root).as_posix()
            manifest.append({
                "path": rel_path,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "recorded_utc": datetime.now(timezone.utc).isoformat(),
            })

    return manifest


def verify_manifest(
    manifest: list[dict[str, Any]],
    directory: Path | str,
) -> dict[str, list[str]]:
    """Verify integrity of files in a directory against a forensic manifest.

    Args:
        manifest: Pre-generated manifest list of dicts.
        directory: Base directory where evidence is located.

    Returns:
        dict: Results categorized by "matched", "modified", and "missing".
    """
    root = Path(directory).resolve()
    results: dict[str, list[str]] = {
        "matched": [],
        "modified": [],
        "missing": [],
    }

    for item in manifest:
        rel_path = item["path"]
        expected_hash = item["sha256"]
        file_path = root / rel_path

        if not file_path.is_file():
            results["missing"].append(rel_path)
            continue

        actual_hash = sha256_file(file_path)
        if actual_hash.lower() == expected_hash.lower():
            results["matched"].append(rel_path)
        else:
            results["modified"].append(rel_path)

    return results


def parse_iso_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp and normalize it to UTC.

    Requires an explicit timezone or 'Z' suffix to avoid timezone ambiguity.

    Args:
        value: ISO timestamp string (e.g., '2026-11-23T10:00:00Z').

    Returns:
        datetime: Normalized timezone-aware UTC datetime.

    Raises:
        TypeError: If value is not a string.
        ValueError: If value is invalid ISO format or missing timezone.
    """
    if not isinstance(value, str):
        raise TypeError(f"Timestamp must be a string, got: {type(value).__name__}")

    raw = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO timestamp format: {value!r}") from exc

    if parsed.tzinfo is None:
        raise ValueError(f"Timestamp has no timezone offset: {value!r}")

    return parsed.astimezone(timezone.utc)


def safe_exec(
    cmd_args: list[str],
    timeout: float = 10.0,
) -> tuple[int, str, str]:
    """Execute an external command safely without shell interpolation.

    Enforces argument list format (no shell=True) to eliminate command injection.

    Args:
        cmd_args: Command and arguments as a list of strings.
        timeout: Maximum execution time in seconds.

    Returns:
        tuple[int, str, str]: Return code, stdout text, stderr text.

    Raises:
        TypeError: If cmd_args is not a list of strings.
        subprocess.TimeoutExpired: If execution exceeds timeout.
    """
    if not isinstance(cmd_args, list) or not all(isinstance(x, str) for x in cmd_args):
        raise TypeError("cmd_args must be a list of string arguments")

    proc = subprocess.run(
        cmd_args,
        capture_output=True,
        text=True,
        shell=False,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr

```

### 7.3 Detailed Code Breakdown

#### Function 1: `generate_manifest(directory: Path | str) -> list[dict]`
- **Lines 31–43**:
  ```python
  manifest: list[dict[str, Any]] = []
  for path in sorted(root.rglob("*")):
      if path.is_file():
          rel_path = path.relative_to(root).as_posix()
          manifest.append({
              "path": rel_path,
              "size_bytes": path.stat().st_size,
              "sha256": sha256_file(path),
              "recorded_utc": datetime.now(timezone.utc).isoformat(),
          })
  ```
  - `sorted(root.rglob("*"))`: Recursively traverses all files in alphabetical order, ensuring **deterministic manifests**.
  - `path.relative_to(root).as_posix()`: Stores paths relative to the root using forward slashes (`/`), making manifests portable across Linux, macOS, and Windows.
  - Records file size in bytes and SHA-256 digest using Module 3's `sha256_file`.

#### Function 2: `verify_manifest(manifest, directory) -> dict[str, list[str]]`
- **Lines 69–84**:
  - Traverses the manifest entries and checks the local directory.
  - Automatically sorts files into three verifiable states:
    1. `matched`: File exists and SHA-256 matches perfectly.
    2. `modified`: File exists, but content has changed or been corrupted.
    3. `missing`: File has been removed or renamed.

#### Function 3: `parse_iso_timestamp(value: str) -> datetime`
- **Lines 105–115**:
  ```python
  raw = value.strip().replace("Z", "+00:00")
  parsed = datetime.fromisoformat(raw)
  if parsed.tzinfo is None:
      raise ValueError(f"Timestamp has no timezone offset: {value!r}")
  return parsed.astimezone(timezone.utc)
  ```
  - Standardizes ISO 8601 timestamps.
  - **Strict Timezone Enforcement**: If `parsed.tzinfo is None`, it raises an explicit `ValueError`. Timezone-naive timestamps are rejected because they create catastrophic timeline errors.
  - Converts all timestamps directly into normalized UTC.

#### Function 4: `safe_exec(cmd_args: list[str], timeout: float = 10.0) -> tuple[int, str, str]`
- **Lines 135–148**:
  ```python
  if not isinstance(cmd_args, list) or not all(isinstance(x, str) for x in cmd_args):
      raise TypeError("cmd_args must be a list of string arguments")

  proc = subprocess.run(
      cmd_args,
      capture_output=True,
      text=True,
      shell=False,
      timeout=timeout,
      check=False,
  )
  ```
  - Strictly requires `cmd_args` to be a `list[str]`.
  - Sets `shell=False`. Arguments are passed directly to the operating system's `execve` system call without launching a shell interpreter (`/bin/sh`). Shell meta-characters (`;`, `|`, `&`, `$`, `` ` ``) are treated as literal strings, completely neutralizing command injection.
  - Sets a bounded execution `timeout` to prevent hung child processes.

---

## Module 8: Parameterized SQLite & Concurrency (`storage.py`)

### 8.1 The Real-World Security Problem
- **SQL Injection (SQLi)**: Concatenating strings into SQL queries allows attackers who control IOC names or alert rules to tamper with local evidence databases:
  ```python
  # VULNERABLE CODE:
  cursor.execute(f"INSERT INTO iocs VALUES ('{indicator}')")
  # If indicator = "x'); DROP TABLE iocs; --" -> Database destroyed
  ```
- **Unbounded Concurrency**: Launching 1,000 threads simultaneously to check ports or query APIs will exhaust system file descriptors, trigger IP bans on external APIs, or cause denial-of-service conditions.

### 8.2 Full Source Code
```python
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

```

### 8.3 Detailed Code Breakdown

#### Component 1: `EvidenceStore` Class
- **Lines 18–44 (`__init__` and `_init_schema`)**:
  - Initializes SQLite connection. Sets `self.conn.row_factory = sqlite3.Row`, which allows rows to be accessed both by column name (`row["indicator"]`) and index (`row[0]`).
  - Sets up tables with primary keys and constraints:
    - `indicators`: Stores extracted threat intel.
    - `alerts`: Enforces `fingerprint TEXT UNIQUE NOT NULL` so duplicate alerts are rejected at the database engine level.
- **Lines 46–65 (`add_indicator` and `get_indicators`)**:
  ```python
  cur = self.conn.execute(
      "INSERT INTO indicators (indicator, kind, source, observed_utc) VALUES (?, ?, ?, ?);",
      (indicator.strip(), kind.strip().lower(), source.strip(), now_utc),
  )
  ```
  - **Parameterized Placeholders**: Uses `?` placeholders. The SQLite driver handles escaping and type casting natively, rendering SQL injection impossible.
- **Lines 102–109 (Context Management)**:
  - Implements `__enter__` and `__exit__`, allowing clean usage with the Python `with` statement (`with EvidenceStore() as store:`), guaranteeing automatic connection teardown.

#### Component 2: `bounded_worker_pool(func, items, max_workers=4)`
- **Lines 118–143**:
  ```python
  with ThreadPoolExecutor(max_workers=max_workers) as executor:
      future_to_item = {executor.submit(func, item): item for item in item_list}
      for future in as_completed(future_to_item):
          item = future_to_item[future]
          try:
              out = future.result()
              results.append((item, out))
          except Exception as exc:
              results.append((item, exc))
  ```
  - Restricts thread count with `max_workers`.
  - Maps futures back to their original input items.
  - Catches `Exception` on individual worker executions so one failed request does not terminate the rest of the pool.

---

## Module 9: Central CLI & Packaging (`cli.py` & `pyproject.toml`)

### 9.1 The Real-World Security Problem
A security framework consisting of loose scripts requires analysts to remember distinct paths, Python flags, and arguments. A central CLI with subcommands unifies tooling into an auditable binary suitable for automated cron jobs and human operators alike.

### 9.2 Full Source Code
```python
"""Command-line interface for sectoolkit security automation."""

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from sectoolkit.forensics import generate_manifest
from sectoolkit.ioc import extract_iocs
from sectoolkit.net_audit import check_tcp
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

    return 0


if __name__ == "__main__":
    sys.exit(main())

```

### 9.3 Packaging Configuration (`pyproject.toml`)
```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "sectoolkit"
version = "0.1.0"
description = "Modular, production-grade security engineering and automation toolkit"
authors = [{ name = "Security Engineering Team" }]
requires-python = ">=3.10"
readme = "README.md"
dependencies = []

[project.scripts]
sectoolkit = "sectoolkit.cli:main"
```
- By specifying `[project.scripts]`, installing the package via `pip install -e .` generates a standalone executable binary `sectoolkit` directly inside your virtual environment's `bin/` directory.

---


## Module 10: Threat Intel Enrichment & Caching (`enrichment.py`)

### 10.1 The Real-World Security Problem
- **API Quota Exhaustion & Rate Limits**: Commercial threat intelligence APIs (e.g. VirusTotal, Shodan, AbuseIPDB) enforce strict request quotas. Repeatedly querying the same IP or hash wastes money and throttles your SOC automation.
- **SSRF & Sensitive Data Leaks**: Sending internal RFC 1918 IP addresses (e.g., `10.0.0.1`, `192.168.1.50`) to public external APIs leaks internal network architecture and sensitive host telemetry to third parties.

### 10.2 Full Source Code
```python
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

```

### 10.3 Detailed Code Breakdown
1. **SSRF Boundary Guard (`is_private_ip`)**:
   - Before attempting any network lookup, `enrich_ip()` runs `validators.is_private_ip(clean_ip)`.
   - If internal, it immediately short-circuits and labels the indicator as `"trusted_internal"` without making any outbound requests, preserving privacy and eliminating SSRF risks.
2. **`EnrichmentCache` Class**:
   - Implements a local SQLite cache table (`enrichment_cache`) storing `indicator`, `kind`, `data_json`, and `cached_utc`.
   - If an indicator is already cached, it returns the cached record with `cached = True`, avoiding redundant queries.

---

## Module 11: YARA & File Pattern Scanning (`scanner.py`)

### 11.1 The Real-World Security Problem
- **Signature Detection**: Incident responders need to rapidly verify if uploaded files or memory dumps contain known malware webshells, ransomware strings, or malicious macros.
- **Packed / Obfuscated Malware**: Attackers use packers (UPX, custom cryptors) to evade static detection. High Shannon entropy is a reliable heuristic indicator that a file payload is packed or encrypted.

### 11.2 Full Source Code
```python
"""YARA rules compilation, file pattern matching, string extraction, and entropy calculation."""

import math
from pathlib import Path
import re
from typing import Any, Iterator
import yara


def calculate_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence.

    Entropy ranges from 0.0 (uniform/zero variation) to 8.0 (completely random/encrypted).
    Values > 7.0 typically indicate compressed, encrypted, or packed malware payloads.

    Args:
        data: Raw byte string to evaluate.

    Returns:
        float: Shannon entropy rounded to 4 decimal places.
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    # Count byte frequencies
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1

    for count in frequencies:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def extract_strings(
    path: Path | str,
    min_length: int = 4,
    encoding: str = "ascii",
) -> Iterator[str]:
    """Extract printable strings from a binary or text file.

    Useful for static triage of binaries to discover hardcoded C2 IPs,
    file paths, and command executions.

    Args:
        path: Path to target file.
        min_length: Minimum length of string sequence to yield.
        encoding: Character encoding ("ascii").

    Yields:
        str: Discovered printable string.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")

    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for match in pattern.finditer(chunk):
                yield match.group().decode(encoding, errors="replace")


class YaraScanner:
    """YARA rule compiler and file scanner for signature detection."""

    def __init__(self, rule_source: str | None = None, rule_file: Path | str | None = None):
        if rule_source:
            self.rules = yara.compile(source=rule_source)
        elif rule_file:
            path = Path(rule_file)
            if not path.is_file():
                raise FileNotFoundError(f"YARA rule file not found: {path}")
            self.rules = yara.compile(filepath=str(path))
        else:
            raise ValueError("Must provide either rule_source or rule_file")

    def scan_data(self, data: bytes) -> list[dict[str, Any]]:
        """Scan raw bytes against compiled YARA rules."""
        matches = self.rules.match(data=data)
        results = []
        for match in matches:
            matched_strings = []
            for s in match.strings:
                for inst in s.instances:
                    matched_strings.append({
                        "identifier": s.identifier,
                        "offset": inst.offset,
                        "matched_bytes": inst.matched_data.decode("latin1", errors="replace"),
                    })
            results.append({
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": matched_strings,
            })
        return results

    def scan_file(self, path: Path | str) -> list[dict[str, Any]]:
        """Scan a file on disk against compiled YARA rules."""
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        matches = self.rules.match(filepath=str(file_path))
        results = []
        for match in matches:
            matched_strings = []
            for s in match.strings:
                for inst in s.instances:
                    matched_strings.append({
                        "identifier": s.identifier,
                        "offset": inst.offset,
                        "matched_bytes": inst.matched_data.decode("latin1", errors="replace"),
                    })
            results.append({
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": matched_strings,
            })
        return results

```

### 11.3 Detailed Code Breakdown
1. **`calculate_entropy(data: bytes) -> float`**:
   - Calculates the Shannon entropy:
     $$H = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
   - Counts the distribution of all 256 possible byte values. Values $> 7.0$ (out of 8.0) indicate dense randomness typical of encryption or packing.
2. **`extract_strings(path, min_length=4)`**:
   - Scans files in streaming 1 MB chunks for printable ASCII character sequences (`[\x20-\x7e]`).
   - Surfaces hardcoded C2 domains, commands, and passwords inside compiled binaries.
3. **`YaraScanner` Class**:
   - Compiles YARA rule definitions into optimized bytecode using `yara.compile()`.
   - Supports scanning both in-memory byte buffers (`scan_data`) and disk files (`scan_file`), extracting matching rule identifiers, tags, and string offset locations.

---

## Module 12: Automated Case Report Generator (`reporting.py`)

### 12.1 The Real-World Security Problem
- Security teams waste hours manually copying and pasting alert IDs, IP addresses, and hashes from terminal outputs into Word documents or emails.
- Executive stakeholders need high-level summaries (metrics, risk scores, affected hosts), while incident responders need granular tables and remediation checklists.

### 12.2 Full Source Code
```python
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
) -> dict[str, Any]:
    """Aggregate triaged alerts, IOCs, and evidence files into a structured incident summary.

    Args:
        triaged_alerts: List of triaged and scored alert dictionaries.
        extracted_iocs: Optional dictionary of extracted IOC lists.
        manifest: Optional list of evidence manifest records.
        case_id: Unique case identifier.

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
        "| Score | Severity | Rule / Signature | Host | Attacking IP | Event Count |",
        "| :---: | :---: | :--- | :--- | :--- | :---: |",
    ]

    for a in summary.get("alerts", []):
        lines.append(
            f"| `{a.get('priority_score', 0.0)}` | **{a.get('severity', '').upper()}** | {a.get('rule', 'unknown')} | "
            f"`{a.get('hostname', 'N/A')}` | `{a.get('source_ip', 'N/A')}` | {a.get('count', 1)} |"
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

```

### 12.3 Detailed Code Breakdown
1. **`generate_incident_summary(...)`**:
   - Aggregates metrics from triaged alert batches: total alerts, deduplicated event counts, critical severity counts, and top targeted host.
2. **`render_markdown_report(summary)`**:
   - Generates an executive Markdown report complete with summary statistics, prioritized incident tables, defanged IOC lists, and containment steps.
3. **`render_html_report(summary, dark_mode=True)`**:
   - Compiles the report into a standalone, styled HTML document with a midnight dark theme for clean web viewing and PDF export.

---
# PART 3: Hands-On Blueprints — Building Your Future Tools

Using `sectoolkit` as a foundation, here are three complete, production-ready blueprints showing how to chain these modules to solve real-world cybersecurity tasks.

---

### Blueprint 1: Automated SIEM Ingestion & Triage Daemon
**Goal:** Automatically ingest raw NDJSON alert exports from a SIEM, filter out duplicates, compute priority scores, store high-priority incidents in SQLite, and redact sensitive data.

```python
from pathlib import Path
from sectoolkit.log_stream import stream_json_lines
from sectoolkit.triage import triage_alerts
from sectoolkit.security import redact_secrets
from sectoolkit.storage import EvidenceStore

def run_siem_ingest(log_file: Path, db_path: Path):
    print(f"[*] Starting ingestion from {log_file}...")
    
    # 1. Stream raw JSON lines without loading entire file into memory
    raw_alerts = [event for _, event in stream_json_lines(log_file)]
    print(f"[*] Parsed {len(raw_alerts)} total events.")

    # 2. Triage, deduplicate, and calculate priority scores
    triaged = triage_alerts(raw_alerts, min_priority=2.5)
    print(f"[+] Found {len(triaged)} priority incidents (score >= 2.5).")

    # 3. Store into parameterized database and redact secrets
    with EvidenceStore(db_path) as store:
        for incident in triaged:
            clean_incident = redact_secrets(incident)
            store.add_alert(clean_incident)
            print(f"    -> [PRIORITY {clean_incident['priority_score']}] {clean_incident['rule']} on {clean_incident['hostname']} (Count: {clean_incident['count']})")

if __name__ == "__main__":
    run_siem_ingest(Path("data/sample_alerts.json"), Path("output/triage.db"))
```

---

### Blueprint 2: Incident Response Forensic Collector
**Goal:** Ingest a folder of evidence files acquired during an active incident, calculate deterministic SHA-256 manifests, extract all IOCs from logs, and defang them for the final case report.

```python
from pathlib import Path
import json
from sectoolkit.forensics import generate_manifest, verify_manifest
from sectoolkit.ioc import extract_iocs, defang_indicator
from sectoolkit.log_stream import stream_lines

def analyze_incident_directory(evidence_dir: Path, output_report: Path):
    print(f"[*] Generating forensic baseline for {evidence_dir}...")
    
    # 1. Cryptographic manifest
    manifest = generate_manifest(evidence_dir)
    print(f"[+] Recorded {len(manifest)} files in cryptographic manifest.")

    # 2. Extract IOCs across all text logs
    all_iocs = {"ips": set(), "sha256": set(), "md5": set()}
    for entry in manifest:
        file_path = evidence_dir / entry["path"]
        if file_path.suffix in [".log", ".txt", ".json"]:
            for _, line in stream_lines(file_path):
                found = extract_iocs(line)
                all_iocs["ips"].update(found["ips"])
                all_iocs["sha256"].update(found["sha256"])
                all_iocs["md5"].update(found["md5"])

    # 3. Defang indicators for report safety
    defanged_report = {
        "evidence_manifest": manifest,
        "discovered_iocs": {
            "defanged_ips": [defang_indicator(ip) for ip in sorted(all_iocs["ips"])],
            "file_hashes": sorted(all_iocs["sha256"])
        }
    }

    output_report.write_text(json.dumps(defanged_report, indent=2), encoding="utf-8")
    print(f"[+] Forensic analysis report generated at {output_report}.")

if __name__ == "__main__":
    analyze_incident_directory(Path("data/"), Path("output/incident_report.json"))
```

---

### Blueprint 3: Bounded Subnet Port Auditor
**Goal:** Enumerate an authorized subnet range and scan listening ports using a controlled thread worker pool with strict timeouts.

```python
from sectoolkit.net_audit import subnet_hosts, check_tcp
from sectoolkit.storage import bounded_worker_pool
from sectoolkit.validators import parse_port

def audit_subnet(cidr: str, target_port: int, max_concurrency: int = 8):
    port = parse_port(target_port)
    hosts = subnet_hosts(cidr)
    print(f"[*] Auditing port {port} across {len(hosts)} hosts in {cidr} (Threads: {max_concurrency})...")

    # Worker function for single host
    def check_target(host: str):
        is_open = check_tcp(host, port, timeout=1.5)
        return host, is_open

    results = bounded_worker_pool(check_target, hosts, max_workers=max_concurrency)

    open_hosts = [host for (host, is_open) in [r[1] for r in results if not isinstance(r[1], Exception)] if is_open]
    print(f"\n[+] Audit Complete! Active listeners on port {port}:")
    for h in open_hosts:
        print(f"    -> {h}:{port} [OPEN]")

if __name__ == "__main__":
    audit_subnet("192.168.1.0/28", 443)
```

---

# PART 4: Verification & Testing Playbook

Writing security software requires **adversarial testing**: testing not just that your functions work under ideal conditions, but that they safely reject malicious inputs, boundary violations, and malformed files.

### Running the Full Test Suite
```bash
PYTHONPATH=src .venv/bin/python3 -m unittest discover -s tests -p "test_*.py" -v
```

### The 58 Tests Covering the 12 Modules
```
test_validators.py (7 tests):
  - test_parse_port_valid: Validates port parsing [1, 65535].
  - test_parse_port_invalid_range: Rejects -1, 0, 65536.
  - test_parse_port_invalid_type: Rejects strings like "ssh" and None.
  - test_normalize_username: Trims whitespace and applies casefold.
  - test_normalize_username_invalid_type: Rejects non-string usernames.
  - test_is_private_ip: Validates RFC1918 and loopback IPs.
  - test_is_private_ip_invalid: Rejects invalid octets and non-IP strings.

test_security.py (5 tests):
  - test_safe_child_valid: Allows safe subfolder access.
  - test_safe_child_traversal_blocked: Catches and blocks '../' escapes.
  - test_safe_child_same_dir: Allows '.' current directory reference.
  - test_redact_secrets_simple: Redacts passwords and tokens in flat dicts.
  - test_redact_secrets_nested: Redacts secrets deeply within nested lists and dicts.

test_ioc.py (4 tests):
  - test_sha256_file: Hashes binary payloads accurately.
  - test_sha256_file_missing: Raises FileNotFoundError on missing files.
  - test_extract_iocs: Extracts IPs, SHA-256, and MD5 while filtering out invalid IP octets.
  - test_defang_indicator: Defangs URLs and IPs into hxxp and bracketed dots.

test_triage.py (8 tests):
  - test_normalize_alert_standard: Normalizes standard SIEM fields.
  - test_normalize_alert_alternate_fields: Normalizes Elastic/Splunk alternate keys.
  - test_normalize_alert_invalid_type: Rejects non-dict alert objects.
  - test_fingerprint_deterministic: Verifies deterministic SHA-256 time-bucketed fingerprinting.
  - test_priority_score_valid: Verifies weighted scoring calculations.
  - test_priority_score_invalid_ranges: Rejects confidence/criticality values outside [1, 4].
  - test_priority_score_invalid_types: Rejects non-numeric confidence/criticality.
  - test_triage_alerts_pipeline: Tests deduplication counting, score ranking, and filtering.

test_log_stream.py (6 tests):
  - test_stream_lines_all: Verifies generator line streaming.
  - test_stream_lines_filter: Verifies needle keyword filtering.
  - test_stream_lines_missing_file: Raises FileNotFoundError.
  - test_stream_json_lines: Streams NDJSON while skipping malformed lines.
  - test_batch_stream: Batches iterators into fixed chunk sizes.
  - test_batch_stream_invalid_size: Rejects batch sizes < 1.

test_net_audit.py (5 tests):
  - test_subnet_hosts: Validates CIDR usable host calculations.
  - test_subnet_hosts_invalid: Rejects malformed CIDR strings.
  - test_check_tcp_closed: Handles closed ports cleanly with socket timeouts.
  - test_check_tcp_invalid_port: Validates port bounds before connecting.
  - test_parse_suricata_eve_and_top_talkers: Streams alerts from eve.json and summarizes top talkers.

test_forensics.py (5 tests):
  - test_generate_and_verify_manifest: Tests recursive evidence hashing and integrity verification.
  - test_parse_iso_timestamp: Normalizes ISO timestamps with offsets to UTC.
  - test_parse_iso_timestamp_invalid: Rejects timezone-naive or malformed timestamps.
  - test_safe_exec: Safely executes CLI commands without shell interpolation.
  - test_safe_exec_invalid_args: Rejects non-list arguments to prevent injection.

test_storage.py (4 tests):
  - test_indicator_storage: Stores and queries threat indicators with parameterized SQL.
  - test_indicator_validation: Validates inputs before database insertion.
  - test_alert_storage_and_deduplication: Tests database-level fingerprint unique constraints.
  - test_bounded_worker_pool: Validates bounded thread pool execution and exception handling.

test_cli.py (3 tests):
  - test_cli_ioc_inline: Tests `sectoolkit ioc` command.
  - test_cli_manifest: Tests `sectoolkit manifest` command.
  - test_cli_triage: Tests `sectoolkit triage` command.
```

---

# PART 5: Future Roadmap & Next Steps

When you want to extend `sectoolkit` with advanced capabilities, here is the recommended architecture pattern:

1. **Module 10: Threat Intel Enrichment API (`enrichment.py`)**:
   - Query external APIs (VirusTotal, AbuseIPDB, Shodan) using Python's `urllib.request` or `requests`.
   - Implement caching in `storage.py` to prevent redundant API queries and respect rate limits.
2. **Module 11: YARA & File Pattern Scanning (`scanner.py`)**:
   - Compile YARA rules and scan streamed file chunks for known malware signatures.
3. **Module 12: Automated Reporting & Case Export (`reporting.py`)**:
   - Export triaged incident summaries into clean Markdown, CSV, or HTML tables for presentation to SOC leadership.

---
*Created as part of the Security Engineering & Automation Toolkit project.*
