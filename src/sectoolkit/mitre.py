"""MITRE ATT&CK tactic and technique tagging for normalized security alerts."""

from typing import Any, Mapping, Sequence

# Keyword-to-MITRE ATT&CK mapping table ordered from most specific to general.
MITRE_TECHNIQUE_RULES: tuple[tuple[tuple[str, ...], dict[str, str]], ...] = (
    (
        ("webshell", "web shell"),
        {
            "technique_id": "T1505.003",
            "technique_name": "Server Software Component: Web Shell",
            "tactic": "Persistence",
        },
    ),
    (
        ("powershell", "encodedcommand"),
        {
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
        },
    ),
    (
        ("brute force", "bruteforce", "ssh", "failed password", "credential stuffing"),
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
        },
    ),
    (
        ("log4j", "jndi", "rce", "sql injection", "sqli", "xss", "exploit"),
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        },
    ),
    (
        ("beacon", "cobalt strike", "c2", "command and control", "dns tunnel"),
        {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
        },
    ),
    (
        ("port scan", "nmap", "network scan", "service discovery"),
        {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery",
        },
    ),
    (
        ("rdp", "smb", "lateral", "remote service"),
        {
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "tactic": "Lateral Movement",
        },
    ),
    (
        ("exfil", "data transfer", "archive"),
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
        },
    ),
    (
        ("ransomware", "encrypt", "wiper"),
        {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "Impact",
        },
    ),
)

_UNMAPPED_MITRE: dict[str, str] = {
    "technique_id": "UNMAPPED",
    "technique_name": "Unmapped Technique",
    "tactic": "Unmapped",
}


def tag_alert_mitre(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of an alert enriched with MITRE ATT&CK metadata.

    Preserves an existing explicit ``technique_id`` if already present on the
    alert; otherwise matches ``rule``, ``signature``, ``description``, and
    ``category`` text against known ATT&CK patterns.

    Args:
        alert: Normalized or raw alert dictionary.

    Returns:
        dict: New alert dictionary containing ``mitre`` metadata.

    Raises:
        TypeError: If ``alert`` is not a mapping.
    """
    if not isinstance(alert, Mapping):
        raise TypeError(f"Alert must be a mapping, got {type(alert).__name__}")

    enriched = dict(alert)

    # Preserve caller-supplied MITRE mapping if already populated.
    existing = enriched.get("mitre")
    if isinstance(existing, Mapping) and existing.get("technique_id"):
        enriched["mitre"] = {
            "technique_id": str(existing["technique_id"]),
            "technique_name": str(existing.get("technique_name", "Custom")),
            "tactic": str(existing.get("tactic", "Unknown")),
        }
        return enriched

    if enriched.get("technique_id"):
        enriched["mitre"] = {
            "technique_id": str(enriched["technique_id"]),
            "technique_name": str(enriched.get("technique_name", "Custom")),
            "tactic": str(enriched.get("tactic", "Unknown")),
        }
        return enriched

    searchable = " ".join(
        str(enriched.get(field, ""))
        for field in ("rule", "signature", "description", "category", "message")
        if enriched.get(field)
    ).lower()

    for keywords, metadata in MITRE_TECHNIQUE_RULES:
        if any(kw in searchable for kw in keywords):
            enriched["mitre"] = dict(metadata)
            return enriched

    enriched["mitre"] = dict(_UNMAPPED_MITRE)
    return enriched


def tag_alerts_mitre(alerts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Tag a sequence of alerts with MITRE ATT&CK metadata.

    Args:
        alerts: Sequence of alert mappings.

    Returns:
        list[dict]: New list of MITRE-enriched alert dictionaries.
    """
    return [tag_alert_mitre(alert) for alert in alerts]
