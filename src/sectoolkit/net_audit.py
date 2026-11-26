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
