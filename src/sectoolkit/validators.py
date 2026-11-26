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
