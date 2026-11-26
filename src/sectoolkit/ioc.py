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
