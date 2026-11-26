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
