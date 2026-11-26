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
