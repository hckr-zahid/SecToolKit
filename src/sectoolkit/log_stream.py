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
