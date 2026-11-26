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
