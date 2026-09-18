from __future__ import annotations

import re
from pathlib import Path


SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(api[_-]?key|secret|token|password)[\s:=]+['\"][^\s'\"]+['\"]", re.IGNORECASE),
    re.compile(r"gh[pousr]_[0-9a-zA-Z]{36}"),
    re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
]


def scrub_secrets(text: str) -> str:
    """Mask credentials and sensitive strings from logs and output."""
    if not text:
        return text
    sanitized = text
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized


def safe_path(base_dir: Path, user_subpath: str) -> Path:
    """Resolve and verify that user_subpath stays strictly within base_dir."""
    resolved_base = base_dir.resolve()
    target = (base_dir / user_subpath).resolve()
    try:
        target.relative_to(resolved_base)
    except ValueError as exc:
        raise ValueError(f"Path traversal attempted: {user_subpath}") from exc
    return target
