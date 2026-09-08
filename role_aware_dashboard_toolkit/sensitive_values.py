from __future__ import annotations

import re


REDACTED_SECRET = "<redacted-secret>"
_SENSITIVE_NAME_PATTERN = re.compile(
    r"(token|secret|password|passphrase|api[_\-\s]?key|authorization|credential)",
    re.IGNORECASE,
)


def is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_NAME_PATTERN.search(str(name or "")))


__all__ = ["REDACTED_SECRET", "is_sensitive_name"]
