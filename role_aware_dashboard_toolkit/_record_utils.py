from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def normalize_string_list(
    values: Iterable[Any] | None,
    *,
    case_sensitive: bool = False,
) -> list[str]:
    """Return unique, non-empty strings while preserving input order."""

    if values is None:
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        token = value if case_sensitive else value.lower()
        if token in seen:
            continue
        seen.add(token)
        normalized.append(value)
    return normalized


__all__ = ["normalize_string_list"]
