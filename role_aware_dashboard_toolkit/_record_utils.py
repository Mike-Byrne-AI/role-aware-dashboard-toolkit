from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any


def _record_timestamp_key(value: Any) -> tuple[bool, datetime]:
    """Order ISO evidence by UTC time, retaining undated records after dated ones.

    Historical naive timestamps mean UTC, matching ledger ordering. Invalid or
    missing timestamps have no inferred chronology; callers retain their stable
    secondary ordering or explicitly resolve uncertain approval evidence.
    """
    if isinstance(value, str):
        try:
            text = value.strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            timestamp = datetime.fromisoformat(text)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            return False, timestamp.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            pass
    return True, datetime.max.replace(tzinfo=timezone.utc)


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
