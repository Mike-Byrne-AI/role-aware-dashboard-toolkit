from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

APPROVAL_SCHEMA_VERSION = 1
VALID_APPROVAL_STATES = (
    "proposed",
    "approved",
    "rejected",
    "frozen",
    "replay_only",
)


def coerce_approval_state(state: str) -> str:
    value = str(state or "proposed").strip().lower() or "proposed"
    if value not in VALID_APPROVAL_STATES:
        raise ValueError(f"Invalid approval state '{state}'. Must be one of {VALID_APPROVAL_STATES}")
    return value


def build_approval_record(
    state: str,
    *,
    actor: str = "",
    role: str = "",
    reason: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    return {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "ts": datetime.now(timezone.utc).isoformat(),
        "state": coerce_approval_state(state),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "reason": str(reason or ""),
        "source": str(source or "ui"),
    }


def approval_blocks_writes(state: str) -> bool:
    return coerce_approval_state(state) in {"rejected", "frozen", "replay_only"}


__all__ = [
    "APPROVAL_SCHEMA_VERSION",
    "VALID_APPROVAL_STATES",
    "approval_blocks_writes",
    "build_approval_record",
    "coerce_approval_state",
]
