from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .profiles import profile_diff

LEDGER_SCHEMA_VERSION = 1
VALID_LEDGER_ENTRY_TYPES = (
    "run_started",
    "checkpoint",
    "audit_event",
    "run_ended",
)


def build_run_ledger(run: dict[str, Any]) -> dict[str, Any]:
    """Build a detached chronological view without changing run sequence semantics."""
    run_copy = deepcopy(dict(run or {}))
    checkpoints = list(run_copy.get("checkpoints") or [])
    initial_controls = dict(run_copy.get("initial_controls") or {})
    entries: list[dict[str, Any]] = [
        {
            "entry_type": "run_started",
            "entry_id": f"{run_copy.get('run_id', '')}:start",
            "ts": run_copy.get("started_at", ""),
            "run_id": run_copy.get("run_id", ""),
            "actor": run_copy.get("actor", ""),
            "role": run_copy.get("role", ""),
            "approval_state": "",
            "controls": initial_controls,
            "controls_diff": profile_diff({}, initial_controls),
            "telemetry": {},
            "detail": "run_started",
        }
    ]
    previous_controls = initial_controls
    for checkpoint in checkpoints:
        controls = dict(checkpoint.get("controls") or {})
        entry = {
            "entry_type": "checkpoint",
            "entry_id": str(checkpoint.get("checkpoint_id") or ""),
            "ts": checkpoint.get("ts", ""),
            "run_id": run_copy.get("run_id", ""),
            "checkpoint_id": checkpoint.get("checkpoint_id", ""),
            "label": checkpoint.get("label", ""),
            "reason": checkpoint.get("reason", ""),
            "actor": checkpoint.get("actor", "") or run_copy.get("actor", ""),
            "role": checkpoint.get("role", "") or run_copy.get("role", ""),
            "approval_state": checkpoint.get("approval_state", ""),
            "controls": controls,
            "controls_diff": profile_diff(previous_controls, controls),
            "telemetry": dict(checkpoint.get("telemetry_slice") or {}),
            "audit_count": len(list(checkpoint.get("audit_slice") or [])),
            "detail": checkpoint.get("reason", "") or checkpoint.get("label", ""),
        }
        entries.append(entry)
        previous_controls = controls
        for idx, event in enumerate(list(checkpoint.get("audit_slice") or [])):
            entries.append(
                {
                    "entry_type": "audit_event",
                    "entry_id": f"{checkpoint.get('checkpoint_id', '')}:audit:{idx}",
                    "ts": event.get("ts", checkpoint.get("ts", "")),
                    "run_id": run_copy.get("run_id", ""),
                    "checkpoint_id": checkpoint.get("checkpoint_id", ""),
                    "actor": event.get("user_id", "") or checkpoint.get("actor", ""),
                    "role": event.get("role", "") or checkpoint.get("role", ""),
                    "approval_state": checkpoint.get("approval_state", ""),
                    "controls": {},
                    "controls_diff": {},
                    "telemetry": {},
                    "detail": event.get("detail", "") or event.get("type", ""),
                    "audit_event": dict(event),
                }
            )
    if run_copy.get("ended_at"):
        entries.append(
            {
                "entry_type": "run_ended",
                "entry_id": f"{run_copy.get('run_id', '')}:end",
                "ts": run_copy.get("ended_at", ""),
                "run_id": run_copy.get("run_id", ""),
                "actor": run_copy.get("actor", ""),
                "role": run_copy.get("role", ""),
                "approval_state": "",
                "controls": dict(
                    run_copy["latest_controls"]
                    if isinstance(run_copy.get("latest_controls"), dict)
                    else previous_controls
                ),
                "controls_diff": {},
                "telemetry": {},
                "detail": run_copy.get("outcome", "") or run_copy.get("status", ""),
            }
        )
    # Display time can differ from append order (clock skew, imported evidence).
    # Preserve source sequence so sorting never changes authoritative snapshots.
    for sequence, entry in enumerate(entries):
        entry["source_sequence"] = sequence
    entries.sort(key=_entry_timestamp_key)
    latest_controls = reconstruct_controls_from_entries(entries)
    return {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_copy.get("run_id", ""),
        "run_status": run_copy.get("status", ""),
        "entry_count": len(entries),
        "entries": entries,
        "latest_controls": latest_controls,
        "checkpoint_count": len(checkpoints),
        "latest_approval_state": _latest_approval_state(entries),
    }


def reconstruct_controls_from_ledger(ledger: dict[str, Any]) -> dict[str, Any]:
    return reconstruct_controls_from_entries(list(ledger.get("entries") or []))


def reconstruct_controls_from_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    current: dict[str, Any] = {}
    for entry in _source_order(entries):
        controls = entry.get("controls")
        is_snapshot = entry.get("entry_type") in {"run_started", "checkpoint", "run_ended"}
        if isinstance(controls, dict) and (controls or is_snapshot):
            current = deepcopy(controls)
    return current


def ledger_summary(ledger: dict[str, Any]) -> dict[str, Any]:
    entries = list(ledger.get("entries") or [])
    return {
        "run_id": ledger.get("run_id", ""),
        "run_status": ledger.get("run_status", ""),
        "entry_count": len(entries),
        "checkpoint_count": ledger.get("checkpoint_count", 0),
        "latest_approval_state": ledger.get("latest_approval_state", ""),
        "control_count": len(dict(ledger.get("latest_controls") or {})),
        "generated_at": ledger.get("generated_at", ""),
    }


def _source_order(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Use complete sequence metadata; legacy ledgers retain their list order."""
    sequences = [entry.get("source_sequence") for entry in entries]
    if (
        all(type(sequence) is int and sequence >= 0 for sequence in sequences)
        and len(set(sequences)) == len(sequences)
    ):
        return sorted(entries, key=lambda entry: entry["source_sequence"])
    return entries


def _entry_timestamp_key(entry: dict[str, Any]) -> tuple[bool, datetime]:
    # Never guess local time: historical naive ISO timestamps mean UTC.
    # Keep undated/malformed evidence, sorting it after dated entries stably.
    try:
        text = str(entry.get("ts") or "")
        # Python 3.10 requires the explicit UTC offset instead of a trailing Z.
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        timestamp = datetime.fromisoformat(text)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return False, timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return True, datetime.max.replace(tzinfo=timezone.utc)


def _latest_approval_state(entries: list[dict[str, Any]]) -> str:
    for entry in reversed(_source_order(entries)):
        if entry.get("entry_type") != "checkpoint":
            continue
        state = str(entry.get("approval_state") or "")
        if state:
            return state
    return ""


__all__ = [
    "LEDGER_SCHEMA_VERSION",
    "VALID_LEDGER_ENTRY_TYPES",
    "build_run_ledger",
    "ledger_summary",
    "reconstruct_controls_from_entries",
    "reconstruct_controls_from_ledger",
]
