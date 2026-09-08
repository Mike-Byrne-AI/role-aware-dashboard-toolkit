from __future__ import annotations

from copy import deepcopy
from typing import Any

from .controls import ControlRegistry
from .sensitive_values import REDACTED_SECRET

REPLAY_SCHEMA_VERSION = 1


def _is_redacted_secret(value: Any) -> bool:
    """Recognize the sentinel without invoking an arbitrary value's equality hook."""
    return isinstance(value, str) and str.__eq__(value, REDACTED_SECRET) is True



def build_replay_packet_from_checkpoint(checkpoint: dict[str, Any]) -> dict[str, Any]:
    controls = deepcopy(dict(checkpoint.get("controls") or {}))
    return {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "source_type": "checkpoint",
        "source_id": checkpoint.get("checkpoint_id", ""),
        "approval_state": checkpoint.get("approval_state", ""),
        "controls": controls,
        "touched_keys": sorted(controls.keys()),
    }



def build_replay_packet_from_audit(events: list[dict[str, Any]]) -> dict[str, Any]:
    preview: dict[str, Any] = {}
    for event in events:
        if event.get("type") != "control_change":
            continue
        key = str(event.get("key") or "")
        if not key:
            continue
        preview[key] = deepcopy(event.get("new"))
    return {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "source_type": "audit",
        "source_id": "audit_preview",
        "controls": preview,
        "touched_keys": sorted(preview.keys()),
    }



def apply_replay_packet(packet: dict[str, Any], registry: ControlRegistry, session_state: dict[str, Any]) -> dict[str, Any]:
    packet_controls = deepcopy(dict(packet.get("controls") or {}))
    controls = {
        key: value
        for key, value in packet_controls.items()
        if (ctrl := registry.get(key)) is not None
        and not ctrl.sensitive
        and not _is_redacted_secret(value)
    }
    corrected = registry.restore(session_state, controls, include_sensitive=False)
    return {
        "applied": len(controls),
        "corrected": int(corrected),
        "touched_keys": sorted(controls.keys()),
    }


__all__ = [
    "REPLAY_SCHEMA_VERSION",
    "apply_replay_packet",
    "build_replay_packet_from_audit",
    "build_replay_packet_from_checkpoint",
]
