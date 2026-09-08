from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .approvals import build_approval_record, coerce_approval_state

CHECKPOINT_SCHEMA_VERSION = 1
DASHBOARD_SNAPSHOT_SCHEMA_VERSION = 1
_REDACTED_VALUE = "[REDACTED]"


def build_checkpoint(
    controls: dict[str, Any],
    *,
    checkpoint_id: str = "",
    label: str = "",
    reason: str = "",
    approval_state: str = "proposed",
    actor: str = "",
    role: str = "",
    source: str = "ui",
    audit_events: list[dict[str, Any]] | None = None,
    telemetry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = coerce_approval_state(approval_state)
    checkpoint_id = str(checkpoint_id or f"chk_{uuid4().hex[:12]}")
    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "checkpoint_id": checkpoint_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "label": str(label or checkpoint_id),
        "reason": str(reason or ""),
        "controls": deepcopy(dict(controls or {})),
        "audit_slice": deepcopy(list(audit_events or [])),
        "telemetry_slice": deepcopy(dict(telemetry or {})),
        "approval_state": state,
        "approval": build_approval_record(state, actor=actor, role=role, reason=reason, source=source),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "source": str(source or "ui"),
    }


def checkpoint_summary(checkpoint: dict[str, Any]) -> dict[str, Any]:
    controls = dict(checkpoint.get("controls") or {})
    telemetry = dict(checkpoint.get("telemetry_slice") or {})
    return {
        "checkpoint_id": checkpoint.get("checkpoint_id", ""),
        "ts": checkpoint.get("ts", ""),
        "label": checkpoint.get("label", ""),
        "approval_state": checkpoint.get("approval_state", ""),
        "control_count": len(controls),
        "telemetry_keys": sorted(telemetry.keys()),
    }


def build_dashboard_snapshot(
    controls: Mapping[str, Any],
    *,
    snapshot_id: str = "",
    label: str = "",
    groups: Mapping[str, Sequence[str]] | Sequence[Mapping[str, Any]] | None = None,
    role: str = "",
    controls_writable: bool = True,
    available_roles: Sequence[str] | None = None,
    active_profile_id: str = "",
    available_profiles: Sequence[str] | None = None,
    audit_events: Sequence[Mapping[str, Any]] | None = None,
    plugin_metadata: Sequence[Mapping[str, Any]] | None = None,
    redact_keys: Sequence[str] | None = None,
    source: str = "ui",
) -> dict[str, Any]:
    """Build a dashboard-state snapshot with restore-safe payloads.

    This wrapper keeps dashboard controls, role/writable state, profile metadata,
    audit summary, and plugin metadata together in one explicit snapshot object.
    """
    checkpoint = build_checkpoint(
        dict(controls or {}),
        checkpoint_id=snapshot_id,
        label=label,
        source=source,
        audit_events=[dict(event) for event in (audit_events or []) if isinstance(event, Mapping)],
    )
    control_values = dict(checkpoint.get("controls") or {})
    redacted_controls, restore_controls, redacted_keys = _build_redacted_controls(control_values, redact_keys)
    return {
        "schema_version": DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
        "snapshot_type": "dashboard_state",
        "snapshot_id": checkpoint.get("checkpoint_id", ""),
        "ts": checkpoint.get("ts", ""),
        "label": str(label or checkpoint.get("label") or ""),
        "source": str(source or "ui"),
        "controls": redacted_controls,
        "groups": _normalize_groups(groups, control_values),
        "security": {
            "active_role": str(role or ""),
            "controls_writable": bool(controls_writable),
            "available_roles": [str(item) for item in (available_roles or []) if str(item).strip()],
        },
        "profiles": {
            "active_profile_id": str(active_profile_id or ""),
            "available_profiles": [str(item) for item in (available_profiles or []) if str(item).strip()],
        },
        "audit_summary": _build_audit_summary(audit_events),
        "plugins": _build_plugin_summary(plugin_metadata),
        "redaction": {
            "redacted_keys": redacted_keys,
            "replacement": _REDACTED_VALUE,
        },
        "restore_payload": {
            "controls": restore_controls,
            "active_role": str(role or ""),
            "controls_writable": bool(controls_writable),
            "active_profile_id": str(active_profile_id or ""),
        },
    }


def _build_redacted_controls(
    controls: Mapping[str, Any],
    redact_keys: Sequence[str] | None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    redact_set = {str(item) for item in (redact_keys or []) if str(item).strip()}
    redacted_keys: list[str] = []
    visible_controls: dict[str, Any] = {}
    restore_controls: dict[str, Any] = {}
    for raw_key, value in dict(controls or {}).items():
        key = str(raw_key)
        if key in redact_set:
            visible_controls[key] = _REDACTED_VALUE
            redacted_keys.append(key)
            continue
        visible_controls[key] = deepcopy(value)
        restore_controls[key] = deepcopy(value)
    return visible_controls, restore_controls, sorted(redacted_keys)


def _normalize_groups(
    groups: Mapping[str, Sequence[str]] | Sequence[Mapping[str, Any]] | None,
    controls: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if isinstance(groups, Mapping):
        normalized: list[dict[str, Any]] = []
        for group_name, group_keys in groups.items():
            normalized.append({
                "group": str(group_name or ""),
                "keys": [str(item) for item in (group_keys or []) if str(item).strip()],
            })
        return normalized
    if isinstance(groups, Sequence) and not isinstance(groups, (str, bytes)):
        normalized: list[dict[str, Any]] = []
        for item in groups:
            if not isinstance(item, Mapping):
                continue
            normalized.append({
                "group": str(item.get("group") or item.get("name") or ""),
                "keys": [str(key) for key in (item.get("keys") or []) if str(key).strip()],
            })
        return normalized
    return [{
        "group": "Controls",
        "keys": [str(key) for key in dict(controls or {}).keys()],
    }]


def _build_audit_summary(audit_events: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    events = [dict(event) for event in (audit_events or []) if isinstance(event, Mapping)]
    last_event = events[-1] if events else {}
    return {
        "event_count": len(events),
        "last_event_type": str(last_event.get("type") or ""),
        "last_event_ts": str(last_event.get("ts") or ""),
    }


def _build_plugin_summary(plugin_metadata: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    normalized: list[dict[str, Any]] = []
    for item in plugin_metadata or []:
        if not isinstance(item, Mapping):
            continue
        normalized.append({
            "name": str(item.get("name") or ""),
            "version": str(item.get("version") or ""),
            "capabilities": [str(cap) for cap in (item.get("capabilities") or []) if str(cap).strip()],
        })
    return {
        "count": len(normalized),
        "registered": normalized,
    }


__all__ = [
    "CHECKPOINT_SCHEMA_VERSION",
    "DASHBOARD_SNAPSHOT_SCHEMA_VERSION",
    "build_checkpoint",
    "build_dashboard_snapshot",
    "checkpoint_summary",
]
