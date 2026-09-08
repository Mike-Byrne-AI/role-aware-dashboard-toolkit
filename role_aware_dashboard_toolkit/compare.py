from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .profiles import profile_diff
from .runs import run_summary



def diff_mapping(old_values: dict[str, Any], new_values: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return profile_diff(dict(old_values or {}), dict(new_values or {}))



def compare_checkpoints(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_controls = dict(left.get("controls") or {})
    right_controls = dict(right.get("controls") or {})
    return {
        "left_checkpoint_id": left.get("checkpoint_id", ""),
        "right_checkpoint_id": right.get("checkpoint_id", ""),
        "approval_transition": {
            "from": left.get("approval_state", ""),
            "to": right.get("approval_state", ""),
        },
        "control_diff": diff_mapping(left_controls, right_controls),
    }



def compare_runs(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_summary = run_summary(left)
    right_summary = run_summary(right)
    left_controls = dict(left.get("latest_controls") or left.get("initial_controls") or {})
    right_controls = dict(right.get("latest_controls") or right.get("initial_controls") or {})
    return {
        "left_run": left_summary,
        "right_run": right_summary,
        "field_diff": {
            key: {"from": left_summary.get(key), "to": right_summary.get(key)}
            for key in sorted(set(left_summary.keys()) | set(right_summary.keys()))
            if left_summary.get(key) != right_summary.get(key)
        },
        "control_diff": diff_mapping(left_controls, right_controls),
    }


def compare_dashboard_snapshots(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_controls = _snapshot_controls(left)
    right_controls = _snapshot_controls(right)
    left_security = _mapping(left.get("security"))
    right_security = _mapping(right.get("security"))
    left_profiles = _mapping(left.get("profiles"))
    right_profiles = _mapping(right.get("profiles"))
    left_plugins = _plugin_name_set(left)
    right_plugins = _plugin_name_set(right)
    left_audit = _mapping(left.get("audit_summary"))
    right_audit = _mapping(right.get("audit_summary"))
    return {
        "left_snapshot_id": str(left.get("snapshot_id") or ""),
        "right_snapshot_id": str(right.get("snapshot_id") or ""),
        "control_diff": diff_mapping(left_controls, right_controls),
        "security_transition": {
            "role": {"from": left_security.get("active_role", ""), "to": right_security.get("active_role", "")},
            "controls_writable": {
                "from": bool(left_security.get("controls_writable", True)),
                "to": bool(right_security.get("controls_writable", True)),
            },
        },
        "profile_transition": {
            "active_profile_id": {
                "from": left_profiles.get("active_profile_id", ""),
                "to": right_profiles.get("active_profile_id", ""),
            },
        },
        "plugin_diff": {
            "added": sorted(right_plugins - left_plugins),
            "removed": sorted(left_plugins - right_plugins),
        },
        "audit_event_delta": int(right_audit.get("event_count", 0) or 0) - int(left_audit.get("event_count", 0) or 0),
    }


def _snapshot_controls(snapshot: Mapping[str, Any] | dict[str, Any]) -> dict[str, Any]:
    restore = _mapping(snapshot.get("restore_payload"))
    restore_controls = _mapping(restore.get("controls"))
    if restore_controls:
        return dict(restore_controls)
    return _mapping(snapshot.get("controls"))


def _plugin_name_set(snapshot: Mapping[str, Any] | dict[str, Any]) -> set[str]:
    plugins = _mapping(snapshot.get("plugins"))
    names: set[str] = set()
    for item in plugins.get("registered") or []:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            names.add(name)
    return names


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


__all__ = [
    "compare_dashboard_snapshots",
    "compare_checkpoints",
    "compare_runs",
    "diff_mapping",
]
