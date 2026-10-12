from __future__ import annotations

from collections.abc import Mapping
from math import isfinite
from typing import Any

from .profiles import profile_diff
from .runs import run_summary



def diff_mapping(old_values: dict[str, Any], new_values: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return profile_diff(dict(old_values or {}), dict(new_values or {}))



def compare_checkpoints(
    left: dict[str, Any], right: dict[str, Any], *, include_telemetry: bool = False,
) -> dict[str, Any]:
    """Compare controls and approval; optionally include observed metric changes.

    Telemetry deltas are right minus left, without unit conversion, preferred
    direction, or any inference that changed controls caused changed outcomes.
    Direct callers own authorization to view the supplied checkpoint evidence.
    """
    left_controls = dict(left.get("controls") or {})
    right_controls = dict(right.get("controls") or {})
    comparison = {
        "left_checkpoint_id": left.get("checkpoint_id", ""),
        "right_checkpoint_id": right.get("checkpoint_id", ""),
        "approval_transition": {
            "from": left.get("approval_state", ""),
            "to": right.get("approval_state", ""),
        },
        "control_diff": diff_mapping(left_controls, right_controls),
    }
    if include_telemetry:
        comparison["telemetry_comparison"] = _compare_telemetry(left, right)
    return comparison



def compare_runs(
    left: dict[str, Any], right: dict[str, Any], *, include_telemetry: bool = False,
) -> dict[str, Any]:
    """Compare runs, optionally using telemetry from each final checkpoint.

    An empty latest control snapshot is authoritative. Initial controls are
    used only when the latest snapshot is missing or None. An empty final
    checkpoint is not replaced by an older telemetry sample. Sample timestamps
    and checkpoint IDs identify which observations were compared.
    """
    left_summary = run_summary(left)
    right_summary = run_summary(right)
    left_controls = _run_controls(left)
    right_controls = _run_controls(right)
    comparison = {
        "left_run": left_summary,
        "right_run": right_summary,
        "field_diff": {
            key: {"from": left_summary.get(key), "to": right_summary.get(key)}
            for key in sorted(set(left_summary.keys()) | set(right_summary.keys()))
            if left_summary.get(key) != right_summary.get(key)
        },
        "control_diff": diff_mapping(left_controls, right_controls),
    }
    if include_telemetry:
        left_checkpoint = _final_checkpoint(left)
        right_checkpoint = _final_checkpoint(right)
        comparison["telemetry_comparison"] = {
            "left_checkpoint_id": left_checkpoint.get("checkpoint_id", ""),
            "right_checkpoint_id": right_checkpoint.get("checkpoint_id", ""),
            **_compare_telemetry(left_checkpoint, right_checkpoint),
        }
    return comparison


def _run_controls(run: Mapping[str, Any]) -> dict[str, Any]:
    controls = run.get("latest_controls")
    if controls is None:
        controls = run.get("initial_controls")
    return dict(controls or {})


def _final_checkpoint(run: Mapping[str, Any]) -> dict[str, Any]:
    checkpoints = run.get("checkpoints")
    return _mapping(checkpoints[-1]) if isinstance(checkpoints, (list, tuple)) and checkpoints else {}


def _compare_telemetry(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    left_sample = _mapping(left.get("telemetry_slice"))
    right_sample = _mapping(right.get("telemetry_slice"))
    left_metrics = _metric_values(left_sample)
    right_metrics = _metric_values(right_sample)
    left_units = _mapping(left_sample.get("units"))
    right_units = _mapping(right_sample.get("units"))
    rows = {}
    for name in sorted(left_metrics.keys() | right_metrics.keys()):
        old = left_metrics.get(name)
        new = right_metrics.get(name)
        old_unit = _unit(left_units.get(name))
        new_unit = _unit(right_units.get(name))
        delta = None
        if name not in left_metrics:
            status = "missing_left"
        elif name not in right_metrics:
            status = "missing_right"
        elif old is None or new is None:
            status = "invalid_value"
        elif old_unit != new_unit:
            status = "unit_mismatch"
        else:
            delta = new - old
            status = "comparable"
            if not isfinite(delta):
                status = "non_finite_delta"
                delta = None
        rows[name] = {
            "from": old, "to": new,
            "from_unit": old_unit, "to_unit": new_unit,
            "delta": delta, "status": status,
        }
    return {
        "left_sample_ts": _sample_timestamp(left_sample),
        "right_sample_ts": _sample_timestamp(right_sample),
        "metrics": rows,
    }


def _metric_values(sample: dict[str, Any]) -> dict[str, float | None]:
    # Normalized metrics are already named, including any retained leaf aliases.
    # Never re-normalize them: that can overwrite a same-named independent value.
    if "metrics" in sample:
        payload = _mapping(sample["metrics"])
    else:
        metadata = {"schema_version", "ts", "units", "labels", "source", "service", "health"}
        payload = {key: value for key, value in sample.items() if key not in metadata}
    values: dict[str, float | None] = {}

    def visit(value: Any, name: str) -> None:
        if isinstance(value, Mapping) and value:
            for key, child in value.items():
                visit(child, f"{name}.{key}" if name else str(key))
            return
        if isinstance(value, (list, tuple)) and value:
            for child in value:
                visit(child, name)
            return
        numeric = None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                candidate = float(value)
            except OverflowError:
                candidate = float("nan")
            if isfinite(candidate):
                numeric = candidate
        previous = values.get(name)
        values[name] = max(numeric, previous) if numeric is not None and previous is not None else (
            numeric if numeric is not None else previous
        )

    for key, value in payload.items():
        visit(value, str(key))
    return values


def _unit(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _sample_timestamp(sample: Mapping[str, Any]) -> str:
    value = sample.get("ts")
    return value if isinstance(value, str) else ""


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
    restore_controls = restore.get("controls")
    if isinstance(restore_controls, Mapping):
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
