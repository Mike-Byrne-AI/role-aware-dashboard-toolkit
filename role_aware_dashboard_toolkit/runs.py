from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from .checkpoints import build_checkpoint
from .profiles import profile_diff
RUN_SCHEMA_VERSION = 1
VALID_RUN_STATUSES = (
    "draft",
    "active",
    "completed",
    "aborted",
)
def build_run(
    controls: dict[str, Any],
    *,
    run_id: str = "",
    actor: str = "",
    role: str = "",
    source_profile_id: str = "",
    active_profile_id: str = "",
    status: str = "active",
    notes: str = "",
    tags: list[str] | None = None,
    outcome: str = "",
    app_name: str = "role_aware_dashboard_toolkit",
    app_version: str = "",
    session_id: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    status = coerce_run_status(status)
    now = datetime.now(timezone.utc).isoformat()
    run_id = str(run_id or f"run_{uuid4().hex[:12]}")
    initial_controls = deepcopy(dict(controls or {}))
    return {
        "schema_version": RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": now,
        "ended_at": "",
        "actor": str(actor or ""),
        "role": str(role or ""),
        "source_profile_id": str(source_profile_id or ""),
        "active_profile_id": str(active_profile_id or ""),
        "status": status,
        "notes": str(notes or ""),
        "tags": normalize_tags(tags),
        "outcome": str(outcome or ""),
        "app_name": str(app_name or "role_aware_dashboard_toolkit"),
        "app_version": str(app_version or ""),
        "session_id": str(session_id or ""),
        "source": str(source or "ui"),
        "initial_controls": initial_controls,
        "latest_controls": deepcopy(initial_controls),
        "checkpoints": [],
        "last_checkpoint_id": "",
    }
def coerce_run_status(status: str) -> str:
    value = str(status or "draft").strip().lower() or "draft"
    if value not in VALID_RUN_STATUSES:
        raise ValueError(f"Invalid run status '{status}'. Must be one of {VALID_RUN_STATUSES}")
    return value
def normalize_tags(tags: list[str] | None) -> list[str]:
    if tags is None:
        return []
    out: list[str] = []
    seen = set()
    for raw in tags:
        value = str(raw or "").strip()
        if not value:
            continue
        lowered = value.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(value)
    return out
def append_checkpoint(
    run: dict[str, Any],
    controls: dict[str, Any],
    *,
    label: str = "",
    reason: str = "",
    approval_state: str = "proposed",
    actor: str = "",
    role: str = "",
    source: str = "ui",
    audit_events: list[dict[str, Any]] | None = None,
    telemetry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    checkpoint = build_checkpoint(
        controls,
        label=label,
        reason=reason,
        approval_state=approval_state,
        actor=actor,
        role=role,
        source=source,
        audit_events=audit_events,
        telemetry=telemetry,
    )
    updated = deepcopy(run)
    checkpoints = list(updated.get("checkpoints") or [])
    checkpoints.append(checkpoint)
    updated["checkpoints"] = checkpoints
    updated["latest_controls"] = deepcopy(dict(controls or {}))
    updated["last_checkpoint_id"] = checkpoint["checkpoint_id"]
    return updated
def end_run(run: dict[str, Any], *, outcome: str = "", notes: str = "", status: str = "completed") -> dict[str, Any]:
    updated = deepcopy(run)
    updated["status"] = coerce_run_status(status)
    updated["ended_at"] = datetime.now(timezone.utc).isoformat()
    if outcome:
        updated["outcome"] = str(outcome)
    if notes:
        existing = str(run.get("notes") or "")
        updated["notes"] = (existing + "\n" + str(notes)).strip()
    return updated
def run_summary(run: dict[str, Any]) -> dict[str, Any]:
    checkpoints = list(run.get("checkpoints") or [])
    latest_controls = dict(run.get("latest_controls") or {})
    initial_controls = dict(run.get("initial_controls") or {})
    return {
        "run_id": run.get("run_id", ""),
        "status": run.get("status", ""),
        "started_at": run.get("started_at", ""),
        "ended_at": run.get("ended_at", ""),
        "actor": run.get("actor", ""),
        "role": run.get("role", ""),
        "checkpoint_count": len(checkpoints),
        "control_diff_count": len(profile_diff(initial_controls, latest_controls)),
        "outcome": run.get("outcome", ""),
        "tags": list(run.get("tags") or []),
    }
__all__ = [
    "RUN_SCHEMA_VERSION",
    "VALID_RUN_STATUSES",
    "append_checkpoint",
    "build_run",
    "coerce_run_status",
    "end_run",
    "normalize_tags",
    "run_summary",
]
