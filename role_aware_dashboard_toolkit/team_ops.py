from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from collections.abc import Iterable
from uuid import uuid4

from ._record_utils import normalize_string_list as _normalize_string_list_shared

TEAM_SCHEMA_VERSION = 1
VALID_TEAM_EVENT_TYPES = (
    "comment",
    "assignment",
    "signoff",
    "handoff",
)
VALID_ASSIGNMENT_STATUSES = (
    "open",
    "in_review",
    "blocked",
    "completed",
)
VALID_SIGNOFF_DECISIONS = (
    "approved",
    "changes_requested",
    "rejected",
    "acknowledged",
)
VALID_HANDOFF_STATUSES = (
    "pending",
    "accepted",
    "closed",
)


def build_team_comment(
    body: str,
    *,
    run_id: str,
    checkpoint_id: str = "",
    comment_id: str = "",
    actor: str = "",
    role: str = "",
    reply_to: str = "",
    tags: Iterable[str] | None = None,
    visibility: str = "team",
    source: str = "ui",
) -> dict[str, Any]:
    text = str(body or "").strip()
    if not text:
        raise ValueError("Comment body must not be empty.")
    return {
        "schema_version": TEAM_SCHEMA_VERSION,
        "event_type": "comment",
        "comment_id": str(comment_id or f"comment_{uuid4().hex[:12]}"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": str(run_id or ""),
        "checkpoint_id": str(checkpoint_id or ""),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "body": text,
        "reply_to": str(reply_to or ""),
        "tags": normalize_string_list(tags),
        "visibility": str(visibility or "team"),
        "source": str(source or "ui"),
    }



def build_review_assignment(
    run_id: str,
    *,
    checkpoint_id: str = "",
    assignment_id: str = "",
    title: str = "",
    instructions: str = "",
    assignee: str = "",
    assignee_role: str = "",
    assigned_by: str = "",
    assigned_role: str = "",
    priority: str = "normal",
    status: str = "open",
    due_at: str = "",
    watchers: Iterable[str] | None = None,
    source: str = "ui",
) -> dict[str, Any]:
    return {
        "schema_version": TEAM_SCHEMA_VERSION,
        "event_type": "assignment",
        "assignment_id": str(assignment_id or f"assign_{uuid4().hex[:12]}"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": str(run_id or ""),
        "checkpoint_id": str(checkpoint_id or ""),
        "title": str(title or "Review assignment").strip() or "Review assignment",
        "instructions": str(instructions or ""),
        "assignee": str(assignee or ""),
        "assignee_role": str(assignee_role or ""),
        "assigned_by": str(assigned_by or ""),
        "assigned_role": str(assigned_role or ""),
        "priority": str(priority or "normal"),
        "status": coerce_assignment_status(status),
        "due_at": str(due_at or ""),
        "watchers": normalize_string_list(watchers),
        "source": str(source or "ui"),
    }



def build_signoff_record(
    run_id: str,
    decision: str,
    *,
    checkpoint_id: str = "",
    assignment_id: str = "",
    signoff_id: str = "",
    actor: str = "",
    role: str = "",
    reason: str = "",
    summary: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    normalized = coerce_signoff_decision(decision)
    return {
        "schema_version": TEAM_SCHEMA_VERSION,
        "event_type": "signoff",
        "signoff_id": str(signoff_id or f"signoff_{uuid4().hex[:12]}"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": str(run_id or ""),
        "checkpoint_id": str(checkpoint_id or ""),
        "assignment_id": str(assignment_id or ""),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "decision": normalized,
        "reason": str(reason or ""),
        "summary": str(summary or ""),
        "source": str(source or "ui"),
    }



def build_handoff_summary(
    run: dict[str, Any],
    *,
    handoff_to: str = "",
    handoff_role: str = "",
    actor: str = "",
    role: str = "",
    notes: str = "",
    status: str = "pending",
    comments: list[dict[str, Any]] | None = None,
    assignments: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
    handoff_id: str = "",
    source: str = "ui",
    max_items: int = 5,
) -> dict[str, Any]:
    run_copy = dict(run or {})
    run_id = str(run_copy.get("run_id") or "")
    checkpoint_id = str(run_copy.get("last_checkpoint_id") or "")
    comment_list = list(comments or [])
    assignment_list = list(assignments or [])
    signoff_list = list(signoffs or [])
    summary = summarize_team_ops(assignment_list, comment_list, signoff_list)
    recent_comments: list[dict[str, Any]] = []
    for record in sorted(comment_list, key=lambda item: str(item.get("ts", "")), reverse=True)[: max(1, int(max_items))]:
        recent_comments.append(
            {
                "ts": record.get("ts", ""),
                "actor": record.get("actor", ""),
                "role": record.get("role", ""),
                "body": str(record.get("body", ""))[:240],
            }
        )
    recent_signoffs: list[dict[str, Any]] = []
    for record in sorted(signoff_list, key=lambda item: str(item.get("ts", "")), reverse=True)[: max(1, int(max_items))]:
        recent_signoffs.append(
            {
                "ts": record.get("ts", ""),
                "actor": record.get("actor", ""),
                "role": record.get("role", ""),
                "decision": record.get("decision", ""),
                "reason": record.get("reason", ""),
            }
        )
    return {
        "schema_version": TEAM_SCHEMA_VERSION,
        "event_type": "handoff",
        "handoff_id": str(handoff_id or f"handoff_{uuid4().hex[:12]}"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "checkpoint_id": checkpoint_id,
        "actor": str(actor or ""),
        "role": str(role or ""),
        "handoff_to": str(handoff_to or ""),
        "handoff_role": str(handoff_role or ""),
        "status": coerce_handoff_status(status),
        "notes": str(notes or ""),
        "summary": {
            "run_status": run_copy.get("status", ""),
            "checkpoint_count": len(list(run_copy.get("checkpoints") or [])),
            "last_checkpoint_id": checkpoint_id,
            "outcome": run_copy.get("outcome", ""),
            "tags": list(run_copy.get("tags") or []),
            "open_assignments": summary["open_assignments"],
            "latest_signoff_decision": summary["latest_signoff_decision"],
            "comment_count": summary["comment_count"],
            "signoff_count": summary["signoff_count"],
            "latest_controls": dict(run_copy.get("latest_controls") or {}),
            "recent_comments": recent_comments,
            "recent_signoffs": recent_signoffs,
        },
        "source": str(source or "ui"),
    }



def summarize_team_ops(
    assignments: list[dict[str, Any]] | None = None,
    comments: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    assignment_list = list(assignments or [])
    comment_list = list(comments or [])
    signoff_list = list(signoffs or [])
    open_assignments = 0
    for record in assignment_list:
        if str(record.get("status") or "") != "completed":
            open_assignments += 1
    latest_signoff = ""
    if signoff_list:
        latest = sorted(signoff_list, key=lambda item: str(item.get("ts", "")))[-1]
        latest_signoff = str(latest.get("decision") or "")
    roles = set()
    for collection in (assignment_list, comment_list, signoff_list):
        for record in collection:
            value = str(record.get("role") or record.get("assigned_role") or record.get("assignee_role") or "").strip()
            if value:
                roles.add(value)
    return {
        "assignment_count": len(assignment_list),
        "open_assignments": open_assignments,
        "comment_count": len(comment_list),
        "signoff_count": len(signoff_list),
        "latest_signoff_decision": latest_signoff,
        "roles_touched": sorted(roles),
    }



def coerce_assignment_status(status: str) -> str:
    value = str(status or "open").strip().lower() or "open"
    if value not in VALID_ASSIGNMENT_STATUSES:
        raise ValueError(f"Invalid assignment status '{status}'. Must be one of {VALID_ASSIGNMENT_STATUSES}")
    return value



def coerce_signoff_decision(decision: str) -> str:
    value = str(decision or "acknowledged").strip().lower() or "acknowledged"
    if value not in VALID_SIGNOFF_DECISIONS:
        raise ValueError(f"Invalid signoff decision '{decision}'. Must be one of {VALID_SIGNOFF_DECISIONS}")
    return value



def coerce_handoff_status(status: str) -> str:
    value = str(status or "pending").strip().lower() or "pending"
    if value not in VALID_HANDOFF_STATUSES:
        raise ValueError(f"Invalid handoff status '{status}'. Must be one of {VALID_HANDOFF_STATUSES}")
    return value



def normalize_string_list(values: Iterable[str] | None) -> list[str]:
    return _normalize_string_list_shared(values)


__all__ = [
    "TEAM_SCHEMA_VERSION",
    "VALID_ASSIGNMENT_STATUSES",
    "VALID_HANDOFF_STATUSES",
    "VALID_SIGNOFF_DECISIONS",
    "VALID_TEAM_EVENT_TYPES",
    "build_handoff_summary",
    "build_review_assignment",
    "build_signoff_record",
    "build_team_comment",
    "coerce_assignment_status",
    "coerce_handoff_status",
    "coerce_signoff_decision",
    "normalize_string_list",
    "summarize_team_ops",
]
