from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from collections.abc import Iterable
from uuid import uuid4

from .approvals import coerce_approval_state
from ._record_utils import _record_timestamp_key
from .team_ops import coerce_assignment_status, coerce_handoff_status, coerce_signoff_decision

DECISION_SCHEMA_VERSION = 1
VALID_DECISION_STATES = (
    "proposed",
    "review_requested",
    "in_review",
    "changes_requested",
    "approved",
    "rejected",
    "frozen",
    "replay_only",
    "handoff_pending",
    "handed_off",
    "closed",
)
VALID_DECISION_EVENT_TYPES = (
    "decision_created",
    "approval_synced",
    "review_requested",
    "review_started",
    "signoff_recorded",
    "handoff_created",
    "handoff_accepted",
    "handoff_closed",
    "decision_closed",
    "decision_reopened",
)


def coerce_decision_state(state: str) -> str:
    value = str(state or "proposed").strip().lower() or "proposed"
    if value not in VALID_DECISION_STATES:
        raise ValueError(f"Invalid decision state '{state}'. Must be one of {VALID_DECISION_STATES}")
    return value



def build_decision_case(
    run: dict[str, Any],
    *,
    checkpoint: dict[str, Any] | None = None,
    decision_id: str = "",
    actor: str = "",
    role: str = "",
    source: str = "ui",
    notes: str = "",
    tags: Iterable[str] | None = None,
) -> dict[str, Any]:
    run_copy = dict(run or {})
    checkpoint_record = dict(checkpoint or _last_checkpoint(run_copy))
    approval_state = _extract_approval_state(checkpoint_record)
    state = derive_decision_state(
        approval_state=approval_state,
        assignments=[],
        signoffs=[],
        handoffs=[],
    )
    now = _iso_now()
    decision = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "decision_id": str(decision_id or f"decision_{uuid4().hex[:12]}"),
        "run_id": str(run_copy.get("run_id") or ""),
        "checkpoint_id": str(checkpoint_record.get("checkpoint_id") or run_copy.get("last_checkpoint_id") or ""),
        "created_at": now,
        "updated_at": now,
        "actor": str(actor or run_copy.get("actor") or ""),
        "role": str(role or run_copy.get("role") or ""),
        "source": str(source or "ui"),
        "state": state,
        "approval_state": approval_state,
        "latest_signoff_decision": "",
        "latest_handoff_status": "",
        "open_assignment_count": 0,
        "comment_count": 0,
        "signoff_count": 0,
        "handoff_count": 0,
        "blockers": blockers_for_decision(state, approval_state=approval_state, open_assignment_count=0, latest_signoff_decision="", latest_handoff_status=""),
        "allowed_actions": allowed_actions_for_state(state),
        "notes": str(notes or ""),
        "tags": _normalize_tags(tags),
        "history": [
            {
                "ts": now,
                "event_type": "decision_created",
                "from_state": "",
                "to_state": state,
                "actor": str(actor or run_copy.get("actor") or ""),
                "role": str(role or run_copy.get("role") or ""),
                "reason": "Decision case created from run/checkpoint context.",
                "source": str(source or "ui"),
                "ref_id": str(checkpoint_record.get("checkpoint_id") or ""),
            }
        ],
        "last_event_type": "decision_created",
        "summary": {
            "run_status": str(run_copy.get("status") or ""),
            "checkpoint_count": len(list(run_copy.get("checkpoints") or [])),
            "latest_controls": dict(run_copy.get("latest_controls") or {}),
            "outcome": str(run_copy.get("outcome") or ""),
        },
    }
    return decision



def build_decision_case_from_run(
    run: dict[str, Any],
    *,
    checkpoint: dict[str, Any] | None = None,
    assignments: list[dict[str, Any]] | None = None,
    comments: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
    handoffs: list[dict[str, Any]] | None = None,
    existing: dict[str, Any] | None = None,
    actor: str = "",
    role: str = "",
    source: str = "derived",
) -> dict[str, Any]:
    decision = dict(existing or build_decision_case(run, checkpoint=checkpoint, actor=actor, role=role, source=source))
    return sync_decision_case(
        decision,
        run=run,
        checkpoint=checkpoint,
        assignments=assignments,
        comments=comments,
        signoffs=signoffs,
        handoffs=handoffs,
        actor=actor,
        role=role,
        source=source,
    )



def sync_decision_case(
    decision: dict[str, Any],
    *,
    run: dict[str, Any] | None = None,
    checkpoint: dict[str, Any] | None = None,
    assignments: list[dict[str, Any]] | None = None,
    comments: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
    handoffs: list[dict[str, Any]] | None = None,
    actor: str = "",
    role: str = "",
    source: str = "derived",
) -> dict[str, Any]:
    updated = dict(decision or {})
    run_copy = dict(run or {})
    checkpoint_record = dict(checkpoint or _last_checkpoint(run_copy))
    assignment_list = _sorted_records(assignments)
    comment_list = _sorted_records(comments)
    signoff_list = _sorted_records(signoffs)
    handoff_list = _sorted_records(handoffs)
    approval_state = _extract_approval_state(checkpoint_record)
    target_state = derive_decision_state(
        approval_state=approval_state,
        assignments=assignment_list,
        signoffs=signoff_list,
        handoffs=handoff_list,
    )
    open_assignment_count = _open_assignment_count(assignment_list)
    latest_signoff = _latest_value(signoff_list, "decision")
    latest_handoff = _latest_value(handoff_list, "status")
    updated["run_id"] = str(updated.get("run_id") or run_copy.get("run_id") or "")
    updated["checkpoint_id"] = str(updated.get("checkpoint_id") or checkpoint_record.get("checkpoint_id") or run_copy.get("last_checkpoint_id") or "")
    previous_state = str(updated.get("state") or "")
    updated["state"] = target_state
    updated["approval_state"] = approval_state
    updated["latest_signoff_decision"] = latest_signoff
    updated["latest_handoff_status"] = latest_handoff
    updated["open_assignment_count"] = open_assignment_count
    updated["comment_count"] = len(comment_list)
    updated["signoff_count"] = len(signoff_list)
    updated["handoff_count"] = len(handoff_list)
    updated["blockers"] = blockers_for_decision(
        target_state,
        approval_state=approval_state,
        open_assignment_count=open_assignment_count,
        latest_signoff_decision=latest_signoff,
        latest_handoff_status=latest_handoff,
    )
    updated["allowed_actions"] = allowed_actions_for_state(target_state)
    updated["updated_at"] = _iso_now()
    latest_controls = run_copy.get("latest_controls")
    if latest_controls is None:
        latest_controls = updated.get("summary", {}).get("latest_controls")
    updated["summary"] = {
        "run_status": str(run_copy.get("status") or updated.get("summary", {}).get("run_status") or ""),
        "checkpoint_count": len(list(run_copy.get("checkpoints") or [])),
        "latest_controls": dict(latest_controls or {}),
        "outcome": str(run_copy.get("outcome") or updated.get("summary", {}).get("outcome") or ""),
        "latest_assignment_status": _latest_value(assignment_list, "status"),
        "comment_count": len(comment_list),
        "signoff_count": len(signoff_list),
        "handoff_count": len(handoff_list),
    }
    history = list(updated.get("history") or [])
    if previous_state != target_state or not history:
        event_type, reason, ref_id, event_actor, event_role = infer_transition_event(
            target_state,
            approval_state=approval_state,
            assignments=assignment_list,
            signoffs=signoff_list,
            handoffs=handoff_list,
            actor=actor,
            role=role,
        )
        history.append(
            {
                "ts": updated["updated_at"],
                "event_type": event_type,
                "from_state": previous_state,
                "to_state": target_state,
                "actor": event_actor,
                "role": event_role,
                "reason": reason,
                "source": str(source or "derived"),
                "ref_id": ref_id,
            }
        )
        updated["last_event_type"] = event_type
    elif not updated.get("last_event_type"):
        updated["last_event_type"] = "approval_synced"
    updated["history"] = history
    return updated



def decision_summary(decision: dict[str, Any]) -> dict[str, Any]:
    decision_copy = dict(decision or {})
    return {
        "decision_id": decision_copy.get("decision_id", ""),
        "run_id": decision_copy.get("run_id", ""),
        "checkpoint_id": decision_copy.get("checkpoint_id", ""),
        "state": decision_copy.get("state", ""),
        "approval_state": decision_copy.get("approval_state", ""),
        "latest_signoff_decision": decision_copy.get("latest_signoff_decision", ""),
        "latest_handoff_status": decision_copy.get("latest_handoff_status", ""),
        "open_assignment_count": int(decision_copy.get("open_assignment_count") or 0),
        "comment_count": int(decision_copy.get("comment_count") or 0),
        "signoff_count": int(decision_copy.get("signoff_count") or 0),
        "handoff_count": int(decision_copy.get("handoff_count") or 0),
        "blocker_count": len(list(decision_copy.get("blockers") or [])),
        "allowed_actions": list(decision_copy.get("allowed_actions") or []),
        "last_event_type": decision_copy.get("last_event_type", ""),
    }



def derive_decision_state(
    *,
    approval_state: str = "proposed",
    assignments: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
    handoffs: list[dict[str, Any]] | None = None,
) -> str:
    approval = coerce_approval_state(approval_state)
    assignment_list = _sorted_records(assignments)
    signoff_list = _sorted_records(signoffs)
    handoff_list = _sorted_records(handoffs)
    open_assignment_count = _open_assignment_count(assignment_list)
    latest_assignment_status = _latest_value(assignment_list, "status")
    latest_signoff = _latest_value(signoff_list, "decision")
    latest_handoff = _latest_value(handoff_list, "status")

    if latest_handoff == "closed":
        return "closed"
    if approval == "frozen":
        return "frozen"
    if approval == "replay_only":
        return "replay_only"
    if approval == "rejected" or latest_signoff == "rejected":
        return "rejected"
    if latest_handoff == "accepted":
        return "handed_off"
    if latest_handoff == "pending":
        return "handoff_pending"
    if latest_signoff == "changes_requested":
        return "changes_requested"
    if latest_signoff == "approved":
        return "approved"
    if latest_assignment_status == "in_review":
        return "in_review"
    if open_assignment_count > 0:
        return "review_requested"
    if approval == "approved":
        return "approved"
    return "proposed"



def allowed_actions_for_state(state: str) -> list[str]:
    normalized = coerce_decision_state(state)
    mapping = {
        "proposed": ["request_review", "freeze", "mark_replay_only", "reject"],
        "review_requested": ["start_review", "signoff", "request_changes", "freeze", "handoff"],
        "in_review": ["signoff", "request_changes", "reject", "handoff"],
        "changes_requested": ["reopen", "request_review", "freeze"],
        "approved": ["handoff", "close", "reopen", "freeze"],
        "rejected": ["reopen", "freeze"],
        "frozen": ["reopen"],
        "replay_only": ["reopen"],
        "handoff_pending": ["accept_handoff", "close", "comment"],
        "handed_off": ["close", "reopen"],
        "closed": ["reopen"],
    }
    return list(mapping.get(normalized, []))



def blockers_for_decision(
    state: str,
    *,
    approval_state: str,
    open_assignment_count: int,
    latest_signoff_decision: str,
    latest_handoff_status: str,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    if open_assignment_count > 0:
        blockers.append({"kind": "open_assignments", "detail": str(open_assignment_count)})
    if latest_signoff_decision == "changes_requested":
        blockers.append({"kind": "changes_requested", "detail": "Latest signoff requested changes."})
    if latest_signoff_decision == "rejected":
        blockers.append({"kind": "rejected", "detail": "Latest signoff rejected the decision."})
    elif approval_state == "rejected":
        blockers.append({"kind": "rejected", "detail": "Checkpoint approval is rejected."})
    if approval_state in {"frozen", "replay_only"}:
        blockers.append({"kind": approval_state, "detail": f"Approval state is {approval_state}."})
    if latest_handoff_status == "pending":
        blockers.append({"kind": "handoff_pending", "detail": "Waiting for receiving role to accept handoff."})
    if coerce_decision_state(state) == "closed":
        blockers.append({"kind": "closed", "detail": "Decision case is closed."})
    return blockers



def infer_transition_event(
    target_state: str,
    *,
    approval_state: str,
    assignments: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
    handoffs: list[dict[str, Any]] | None = None,
    actor: str = "",
    role: str = "",
) -> tuple[str, str, str, str, str]:
    handoff = _latest_record(handoffs)
    signoff = _latest_record(signoffs)
    assignment = _latest_record(assignments)
    if target_state == "closed" and handoff:
        return "handoff_closed", "Handoff was closed.", str(handoff.get("handoff_id") or ""), str(handoff.get("actor") or actor or ""), str(handoff.get("role") or role or "")
    if target_state == "handed_off" and handoff:
        return "handoff_accepted", "Handoff was accepted.", str(handoff.get("handoff_id") or ""), str(handoff.get("actor") or actor or ""), str(handoff.get("role") or role or "")
    if target_state == "handoff_pending" and handoff:
        return "handoff_created", "Decision is waiting on handoff acceptance.", str(handoff.get("handoff_id") or ""), str(handoff.get("actor") or actor or ""), str(handoff.get("role") or role or "")
    if target_state in {"approved", "changes_requested", "rejected"} and signoff and signoff.get("decision") == target_state:
        return "signoff_recorded", f"Latest signoff moved decision to {target_state}.", str(signoff.get("signoff_id") or ""), str(signoff.get("actor") or actor or ""), str(signoff.get("role") or role or "")
    if target_state == "in_review" and assignment:
        return "review_started", "An assignment is actively in review.", str(assignment.get("assignment_id") or ""), str(assignment.get("assigned_by") or actor or ""), str(assignment.get("assigned_role") or role or "")
    if target_state == "review_requested" and assignment:
        return "review_requested", "A review assignment is open.", str(assignment.get("assignment_id") or ""), str(assignment.get("assigned_by") or actor or ""), str(assignment.get("assigned_role") or role or "")
    event_type = "approval_synced"
    reason = f"Approval state synced as {approval_state}."
    if target_state in {"approved", "rejected", "frozen", "replay_only"}:
        reason = f"Approval state moved decision to {target_state}."
    return event_type, reason, "", str(actor or ""), str(role or "")



def _extract_approval_state(checkpoint: dict[str, Any]) -> str:
    checkpoint_copy = dict(checkpoint or {})
    approval = checkpoint_copy.get("approval")
    if isinstance(approval, dict):
        state = approval.get("state")
        if state:
            return coerce_approval_state(str(state))
    return coerce_approval_state(str(checkpoint_copy.get("approval_state") or "proposed"))



def _last_checkpoint(run: dict[str, Any]) -> dict[str, Any]:
    checkpoints = list(run.get("checkpoints") or [])
    if checkpoints:
        return dict(checkpoints[-1])
    return {}



def _open_assignment_count(assignments: list[dict[str, Any]]) -> int:
    count = 0
    for record in assignments:
        status = coerce_assignment_status(str(record.get("status") or "open"))
        if status != "completed":
            count += 1
    return count



def _latest_value(records: list[dict[str, Any]], field: str) -> str:
    latest = _latest_record(records)
    if not latest:
        return ""
    return str(latest.get(field) or "")



def _latest_record(records: list[dict[str, Any]] | None) -> dict[str, Any]:
    rows = _sorted_records(records)
    if not rows:
        return {}
    return dict(rows[-1])



def _sorted_records(records: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows = [dict(record) for record in list(records or [])]
    for row in rows:
        if "status" in row and row.get("event_type") == "assignment":
            row["status"] = coerce_assignment_status(str(row.get("status") or "open"))
        if "decision" in row and row.get("event_type") == "signoff":
            row["decision"] = coerce_signoff_decision(str(row.get("decision") or "acknowledged"))
        if "status" in row and row.get("event_type") == "handoff":
            row["status"] = coerce_handoff_status(str(row.get("status") or "pending"))
    rows.sort(key=lambda item: (_record_timestamp_key(item.get("ts")), str(item.get("event_type", ""))))
    return rows



def _normalize_tags(tags: Iterable[str] | None) -> list[str]:
    values: list[str] = []
    seen = set()
    for raw in list(tags or []):
        value = str(raw or "").strip()
        if not value:
            continue
        lowered = value.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        values.append(value)
    return values



def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "DECISION_SCHEMA_VERSION",
    "VALID_DECISION_EVENT_TYPES",
    "VALID_DECISION_STATES",
    "allowed_actions_for_state",
    "blockers_for_decision",
    "build_decision_case",
    "build_decision_case_from_run",
    "coerce_decision_state",
    "decision_summary",
    "derive_decision_state",
    "sync_decision_case",
]
