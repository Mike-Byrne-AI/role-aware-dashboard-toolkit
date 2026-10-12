from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from collections.abc import Iterable
from uuid import uuid4

from ._record_utils import normalize_string_list as _normalize_string_list_shared
from ._record_utils import _record_timestamp_key

CASEBOARD_SCHEMA_VERSION = 1
VALID_CASE_STATES = (
    "open",
    "investigating",
    "monitoring",
    "mitigated",
    "closed",
)
VALID_CASE_PRIORITIES = (
    "low",
    "normal",
    "high",
    "critical",
)
VALID_CASE_EVENT_TYPES = (
    "case_created",
    "run_linked",
    "incident_linked",
    "narrative_linked",
    "decision_linked",
    "checkpoint_linked",
    "note_added",
    "status_changed",
    "reopened",
    "closed",
)


def coerce_case_state(state: str) -> str:
    value = str(state or "open").strip().lower() or "open"
    if value not in VALID_CASE_STATES:
        raise ValueError(f"Invalid case state '{state}'. Must be one of {VALID_CASE_STATES}")
    return value



def coerce_case_priority(priority: str) -> str:
    value = str(priority or "normal").strip().lower() or "normal"
    if value not in VALID_CASE_PRIORITIES:
        raise ValueError(f"Invalid case priority '{priority}'. Must be one of {VALID_CASE_PRIORITIES}")
    return value



def build_case_record(
    title: str,
    *,
    case_id: str = "",
    summary: str = "",
    state: str = "open",
    priority: str = "normal",
    actor: str = "",
    role: str = "",
    source: str = "ui",
    tags: Iterable[str] | None = None,
    linked_run_ids: Iterable[str] | None = None,
    linked_checkpoint_ids: Iterable[str] | None = None,
    linked_decision_ids: Iterable[str] | None = None,
    linked_incident_ids: Iterable[str] | None = None,
    linked_narrative_ids: Iterable[str] | None = None,
    linked_note_ids: Iterable[str] | None = None,
    hypotheses: Iterable[str] | None = None,
    findings: Iterable[str] | None = None,
) -> dict[str, Any]:
    heading = str(title or "").strip()
    if not heading:
        raise ValueError("Case title must not be empty.")
    created_at = datetime.now(timezone.utc).isoformat()
    record = {
        "schema_version": CASEBOARD_SCHEMA_VERSION,
        "case_id": str(case_id or f"case_{uuid4().hex[:12]}"),
        "created_at": created_at,
        "updated_at": created_at,
        "title": heading,
        "summary": str(summary or ""),
        "state": coerce_case_state(state),
        "priority": coerce_case_priority(priority),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "source": str(source or "ui"),
        "tags": _normalize_string_list(tags),
        "linked_run_ids": _normalize_string_list(linked_run_ids),
        "linked_checkpoint_ids": _normalize_string_list(linked_checkpoint_ids),
        "linked_decision_ids": _normalize_string_list(linked_decision_ids),
        "linked_incident_ids": _normalize_string_list(linked_incident_ids),
        "linked_narrative_ids": _normalize_string_list(linked_narrative_ids),
        "linked_note_ids": _normalize_string_list(linked_note_ids),
        "hypotheses": _normalize_string_list(hypotheses),
        "findings": _normalize_string_list(findings),
        "history": [],
    }
    return append_case_event(
        record,
        "case_created",
        detail="Case created.",
        actor=actor,
        role=role,
        source=source,
        refs={
            "run_ids": list(record.get("linked_run_ids") or []),
            "incident_ids": list(record.get("linked_incident_ids") or []),
        },
    )



def append_case_event(
    case: dict[str, Any],
    event_type: str,
    *,
    detail: str = "",
    actor: str = "",
    role: str = "",
    source: str = "ui",
    refs: dict[str, Any] | None = None,
    from_state: str = "",
    to_state: str = "",
) -> dict[str, Any]:
    kind = str(event_type or "").strip().lower()
    if kind not in VALID_CASE_EVENT_TYPES:
        raise ValueError(f"Invalid case event_type '{event_type}'. Must be one of {VALID_CASE_EVENT_TYPES}")
    updated = _clone(case)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event_type": kind,
        "detail": str(detail or ""),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "source": str(source or "ui"),
        "refs": dict(refs or {}),
    }
    if from_state or to_state:
        entry["from_state"] = str(from_state or "")
        entry["to_state"] = str(to_state or "")
    history = list(updated.get("history") or [])
    history.append(entry)
    updated["history"] = history
    updated["updated_at"] = entry["ts"]
    return updated



def link_case_records(
    case: dict[str, Any],
    *,
    run_ids: Iterable[str] | None = None,
    checkpoint_ids: Iterable[str] | None = None,
    decision_ids: Iterable[str] | None = None,
    incident_ids: Iterable[str] | None = None,
    narrative_ids: Iterable[str] | None = None,
    note_ids: Iterable[str] | None = None,
    actor: str = "",
    role: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    updated = _clone(case)
    for field, values, event_type in (
        ("linked_run_ids", run_ids, "run_linked"),
        ("linked_checkpoint_ids", checkpoint_ids, "checkpoint_linked"),
        ("linked_decision_ids", decision_ids, "decision_linked"),
        ("linked_incident_ids", incident_ids, "incident_linked"),
        ("linked_narrative_ids", narrative_ids, "narrative_linked"),
        ("linked_note_ids", note_ids, "note_added"),
    ):
        incoming = _normalize_string_list(values)
        if not incoming:
            continue
        existing = list(updated.get(field) or [])
        merged = _merge_unique(existing, incoming)
        added = [item for item in incoming if item not in existing]
        updated[field] = merged
        if added:
            updated = append_case_event(
                updated,
                event_type,
                detail=f"Linked {len(added)} item(s) into {field}.",
                actor=actor,
                role=role,
                source=source,
                refs={field: added},
            )
    return updated



def add_case_notes(
    case: dict[str, Any],
    notes: Iterable[str],
    *,
    actor: str = "",
    role: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    updated = _clone(case)
    incoming = _normalize_string_list(notes)
    if not incoming:
        return updated
    findings = _merge_unique(list(updated.get("findings") or []), incoming)
    updated["findings"] = findings
    return append_case_event(
        updated,
        "note_added",
        detail=f"Added {len(incoming)} investigation note(s).",
        actor=actor,
        role=role,
        source=source,
        refs={"notes": incoming},
    )



def set_case_state(
    case: dict[str, Any],
    state: str,
    *,
    reason: str = "",
    actor: str = "",
    role: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    updated = _clone(case)
    next_state = coerce_case_state(state)
    current_state = str(updated.get("state") or "open")
    if current_state == next_state:
        return updated
    updated["state"] = next_state
    event_type = "status_changed"
    if next_state == "closed":
        event_type = "closed"
    elif current_state == "closed" and next_state != "closed":
        event_type = "reopened"
    return append_case_event(
        updated,
        event_type,
        detail=str(reason or f"Case state changed to {next_state}."),
        actor=actor,
        role=role,
        source=source,
        from_state=current_state,
        to_state=next_state,
    )



def reopen_case(
    case: dict[str, Any],
    *,
    reason: str = "",
    actor: str = "",
    role: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    return set_case_state(
        case,
        "investigating",
        reason=str(reason or "Case reopened for further investigation."),
        actor=actor,
        role=role,
        source=source,
    )



def close_case(
    case: dict[str, Any],
    *,
    reason: str = "",
    actor: str = "",
    role: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    return set_case_state(
        case,
        "closed",
        reason=str(reason or "Case closed."),
        actor=actor,
        role=role,
        source=source,
    )



def build_case_from_records(
    title: str,
    *,
    incidents: list[dict[str, Any]] | None = None,
    narratives: list[dict[str, Any]] | None = None,
    notes: list[dict[str, Any]] | None = None,
    actor: str = "",
    role: str = "",
    source: str = "ui",
    priority: str = "normal",
    state: str = "open",
) -> dict[str, Any]:
    incidents = list(incidents or [])
    narratives = list(narratives or [])
    notes = list(notes or [])
    run_ids = _normalize_string_list(item.get("run_id") for item in incidents + narratives + notes)
    checkpoint_ids = _normalize_string_list(item.get("checkpoint_id") for item in incidents + narratives + notes)
    decision_ids = _normalize_string_list(item.get("decision_id") for item in incidents + notes)
    case = build_case_record(
        title,
        summary=_auto_summary(incidents=incidents, narratives=narratives, notes=notes),
        actor=actor,
        role=role,
        source=source,
        priority=priority,
        state=state,
        linked_run_ids=run_ids,
        linked_checkpoint_ids=checkpoint_ids,
        linked_decision_ids=decision_ids,
        linked_incident_ids=[item.get("incident_id") for item in incidents],
        linked_narrative_ids=[item.get("narrative_id") for item in narratives],
        linked_note_ids=[item.get("note_id") for item in notes],
        findings=[item.get("title") or item.get("body") for item in incidents + notes],
    )
    return case



def case_summary(case: dict[str, Any]) -> dict[str, Any]:
    history = list(case.get("history") or [])
    return {
        "case_id": str(case.get("case_id") or ""),
        "title": str(case.get("title") or ""),
        "state": str(case.get("state") or ""),
        "priority": str(case.get("priority") or ""),
        "run_count": len(list(case.get("linked_run_ids") or [])),
        "incident_count": len(list(case.get("linked_incident_ids") or [])),
        "narrative_count": len(list(case.get("linked_narrative_ids") or [])),
        "note_count": len(list(case.get("linked_note_ids") or [])),
        "history_count": len(history),
        "updated_at": str(case.get("updated_at") or ""),
        "summary": str(case.get("summary") or ""),
    }



def compare_cases(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_runs = set(str(item) for item in list(left.get("linked_run_ids") or []))
    right_runs = set(str(item) for item in list(right.get("linked_run_ids") or []))
    left_incidents = set(str(item) for item in list(left.get("linked_incident_ids") or []))
    right_incidents = set(str(item) for item in list(right.get("linked_incident_ids") or []))
    return {
        "left_case_id": str(left.get("case_id") or ""),
        "right_case_id": str(right.get("case_id") or ""),
        "state": {"left": str(left.get("state") or ""), "right": str(right.get("state") or "")},
        "priority": {"left": str(left.get("priority") or ""), "right": str(right.get("priority") or "")},
        "runs_only_in_left": sorted(left_runs - right_runs),
        "runs_only_in_right": sorted(right_runs - left_runs),
        "shared_runs": sorted(left_runs & right_runs),
        "incidents_only_in_left": sorted(left_incidents - right_incidents),
        "incidents_only_in_right": sorted(right_incidents - left_incidents),
        "shared_incidents": sorted(left_incidents & right_incidents),
        "history_count": {"left": len(list(left.get("history") or [])), "right": len(list(right.get("history") or []))},
    }



def summarize_caseboard(cases: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(cases or [])
    counts = {state: 0 for state in VALID_CASE_STATES}
    priorities = {priority: 0 for priority in VALID_CASE_PRIORITIES}
    run_ids = set()
    incident_ids = set()
    for row in rows:
        state = str(row.get("state") or "")
        priority = str(row.get("priority") or "")
        if state in counts:
            counts[state] += 1
        if priority in priorities:
            priorities[priority] += 1
        run_ids.update(str(item) for item in list(row.get("linked_run_ids") or []))
        incident_ids.update(str(item) for item in list(row.get("linked_incident_ids") or []))
    latest = sorted(
        rows,
        key=lambda item: (_record_timestamp_key(item.get("updated_at") or item.get("created_at")), str(item.get("case_id") or "")),
    )[-1] if rows else {}
    return {
        "case_count": len(rows),
        "state_counts": counts,
        "priority_counts": priorities,
        "linked_run_count": len(run_ids),
        "linked_incident_count": len(incident_ids),
        "latest_case": case_summary(latest) if latest else {},
    }



def _auto_summary(*, incidents: list[dict[str, Any]], narratives: list[dict[str, Any]], notes: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    if incidents:
        parts.append(f"{len(incidents)} linked incident(s)")
    if narratives:
        parts.append(f"{len(narratives)} narrative packet(s)")
    if notes:
        parts.append(f"{len(notes)} operator note(s)")
    return "; ".join(parts)



def _merge_unique(existing: list[str], incoming: list[str]) -> list[str]:
    merged = list(existing)
    seen = set(existing)
    for item in incoming:
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    return merged



def _normalize_string_list(values: Iterable[Any] | None) -> list[str]:
    return _normalize_string_list_shared(values, case_sensitive=True)



def _clone(record: dict[str, Any]) -> dict[str, Any]:
    cloned: dict[str, Any] = {}
    for key, value in dict(record or {}).items():
        if isinstance(value, list):
            cloned[key] = [dict(item) if isinstance(item, dict) else item for item in value]
        elif isinstance(value, dict):
            cloned[key] = dict(value)
        else:
            cloned[key] = value
    return cloned


__all__ = [
    "CASEBOARD_SCHEMA_VERSION",
    "VALID_CASE_EVENT_TYPES",
    "VALID_CASE_PRIORITIES",
    "VALID_CASE_STATES",
    "add_case_notes",
    "append_case_event",
    "build_case_from_records",
    "build_case_record",
    "case_summary",
    "close_case",
    "coerce_case_priority",
    "coerce_case_state",
    "compare_cases",
    "link_case_records",
    "reopen_case",
    "set_case_state",
    "summarize_caseboard",
]
