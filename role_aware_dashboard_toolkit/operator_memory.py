from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from collections.abc import Iterable
from uuid import uuid4

from .operator_memory_normalization import (
    VALID_INCIDENT_SEVERITIES,
    summarize_incident_timeline as _summarize_incident_timeline,
)
from ._record_utils import normalize_string_list as _normalize_string_list_shared

OPERATOR_MEMORY_SCHEMA_VERSION = 1
VALID_MEMORY_EVENT_TYPES = (
    "note",
    "annotation",
    "incident",
    "narrative_handoff",
    "incident_timeline",
)
VALID_NOTE_EVENT_TYPES = (
    "note",
    "annotation",
)
VALID_INCIDENT_STATUSES = (
    "open",
    "monitoring",
    "mitigated",
    "closed",
)
VALID_NOTE_IMPORTANCE = (
    "low",
    "normal",
    "high",
)


def build_operator_note(
    body: str,
    *,
    run_id: str,
    checkpoint_id: str = "",
    decision_id: str = "",
    note_id: str = "",
    actor: str = "",
    role: str = "",
    event_type: str = "note",
    importance: str = "normal",
    tags: Iterable[str] | None = None,
    source: str = "ui",
) -> dict[str, Any]:
    text = str(body or "").strip()
    if not text:
        raise ValueError("Operator note body must not be empty.")
    note_type = coerce_note_event_type(event_type)
    return {
        "schema_version": OPERATOR_MEMORY_SCHEMA_VERSION,
        "event_type": note_type,
        "note_id": str(note_id or f"note_{uuid4().hex[:12]}"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": str(run_id or ""),
        "checkpoint_id": str(checkpoint_id or ""),
        "decision_id": str(decision_id or ""),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "body": text,
        "importance": coerce_note_importance(importance),
        "tags": normalize_string_list(tags),
        "source": str(source or "ui"),
    }



def build_incident_record(
    run_id: str,
    title: str,
    *,
    checkpoint_id: str = "",
    decision_id: str = "",
    incident_id: str = "",
    actor: str = "",
    role: str = "",
    severity: str = "medium",
    status: str = "open",
    summary: str = "",
    suspected_cause: str = "",
    impact: str = "",
    tags: Iterable[str] | None = None,
    source: str = "ui",
) -> dict[str, Any]:
    heading = str(title or "").strip()
    if not heading:
        raise ValueError("Incident title must not be empty.")
    return {
        "schema_version": OPERATOR_MEMORY_SCHEMA_VERSION,
        "event_type": "incident",
        "incident_id": str(incident_id or f"incident_{uuid4().hex[:12]}"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": str(run_id or ""),
        "checkpoint_id": str(checkpoint_id or ""),
        "decision_id": str(decision_id or ""),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "title": heading,
        "summary": str(summary or ""),
        "severity": coerce_incident_severity(severity),
        "status": coerce_incident_status(status),
        "suspected_cause": str(suspected_cause or ""),
        "impact": str(impact or ""),
        "tags": normalize_string_list(tags),
        "source": str(source or "ui"),
    }



def build_incident_timeline(
    run: dict[str, Any],
    *,
    checkpoints: list[dict[str, Any]] | None = None,
    decisions: list[dict[str, Any]] | None = None,
    notes: list[dict[str, Any]] | None = None,
    incidents: list[dict[str, Any]] | None = None,
    audit_events: list[dict[str, Any]] | None = None,
    telemetry_history: list[dict[str, Any]] | None = None,
    handoffs: list[dict[str, Any]] | None = None,
    max_items: int = 80,
) -> dict[str, Any]:
    run_copy = dict(run or {})
    run_id = str(run_copy.get("run_id") or "")
    items: list[dict[str, Any]] = []
    if run_copy.get("started_at"):
        items.append(
            _timeline_event(
                str(run_copy.get("started_at") or ""),
                "run_start",
                "Run started",
                str(run_copy.get("notes") or "")[:240],
                refs={"run_id": run_id},
                actor=str(run_copy.get("actor") or ""),
                role=str(run_copy.get("role") or ""),
                source=str(run_copy.get("source") or ""),
            )
        )
    for checkpoint in list(checkpoints if checkpoints is not None else run_copy.get("checkpoints") or []):
        label = str(checkpoint.get("label") or checkpoint.get("checkpoint_id") or "Checkpoint")
        detail = str(checkpoint.get("reason") or "")
        approval = str(checkpoint.get("approval_state") or "")
        if approval:
            detail = f"{detail} | approval={approval}".strip(" |")
        items.append(
            _timeline_event(
                str(checkpoint.get("ts") or ""),
                "checkpoint",
                label,
                detail,
                severity="medium" if approval == "rejected" else "info",
                refs={
                    "run_id": run_id,
                    "checkpoint_id": str(checkpoint.get("checkpoint_id") or ""),
                },
                actor=str(checkpoint.get("actor") or ""),
                role=str(checkpoint.get("role") or ""),
                source=str(checkpoint.get("source") or ""),
            )
        )
    for decision in list(decisions or []):
        state = str(decision.get("state") or "unknown")
        blockers = list(decision.get("blockers") or [])
        severity = "high" if blockers else ("info" if state in {"approved", "closed"} else "medium")
        detail = f"state={state}; blockers={len(blockers)}; actions={len(list(decision.get('allowed_actions') or []))}"
        items.append(
            _timeline_event(
                str(decision.get("updated_at") or decision.get("created_at") or ""),
                "decision_state",
                f"Decision {state}",
                detail,
                severity=severity,
                refs={
                    "run_id": run_id,
                    "checkpoint_id": str(decision.get("checkpoint_id") or ""),
                    "decision_id": str(decision.get("decision_id") or ""),
                },
                actor=str(decision.get("actor") or ""),
                role=str(decision.get("role") or ""),
                source=str(decision.get("source") or ""),
            )
        )
    for note in list(notes or []):
        items.append(
            _timeline_event(
                str(note.get("ts") or ""),
                str(note.get("event_type") or "note"),
                f"Operator {note.get('event_type') or 'note'!s}",
                str(note.get("body") or "")[:320],
                severity=_importance_to_severity(str(note.get("importance") or "normal")),
                refs={
                    "run_id": str(note.get("run_id") or run_id),
                    "checkpoint_id": str(note.get("checkpoint_id") or ""),
                    "decision_id": str(note.get("decision_id") or ""),
                    "note_id": str(note.get("note_id") or ""),
                },
                actor=str(note.get("actor") or ""),
                role=str(note.get("role") or ""),
                source=str(note.get("source") or ""),
            )
        )
    for incident in list(incidents or []):
        detail_parts = [f"status={incident.get('status', '')}".strip()]
        if incident.get("summary"):
            detail_parts.append(str(incident.get("summary") or "")[:220])
        if incident.get("suspected_cause"):
            detail_parts.append(f"suspected_cause={str(incident.get('suspected_cause') or '')[:120]}")
        items.append(
            _timeline_event(
                str(incident.get("ts") or ""),
                "incident",
                str(incident.get("title") or "Incident"),
                " | ".join(part for part in detail_parts if part),
                severity=str(incident.get("severity") or "medium"),
                refs={
                    "run_id": str(incident.get("run_id") or run_id),
                    "checkpoint_id": str(incident.get("checkpoint_id") or ""),
                    "decision_id": str(incident.get("decision_id") or ""),
                    "incident_id": str(incident.get("incident_id") or ""),
                },
                actor=str(incident.get("actor") or ""),
                role=str(incident.get("role") or ""),
                source=str(incident.get("source") or ""),
            )
        )
    for audit in list(audit_events or []):
        items.append(
            _timeline_event(
                str(audit.get("ts") or ""),
                "audit_event",
                str(audit.get("type") or "audit_event"),
                str(audit.get("detail") or "")[:220],
                severity="medium" if str(audit.get("type") or "") in {"freeze", "checkpoint_replay"} else "info",
                refs={"run_id": run_id},
                actor=str(audit.get("actor") or ""),
                role=str(audit.get("role") or ""),
                source=str(audit.get("source") or ""),
            )
        )
    for sample in list(telemetry_history or []):
        alert = _telemetry_alert_event(sample, run_id=run_id)
        if alert is not None:
            items.append(alert)
    for handoff in list(handoffs or []):
        items.append(
            _timeline_event(
                str(handoff.get("ts") or ""),
                "handoff",
                f"Handoff to {handoff.get('handoff_to') or ''!s}".strip() or "Handoff",
                str(handoff.get("notes") or "")[:220],
                severity="medium" if str(handoff.get("status") or "") == "pending" else "info",
                refs={
                    "run_id": str(handoff.get("run_id") or run_id),
                    "checkpoint_id": str(handoff.get("checkpoint_id") or ""),
                    "handoff_id": str(handoff.get("handoff_id") or ""),
                },
                actor=str(handoff.get("actor") or ""),
                role=str(handoff.get("role") or ""),
                source=str(handoff.get("source") or ""),
            )
        )

    items.sort(key=lambda item: (str(item.get("ts") or ""), str(item.get("event_id") or "")))
    if max_items > 0:
        items = items[-int(max_items):]
    timeline_id = f"timeline_{run_id or 'default'}"
    timeline = {
        "schema_version": OPERATOR_MEMORY_SCHEMA_VERSION,
        "event_type": "incident_timeline",
        "timeline_id": timeline_id,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events": items,
        "summary": summarize_incident_timeline(items),
    }
    return timeline



def summarize_incident_timeline(events_or_timeline: Any) -> dict[str, Any]:
    return _summarize_incident_timeline(events_or_timeline)



def build_operator_summary(
    run: dict[str, Any],
    *,
    timeline: dict[str, Any],
    decisions: list[dict[str, Any]] | None = None,
    incidents: list[dict[str, Any]] | None = None,
    max_items: int = 5,
) -> dict[str, Any]:
    events = list(timeline.get("events") or [])
    summary = dict(timeline.get("summary") or summarize_incident_timeline(events))
    recent_events = list(reversed(events[-max(1, int(max_items)):]))
    open_incidents = [item for item in list(incidents or []) if str(item.get("status") or "open") != "closed"]
    latest_decision_state = ""
    if decisions:
        latest_decision = sorted(
            list(decisions),
            key=lambda item: (str(item.get("updated_at") or item.get("created_at") or ""), str(item.get("decision_id") or "")),
        )[-1]
        latest_decision_state = str(latest_decision.get("state") or "")
    possible_contributors = []
    for event in recent_events:
        if str(event.get("event_type") or "") in {"checkpoint", "decision_state", "telemetry_alert", "incident"}:
            possible_contributors.append(
                {
                    "ts": event.get("ts", ""),
                    "event_type": event.get("event_type", ""),
                    "title": event.get("title", ""),
                    "detail": event.get("detail", ""),
                    "severity": event.get("severity", "info"),
                }
            )
    narrative_parts = []
    narrative_parts.append(
        f"Run {run.get('run_id') or ''!s} has {summary.get('event_count', 0)} tracked timeline events and {len(open_incidents)} open incident(s)."
    )
    if latest_decision_state:
        narrative_parts.append(f"Latest decision state: {latest_decision_state}.")
    latest_event = summary.get("latest_event") or {}
    if latest_event:
        narrative_parts.append(
            f"Latest timeline event: {latest_event.get('event_type', '')} at {latest_event.get('ts', '')} ({latest_event.get('title', '')})."
        )
    if possible_contributors:
        labels = ", ".join(str(item.get("title") or item.get("event_type") or "") for item in possible_contributors[:3])
        narrative_parts.append(f"Recent signals to review: {labels}.")
    return {
        "run_id": str(run.get("run_id") or ""),
        "latest_checkpoint_id": str(run.get("last_checkpoint_id") or ""),
        "latest_decision_state": latest_decision_state,
        "open_incident_count": len(open_incidents),
        "possible_contributors": possible_contributors,
        "descriptive_only": True,
        "disclaimer": "This summary describes temporal adjacency across operator records. It does not prove causation.",
        "narrative": " ".join(part for part in narrative_parts if part).strip(),
    }



def build_narrative_handoff_packet(
    run: dict[str, Any],
    *,
    timeline: dict[str, Any] | None = None,
    decisions: list[dict[str, Any]] | None = None,
    incidents: list[dict[str, Any]] | None = None,
    handoff_to: str = "",
    actor: str = "",
    role: str = "",
    source: str = "ui",
    source_version: str = "",
    narrative_id: str = "",
    max_items: int = 8,
) -> dict[str, Any]:
    timeline = timeline or build_incident_timeline(run, decisions=decisions, incidents=incidents)
    operator_summary = build_operator_summary(run, timeline=timeline, decisions=decisions, incidents=incidents, max_items=max_items)
    highlights = [
        {
            "ts": item.get("ts", ""),
            "event_type": item.get("event_type", ""),
            "title": item.get("title", ""),
            "detail": item.get("detail", ""),
            "severity": item.get("severity", "info"),
        }
        for item in list(reversed(list(timeline.get("events") or [])[-max(1, int(max_items)):]))
    ]
    return {
        "schema_version": OPERATOR_MEMORY_SCHEMA_VERSION,
        "event_type": "narrative_handoff",
        "narrative_id": str(narrative_id or f"narrative_{uuid4().hex[:12]}"),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "run_id": str(run.get("run_id") or ""),
        "checkpoint_id": str(run.get("last_checkpoint_id") or ""),
        "handoff_to": str(handoff_to or ""),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "source": str(source or "ui"),
        "source_version": str(source_version or ""),
        "headline": f"Run {run.get('run_id') or ''!s} handoff",
        "narrative": str(operator_summary.get("narrative") or ""),
        "summary": operator_summary,
        "highlights": highlights,
        "refs": {
            "run_id": str(run.get("run_id") or ""),
            "checkpoint_id": str(run.get("last_checkpoint_id") or ""),
            "decision_ids": [str(item.get("decision_id") or "") for item in list(decisions or []) if str(item.get("decision_id") or "")],
            "incident_ids": [str(item.get("incident_id") or "") for item in list(incidents or []) if str(item.get("incident_id") or "")],
        },
    }



def coerce_note_event_type(event_type: str) -> str:
    value = str(event_type or "note").strip().lower() or "note"
    if value not in VALID_NOTE_EVENT_TYPES:
        raise ValueError(f"Invalid note event_type '{event_type}'. Must be one of {VALID_NOTE_EVENT_TYPES}")
    return value



def coerce_note_importance(importance: str) -> str:
    value = str(importance or "normal").strip().lower() or "normal"
    if value not in VALID_NOTE_IMPORTANCE:
        raise ValueError(f"Invalid note importance '{importance}'. Must be one of {VALID_NOTE_IMPORTANCE}")
    return value



def coerce_incident_severity(severity: str) -> str:
    value = str(severity or "medium").strip().lower() or "medium"
    if value not in VALID_INCIDENT_SEVERITIES:
        raise ValueError(f"Invalid incident severity '{severity}'. Must be one of {VALID_INCIDENT_SEVERITIES}")
    return value



def coerce_incident_status(status: str) -> str:
    value = str(status or "open").strip().lower() or "open"
    if value not in VALID_INCIDENT_STATUSES:
        raise ValueError(f"Invalid incident status '{status}'. Must be one of {VALID_INCIDENT_STATUSES}")
    return value



def normalize_string_list(values: Iterable[str] | None) -> list[str]:
    return _normalize_string_list_shared(values)



def _timeline_event(
    ts: str,
    event_type: str,
    title: str,
    detail: str,
    *,
    severity: str = "info",
    refs: dict[str, Any] | None = None,
    actor: str = "",
    role: str = "",
    source: str = "",
) -> dict[str, Any]:
    event_id = f"event_{uuid4().hex[:12]}"
    record = {
        "event_id": event_id,
        "ts": str(ts or ""),
        "event_type": str(event_type or ""),
        "title": str(title or ""),
        "detail": str(detail or ""),
        "severity": coerce_incident_severity(severity if severity in VALID_INCIDENT_SEVERITIES else "info"),
        "refs": dict(refs or {}),
        "actor": str(actor or ""),
        "role": str(role or ""),
        "source": str(source or ""),
    }
    if "incident_id" in record["refs"] and "incident_status" not in record["refs"]:
        record["refs"]["incident_status"] = "open"
    return record



def _importance_to_severity(importance: str) -> str:
    mapping = {
        "low": "low",
        "normal": "info",
        "high": "medium",
    }
    return mapping.get(str(importance or "normal").strip().lower(), "info")



def _telemetry_alert_event(sample: dict[str, Any], *, run_id: str) -> dict[str, Any] | None:
    if not isinstance(sample, dict):
        return None
    health = dict(sample.get("health") or {})
    metrics = dict(sample.get("metrics") or {})
    status = str(health.get("status") or "").strip().lower()
    risk_score = _safe_float(metrics.get("risk_score"))
    latency = _safe_float(metrics.get("latency_ms"))
    should_emit = False
    reasons: list[str] = []
    severity = "info"
    if status and status not in {"ok", "healthy", "normal"}:
        should_emit = True
        reasons.append(f"health.status={status}")
        severity = "high" if status in {"error", "critical"} else "medium"
    if risk_score is not None and risk_score >= 0.8:
        should_emit = True
        reasons.append(f"risk_score={risk_score}")
        severity = "high"
    if latency is not None and latency >= 500:
        should_emit = True
        reasons.append(f"latency_ms={latency}")
        if severity == "info":
            severity = "medium"
    if not should_emit:
        return None
    title = "Telemetry alert"
    detail = "; ".join(reasons)
    return _timeline_event(
        str(sample.get("ts") or ""),
        "telemetry_alert",
        title,
        detail,
        severity=severity,
        refs={"run_id": run_id},
        source=str(sample.get("source") or sample.get("service") or "telemetry"),
    )



def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


__all__ = [
    "OPERATOR_MEMORY_SCHEMA_VERSION",
    "VALID_INCIDENT_SEVERITIES",
    "VALID_INCIDENT_STATUSES",
    "VALID_MEMORY_EVENT_TYPES",
    "VALID_NOTE_EVENT_TYPES",
    "VALID_NOTE_IMPORTANCE",
    "build_incident_record",
    "build_incident_timeline",
    "build_narrative_handoff_packet",
    "build_operator_note",
    "build_operator_summary",
    "coerce_incident_severity",
    "coerce_incident_status",
    "coerce_note_event_type",
    "coerce_note_importance",
    "normalize_string_list",
    "summarize_incident_timeline",
]
