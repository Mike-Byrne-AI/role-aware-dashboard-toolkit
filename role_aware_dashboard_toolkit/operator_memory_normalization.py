from __future__ import annotations

from typing import Any

VALID_INCIDENT_SEVERITIES = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)


def summarize_incident_timeline(events_or_timeline: Any) -> dict[str, Any]:
    if isinstance(events_or_timeline, dict):
        events = list(events_or_timeline.get("events") or [])
    else:
        events = list(events_or_timeline or [])
    severity_counts = {level: 0 for level in VALID_INCIDENT_SEVERITIES}
    counts = {
        "event_count": len(events),
        "note_count": 0,
        "incident_count": 0,
        "open_incident_count": 0,
        "telemetry_alert_count": 0,
        "decision_event_count": 0,
        "handoff_count": 0,
    }
    highlights: list[dict[str, Any]] = []
    for item in events:
        event_type = str(item.get("event_type") or "")
        severity = str(item.get("severity") or "info")
        if severity in severity_counts:
            severity_counts[severity] += 1
        if event_type in {"note", "annotation"}:
            counts["note_count"] += 1
        if event_type == "incident":
            counts["incident_count"] += 1
            status = str((item.get("refs") or {}).get("incident_status") or item.get("incident_status") or "open")
            if status != "closed":
                counts["open_incident_count"] += 1
        if event_type == "telemetry_alert":
            counts["telemetry_alert_count"] += 1
        if event_type == "decision_state":
            counts["decision_event_count"] += 1
        if event_type == "handoff":
            counts["handoff_count"] += 1
        if severity in {"high", "critical"}:
            highlights.append(
                {
                    "ts": item.get("ts", ""),
                    "event_type": event_type,
                    "title": item.get("title", ""),
                    "detail": item.get("detail", ""),
                    "severity": severity,
                }
            )
    latest = events[-1] if events else {}
    return {
        **counts,
        "severity_counts": severity_counts,
        "latest_event": {
            "ts": latest.get("ts", ""),
            "event_type": latest.get("event_type", ""),
            "title": latest.get("title", ""),
        },
        "highlights": highlights[-5:],
    }


__all__ = ["VALID_INCIDENT_SEVERITIES", "summarize_incident_timeline"]
