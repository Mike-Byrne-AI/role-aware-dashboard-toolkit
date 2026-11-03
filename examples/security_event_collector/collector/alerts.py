"""Four persistent alert conditions; acknowledgement never means resolution."""

import json
import secrets

from .event_wire import wire
from .storage import ServiceError, safe_json


def _transition(store, connection, row, state, now, details, severity=None):
    if connection.execute("SELECT COUNT(*) FROM alert_transitions").fetchone()[0] >= store.settings["max_transitions"]:
        raise ServiceError("storage_full", 507)
    number = row["number"] + 1
    severity = severity or row["severity"]
    frozen = wire.freeze_alert({"v": 1, "collector_id": store.settings["service_id"], "alert_id": row["id"],
                                "source_id": row["source_id"], "number": number, "at": now,
                                "rule": row["rule"], "severity": severity, "state": state, "details": details})
    connection.execute("INSERT INTO alert_transitions VALUES(?,?,?,?)", (row["id"], number, frozen.data, frozen.sha256))
    connection.execute("INSERT INTO alert_outbox(alert_id,number) VALUES(?,?)", (row["id"], number))
    acknowledged = int(state == "acknowledged") if state in {"opened", "escalated", "acknowledged"} else row["acknowledged"]
    connection.execute("UPDATE alert_cases SET number=?,severity=?,condition_open=?,acknowledged=?,last_observed=?,details=? WHERE id=?",
                       (number, severity, int(state != "resolved"), acknowledged, now, safe_json(details).decode("ascii"), row["id"]))


def observe(store, connection, rule, subject, condition, details, now, *, severity="warning"):
    row = connection.execute("SELECT * FROM alert_cases WHERE source_id=? AND rule=? AND subject=? AND condition_open=1",
                             (store.settings["source_id"], rule, subject)).fetchone()
    if not condition:
        if row:
            _transition(store, connection, row, "resolved", now, details)
        return
    if row is None:
        if connection.execute("SELECT COUNT(*) FROM alert_cases").fetchone()[0] >= store.settings["max_cases"]:
            raise ServiceError("storage_full", 507)
        case_id = secrets.token_hex(16)
        connection.execute("INSERT INTO alert_cases VALUES(?,?,?,?,?,1,0,0,?,?,?)", (
            case_id, store.settings["source_id"], rule, subject, severity, now, now, safe_json(details).decode("ascii"),
        ))
        row = connection.execute("SELECT * FROM alert_cases WHERE id=?", (case_id,)).fetchone()
        _transition(store, connection, row, "opened", now, details)
    elif severity == "critical" and row["severity"] != "critical":
        _transition(store, connection, row, "escalated", now, details, severity)
    else:
        connection.execute("UPDATE alert_cases SET last_observed=?,details=? WHERE id=?", (now, safe_json(details).decode("ascii"), row["id"]))


def evaluate(store, connection, now):
    store.advance_clock(connection, now)
    heartbeat = connection.execute("SELECT * FROM heartbeats WHERE source_id=?", (store.settings["source_id"],)).fetchone()
    seen = heartbeat["received_at"] if heartbeat else None
    deadline = (seen if seen is not None else store.settings["created_at"]) + store.settings["heartbeat_timeout"]
    observe(store, connection, "source_missing", "source", now > deadline,
            {"last_seen_at": seen, "deadline_at": float(deadline)}, now, severity="critical")
    if heartbeat:
        body = json.loads(heartbeat["body"])
        pending, oldest = body["pending_events"], body["oldest_pending_at"]
        untrusted = bool(heartbeat["clock_untrusted"])
        overdue = pending > 0 and (untrusted or now - oldest > store.settings["backlog_threshold"])
        observe(store, connection, "source_backlog", "source", overdue,
                {"pending_events": pending, "oldest_pending_at": oldest, "threshold_seconds": 0 if untrusted else store.settings["backlog_threshold"],
                 "basis": "clock_untrusted" if untrusted else "source_age"}, now,
                severity="critical" if untrusted else "warning")
    byte_used, byte_limit = store.event_byte_capacity(connection)
    for resource, used, limit in (
        ("events", connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], store.settings["max_events"]),
        ("bytes", byte_used, byte_limit),
        ("alert_cases", connection.execute("SELECT COUNT(*) FROM alert_cases").fetchone()[0], store.settings["max_cases"]),
        ("alert_transitions", connection.execute("SELECT COUNT(*) FROM alert_transitions").fetchone()[0], store.settings["max_transitions"]),
    ):
        observe(store, connection, "collector_capacity", resource, used * 5 >= limit * 4,
                {"resource": resource, "used": used, "limit": limit}, now,
                severity="critical" if used >= limit else "warning")


def acknowledge(store, connection, case_id, number, now, *, resolve=False):
    row = connection.execute("SELECT * FROM alert_cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        raise ServiceError("unavailable", 404)
    if not resolve and row["acknowledged"] and number in (row["number"], row["number"] - 1):
        return
    if type(number) is not int or number != row["number"] or not row["condition_open"]:
        raise ServiceError("identity_conflict", 409)
    if resolve and row["rule"] != "event_conflict":
        raise ServiceError("channel_forbidden", 403)
    _transition(store, connection, row, "resolved" if resolve else "acknowledged", now, json.loads(row["details"]))
