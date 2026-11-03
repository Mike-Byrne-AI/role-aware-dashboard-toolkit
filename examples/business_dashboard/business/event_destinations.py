"""Durable destination identity and frozen source events; no network operations."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
import time
from urllib.parse import urlsplit

from .event_wire import wire

LOCAL_DESTINATION = "local-v1"
MAX_TIME = 253402300799.0
MAX_COUNTER = 2**63 - 1
_ID = re.compile(r"[0-9a-f]{32}\Z")
DELIVERY_ERRORS = frozenset({
    "config_unavailable", "transport_failed", "tls_failed", "remote_auth_failed",
    "remote_conflict", "remote_capacity", "remote_throttled", "remote_unavailable", "invalid_receipt",
})


def _time(value=None):
    value = time.time() if value is None else value
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= MAX_TIME:
        raise ValueError("Invalid security delivery time.")
    if value == 0 and math.copysign(1, value) < 0:
        raise ValueError("Invalid security delivery time.")
    return float(value)


def _transaction(connection):
    if not connection.in_transaction:
        raise ValueError("Security delivery changes require the action transaction.")


@dataclass(frozen=True)
class DestinationDescriptor:
    destination_id: str
    collector_id: str
    endpoint: str
    config_revision: int = 1

    def __post_init__(self):
        if (not isinstance(self.destination_id, str) or not _ID.fullmatch(self.destination_id)
                or not isinstance(self.collector_id, str) or not _ID.fullmatch(self.collector_id)
                or type(self.config_revision) is not int or not 1 <= self.config_revision <= MAX_COUNTER
                or not isinstance(self.endpoint, str) or not self.endpoint.isascii()
                or len(self.endpoint) > 2048 or any(ord(char) <= 32 or ord(char) == 127 for char in self.endpoint)
                or any(char in self.endpoint for char in ("%", "\\"))):
            raise ValueError("Invalid security destination descriptor.")
        try:
            parts = urlsplit(self.endpoint)
            valid = (parts.scheme == "https" and parts.hostname and parts.netloc
                     and parts.username is None and parts.password is None and not parts.query and not parts.fragment
                     and parts.path == "/v1/events" and parts.port != 0 and self.endpoint == parts.geturl())
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Security destinations require a fixed HTTPS events endpoint.")


def source_identity(connection):
    row = connection.execute("SELECT * FROM security_delivery_identity WHERE id=1").fetchone()
    if (row is None or not isinstance(row["source_id"], str) or not _ID.fullmatch(row["source_id"])
            or type(row["heartbeat_sequence"]) is not int or not 0 <= row["heartbeat_sequence"] <= MAX_COUNTER):
        raise ValueError("Security delivery identity is unavailable or invalid.")
    return dict(row)


def load_event_payload(connection, event_id):
    """Validate and copy stored bytes without consulting the current serializer."""
    row = connection.execute("SELECT * FROM security_event_payloads WHERE event_id=?", (event_id,)).fetchone()
    if row is None or row["protocol_version"] != 1:
        raise ValueError("A frozen security event payload is unavailable.")
    frozen = wire.from_stored(row["canonical_payload"], row["payload_sha256"], kind="event")
    content = json.loads(frozen.data)
    if content["source_id"] != source_identity(connection)["source_id"] or content["event"]["id"] != event_id:
        raise ValueError("A frozen security event has the wrong source identity.")
    return frozen


def freeze_new_event(connection, event_id, *, queued_at=None):
    _transaction(connection)
    now = _time(queued_at)
    if connection.execute("SELECT 1 FROM security_destinations WHERE destination_id=? AND kind='local' AND state='active'",
                          (LOCAL_DESTINATION,)).fetchone() is None:
        raise ValueError("The required local security destination is unavailable.")
    event = connection.execute("SELECT * FROM security_events WHERE id=?", (event_id,)).fetchone()
    if event is None:
        raise ValueError("The required security event is unavailable.")
    frozen = wire.freeze_event(source_identity(connection)["source_id"], dict(event))
    connection.execute("INSERT INTO security_event_payloads VALUES(?,1,?,?)", (event_id, frozen.data, frozen.sha256))
    connection.execute(
        "INSERT INTO security_delivery_obligations(destination_id,event_id,payload_sha256,kind,queued_at) "
        "SELECT destination_id,?,?,'live',? FROM security_destinations WHERE state='active'",
        (event_id, frozen.sha256, now),
    )
    return frozen


def freeze_retained_events(connection, previous):
    """Only the explicit eight-to-nine migration calls this one-time serializer."""
    _transaction(connection)
    now = _time()
    source_id = source_identity(connection)["source_id"]
    previous = {row["event_id"]: row for row in previous}
    for event in connection.execute("SELECT * FROM security_events ORDER BY sequence").fetchall():
        frozen = wire.freeze_event(source_id, dict(event))
        old = previous[event["id"]]
        if type(old["attempts"]) is not int or not 0 <= old["attempts"] <= MAX_COUNTER:
            raise ValueError("An existing security delivery attempt counter is invalid.")
        retry = _time(old["next_attempt_at"])
        delivered = None if old["delivered_at"] is None else _time(old["delivered_at"])
        connection.execute("INSERT INTO security_event_payloads VALUES(?,1,?,?)", (event["id"], frozen.data, frozen.sha256))
        connection.execute("INSERT INTO security_delivery_obligations VALUES(?,?,?,'live',?,?,?,?,NULL,?)",
                           (LOCAL_DESTINATION, event["id"], frozen.sha256, now, old["attempts"], retry,
                            delivered, old["last_error"]))


def validate_delivery_state(connection):
    """Refuse inconsistent authority at startup/restore; never rebuild it."""
    source_identity(connection)
    destinations = connection.execute("SELECT * FROM security_destinations").fetchall()
    local = [row for row in destinations if row["destination_id"] == LOCAL_DESTINATION]
    if len(local) != 1 or local[0]["kind"] != "local" or local[0]["state"] != "active":
        raise ValueError("The local security destination is missing or invalid.")
    for row in destinations:
        if row["kind"] not in {"local", "https"} or row["state"] not in {"active", "retired"}:
            raise ValueError("A security destination has an invalid type or state.")
        if row["kind"] == "https":
            DestinationDescriptor(row["destination_id"], row["collector_id"], row["endpoint"], row["config_revision"])
        elif row["collector_id"] is not None or row["endpoint"] is not None or row["config_revision"] != 0:
            raise ValueError("The local security destination has invalid remote configuration.")
        _time(row["enabled_at"])
        if any(type(row[name]) is not int or not 0 <= row[name] <= MAX_COUNTER
               for name in ("backfill_cutoff_sequence", "backfill_retained_count")):
            raise ValueError("A security destination has invalid activation metadata.")
    by_destination = {row["destination_id"]: row for row in destinations}
    for row in connection.execute("SELECT * FROM security_events"):
        frozen = load_event_payload(connection, row["id"])
        if json.loads(frozen.data)["event"] != dict(row):
            raise ValueError("The frozen security event differs from its source record.")
        obligations = connection.execute("SELECT * FROM security_delivery_obligations WHERE event_id=?", (row["id"],)).fetchall()
        if not any(item["destination_id"] == LOCAL_DESTINATION for item in obligations):
            raise ValueError("A security event is missing its local obligation.")
        active = {item["destination_id"] for item in destinations if item["state"] == "active"}
        if not active.issubset({item["destination_id"] for item in obligations}):
            raise ValueError("A security event is missing an active destination obligation.")
        for item in obligations:
            if item["payload_sha256"] != frozen.sha256:
                raise ValueError("A security obligation has the wrong frozen payload.")
            _time(item["queued_at"])
            _time(item["next_attempt_at"])
            if item["acknowledged_at"] is not None:
                _time(item["acknowledged_at"])
                if by_destination[item["destination_id"]]["kind"] == "https" and (
                    not isinstance(item["receiver_receipt_id"], str) or not _ID.fullmatch(item["receiver_receipt_id"])
                ):
                    raise ValueError("A remote acknowledgement has no validated receipt identity.")
            allowed_errors = {"delivery_failed"} if item["destination_id"] == LOCAL_DESTINATION else DELIVERY_ERRORS
            if item["last_error"] is not None and item["last_error"] not in allowed_errors:
                raise ValueError("A security delivery failure has the wrong destination error class.")


def enable_remote_destination(connection, descriptor, *, now=None):
    """Offline activation/cutover; preserve and enqueue every retained event."""
    from . import security_events as events

    _transaction(connection)
    if not isinstance(descriptor, DestinationDescriptor):
        raise ValueError("A validated security destination descriptor is required.")
    now = _time(now)
    if connection.execute("SELECT 1 FROM security_destinations WHERE destination_id=?", (descriptor.destination_id,)).fetchone():
        raise ValueError("A security destination identity cannot be reused or retargeted.")
    current = connection.execute("SELECT destination_id FROM security_destinations WHERE kind='https' AND state='active'").fetchone()
    if current and connection.execute(
        "SELECT 1 FROM security_delivery_obligations WHERE destination_id=? AND acknowledged_at IS NULL LIMIT 1", (current[0],),
    ).fetchone():
        raise ValueError("Drain the current remote destination before a reviewed cutover.")
    count, cutoff = connection.execute("SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM security_events").fetchone()
    capacity = events._normal_capacity() - events._session_reserve(connection)
    if count >= capacity:
        raise events.EventCapacityError("Activation cannot discard retained history to make space for its required event.")
    # A malformed retained payload cannot be silently omitted from backfill.
    validate_delivery_state(connection)
    if current:
        connection.execute("UPDATE security_destinations SET state='retired' WHERE destination_id=?", (current[0],))
    connection.execute("INSERT INTO security_destinations VALUES(?,'https','active',?,?,?,?,?,?)",
                       (descriptor.destination_id, descriptor.collector_id, descriptor.endpoint, descriptor.config_revision,
                        now, cutoff, count))
    connection.execute(
        "INSERT INTO security_delivery_obligations(destination_id,event_id,payload_sha256,kind,queued_at) "
        "SELECT ?,event_id,payload_sha256,'retained_backfill',? FROM security_event_payloads", (descriptor.destination_id, now),
    )
    # Activation has already reserved a slot and must not invoke age/capacity trim.
    event_id = events._record_event(connection, "security_destination_enabled", now=now,
                                    preserve_retained=True, queued_at=now)
    return {"destination_id": descriptor.destination_id, "source_id": source_identity(connection)["source_id"],
            "backfill_cutoff_sequence": cutoff, "backfill_retained_count": count, "activation_event_id": event_id}


def destination_status(connection, destination_id):
    destination = connection.execute("SELECT * FROM security_destinations WHERE destination_id=?", (destination_id,)).fetchone()
    if destination is None:
        raise ValueError("Unknown security destination.")
    row = connection.execute(
        "SELECT COUNT(*),SUM(acknowledged_at IS NULL),SUM(acknowledged_at IS NULL AND last_error IS NOT NULL),"
        "SUM(acknowledged_at IS NOT NULL),MIN(CASE WHEN acknowledged_at IS NULL THEN queued_at END),"
        "MAX(acknowledged_at),SUM(kind='retained_backfill' AND acknowledged_at IS NULL) "
        "FROM security_delivery_obligations WHERE destination_id=?", (destination_id,),
    ).fetchone()
    return {"destination_id": destination_id, "kind": destination["kind"], "state": destination["state"],
            "pending": row[1] or 0, "failed": row[2] or 0, "acknowledged": row[3] or 0,
            "oldest_pending_at": row[4], "last_acknowledged_at": row[5],
            "backfill_cutoff_sequence": destination["backfill_cutoff_sequence"],
            "backfill_retained_count": destination["backfill_retained_count"], "backfill_remaining": row[6] or 0}


def allocate_heartbeat(connection, destination_id, *, delivery_error=None):
    """Capture remote-only metrics and reserve one durable, never-reused sequence."""
    from .security_events import _session_reserve

    _transaction(connection)
    if delivery_error is not None and delivery_error not in DELIVERY_ERRORS:
        raise ValueError("Invalid security delivery error class.")
    destination = connection.execute("SELECT * FROM security_destinations WHERE destination_id=? AND kind='https' AND state='active'",
                                     (destination_id,)).fetchone()
    if destination is None:
        raise ValueError("An active remote security destination is required.")
    identity = source_identity(connection)
    if identity["heartbeat_sequence"] == MAX_COUNTER:
        raise ValueError("The durable security heartbeat counter is exhausted.")
    sequence = identity["heartbeat_sequence"] + 1
    status = destination_status(connection, destination_id)
    frozen = wire.heartbeat_request({
        "v": 1, "collector_id": destination["collector_id"], "destination_id": destination_id,
        "source_id": identity["source_id"], "sequence": sequence, "pending_events": status["pending"],
        "oldest_pending_at": status["oldest_pending_at"],
        "retained_events": connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0],
        "employee_session_reserve": _session_reserve(connection), "delivery_error": delivery_error,
    })
    connection.execute("UPDATE security_delivery_identity SET heartbeat_sequence=? WHERE id=1", (sequence,))
    return frozen
