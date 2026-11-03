"""Short source transactions around remote delivery; this module performs no I/O."""

from dataclasses import dataclass

from .event_destinations import DELIVERY_ERRORS, MAX_COUNTER, _time, _transaction, load_event_payload, source_identity
from .event_wire import wire


@dataclass(frozen=True)
class DeliveryAttempt:
    destination_id: str
    collector_id: str
    source_id: str
    event_id: str
    payload_sha256: str
    config_revision: int
    endpoint: str
    request: bytes
    attempts: int = 1

    @property
    def expected_receipt(self):
        return {"collector_id": self.collector_id, "destination_id": self.destination_id,
                "source_id": self.source_id, "event_id": self.event_id, "sha256": self.payload_sha256}


def prepare_event_batch(connection, destination_id, *, limit=20, now=None):
    """Reserve attempts; commit the caller's transaction before sending bytes."""
    _transaction(connection)
    if type(limit) is not int or not 1 <= limit <= 20:
        raise ValueError("Invalid remote security delivery batch limit.")
    now = _time(now)
    destination = connection.execute("SELECT * FROM security_destinations WHERE destination_id=? AND kind='https' AND state='active'",
                                     (destination_id,)).fetchone()
    if destination is None:
        raise ValueError("An active remote security destination is required.")
    source_id = source_identity(connection)["source_id"]
    rows = connection.execute(
        "SELECT o.* FROM security_delivery_obligations o JOIN security_events e ON e.id=o.event_id "
        "WHERE o.destination_id=? AND o.acknowledged_at IS NULL AND o.next_attempt_at<=? ORDER BY e.sequence LIMIT ?",
        (destination_id, now, limit),
    ).fetchall()
    attempts = []
    for row in rows:
        frozen = load_event_payload(connection, row["event_id"])
        if frozen.sha256 != row["payload_sha256"]:
            raise ValueError("The security obligation differs from its frozen payload.")
        request = wire.event_request(destination["collector_id"], destination_id, row["kind"], frozen)
        connection.execute("UPDATE security_delivery_obligations SET attempts=MIN(attempts+1,?) WHERE destination_id=? AND event_id=?",
                           (MAX_COUNTER, destination_id, row["event_id"]))
        attempts.append(DeliveryAttempt(destination_id, destination["collector_id"], source_id, row["event_id"],
                                        frozen.sha256, destination["config_revision"], destination["endpoint"], request,
                                        min(row["attempts"] + 1, MAX_COUNTER)))
    return tuple(attempts)


def _current(connection, attempt):
    if not isinstance(attempt, DeliveryAttempt):
        raise ValueError("A prepared security delivery attempt is required.")
    return source_identity(connection)["source_id"] == attempt.source_id and connection.execute(
        "SELECT 1 FROM security_destinations WHERE destination_id=? AND kind='https' AND state='active' "
        "AND collector_id=? AND config_revision=? AND endpoint=?",
        (attempt.destination_id, attempt.collector_id, attempt.config_revision, attempt.endpoint),
    ).fetchone() is not None


def acknowledge_event(connection, attempt, receipt_body, *, now=None):
    _transaction(connection)
    receipt = wire.parse_event_receipt(receipt_body, attempt.expected_receipt)
    now = _time(now)
    if not _current(connection, attempt):
        return False
    return connection.execute(
        "UPDATE security_delivery_obligations SET acknowledged_at=?,receiver_receipt_id=?,last_error=NULL "
        "WHERE destination_id=? AND event_id=? AND payload_sha256=? AND acknowledged_at IS NULL",
        (now, receipt.fields["receipt_id"], attempt.destination_id, attempt.event_id, attempt.payload_sha256),
    ).rowcount == 1


def fail_event(connection, attempt, error, *, retry_at):
    _transaction(connection)
    if error not in DELIVERY_ERRORS:
        raise ValueError("Invalid remote security delivery error class.")
    retry_at = _time(retry_at)
    if not _current(connection, attempt):
        return False
    return connection.execute(
        "UPDATE security_delivery_obligations SET last_error=?,next_attempt_at=? "
        "WHERE destination_id=? AND event_id=? AND payload_sha256=? AND acknowledged_at IS NULL",
        (error, retry_at, attempt.destination_id, attempt.event_id, attempt.payload_sha256),
    ).rowcount == 1
