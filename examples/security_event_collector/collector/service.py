"""Durable event ingestion, heartbeat freshness and alert-delivery boundaries."""

from dataclasses import dataclass, field
import json
import secrets

from . import alerts
from .event_wire import wire
from .pagination import decode_cursor, page, page_limit
from .storage import ServiceError, Store, identifier

ERRORS = frozenset({"config_unavailable", "transport_failed", "tls_failed", "remote_auth_failed", "remote_conflict",
                    "remote_capacity", "remote_throttled", "remote_unavailable", "invalid_receipt"})


@dataclass(frozen=True)
class Delivery:
    alert_id: str
    number: int
    body: bytes = field(repr=False)
    expected: dict
    attempts: int


class Collector:
    def __init__(self, directory, **kwargs):
        self.store = Store(directory, **kwargs)
        if self.store.settings["kind"] != "collector":
            raise ValueError("Collector storage is required.")

    def _channel(self, connection, token):
        channel = self.store.authenticate_in(connection, token, "ingest")
        return {"collector_id": self.store.settings["service_id"], "destination_id": channel["destination_id"],
                "source_id": self.store.settings["source_id"]}

    def ingest_event(self, token, body):
        failure = None
        with self.store.transaction() as connection:
            now = self.store.now()
            channel = self._channel(connection, token)
            message = wire.parse_event_request(body, channel)
            event = message.payload_fields["event"]
            source_id, event_id = message.payload_fields["source_id"], event["id"]
            old = connection.execute("SELECT * FROM events WHERE source_id=? AND event_id=?", (source_id, event_id)).fetchone()
            if old and (old["sha256"] != message.payload.sha256 or bytes(old["payload"]) != message.payload.data):
                self.store.advance_clock(connection, now)
                alerts.observe(self.store, connection, "event_conflict", event_id, True,
                               {"event_id": event_id, "accepted_sha256": old["sha256"], "rejected_sha256": message.payload.sha256},
                               now, severity="critical")
                failure = ServiceError("identity_conflict", 409)
            else:
                receipt = connection.execute("SELECT receipt FROM event_receipts WHERE source_id=? AND event_id=? AND destination_id=?",
                                             (source_id, event_id, channel["destination_id"])).fetchone()
                if receipt:
                    return bytes(receipt[0])
                self.store.advance_clock(connection, now)
                if self.store.event_storage_full(connection):
                    used, limit = self.store.event_byte_capacity(connection)
                    alerts.observe(self.store, connection, "collector_capacity", "bytes", True,
                                   {"resource": "bytes", "used": used, "limit": limit}, now, severity="critical")
                    failure = ServiceError("storage_full", 507)
                elif old is None:
                    count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                    if count >= self.store.settings["max_events"]:
                        alerts.evaluate(self.store, connection, now)
                        failure = ServiceError("storage_full", 507)
                    else:
                        connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?)", (
                            source_id, event_id, message.payload.data, message.payload.sha256, secrets.token_hex(16), now,
                        ))
                        old = connection.execute("SELECT * FROM events WHERE source_id=? AND event_id=?", (source_id, event_id)).fetchone()
                if failure is None:
                    receipt = wire.event_receipt({"v": 1, **channel, "event_id": event_id, "sha256": old["sha256"],
                                                  "receipt_id": old["receipt_id"], "received_at": float(old["received_at"])})
                    connection.execute("INSERT INTO event_receipts VALUES(?,?,?,?,?)", (source_id, event_id, channel["destination_id"], message.fields["kind"], receipt))
                    alerts.evaluate(self.store, connection, now)
        if failure:
            raise failure
        return receipt

    def accept_heartbeat(self, token, body):
        with self.store.transaction() as connection:
            now = self.store.now()
            channel = self._channel(connection, token)
            message = wire.parse_heartbeat(body, channel)
            sequence = message.fields["sequence"]
            old = connection.execute("SELECT * FROM heartbeats WHERE source_id=?", (channel["source_id"],)).fetchone()
            if old and sequence <= old["sequence"]:
                if sequence == old["sequence"] and message.sha256 == old["sha256"] and message.data == bytes(old["body"]):
                    return bytes(old["receipt"])
                raise ServiceError("stale_heartbeat", 409)
            self.store.advance_clock(connection, now)
            receipt = wire.heartbeat_receipt({"v": 1, **channel, "sequence": sequence, "sha256": message.sha256, "received_at": now})
            oldest = message.fields["oldest_pending_at"]
            untrusted = oldest is not None and oldest > now
            if old:
                previous = json.loads(old["body"])
                if (previous["destination_id"] == channel["destination_id"] and previous["pending_events"] > 0
                        and message.fields["pending_events"] > 0 and oldest < previous["oldest_pending_at"]):
                    untrusted = True
            connection.execute("INSERT INTO heartbeats VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET "
                               "sequence=excluded.sequence,sha256=excluded.sha256,body=excluded.body,receipt=excluded.receipt,received_at=excluded.received_at,clock_untrusted=excluded.clock_untrusted",
                               (channel["source_id"], sequence, message.sha256, message.data, receipt, now, int(untrusted)))
            alerts.evaluate(self.store, connection, now)
        return receipt

    def evaluate_alerts(self):
        with self.store.transaction() as connection:
            alerts.evaluate(self.store, connection, self.store.now())

    def list_alerts(self, token, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Use a bounded alert limit.")
        with self.store.read() as connection:
            self.store.authenticate_in(connection, token, "operator")
            return [dict(row) for row in connection.execute("SELECT * FROM alert_cases ORDER BY created_at DESC,id LIMIT ?", (limit,))]

    def page_alerts(self, token, *, limit=100, cursor=None):
        limit = page_limit(limit)
        with self.store.read() as connection:
            self.store.authenticate_in(connection, token, "operator")
            anchor = decode_cursor(cursor, "alerts")
            where, parameters = "", []
            if anchor is not None:
                row = connection.execute("SELECT created_at,id FROM alert_cases WHERE id=?", (anchor["id"],)).fetchone()
                if row is None:
                    raise ServiceError("invalid_message", 400)
                where = "WHERE created_at<? OR (created_at=? AND id>?) "
                parameters = [row["created_at"], row["created_at"], row["id"]]
            rows = [dict(row) for row in connection.execute(
                "SELECT * FROM alert_cases " + where + "ORDER BY created_at DESC,id LIMIT ?", (*parameters, limit + 1))]
            return page(rows, limit, "alerts")

    def acknowledge_alert(self, token, case_id, number, *, resolve=False):
        identifier(case_id)
        with self.store.transaction() as connection:
            self.store.authenticate_in(connection, token, "operator")
            now = self.store.now()
            self.store.advance_clock(connection, now)
            alerts.acknowledge(self.store, connection, case_id, number, now, resolve=resolve)

    def _delivery(self, connection, row):
        destination = connection.execute("SELECT * FROM alert_destination WHERE id=1").fetchone()
        frozen = wire.from_stored(bytes(row["payload"]), row["sha256"], kind="alert")
        expected = {"inbox_id": destination["inbox_id"], "destination_id": destination["destination_id"],
                    "collector_id": self.store.settings["service_id"], "alert_id": row["alert_id"],
                    "number": row["number"], "sha256": row["sha256"]}
        return Delivery(row["alert_id"], row["number"], wire.alert_request(destination["inbox_id"], destination["destination_id"], frozen), expected, row["attempts"])

    def pending_alerts(self, *, limit=20):
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Use an alert batch of one through twenty.")
        with self.store.read() as connection:
            rows = connection.execute("SELECT o.*,t.payload,t.sha256 FROM alert_outbox o JOIN alert_transitions t "
                                      "USING(alert_id,number) WHERE o.acknowledged_at IS NULL AND o.next_attempt_at<=? "
                                      "ORDER BY o.next_attempt_at,o.alert_id,o.number LIMIT ?", (self.store.now(), limit)).fetchall()
            return [self._delivery(connection, row) for row in rows]

    def begin_alert_attempt(self, alert_id, number):
        with self.store.transaction() as connection:
            row = connection.execute("SELECT o.*,t.payload,t.sha256 FROM alert_outbox o JOIN alert_transitions t USING(alert_id,number) "
                                     "WHERE o.alert_id=? AND o.number=? AND o.acknowledged_at IS NULL AND o.next_attempt_at<=?",
                                     (alert_id, number, self.store.now())).fetchone()
            if row is None:
                return None
            connection.execute("UPDATE alert_outbox SET attempts=attempts+1 WHERE alert_id=? AND number=?", (alert_id, number))
            return self._delivery(connection, {**dict(row), "attempts": row["attempts"] + 1})

    def ack_alert(self, alert_id, number, body):
        with self.store.transaction() as connection:
            row = connection.execute("SELECT o.*,t.payload,t.sha256 FROM alert_outbox o JOIN alert_transitions t USING(alert_id,number) "
                                     "WHERE o.alert_id=? AND o.number=?", (alert_id, number)).fetchone()
            if row is None:
                raise ServiceError("unavailable", 404)
            delivery = self._delivery(connection, row)
            wire.parse_inbox_receipt(body, delivery.expected)
            if row["acknowledged_at"] is not None:
                if bytes(row["receipt"]) != body:
                    raise ServiceError("identity_conflict", 409)
                return
            self.store.advance_clock(connection, self.store.now())
            connection.execute("UPDATE alert_outbox SET acknowledged_at=?,receipt=?,last_error=NULL WHERE alert_id=? AND number=?",
                               (self.store.now(), body, alert_id, number))

    def fail_alert(self, alert_id, number, error, *, retry_after=None):
        if error not in ERRORS:
            raise ValueError("Use a fixed delivery error class.")
        with self.store.transaction() as connection:
            row = connection.execute("SELECT * FROM alert_outbox WHERE alert_id=? AND number=? AND acknowledged_at IS NULL", (alert_id, number)).fetchone()
            if row is None:
                return
            delay = min(300, 5 * 2 ** min(6, max(0, row["attempts"] - 1)) + secrets.randbelow(5))
            if type(retry_after) in (int, float) and 0 <= retry_after <= 2**31:
                delay = max(delay, min(300, max(5, retry_after)))
            connection.execute("UPDATE alert_outbox SET next_attempt_at=?,last_error=? WHERE alert_id=? AND number=? AND acknowledged_at IS NULL",
                               (self.store.now() + delay, error, alert_id, number))

    def status(self, token):
        with self.store.read() as connection:
            self.store.authenticate_in(connection, token, "operator")
            return {"service_id": self.store.settings["service_id"], "events": connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                    "open_alerts": connection.execute("SELECT COUNT(*) FROM alert_cases WHERE condition_open=1").fetchone()[0],
                    "pending_notifications": connection.execute("SELECT COUNT(*) FROM alert_outbox WHERE acknowledged_at IS NULL").fetchone()[0]}
