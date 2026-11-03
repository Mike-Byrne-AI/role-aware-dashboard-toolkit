"""Independently credentialed immutable operator inbox, never human impersonation."""

import secrets

from .event_wire import wire
from .pagination import decode_cursor, page, page_limit
from .storage import ServiceError, Store, identifier


class Inbox:
    def __init__(self, directory, **kwargs):
        self.store = Store(directory, **kwargs)
        if self.store.settings["kind"] != "inbox":
            raise ValueError("Inbox storage is required.")

    def ingest_alert(self, token, body):
        with self.store.transaction() as connection:
            now = self.store.now()
            channel = self.store.authenticate_in(connection, token, "ingest")
            expected = {"inbox_id": self.store.settings["service_id"], "destination_id": channel["destination_id"], "collector_id": channel["peer_id"]}
            message = wire.parse_alert_request(body, expected)
            payload = message.payload_fields
            if payload["source_id"] != self.store.settings["source_id"]:
                raise ServiceError("channel_forbidden", 403)
            key = (payload["collector_id"], payload["alert_id"], payload["number"])
            old = connection.execute("SELECT * FROM inbox_messages WHERE collector_id=? AND alert_id=? AND number=?", key).fetchone()
            if old and (old["sha256"] != message.payload.sha256 or bytes(old["payload"]) != message.payload.data):
                raise ServiceError("identity_conflict", 409)
            receipt = connection.execute("SELECT receipt FROM inbox_receipts WHERE collector_id=? AND alert_id=? AND number=? AND destination_id=?",
                                         (*key, channel["destination_id"])).fetchone()
            if receipt:
                return bytes(receipt[0])
            self.store.advance_clock(connection, now)
            if self.store.event_storage_full(connection):
                raise ServiceError("storage_full", 507)
            if old is None:
                if connection.execute("SELECT COUNT(*) FROM inbox_messages").fetchone()[0] >= self.store.settings["max_events"]:
                    raise ServiceError("storage_full", 507)
                connection.execute("INSERT INTO inbox_messages VALUES(?,?,?,?,?,?,?)", (*key, message.payload.data, message.payload.sha256, secrets.token_hex(16), now))
                old = connection.execute("SELECT * FROM inbox_messages WHERE collector_id=? AND alert_id=? AND number=?", key).fetchone()
            receipt = wire.inbox_receipt({"v": 1, **expected, "alert_id": key[1], "number": key[2], "sha256": old["sha256"],
                                          "receipt_id": old["receipt_id"], "received_at": float(old["received_at"])})
            connection.execute("INSERT INTO inbox_receipts VALUES(?,?,?,?,?)", (*key, channel["destination_id"], receipt))
        return receipt

    def list_messages(self, token, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Use a bounded inbox limit.")
        with self.store.read() as connection:
            self.store.authenticate_in(connection, token, "operator")
            return [{**dict(row), "payload": bytes(row["payload"]).decode("ascii")} for row in connection.execute(
                "SELECT m.*,a.acknowledged_at FROM inbox_messages m LEFT JOIN inbox_acknowledgements a "
                "USING(collector_id,alert_id,number) ORDER BY received_at DESC,collector_id,alert_id,number LIMIT ?", (limit,))]

    def page_messages(self, token, *, limit=100, cursor=None):
        limit = page_limit(limit)
        with self.store.read() as connection:
            self.store.authenticate_in(connection, token, "operator")
            anchor = decode_cursor(cursor, "messages")
            where, parameters = "", []
            if anchor is not None:
                row = connection.execute("SELECT received_at,collector_id,alert_id,number FROM inbox_messages "
                                         "WHERE collector_id=? AND alert_id=? AND number=?",
                                         (anchor["collector_id"], anchor["alert_id"], anchor["number"])).fetchone()
                if row is None:
                    raise ServiceError("invalid_message", 400)
                where = "WHERE m.received_at<? OR (m.received_at=? AND (m.collector_id,m.alert_id,m.number)>(?,?,?)) "
                parameters = [row["received_at"], row["received_at"], row["collector_id"], row["alert_id"], row["number"]]
            rows = [{**dict(row), "payload": bytes(row["payload"]).decode("ascii")} for row in connection.execute(
                "SELECT m.*,a.acknowledged_at FROM inbox_messages m LEFT JOIN inbox_acknowledgements a "
                "USING(collector_id,alert_id,number) " + where +
                "ORDER BY m.received_at DESC,m.collector_id,m.alert_id,m.number LIMIT ?", (*parameters, limit + 1))]
            return page(rows, limit, "messages")

    def acknowledge_message(self, token, collector_id, alert_id, number):
        identifier(collector_id)
        identifier(alert_id)
        if type(number) is not int or number < 1:
            raise ValueError("Invalid transition number.")
        with self.store.transaction() as connection:
            self.store.authenticate_in(connection, token, "operator")
            key = (collector_id, alert_id, number)
            if connection.execute("SELECT 1 FROM inbox_messages WHERE collector_id=? AND alert_id=? AND number=?", key).fetchone() is None:
                raise ServiceError("unavailable", 404)
            self.store.advance_clock(connection, self.store.now())
            connection.execute("INSERT OR IGNORE INTO inbox_acknowledgements VALUES(?,?,?,?)", (*key, self.store.now()))
