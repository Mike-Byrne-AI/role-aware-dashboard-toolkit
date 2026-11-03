"""Recovery preserves current remote-delivery custody with synthetic state only."""

import json

from tests.test_business_dashboard import business as business, business_seed as business_seed
from tests.test_business_backup import backup, _make_backup, _rows, _fingerprint
from business.db import Database
from business.event_destinations import DestinationDescriptor, allocate_heartbeat, enable_remote_destination
from business.event_dispatch import prepare_event_batch, acknowledge_event
from business.event_wire import wire
from business.secret_store import default_key_path
from business.security_events import dispatch_pending, record_event

TABLES = ("security_delivery_identity", "security_destinations", "security_events",
          "security_event_payloads", "security_delivery_obligations", "security_sink_receipts",
          "security_denial_budget")


def test_current_authority_restore_keeps_frozen_bytes_remote_receipts_and_heartbeat_counter(business, monkeypatch):
    database = business.app.state.database
    dispatch_pending(database)
    bundle = _make_backup(business)
    destination = DestinationDescriptor("1" * 32, "2" * 32, "https://collector.example.test/v1/events")
    with business.db() as connection:
        enabled = enable_remote_destination(connection, destination)
        first = allocate_heartbeat(connection, destination.destination_id)
        second = allocate_heartbeat(connection, destination.destination_id)
        batch = prepare_event_batch(connection, destination.destination_id)
    assert enabled["backfill_retained_count"] > 0
    assert json.loads(second.data)["sequence"] == json.loads(first.data)["sequence"] + 1
    # The receiver's canonical receipt establishes only this one obligation.
    attempt = batch[0]
    receipt = wire.event_receipt({"v": 1, **attempt.expected_receipt,
                                  "receipt_id": "3" * 32, "received_at": 1000.0})
    with business.db() as connection:
        assert acknowledge_event(connection, attempt, receipt)
        record_event(connection, "editing_paused")
    before = _fingerprint(business.directory), _fingerprint(bundle)
    original = {table: _rows(business.directory, table) for table in TABLES}

    def refuse_reserialize(*args, **kwargs):
        raise AssertionError("A stored security payload was reserialized during current-authority recovery.")

    monkeypatch.setattr(wire, "freeze_event", refuse_reserialize)
    restored = business.directory.parent / "remote-current-recovery"
    result = backup.restore_backup(bundle, restored, security_source=business.directory,
                                   mfa_key_file=default_key_path(business.directory))
    assert result == {"quarantined": False, "sessions_revoked": True, "frozen": True}
    assert (_fingerprint(business.directory), _fingerprint(bundle)) == before
    assert {table: _rows(restored, table) for table in TABLES} == original
    recovered = Database(restored, mfa_key_file=default_key_path(business.directory))
    with recovered.transaction() as connection:
        next_heartbeat = allocate_heartbeat(connection, destination.destination_id)
        retries = prepare_event_batch(connection, destination.destination_id)
    assert json.loads(next_heartbeat.data)["sequence"] == json.loads(second.data)["sequence"] + 1
    assert attempt.event_id not in {row.event_id for row in retries}
    by_id = {row.event_id: row.request for row in batch[1:]}
    for retry in retries:
        if retry.event_id in by_id:
            assert retry.request == by_id[retry.event_id]
    assert not {"ingest.token", "operator.token", "delivery.json"} & {item.name for item in restored.iterdir()}


def test_restore_preserves_pruned_source_sequence_high_water_mark(business):
    database = business.app.state.database
    dispatch_pending(database)
    bundle = _make_backup(business)
    with business.db() as connection:
        previous = connection.execute("SELECT seq FROM sqlite_sequence WHERE name='security_events'").fetchone()[0]
        # Model a source whose fully acknowledged retained history has expired.
        assert connection.execute(
            "SELECT COUNT(*) FROM security_delivery_obligations WHERE acknowledged_at IS NULL"
        ).fetchone()[0] == 0
        connection.execute("DELETE FROM security_events")
    restored = business.directory.parent / "pruned-current-recovery"
    backup.restore_backup(bundle, restored, security_source=business.directory,
                          mfa_key_file=default_key_path(business.directory))
    recovered = Database(restored, mfa_key_file=default_key_path(business.directory))
    with recovered.transaction() as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0
        assert connection.execute("SELECT seq FROM sqlite_sequence WHERE name='security_events'").fetchone()[0] == previous
        event_id = record_event(connection, "editing_paused")
        assert connection.execute("SELECT sequence FROM security_events WHERE id=?", (event_id,)).fetchone()[0] == previous + 1
