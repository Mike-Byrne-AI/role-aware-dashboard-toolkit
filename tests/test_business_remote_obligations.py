"""Source-only destination obligations, immutable retries and bounded retention."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
from threading import Event
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fastapi")
pytest.importorskip("pyotp")
APPLICATION = Path(__file__).resolve().parents[1] / "examples/business_dashboard"
sys.path.insert(0, str(APPLICATION))

from business import db as storage, event_destinations as destinations, event_dispatch as dispatch, security_events as events  # noqa: E402
from business.event_wire import wire  # noqa: E402
from business.secret_store import SecretStore, create_key_file  # noqa: E402
from business.security import principal_for_user  # noqa: E402

REMOTE = "1" * 32
COLLECTOR = "2" * 32
DESCRIPTOR = destinations.DestinationDescriptor(REMOTE, COLLECTOR, "https://collector.example.test/v1/events")


@pytest.fixture
def sources():
    with tempfile.TemporaryDirectory(prefix="radt-source-obligations-") as temporary:
        # macOS temp paths traverse /var; only this owned root is canonicalized.
        root, created = Path(temporary).resolve(strict=True), []

        def create(version=10):
            directory = root / f"source-{len(created)}"
            directory.mkdir(mode=0o700)
            identity = secrets.token_bytes(32)
            storage.create_private_file(directory / "identity.key", identity)
            key = create_key_file(directory, root / f"key-{len(created)}" / "mfa.key")
            store = SecretStore(directory, identity, key)
            path = directory / "business.sqlite3"
            storage.create_private_file(path, b"")
            with closing(sqlite3.connect(path)) as connection:
                connection.row_factory = sqlite3.Row
                connection.executescript({8: storage.SCHEMA_V8, 9: storage.SCHEMA_V9, 10: storage.SCHEMA}[version])
                for username, role in (("admin", "admin"), ("employee", "employee")):
                    connection.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?,0)",
                                       (username, username, username, "!unusable-test-password!", role,
                                        principal_for_user(username, identity)))
                    connection.execute("INSERT INTO account_security VALUES(?,'pending',0,NULL,NULL)", (username,))
                connection.execute("INSERT INTO mfa_key_binding VALUES(1,?)", (store.create_binding(),))
                connection.commit()
            result = SimpleNamespace(directory=directory, path=path, key=key,
                                     principal=principal_for_user("admin", identity), database=None)
            created.append(result)
            if version == 10:
                result.database = storage.Database(directory, mfa_key_file=key)
            return result

        yield create


@pytest.fixture
def source(sources, monkeypatch):
    from business import browser_flow
    result = sources()
    # These tests compare complete event-action rollback, including the DB.
    # Hold the independent clock observer fixed; clock advancement/rollback has
    # its own flow-state regressions and is allowed to survive an action denial.
    moment = browser_flow.current_time()
    monkeypatch.setattr(browser_flow, "current_time", lambda: moment)
    return result


@contextmanager
def raw(source):
    with closing(sqlite3.connect(source.path)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise


def fingerprint(source):
    with closing(sqlite3.connect(source.path)) as connection:
        return hashlib.sha256("\n".join(connection.iterdump()).encode()).hexdigest()


def record(source, **options):
    with source.database.transaction() as connection:
        return events.record_event(connection, "password_changed", **options)


def enable(source, descriptor=DESCRIPTOR, **options):
    with source.database.transaction() as connection:
        return destinations.enable_remote_destination(connection, descriptor, **options)


def receipt(attempt, **changes):
    return wire.event_receipt({"v": 1, **attempt.expected_receipt, "receipt_id": "3" * 32,
                               "received_at": 100.0, **changes})


def drain_remote(source):
    while True:
        with source.database.transaction() as connection:
            batch = dispatch.prepare_event_batch(connection, REMOTE)
        if not batch:
            return
        for attempt in batch:
            with source.database.transaction() as connection:
                assert dispatch.acknowledge_event(connection, attempt, receipt(attempt))


def test_current_schema_freezes_event_and_keeps_no_legacy_dispatch_alias(source):
    identifier = record(source, now=123)
    with source.database.readonly_snapshot() as connection:
        storage._require_schema(connection, 10)
        frozen = destinations.load_event_payload(connection, identifier)
        body = json.loads(frozen.data)
        assert body["event"]["occurred_at"] == 123.0 and type(body["event"]["occurred_at"]) is float
        assert body["source_id"] == destinations.source_identity(connection)["source_id"]
        assert hashlib.sha256(frozen.data).hexdigest() == frozen.sha256
        row = connection.execute("SELECT * FROM security_delivery_obligations").fetchone()
        assert (row["destination_id"], row["kind"], row["attempts"], row["acknowledged_at"]) == ("local-v1", "live", 0, None)
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            connection.execute("UPDATE security_outbox SET delivered_at=1")


def legacy_event(connection, identifier="a" * 32, **changes):
    value = {"id": identifier, "occurred_at": 10.0, "code": "password_changed", "outcome": "succeeded",
             "reason": "completed", "actor": None, "target": None, "method": "none", **changes}
    connection.execute("INSERT INTO security_events(id,occurred_at,code,outcome,reason,actor,target,method) VALUES(?,?,?,?,?,?,?,?)",
                       tuple(value[key] for key in ("id", "occurred_at", "code", "outcome", "reason", "actor", "target", "method")))
    connection.execute("INSERT INTO security_outbox VALUES(?,4,21.0,22.0,NULL)", (identifier,))


def test_explicit_eight_through_nine_to_current_upgrade_preserves_local_receipt_and_retry_metadata(sources):
    source = sources(8)
    with raw(source) as connection:
        legacy_event(connection)
        legacy_event(connection, "b" * 32)
        connection.execute("UPDATE security_outbox SET delivered_at=NULL,last_error='delivery_failed' WHERE event_id=?", ("b" * 32,))
        connection.execute("INSERT INTO security_sink_receipts VALUES(?,23.0,'historical-local-receipt')", ("a" * 32,))
    before = fingerprint(source)
    with pytest.raises(ValueError, match="schema ten"):
        storage.Database(source.directory, mfa_key_file=source.key)
    assert fingerprint(source) == before
    upgraded = storage.Database(source.directory, mfa_key_file=source.key, migrate=True)
    with upgraded.readonly_snapshot() as connection:
        rows = connection.execute("SELECT * FROM security_delivery_obligations ORDER BY event_id").fetchall()
        assert [(row["attempts"], row["next_attempt_at"], row["acknowledged_at"], row["last_error"]) for row in rows] == [
            (4, 21.0, 22.0, None), (4, 21.0, None, "delivery_failed")]
        assert all(row["destination_id"] == "local-v1" for row in rows)
        assert connection.execute("SELECT payload_json FROM security_sink_receipts").fetchone()[0] == "historical-local-receipt"
        assert connection.execute("SELECT COUNT(*) FROM security_event_payloads").fetchone()[0] == 2
        assert destinations.source_identity(connection)["heartbeat_sequence"] == 0
        storage._require_schema(connection, 10)


@pytest.mark.parametrize("damage", ["time", "code", "missing_obligation"])
def test_unrepresentable_legacy_event_refuses_migration_without_partial_ddl(sources, damage):
    source = sources(8)
    with raw(source) as connection:
        legacy_event(connection, **({"occurred_at": float("inf")} if damage == "time" else
                                    {"code": "unknown_future_event"} if damage == "code" else {}))
        if damage == "missing_obligation":
            connection.execute("DELETE FROM security_outbox")
    before = fingerprint(source)
    with pytest.raises(ValueError):
        storage.Database(source.directory, mfa_key_file=source.key, migrate=True)
    assert fingerprint(source) == before
    with raw(source) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 8
        storage._require_schema(connection, 8)


def test_activation_backfills_all_retained_history_even_after_local_ack(source):
    identifiers = [record(source, now=10.0), record(source, now=11.0)]
    assert events.dispatch_pending(source.database)["delivered"] == 2
    status = enable(source, now=100.0)
    assert status["backfill_retained_count"] == 2
    with source.database.readonly_snapshot() as connection:
        rows = connection.execute("SELECT * FROM security_delivery_obligations WHERE destination_id=? ORDER BY event_id", (REMOTE,)).fetchall()
        assert {row["event_id"] for row in rows if row["kind"] == "retained_backfill"} == set(identifiers)
        assert all(row["queued_at"] == 100.0 for row in rows if row["kind"] == "retained_backfill")
        assert all(row["acknowledged_at"] is None for row in rows)
        activation = connection.execute("SELECT * FROM security_events WHERE id=?", (status["activation_event_id"],)).fetchone()
        assert activation["code"] == "security_destination_enabled" and activation["sequence"] > status["backfill_cutoff_sequence"]
    assert events.dispatch_pending(source.database)["delivered"] == 1
    with source.database.readonly_snapshot() as connection:
        assert events.delivery_status(connection)["pending"] == 0
        assert destinations.destination_status(connection, REMOTE)["pending"] == 3
        assert destinations.destination_status(connection, REMOTE)["backfill_remaining"] == 2
        assert all(row["delivery"] == "delivered" for row in events.timeline(connection)["events"])


@pytest.mark.parametrize("fault", ["backfill", "activation_event", "live_obligation"])
def test_obligation_or_required_activation_failure_rolls_back_entire_action(source, fault):
    record(source)
    if fault == "live_obligation":
        enable(source)
    with raw(source) as connection:
        if fault == "activation_event":
            connection.execute("CREATE TRIGGER fail_required_activation BEFORE INSERT ON security_events "
                               "WHEN NEW.code='security_destination_enabled' BEGIN SELECT RAISE(ABORT,'synthetic fault'); END")
        else:
            connection.execute("CREATE TRIGGER fail_remote_obligation BEFORE INSERT ON security_delivery_obligations "
                               f"WHEN NEW.destination_id='{REMOTE}' BEGIN SELECT RAISE(ABORT,'synthetic fault'); END")
    before = fingerprint(source)
    with pytest.raises(sqlite3.IntegrityError), source.database.transaction() as connection:
        connection.execute("UPDATE settings SET freeze_revision=freeze_revision+1")
        if fault == "live_obligation":
            events.record_event(connection, "editing_paused")
        else:
            destinations.enable_remote_destination(connection, DESCRIPTOR)
    assert fingerprint(source) == before


def test_activation_never_trims_locally_acknowledged_history_to_reserve_its_event(source, monkeypatch):
    monkeypatch.setattr(events, "MAX_EVENTS", 6)
    for _ in range(3):
        record(source, now=10.0)
    events.dispatch_pending(source.database)
    before = fingerprint(source)
    with pytest.raises(events.EventCapacityError, match="discard retained"):
        enable(source)
    assert fingerprint(source) == before


def test_any_remote_pending_obligation_prevents_age_and_denial_pruning(source, monkeypatch):
    monkeypatch.setattr(events, "MAX_AGE_SECONDS", 10)
    monkeypatch.setattr(events, "MAX_DENIAL_EVENTS", 1)
    enable(source, now=10.0)
    with source.database.transaction() as connection:
        denied = events.record_event(connection, "request_denied", outcome="denied", reason="forbidden", now=10.0)
    events.dispatch_pending(source.database)
    record(source, now=100.0)
    with source.database.transaction() as connection:
        assert connection.execute("SELECT 1 FROM security_events WHERE id=?", (denied,)).fetchone()
        assert events._admit_denial(connection) is False
    drain_remote(source)
    record(source, now=101.0)
    with source.database.readonly_snapshot() as connection:
        assert connection.execute("SELECT 1 FROM security_events WHERE id=?", (denied,)).fetchone() is None


def test_remote_backlog_preserves_containment_and_employee_termination_reserves(source, monkeypatch):
    monkeypatch.setattr(events, "MAX_EVENTS", 10)
    enable(source)
    with source.database.transaction() as connection:
        now = events.time.time()
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", ("a" * 64, "employee", now, now, now + 1000))
    for _ in range(5):
        record(source)
    events.dispatch_pending(source.database)
    with pytest.raises(events.EventCapacityError):
        record(source)
    with source.database.transaction() as connection:
        for _ in range(3):
            events.record_event(connection, "editing_paused", actor=source.principal)
        employee = connection.execute("SELECT principal FROM users WHERE id='employee'").fetchone()[0]
        events.terminate_own_session(connection, "session_logged_out", hashed="a" * 64, actor=employee)
    with source.database.readonly_snapshot() as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 10
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert destinations.destination_status(connection, REMOTE)["pending"] == 10


def test_serialized_activation_has_no_gap_with_a_competing_required_event(source):
    record(source)
    attempted = Event()

    def concurrent_mutation():
        attempted.set()
        return record(source)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with source.database.transaction() as connection:
            enabled = destinations.enable_remote_destination(connection, DESCRIPTOR)
            future = pool.submit(concurrent_mutation)
            assert attempted.wait(timeout=5)
            assert not future.done()
        identifier = future.result(timeout=10)
    with source.database.readonly_snapshot() as connection:
        row = connection.execute("SELECT * FROM security_delivery_obligations WHERE destination_id=? AND event_id=?", (REMOTE, identifier)).fetchone()
        assert row["kind"] == "live"
        assert connection.execute("SELECT sequence FROM security_events WHERE id=?", (identifier,)).fetchone()[0] > enabled["backfill_cutoff_sequence"]
        destinations.validate_delivery_state(connection)


def test_only_drained_remote_destination_can_be_replaced_and_new_target_backfills(source):
    enable(source)
    second = destinations.DestinationDescriptor("4" * 32, "5" * 32, "https://other.example.test/v1/events")
    before = fingerprint(source)
    with pytest.raises(ValueError, match="Drain"):
        enable(source, second)
    assert fingerprint(source) == before
    drain_remote(source)
    result = enable(source, second)
    identifier = record(source)
    with source.database.readonly_snapshot() as connection:
        assert destinations.destination_status(connection, REMOTE)["state"] == "retired"
        assert destinations.destination_status(connection, second.destination_id)["backfill_remaining"] == result["backfill_retained_count"]
        assert {row[0] for row in connection.execute("SELECT destination_id FROM security_delivery_obligations WHERE event_id=?", (identifier,))} == {"local-v1", second.destination_id}
    with pytest.raises(ValueError, match="reused"):
        enable(source)


@pytest.mark.parametrize("statement", [
    "UPDATE security_events SET occurred_at=20",
    "UPDATE security_event_payloads SET canonical_payload=X'00'",
    "UPDATE security_delivery_obligations SET queued_at=20",
    "UPDATE security_delivery_identity SET source_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
    "UPDATE security_destinations SET endpoint='https://other.example.test/v1/events'",
])
def test_frozen_identity_and_payload_cannot_be_rewritten(source, statement):
    enable(source)
    before = fingerprint(source)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"), raw(source) as connection:
        connection.execute(statement)
    assert fingerprint(source) == before


def test_remote_retry_preserves_bytes_across_response_loss_restart_and_serializer_change(source, monkeypatch):
    enable(source)
    with source.database.transaction() as connection:
        first = dispatch.prepare_event_batch(connection, REMOTE)[0]
        assert dispatch.fail_event(connection, first, "transport_failed", retry_at=20.0)
    restarted = storage.Database(source.directory, mfa_key_file=source.key)

    def forbid_reserialization(*args):
        pytest.fail("A retry reconstructed an already frozen event")

    monkeypatch.setattr(wire, "freeze_event", forbid_reserialization)
    with restarted.transaction() as connection:
        retry = dispatch.prepare_event_batch(connection, REMOTE, now=21.0)[0]
    assert retry.request == first.request and retry.expected_receipt == first.expected_receipt
    # Model a committed remote receipt whose first response never reached source.
    original_receipt = receipt(first)
    with restarted.transaction() as connection:
        assert dispatch.acknowledge_event(connection, retry, original_receipt, now=22.0)
        assert not dispatch.acknowledge_event(connection, first, original_receipt, now=23.0)
        row = connection.execute("SELECT * FROM security_delivery_obligations WHERE destination_id=?", (REMOTE,)).fetchone()
        assert row["attempts"] == 2 and row["acknowledged_at"] == 22.0 and row["last_error"] is None
    assert events.dispatch_pending(restarted)["delivered"] == 1


@pytest.mark.parametrize("field", ["collector_id", "destination_id", "source_id", "event_id", "sha256"])
def test_wrong_receipt_identity_never_acknowledges_a_pending_event(source, field):
    enable(source)
    with source.database.transaction() as connection:
        attempt = dispatch.prepare_event_batch(connection, REMOTE)[0]
    before = fingerprint(source)
    value = "f" * (64 if field == "sha256" else 32)
    with pytest.raises(ValueError), source.database.transaction() as connection:
        dispatch.acknowledge_event(connection, attempt, receipt(attempt, **{field: value}))
    assert fingerprint(source) == before


def test_receipt_rechecks_destination_revision_after_network_work(source):
    enable(source)
    with source.database.transaction() as connection:
        attempt = dispatch.prepare_event_batch(connection, REMOTE)[0]
        connection.execute("UPDATE security_destinations SET config_revision=config_revision+1 WHERE destination_id=?", (REMOTE,))
    before = fingerprint(source)
    with source.database.transaction() as connection:
        assert not dispatch.acknowledge_event(connection, attempt, receipt(attempt))
        assert not dispatch.fail_event(connection, attempt, "transport_failed", retry_at=50.0)
    assert fingerprint(source) == before


def test_heartbeat_counts_only_addressed_remote_and_never_reuses_committed_sequence(source):
    enable(source)
    drain_remote(source)  # Local remains pending, but the addressed remote is caught up.
    with source.database.transaction() as connection:
        first = destinations.allocate_heartbeat(connection, REMOTE)
    restarted = storage.Database(source.directory, mfa_key_file=source.key)
    with restarted.transaction() as connection:
        second = destinations.allocate_heartbeat(connection, REMOTE, delivery_error="config_unavailable")
    a, b = json.loads(first.data), json.loads(second.data)
    assert a["pending_events"] == 0 and a["oldest_pending_at"] is None
    assert a["sequence"] == 1 and b["sequence"] == 2 and b["delivery_error"] == "config_unavailable"
    assert wire.from_stored(first.data, first.sha256, kind="heartbeat").data == first.data


def test_heartbeat_counter_exhaustion_is_visible_without_wrap_or_mutation(source):
    enable(source)
    with source.database.transaction() as connection:
        connection.execute("UPDATE security_delivery_identity SET heartbeat_sequence=?", (destinations.MAX_COUNTER,))
    before = fingerprint(source)
    with pytest.raises(ValueError, match="exhausted"), source.database.transaction() as connection:
        destinations.allocate_heartbeat(connection, REMOTE)
    assert fingerprint(source) == before


@pytest.mark.parametrize("damage", ["local", "remote"])
def test_startup_refuses_missing_required_delivery_obligation_without_repair(source, damage):
    enable(source)
    with raw(source) as connection:
        connection.execute("DELETE FROM security_delivery_obligations WHERE destination_id=?", ("local-v1" if damage == "local" else REMOTE,))
    before = fingerprint(source)
    with pytest.raises(ValueError, match="missing"):
        storage.Database(source.directory, mfa_key_file=source.key)
    assert fingerprint(source) == before


@pytest.mark.parametrize("endpoint", [
    "http://collector.example.test/v1/events", "https://collector.example.test/v1/other",
    "https://user:password@collector.example.test/v1/events", "https://collector.example.test/v1/events?x=1",
    "https://collector%2eexample.test/v1/events", "https://collector\\example.test/v1/events",
    "https://collector.example.test\x00/v1/events",
])
def test_destination_endpoint_cannot_retarget_or_carry_credentials(endpoint):
    with pytest.raises(ValueError):
        destinations.DestinationDescriptor(REMOTE, COLLECTOR, endpoint)
