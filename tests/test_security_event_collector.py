"""Independent receiver custody, replay, operational alert and authority proofs."""

from concurrent.futures import ThreadPoolExecutor
import asyncio
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from threading import Event
import time

import pytest

pytest.importorskip("anyio")
httpx = pytest.importorskip("httpx")
pytest.importorskip("starlette")
from starlette.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples" / "security_event_collector"))
from collector import alerts  # noqa: E402
from collector.app import create_app  # noqa: E402
from collector.custody import create_backup, restore_quarantined  # noqa: E402
from collector.event_wire import wire  # noqa: E402
from collector.event_wire import load_transport  # noqa: E402
from collector.inbox import Inbox  # noqa: E402
from collector.notifications import Notifier  # noqa: E402
from collector.service import Collector  # noqa: E402
from collector.storage import ServiceError, Store, provision, safe_json  # noqa: E402

SOURCE, COLLECTOR, DESTINATION, INBOX, ALERT_DESTINATION = (str(number) * 32 for number in (1, 2, 3, 7, 8))


@pytest.fixture
def tmp_path():
    # This repository's global tmp_path is inside its managed source scratch.
    # Collector credentials and databases deliberately reject that location.
    with tempfile.TemporaryDirectory(prefix="security-collector-test-") as temporary:
        yield Path(temporary)


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("The collector regression must not send external HTTP")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
    yield
    assert not attempts


@pytest.fixture
def pair(tmp_path):
    clock = [1700000000.0]
    shared = {"source_id": SOURCE, "now": clock[0]}
    issued = provision(tmp_path / "collector", kind="collector", service_id=COLLECTOR, destination_id=DESTINATION,
                       inbox_id=INBOX, alert_destination_id=ALERT_DESTINATION, **shared)
    inbox_issued = provision(tmp_path / "inbox", kind="inbox", service_id=INBOX, destination_id=ALERT_DESTINATION,
                             peer_id=COLLECTOR, **shared)
    collector = Collector(tmp_path / "collector", clock=lambda: clock[0])
    inbox = Inbox(tmp_path / "inbox", clock=lambda: clock[0])
    return collector, issued, inbox, inbox_issued, clock


def event(*, event_id="4" * 32, sequence=7, actor="a" * 64, destination=DESTINATION, kind="live"):
    frozen = wire.freeze_event(SOURCE, {"id": event_id, "sequence": sequence, "occurred_at": 1700000000.0,
                                      "code": "login_succeeded", "outcome": "succeeded", "reason": "completed",
                                      "actor": actor, "target": None, "method": "totp"})
    return wire.event_request(COLLECTOR, destination, kind, frozen)


def heartbeat(sequence, *, pending=0, oldest=None, destination=DESTINATION):
    return wire.heartbeat_request({"v": 1, "collector_id": COLLECTOR, "destination_id": destination, "source_id": SOURCE,
                                   "sequence": sequence, "pending_events": pending, "oldest_pending_at": oldest,
                                   "retained_events": pending, "employee_session_reserve": 0, "delivery_error": None}).data


def counts(store):
    with store.read() as connection:
        return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("events", "event_receipts", "alert_cases", "alert_transitions", "alert_outbox", "inbox_messages", "inbox_receipts", "inbox_acknowledgements")}


def test_fixture_is_independent_from_business_storage_and_raw_tokens_are_not_in_database(pair):
    collector, issued, inbox, inbox_issued, _ = pair
    assert Path(sys.modules["collector"].__file__).is_relative_to(ROOT)
    for service, credentials in ((collector, issued), (inbox, inbox_issued)):
        data = service.store.path.read_bytes()
        assert credentials.ingest_token.encode() not in data and credentials.operator_token.encode() not in data
        assert hashlib.sha256(credentials.ingest_token.encode()).hexdigest().encode() in data
        with service.store.read() as connection:
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        assert not names & {"users", "account_mfa", "sessions"}


def test_commit_then_response_loss_restart_and_concurrent_retries_return_identical_receipt(pair, monkeypatch):
    collector, issued, _, _, clock = pair
    original = collector.ingest_event(issued.ingest_token, event())
    clock[0] += 10
    restarted = Collector(collector.store.directory, clock=lambda: clock[0])
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(restarted.ingest_event, issued.ingest_token, event()) for _ in range(2)]
        assert [future.result() for future in futures] == [original, original]
    monkeypatch.setattr(wire, "event_receipt", lambda fields: pytest.fail("Retry reserialized a committed receipt"))
    assert restarted.ingest_event(issued.ingest_token, event(kind="retained_backfill")) == original
    assert counts(restarted.store)["events"] == counts(restarted.store)["event_receipts"] == 1


def test_new_registered_destination_keeps_event_identity_and_its_own_receipt_bytes(pair):
    collector, issued, _, _, _ = pair
    first = json.loads(collector.ingest_event(issued.ingest_token, event()))
    destination = "9" * 32
    token = collector.store.register_channel(destination)
    raw = collector.ingest_event(token, event(destination=destination, kind="retained_backfill"))
    second = json.loads(raw)
    assert second["destination_id"] == destination and first["destination_id"] == DESTINATION
    assert first["receipt_id"] == second["receipt_id"] and first["received_at"] == second["received_at"]
    assert collector.ingest_event(token, event(destination=destination)) == raw
    assert counts(collector.store)["events"] == 1 and counts(collector.store)["event_receipts"] == 2
    collector.store.retire_channel(DESTINATION)
    with pytest.raises(ServiceError, match="unauthenticated"):
        collector.ingest_event(issued.ingest_token, event())
    assert collector.ingest_event(token, event(destination=destination)) == raw


def test_conflicting_payload_is_refused_and_one_durable_alert_survives_restart(pair):
    collector, issued, _, _, clock = pair
    accepted = collector.ingest_event(issued.ingest_token, event())
    for _ in range(2):
        with pytest.raises(ServiceError) as error:
            collector.ingest_event(issued.ingest_token, event(actor="b" * 64))
        assert error.value.status == 409
    restarted = Collector(collector.store.directory, clock=lambda: clock[0])
    assert restarted.ingest_event(issued.ingest_token, event()) == accepted
    result = counts(restarted.store)
    assert result["events"] == result["alert_cases"] == result["alert_transitions"] == result["alert_outbox"] == 1
    assert restarted.list_alerts(issued.operator_token)[0]["rule"] == "event_conflict"


@pytest.mark.parametrize("table", ["events", "event_receipts", "alert_transitions", "inbox_messages", "inbox_receipts"])
def test_accepted_records_refuse_update_and_delete_even_from_normal_sql_writer(pair, table):
    collector, issued, inbox, inbox_issued, clock = pair
    collector.ingest_event(issued.ingest_token, event())
    clock[0] += 91
    collector.evaluate_alerts()
    delivery = collector.pending_alerts()[0]
    inbox.ingest_alert(inbox_issued.ingest_token, delivery.body)
    store = inbox.store if table.startswith("inbox_") else collector.store
    with store.read() as connection:
        column = connection.execute(f"PRAGMA table_info({table})").fetchone()[1]
    for query in (f"DELETE FROM {table}", f"UPDATE {table} SET {column}={column}"):
        with pytest.raises(sqlite3.IntegrityError, match="Immutable"):
            with store.transaction() as connection:
                connection.execute(query)


def test_heartbeat_replay_cannot_refresh_liveness_and_global_counter_survives_channel_change(pair, monkeypatch):
    collector, issued, _, _, clock = pair
    receipt = collector.accept_heartbeat(issued.ingest_token, heartbeat(5))
    clock[0] += 91
    collector.evaluate_alerts()
    monkeypatch.setattr(wire, "heartbeat_receipt", lambda fields: pytest.fail("Duplicate heartbeat receipt was reserialized"))
    assert collector.accept_heartbeat(issued.ingest_token, heartbeat(5)) == receipt
    assert collector.list_alerts(issued.operator_token)[0]["condition_open"] == 1
    for stale in (heartbeat(4), heartbeat(5, pending=1, oldest=clock[0])):
        with pytest.raises(ServiceError) as error:
            collector.accept_heartbeat(issued.ingest_token, stale)
        assert error.value.code == "stale_heartbeat"
    new_destination = "9" * 32
    token = collector.store.register_channel(new_destination)
    with pytest.raises(ServiceError, match="stale_heartbeat"):
        collector.accept_heartbeat(token, heartbeat(5, destination=new_destination))
    with collector.store.read() as connection:
        assert connection.execute("SELECT received_at FROM heartbeats").fetchone()[0] == 1700000000.0


def test_never_seen_source_alert_is_persistent_ack_is_not_resolution_new_heartbeat_resolves(pair):
    collector, issued, _, _, clock = pair
    clock[0] += 91
    collector.evaluate_alerts()
    row = collector.list_alerts(issued.operator_token)[0]
    collector.acknowledge_alert(issued.operator_token, row["id"], row["number"])
    collector.evaluate_alerts()
    current = collector.list_alerts(issued.operator_token)[0]
    assert current["condition_open"] == current["acknowledged"] == 1 and current["number"] == 2
    restarted = Collector(collector.store.directory, clock=lambda: clock[0])
    restarted.accept_heartbeat(issued.ingest_token, heartbeat(1))
    assert restarted.list_alerts(issued.operator_token)[0]["condition_open"] == 0
    assert counts(restarted.store)["alert_transitions"] == 3


def test_events_and_health_do_not_mask_missing_heartbeat(pair):
    collector, issued, _, _, clock = pair
    clock[0] += 91
    collector.ingest_event(issued.ingest_token, event())
    app = create_app(collector.store.directory, clock=lambda: clock[0], evaluator=False)
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
    assert any(row["rule"] == "source_missing" and row["condition_open"] for row in collector.list_alerts(issued.operator_token))


def test_backfill_queue_age_future_clock_and_resolution_are_separate_from_heartbeat(pair):
    collector, issued, _, _, clock = pair
    collector.accept_heartbeat(issued.ingest_token, heartbeat(1, pending=1, oldest=clock[0]))
    assert not collector.list_alerts(issued.operator_token)
    clock[0] += 301
    collector.accept_heartbeat(issued.ingest_token, heartbeat(2, pending=1, oldest=1700000000.0))
    row = collector.list_alerts(issued.operator_token)[0]
    assert row["rule"] == "source_backlog" and row["severity"] == "warning"
    collector.accept_heartbeat(issued.ingest_token, heartbeat(3, pending=1, oldest=clock[0] + 100))
    current = collector.list_alerts(issued.operator_token)[0]
    assert current["severity"] == "critical" and current["number"] == 2
    assert json.loads(current["details"])["basis"] == "clock_untrusted"
    collector.accept_heartbeat(issued.ingest_token, heartbeat(4, pending=1, oldest=clock[0]))
    assert collector.list_alerts(issued.operator_token)[0]["condition_open"] == 1
    # The backwards enqueue time is a new clock anomaly. A subsequent fresh
    # timing report may clear it without pretending the queue had to be empty.
    collector.accept_heartbeat(issued.ingest_token, heartbeat(5, pending=1, oldest=clock[0]))
    assert collector.list_alerts(issued.operator_token)[0]["condition_open"] == 0


def test_receiver_clock_rollback_cannot_advance_counter_or_clear_missing_condition(pair):
    collector, issued, _, _, clock = pair
    clock[0] += 91
    collector.evaluate_alerts()
    clock[0] -= 20
    with pytest.raises(ServiceError, match="unavailable"):
        collector.accept_heartbeat(issued.ingest_token, heartbeat(1))
    assert collector.list_alerts(issued.operator_token)[0]["condition_open"] == 1
    with collector.store.read() as connection:
        assert connection.execute("SELECT COUNT(*) FROM heartbeats").fetchone()[0] == 0


def test_required_alert_failure_rolls_back_new_event_or_heartbeat_acknowledgement(pair, monkeypatch):
    collector, issued, _, _, clock = pair
    clock[0] += 91

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("Synthetic alert failure")

    monkeypatch.setattr(alerts, "_transition", fail)
    with pytest.raises(sqlite3.OperationalError):
        collector.ingest_event(issued.ingest_token, event())
    assert counts(collector.store)["events"] == counts(collector.store)["alert_cases"] == 0
    # Future source queue requires a clock-untrusted alert in the heartbeat tx.
    with pytest.raises(sqlite3.OperationalError):
        collector.accept_heartbeat(issued.ingest_token, heartbeat(1, pending=1, oldest=clock[0] + 1))
    with collector.store.read() as connection:
        assert connection.execute("SELECT COUNT(*) FROM heartbeats").fetchone()[0] == 0


def test_full_capacity_preserves_old_receipts_and_rejects_new_events(pair):
    collector, issued, _, _, _ = pair
    first = collector.ingest_event(issued.ingest_token, event())
    collector.store.settings["max_events"] = 1
    with pytest.raises(ServiceError) as error:
        collector.ingest_event(issued.ingest_token, event(event_id="5" * 32))
    assert error.value.status == 507
    assert collector.ingest_event(issued.ingest_token, event()) == first
    assert counts(collector.store)["events"] == 1
    assert any(row["rule"] == "collector_capacity" and row["severity"] == "critical" for row in collector.list_alerts(issued.operator_token))


def test_alert_delivery_response_loss_inbox_retry_receipt_validation_and_operator_separation(pair, monkeypatch):
    collector, issued, inbox, inbox_issued, clock = pair
    clock[0] += 91
    collector.evaluate_alerts()
    pending = collector.pending_alerts()[0]
    delivery = collector.begin_alert_attempt(pending.alert_id, pending.number)
    assert delivery.attempts == 1
    receipt = inbox.ingest_alert(inbox_issued.ingest_token, delivery.body)
    monkeypatch.setattr(wire, "inbox_receipt", lambda fields: pytest.fail("Inbox retry reserialized receipt"))
    assert inbox.ingest_alert(inbox_issued.ingest_token, delivery.body) == receipt
    bad = json.loads(receipt)
    bad["inbox_id"] = "0" * 32
    with pytest.raises(wire.ProtocolError):
        collector.ack_alert(delivery.alert_id, delivery.number, safe_json(bad))
    assert collector.pending_alerts()
    collector.ack_alert(delivery.alert_id, delivery.number, receipt)
    collector.fail_alert(delivery.alert_id, delivery.number, "transport_failed")
    assert not collector.pending_alerts()
    assert counts(inbox.store)["inbox_messages"] == 1 and counts(inbox.store)["inbox_acknowledgements"] == 0
    with pytest.raises(ServiceError):
        inbox.list_messages(inbox_issued.ingest_token)
    with pytest.raises(ServiceError):
        collector.list_alerts(issued.ingest_token)
    message = inbox.list_messages(inbox_issued.operator_token)[0]
    inbox.acknowledge_message(inbox_issued.operator_token, message["collector_id"], message["alert_id"], message["number"])
    assert counts(inbox.store)["inbox_acknowledgements"] == 1
    assert collector.list_alerts(issued.operator_token)[0]["acknowledged"] == 0


def test_delivery_backoff_survives_restart_and_token_rotation_rejects_retired_writer(pair):
    collector, issued, _, _, clock = pair
    clock[0] += 91
    collector.evaluate_alerts()
    item = collector.pending_alerts()[0]
    collector.begin_alert_attempt(item.alert_id, item.number)
    collector.fail_alert(item.alert_id, item.number, "remote_throttled", retry_after=999999)
    restarted = Collector(collector.store.directory, clock=lambda: clock[0])
    assert not restarted.pending_alerts()
    clock[0] += 301
    assert restarted.pending_alerts()[0].attempts == 1
    replacement = restarted.store.rotate_ingest(DESTINATION)
    with pytest.raises(ServiceError, match="unauthenticated"):
        restarted.ingest_event(issued.ingest_token, event())
    assert restarted.ingest_event(replacement, event())


def test_backup_excludes_plaintext_tokens_and_stale_restore_cannot_serve(pair, tmp_path):
    collector, issued, _, _, _ = pair
    collector.ingest_event(issued.ingest_token, event())
    bundle = create_backup(collector.store.directory, tmp_path / "bundle")
    collector.ingest_event(issued.ingest_token, event(event_id="5" * 32))
    restored = restore_quarantined(bundle, tmp_path / "restored")
    assert (restored / "RESTORE_QUARANTINE").is_file()
    assert sorted(path.name for path in bundle.iterdir()) == ["manifest.json", "state.sqlite3"]
    with pytest.raises(ValueError, match="quarantined"):
        create_app(restored)
    assert Store(restored, allow_quarantine=True).settings["service_id"] == COLLECTOR
    assert counts(collector.store)["events"] == 2


@pytest.mark.parametrize("fault", ["wrong_token", "operator_as_writer", "wrong_channel", "duplicate_auth", "encoding", "oversize", "noncanonical"])
def test_http_ingress_denials_never_allocate_event_authority(pair, fault):
    collector, issued, _, _, clock = pair
    headers = [("Authorization", "Bearer " + issued.ingest_token), ("Content-Type", "application/json")]
    body = event()
    if fault == "wrong_token":
        headers[0] = ("Authorization", "Bearer " + "x" * 43)
    elif fault == "operator_as_writer":
        headers[0] = ("Authorization", "Bearer " + issued.operator_token)
    elif fault == "wrong_channel":
        body = event(destination="9" * 32)
    elif fault == "duplicate_auth":
        headers.append(headers[0])
    elif fault == "encoding":
        headers.append(("Content-Encoding", "gzip"))
    elif fault == "oversize":
        body = b"x" * 4097
    elif fault == "noncanonical":
        body += b" "
    app = create_app(collector.store.directory, clock=lambda: clock[0], evaluator=False)
    with TestClient(app) as client:
        response = client.post("/v1/events", content=body, headers=headers)
    assert response.status_code in {400, 401, 403, 413, 415}
    assert set(response.json()) == {"v", "error"}
    assert issued.ingest_token not in response.text and "Traceback" not in response.text
    assert counts(collector.store)["events"] == 0


def test_http_valid_delivery_and_persistent_rate_limit_do_not_starve_heartbeat(pair):
    collector, issued, _, _, clock = pair
    headers = {"Authorization": "Bearer " + issued.ingest_token, "Content-Type": "application/json"}
    app = create_app(collector.store.directory, clock=lambda: clock[0], evaluator=False)
    with TestClient(app) as client:
        first = client.post("/v1/events", content=event(), headers=headers)
        assert first.status_code == 200
        for _ in range(19):
            assert client.post("/v1/events", content=event(), headers=headers).content == first.content
        assert client.post("/v1/events", content=event(), headers=headers).status_code == 429
        assert client.post("/v1/heartbeat", content=heartbeat(1), headers=headers).status_code == 200
        assert client.get("/healthz").status_code == 200
    restarted = create_app(collector.store.directory, clock=lambda: clock[0], evaluator=False)
    with TestClient(restarted) as client:
        assert client.post("/v1/events", content=event(), headers=headers).status_code == 429


def test_provisioning_never_overwrites_existing_or_uses_source_tree(pair):
    collector, _, _, _, _ = pair
    arguments = dict(kind="collector", source_id=SOURCE, destination_id=DESTINATION, inbox_id=INBOX, alert_destination_id=ALERT_DESTINATION)
    with pytest.raises(FileExistsError):
        provision(collector.store.directory, **arguments)
    with pytest.raises(ValueError, match="outside source"):
        provision(ROOT / "forbidden-collector-runtime", **arguments)


def test_schema_damage_and_missing_storage_are_not_implicitly_repaired(pair, tmp_path):
    collector, _, _, _, _ = pair
    with collector.store.transaction() as connection:
        connection.execute("DROP TRIGGER immutable_events_update")
    with pytest.raises(ValueError, match="schema"):
        Store(collector.store.directory)
    with pytest.raises(ValueError):
        Store(tmp_path / "missing")
    assert not (tmp_path / "missing").exists()


def test_notifier_receipt_loss_and_restart_retries_without_holding_a_write_transaction(pair, monkeypatch):
    collector, issued, inbox, inbox_issued, clock = pair
    clock[0] += 91
    collector.evaluate_alerts()
    collector.store.configure_alert_endpoint("https://operator-inbox.invalid/v1/alerts")
    notifier = Notifier(collector, token_file=inbox.store.directory / "ingest.token")
    module = load_transport()
    calls = []

    class LostResponse:
        async def post(self, body):
            # Taking an independent collector writer proves no originating
            # transaction remains held across the external transport boundary.
            with collector.store.transaction() as connection:
                assert connection.execute("SELECT COUNT(*) FROM alert_outbox").fetchone()[0] == 1
            receipt = inbox.ingest_alert(inbox_issued.ingest_token, body)
            calls.append(receipt)
            if len(calls) == 1:
                raise module.DeliveryFailure("transport_failed")
            return receipt

    monkeypatch.setattr(notifier, "_transport", lambda: LostResponse())
    assert asyncio.run(notifier.dispatch_once()) == 0
    assert counts(inbox.store)["inbox_messages"] == 1
    clock[0] += 301
    restarted = Collector(collector.store.directory, clock=lambda: clock[0])
    notifier.service = restarted
    assert asyncio.run(notifier.dispatch_once()) == 1
    assert calls[0] == calls[1]
    assert not restarted.pending_alerts()
    assert counts(inbox.store)["inbox_acknowledgements"] == 0
    with restarted.store.read() as connection:
        assert connection.execute("SELECT attempts FROM alert_outbox").fetchone()[0] == 2


def test_notifier_missing_or_changed_configuration_keeps_obligation_and_sanitizes_errors(pair, caplog):
    collector, _, _, _, clock = pair
    clock[0] += 91
    collector.evaluate_alerts()
    notifier = Notifier(collector)
    assert asyncio.run(notifier.dispatch_once()) == 0
    with collector.store.read() as connection:
        row = connection.execute("SELECT * FROM alert_outbox").fetchone()
        assert row["acknowledged_at"] is None and row["last_error"] == "config_unavailable"
    collector.store.configure_alert_endpoint("https://operator-inbox.invalid/v1/alerts")
    with pytest.raises(ValueError, match="immutable"):
        collector.store.configure_alert_endpoint("https://replacement.invalid/v1/alerts")
    assert "config_unavailable" in caplog.text and "Bearer" not in caplog.text


def test_notifier_bad_receipt_never_acks_and_stop_is_checked_between_attempts(pair, monkeypatch):
    collector, _, _, _, clock = pair
    clock[0] += 91
    collector.evaluate_alerts()
    notifier = Notifier(collector)

    class BadReceipt:
        async def post(self, body):
            return b'{"v":1}'

    monkeypatch.setattr(notifier, "_transport", lambda: BadReceipt())
    assert asyncio.run(notifier.dispatch_once()) == 0
    with collector.store.read() as connection:
        row = connection.execute("SELECT * FROM alert_outbox").fetchone()
        assert row["acknowledged_at"] is None and row["last_error"] == "invalid_receipt"
    clock[0] += 301
    stop = Event()
    stop.set()
    assert asyncio.run(notifier.dispatch_once(stop)) == 0
    with collector.store.read() as connection:
        assert connection.execute("SELECT attempts FROM alert_outbox").fetchone()[0] == 1


def test_cancelled_ingress_keeps_actual_worker_admission_until_callback_exits(pair, monkeypatch):
    collector, issued, _, _, clock = pair
    app = create_app(collector.store.directory, clock=lambda: clock[0], evaluator=False)
    entered, release, exited = Event(), Event(), Event()
    original = app.service.ingest_event

    def blocked(token, body):
        entered.set()
        try:
            assert release.wait(5)
            return original(token, body)
        finally:
            exited.set()

    monkeypatch.setattr(app.service, "ingest_event", blocked)

    async def scenario():
        async def request(path, payload, token=issued.ingest_token):
            sent, received = [], False
            async def receive():
                nonlocal received
                if received:
                    await asyncio.sleep(10)
                received = True
                return {"type": "http.request", "body": payload, "more_body": False}
            async def send(message):
                sent.append(message)
            scope = {"type": "http", "method": "POST", "path": path, "query_string": b"",
                     "headers": [(b"authorization", ("Bearer " + token).encode()), (b"content-type", b"application/json")]}
            await app(scope, receive, send)
            return sent[0]["status"]

        first = asyncio.create_task(request("/v1/events", event()))
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        assert entered.is_set()
        first.cancel()
        try:
            await first
        except asyncio.CancelledError:
            pass
        # One actual callback is still running. A second slot may be taken,
        # but cancellation must not create a third callback slot.
        assert app.gates["events"].acquire(blocking=False)
        try:
            assert not app.gates["events"].acquire(blocking=False)
            assert await request("/v1/events", event()) == 429
            assert await request("/v1/heartbeat", heartbeat(1)) == 200
        finally:
            app.gates["events"].release()
            release.set()
        for _ in range(100):
            if exited.is_set():
                break
            await asyncio.sleep(0.01)
        assert exited.is_set()
    asyncio.run(scenario())


@pytest.mark.parametrize("damage", ["sidecar", "extra", "manifest_size", "hash"])
def test_restore_refuses_unreviewed_archive_shape_and_bounded_integrity_failure(pair, tmp_path, damage):
    collector, _, _, _, _ = pair
    bundle = create_backup(collector.store.directory, tmp_path / "bundle")
    if damage == "sidecar":
        (bundle / "state.sqlite3-wal").write_bytes(b"unexpected")
    elif damage == "extra":
        (bundle / "surprise.txt").write_bytes(b"unexpected")
    elif damage == "manifest_size":
        (bundle / "manifest.json").write_bytes(b" " * 4097)
    else:
        with (bundle / "state.sqlite3").open("ab") as stream:
            stream.write(b"changed")
    with pytest.raises(ValueError):
        restore_quarantined(bundle, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()
    assert bundle.exists()


def test_provision_token_write_failure_leaves_an_explicit_unservable_marker(tmp_path, monkeypatch):
    from collector import storage
    original = storage.write_private
    def failed(path, data):
        if path.name == "operator.token":
            raise OSError("Synthetic private credential write failure")
        return original(path, data)
    monkeypatch.setattr(storage, "write_private", failed)
    path = tmp_path / "partial"
    with pytest.raises(OSError):
        provision(path, kind="inbox", source_id=SOURCE, destination_id=ALERT_DESTINATION, peer_id=COLLECTOR)
    assert (path / "PROVISION_INCOMPLETE").exists()
    with pytest.raises(ValueError, match="incomplete"):
        Store(path)


def test_lifespan_evaluator_and_notifier_are_separate_and_finish_on_shutdown(pair, monkeypatch):
    collector, _, inbox, inbox_issued, clock = pair
    clock[0] += 91
    app = create_app(collector.store.directory, clock=lambda: clock[0])
    completed = Event()
    class Deliver:
        async def post(self, body):
            result = inbox.ingest_alert(inbox_issued.ingest_token, body)
            completed.set()
            return result
    monkeypatch.setattr(app.notifier, "_transport", lambda: Deliver())
    # Scheduling is exercised through real ASGI lifespan. Evaluate before
    # startup to avoid relying on which background task runs first.
    app.service.evaluate_alerts()
    with TestClient(app):
        assert completed.wait(5)
        for _ in range(100):
            if not app.service.pending_alerts():
                break
            time.sleep(0.01)
        assert not app.service.pending_alerts()
    assert counts(inbox.store)["inbox_messages"] == 1


def test_byte_admission_reserves_control_room_but_never_evicts_a_receipt(pair, monkeypatch):
    collector, issued, _, _, _ = pair
    original = collector.ingest_event(issued.ingest_token, event())
    monkeypatch.setattr(collector.store, "event_storage_full", lambda connection: True)
    with pytest.raises(ServiceError) as error:
        collector.ingest_event(issued.ingest_token, event(event_id="5" * 32))
    assert error.value.status == 507
    assert collector.ingest_event(issued.ingest_token, event()) == original
    collector.accept_heartbeat(issued.ingest_token, heartbeat(1))
    assert any(row["rule"] == "collector_capacity" for row in collector.list_alerts(issued.operator_token))


def test_http_operator_ack_cannot_be_used_by_ingest_credentials(pair):
    collector, issued, _, _, clock = pair
    clock[0] += 91
    collector.evaluate_alerts()
    row = collector.list_alerts(issued.operator_token)[0]
    app = create_app(collector.store.directory, clock=lambda: clock[0], evaluator=False)
    with TestClient(app) as client:
        path = f"/v1/operator/alerts/{row['id']}/ack"
        headers = {"Authorization": "Bearer " + issued.ingest_token, "Content-Type": "application/json"}
        assert client.post(path, headers=headers, content=safe_json({"number": row["number"]})).status_code == 401
        headers["Authorization"] = "Bearer " + issued.operator_token
        assert client.post(path, headers=headers, content=safe_json({"number": row["number"]})).status_code == 200
    current = collector.list_alerts(issued.operator_token)[0]
    assert current["acknowledged"] == current["condition_open"] == 1
