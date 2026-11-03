"""Private source configuration and cancellation-safe independent worker tasks."""

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from threading import Event
import time
from types import SimpleNamespace

import pytest

from tests.test_business_remote_obligations import (
    COLLECTOR, DESCRIPTOR, REMOTE, enable, source as source, sources as sources,
)
from business import db, event_config as config, event_remote as remote
from business.event_destinations import destination_status, source_identity
from business.event_wire import load_transport, wire


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    import httpx

    attempts = []

    async def fail(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("Worker unit proof must not contact any network destination")

    monkeypatch.setattr(httpx.AsyncClient, "send", fail)
    yield
    assert not attempts


def private_configuration(source, *, updates=None, token=None, name="delivery.json"):
    root = source.directory.parent
    token_path = root / (name + ".token")
    token = token or "X" * 43
    db.create_private_file(token_path, (token + "\n").encode())
    with source.database.readonly_snapshot() as connection:
        identifier = source_identity(connection)["source_id"]
    value = {"v": 1, "source_id": identifier, "collector_id": COLLECTOR, "destination_id": REMOTE,
             "endpoint": DESCRIPTOR.endpoint, "token_file": str(token_path), "ca_file": None}
    value.update(updates or {})
    path = root / name
    db.create_private_file(path, json.dumps(value).encode())
    return path, identifier, token


def configured_transport(monkeypatch, transport):
    monkeypatch.setattr(remote, "load_delivery_configuration", lambda *args, **kwargs: SimpleNamespace(transport=transport))


def answer(body, heartbeat=False):
    fields = json.loads(body)
    if heartbeat:
        return wire.heartbeat_receipt({"v": 1, **{key: fields[key] for key in ("source_id", "collector_id", "destination_id", "sequence")},
                                       "sha256": hashlib.sha256(body).hexdigest(), "received_at": 100.0})
    payload = json.loads(wire.parse_event_request(body, {
        "collector_id": fields["collector_id"], "destination_id": fields["destination_id"],
        "source_id": json.loads(__import__("base64").b64decode(fields["payload"]))["source_id"],
    }).payload.data)
    return wire.event_receipt({"v": 1, "collector_id": fields["collector_id"], "destination_id": fields["destination_id"],
                               "source_id": payload["source_id"], "event_id": payload["event"]["id"], "sha256": fields["sha256"],
                               "receipt_id": "7" * 32, "received_at": 100.0})


def test_private_configuration_validates_before_activation_and_hides_secrets(source):
    path, identity, token = private_configuration(source)
    loaded = config.load_delivery_configuration(path, source_id=identity, descriptor=DESCRIPTOR)
    assert loaded.source_id == identity and loaded.descriptor == DESCRIPTOR
    assert loaded.transport.token == token and loaded.transport.endpoint == DESCRIPTOR.endpoint
    assert token not in repr(loaded) + repr(loaded.transport) and str(path) not in repr(loaded)
    with source.database.readonly_snapshot() as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_destinations WHERE kind='https'").fetchone()[0] == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode proof; no Windows ACL claim")
@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_private_configuration_rejects_nonprivate_containing_directory(source, mode):
    path, identity, _ = private_configuration(source)
    parent = path.parent
    previous_mode = parent.stat().st_mode & 0o777
    parent.chmod(mode)
    try:
        with pytest.raises(config.ConfigurationError):
            config.load_delivery_configuration(path, source_id=identity, descriptor=DESCRIPTOR)
    finally:
        parent.chmod(previous_mode)


@pytest.mark.parametrize("updates", [
    {"v": True}, {"source_id": "a" * 32}, {"collector_id": "a" * 32}, {"destination_id": "a" * 32},
    {"endpoint": "https://different.invalid/v1/events"}, {"token_file": "relative.token"},
    {"ca_file": "relative-ca.pem"}, {"extra": "forbidden"}, {"token_file": None},
])
def test_configuration_rejects_identity_aliases_unbound_paths_and_extra_fields(source, updates):
    path, identity, token = private_configuration(source, updates=updates)
    with pytest.raises(config.ConfigurationError) as caught:
        config.load_delivery_configuration(path, source_id=identity, descriptor=DESCRIPTOR)
    assert str(path) not in str(caught.value) and token not in str(caught.value)


@pytest.mark.parametrize("damage", ["duplicate_key", "oversized", "invalid_ca", "invalid_token", "source_path"])
def test_configuration_fails_closed_on_ambiguous_or_unbounded_private_material(source, damage):
    path, identity, _ = private_configuration(source)
    value = json.loads(path.read_text())
    if damage == "duplicate_key":
        path.write_bytes(path.read_bytes()[:-1] + b',"v":1}')
    elif damage == "oversized":
        path.write_bytes(b" " * (config.MAX_CONFIG_BYTES + 1))
    elif damage == "invalid_ca":
        ca = path.with_suffix(".pem")
        db.create_private_file(ca, b"PRIVATE_INVALID_CA_CANARY")
        value["ca_file"] = str(ca)
        path.write_text(json.dumps(value))
    elif damage == "invalid_token":
        Path(value["token_file"]).write_bytes(b"PRIVATE_TOKEN_CANARY\n")
    else:
        value["token_file"] = str(Path(__file__).resolve())
        path.write_text(json.dumps(value))
    with pytest.raises(config.ConfigurationError) as caught:
        config.load_delivery_configuration(path, source_id=identity, descriptor=DESCRIPTOR)
    assert "CANARY" not in str(caught.value)


def test_missing_configuration_retains_enabled_destination_and_durable_pending_error(source):
    enable(source)
    worker = remote.RemoteSecurityEventDispatcher(source.database)
    result = asyncio.run(worker._deliver_once(Event()))
    worker._record_cycle(result)
    assert result["pending"] == 1 and result["error"] == "config_unavailable"
    with source.database.readonly_snapshot() as connection:
        assert destination_status(connection, REMOTE)["state"] == "active"
        row = connection.execute("SELECT * FROM security_delivery_obligations WHERE destination_id=?", (REMOTE,)).fetchone()
        assert row["acknowledged_at"] is None and row["last_error"] == "config_unavailable" and row["attempts"] == 1
    assert worker.snapshot()["delivery_error"] == "config_unavailable"


def test_failed_deferred_empty_cycle_does_not_report_recovery_until_confirmed_retry(source, monkeypatch, caplog):
    enable(source)

    class Transport:
        fail = True

        async def post(self, body, **kwargs):
            if self.fail:
                raise load_transport().DeliveryFailure("remote_unavailable")
            return answer(body)

    transport = Transport()
    configured_transport(monkeypatch, transport)
    worker = remote.RemoteSecurityEventDispatcher(source.database)
    caplog.set_level(logging.INFO, logger=remote.__name__)
    first = asyncio.run(worker._deliver_once(Event()))
    worker._record_cycle(first)
    transport.fail = False
    deferred = asyncio.run(worker._deliver_once(Event()))
    worker._record_cycle(deferred)
    assert deferred["delivered"] == deferred["failed"] == 0 and deferred["error"] == "remote_unavailable"
    assert worker.snapshot()["consecutive_failed_cycles"] == 2
    assert not any("resumed" in row.message for row in caplog.records)
    with source.database.transaction() as connection:
        connection.execute("UPDATE security_delivery_obligations SET next_attempt_at=0 WHERE destination_id=?", (REMOTE,))
    recovered = asyncio.run(worker._deliver_once(Event()))
    worker._record_cycle(recovered)
    worker._record_cycle(asyncio.run(worker._deliver_once(Event())))
    assert recovered["delivered"] == 1 and recovered["pending"] == 0
    assert sum("resumed" in row.message for row in caplog.records) == 1


def test_network_work_begins_after_attempt_commit_and_receipt_controls_ack(source, monkeypatch):
    enable(source)

    class Transport:
        async def post(self, body, **kwargs):
            # A separate real SQLite write transaction can enter during I/O.
            with source.database.transaction() as connection:
                row = connection.execute("SELECT * FROM security_delivery_obligations WHERE destination_id=?", (REMOTE,)).fetchone()
                assert row["attempts"] == 1 and row["acknowledged_at"] is None
            return answer(body)

    configured_transport(monkeypatch, Transport())
    result = asyncio.run(remote.RemoteSecurityEventDispatcher(source.database)._deliver_once(Event()))
    assert result["delivered"] == 1 and result["pending"] == 0


def test_malformed_receipt_stays_pending_with_bounded_error_class(source, monkeypatch):
    enable(source)

    class Transport:
        async def post(self, body, **kwargs):
            return b'{"private":"UNTRUSTED_RESPONSE_CANARY"}'

    configured_transport(monkeypatch, Transport())
    result = asyncio.run(remote.RemoteSecurityEventDispatcher(source.database)._deliver_once(Event()))
    assert result["error"] == "invalid_receipt" and result["pending"] == 1 and result["delivered"] == 0
    assert "CANARY" not in json.dumps(result)


def test_heartbeat_commits_sequence_before_io_and_checks_ack_identity(source, monkeypatch):
    enable(source)

    class Transport:
        wrong = True

        async def post(self, body, *, heartbeat=False):
            assert heartbeat
            fields = json.loads(body)
            with source.database.readonly_snapshot() as connection:
                assert source_identity(connection)["heartbeat_sequence"] == fields["sequence"]
            response = json.loads(answer(body, heartbeat=True))
            if self.wrong:
                response["source_id"] = "f" * 32
            return wire.heartbeat_receipt(response)

    transport = Transport()
    configured_transport(monkeypatch, transport)
    worker = remote.RemoteSecurityEventDispatcher(source.database)
    with pytest.raises(ValueError):
        asyncio.run(worker._heartbeat_once())
    transport.wrong = False
    assert asyncio.run(worker._heartbeat_once()) == 100.0
    with source.database.readonly_snapshot() as connection:
        assert source_identity(connection)["heartbeat_sequence"] == 2


def test_stalled_event_cannot_starve_heartbeat_and_final_stop_joins_cancelled_work(source, monkeypatch):
    enable(source)
    entered, heartbeat_seen, cancelled = Event(), Event(), Event()

    class Transport:
        async def post(self, body, *, heartbeat=False):
            if heartbeat:
                assert entered.wait(timeout=2)
                heartbeat_seen.set()
                return answer(body, heartbeat=True)
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

    configured_transport(monkeypatch, Transport())
    worker = remote.RemoteSecurityEventDispatcher(source.database, interval=0.02, heartbeat_interval=0.02)
    worker.start()
    worker.start()
    try:
        assert entered.wait(timeout=5) and heartbeat_seen.wait(timeout=5)
        assert worker.snapshot()["running"]
        worker.stop()  # The other overlapping lifespan still owns the worker.
        assert worker.snapshot()["running"] and not cancelled.is_set()
    finally:
        worker.stop()
    assert cancelled.is_set() and not worker.snapshot()["running"]
    with source.database.transaction() as connection:
        assert destination_status(connection, REMOTE)["pending"] == 1
        sequence = source_identity(connection)["heartbeat_sequence"]
    time.sleep(0.05)
    with source.database.transaction() as connection:
        assert source_identity(connection)["heartbeat_sequence"] == sequence


def test_status_does_not_wait_for_a_database_write_transaction(source, monkeypatch):
    enable(source)
    worker = remote.RemoteSecurityEventDispatcher(source.database)
    with source.database.transaction():
        assert worker.snapshot()["running"] is False


@pytest.mark.parametrize("attempts,error,retry_after", [
    (1, "transport_failed", None), (1000, "transport_failed", None), (1, "tls_failed", None),
    (1, "remote_throttled", 999999), (1, "remote_throttled", 0),
])
def test_retries_are_bounded_without_counter_overflow(attempts, error, retry_after):
    delay = remote.retry_delay(attempts, error, retry_after)
    assert 5.0 <= delay <= 300.0
    if error == "tls_failed":
        assert delay >= 48.0


def test_no_remote_destination_remains_explicitly_local_without_configuration(source):
    worker = remote.RemoteSecurityEventDispatcher(source.database)
    result = asyncio.run(worker._deliver_once(Event()))
    worker._record_cycle(result)
    assert result == {"configured": False, "delivered": 0, "failed": 0, "pending": 0, "error": None}
    assert asyncio.run(worker._heartbeat_once()) is None
    assert worker.snapshot()["configured"] is False
