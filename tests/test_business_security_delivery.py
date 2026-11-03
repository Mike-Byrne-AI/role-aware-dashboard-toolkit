"""Automatic outbox delivery with real lifespan, retry and shutdown boundaries."""

import json
import logging
from pathlib import Path
import shutil
import tempfile
from threading import Event, Thread
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    ORIGIN, business_seed as business_seed, create_app, default_key_path,
)
from fastapi.testclient import TestClient  # noqa: E402
from business import security_delivery, security_events  # noqa: E402


@pytest.fixture
def delivery_app(business_seed):
    # Intentionally does not use business(): these tests exercise real workers.
    with tempfile.TemporaryDirectory(prefix="radt-delivery-test-") as temporary:
        directory = Path(temporary).resolve() / "private"
        shutil.copytree(business_seed.directory, directory)
        shutil.copytree(default_key_path(business_seed.directory).parent, default_key_path(directory).parent)
        app = create_app(directory, public_origin=ORIGIN)
        # Keep the shared enrollment evidence intact; this copied database
        # starts an isolated worker-delivery scenario with an empty event queue.
        with app.state.database.transaction() as connection:
            assert connection.execute("SELECT COUNT(*) FROM account_security WHERE lifecycle='active'").fetchone()[0] == 6
            connection.execute("DELETE FROM security_events")
        app.state.security_dispatcher.interval = 0.02
        try:
            yield app
        finally:
            # Stop even after an assertion fails; no background writer may
            # outlive the disposable database or contaminate a later test.
            app.state.security_dispatcher.stop()


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.01)
    raise AssertionError("Bounded delivery condition did not occur")


def pending(database):
    with database.readonly_snapshot() as connection:
        return security_events.delivery_status(connection)["pending"]


def test_lifespan_drains_committed_events_without_replaying_business_action(delivery_app):
    database, dispatcher = delivery_app.state.database, delivery_app.state.security_dispatcher
    with database.transaction() as connection:
        connection.execute("UPDATE settings SET freeze_revision=freeze_revision+1")
        identifier = security_events.record_event(connection, "editing_paused")
    with TestClient(delivery_app, base_url=ORIGIN):
        wait_for(lambda: pending(database) == 0)
        # The durable acknowledgement commits before the worker publishes its
        # in-memory cycle status. Observe both boundaries independently.
        wait_for(lambda: dispatcher.snapshot()["last_delivery_at"] is not None)
        state = dispatcher.snapshot()
        assert state["running"] and state["last_delivery_at"] is not None
        assert state["consecutive_failed_cycles"] == 0
    assert not dispatcher.snapshot()["running"]
    with database.readonly_snapshot() as connection:
        assert connection.execute("SELECT freeze_revision FROM settings").fetchone()[0] == 1
        assert connection.execute("SELECT event_id FROM security_sink_receipts").fetchone()[0] == identifier


def test_overlapping_app_lifespans_share_worker_and_restart_after_final_shutdown(delivery_app):
    dispatcher, database = delivery_app.state.security_dispatcher, delivery_app.state.database
    with TestClient(delivery_app, base_url=ORIGIN) as outer:
        first = dispatcher._thread
        with TestClient(delivery_app, base_url=ORIGIN):
            assert dispatcher._thread is first and first.is_alive()
        assert dispatcher._thread is first and first.is_alive()
        assert outer.get("/healthz").status_code == 200
        with database.transaction() as connection:
            security_events.record_event(connection, "editing_paused")
        wait_for(lambda: pending(database) == 0)
    assert not first.is_alive() and dispatcher._thread is None
    with database.transaction() as connection:
        security_events.record_event(connection, "editing_resumed")
    with TestClient(delivery_app, base_url=ORIGIN):
        assert dispatcher._thread is not first and dispatcher.snapshot()["running"]
        wait_for(lambda: pending(database) == 0)
    assert not dispatcher.snapshot()["running"]


def test_consumer_failure_preserves_obligation_and_reports_redacted_retry(delivery_app, monkeypatch, caplog):
    database, dispatcher = delivery_app.state.database, delivery_app.state.security_dispatcher
    original = security_events.consume_local
    with database.transaction() as connection:
        security_events.record_event(connection, "editing_paused")

    def fail(connection, event):
        raise RuntimeError("PRIVATE_ADAPTER_SECRET_CANARY")

    monkeypatch.setattr(security_events, "consume_local", fail)
    with TestClient(delivery_app, base_url=ORIGIN):
        wait_for(lambda: dispatcher.snapshot()["failed_cycles_since_start"] >= 1)
        assert pending(database) == 1
        with database.readonly_snapshot() as connection:
            row = dict(connection.execute("SELECT * FROM security_delivery_obligations").fetchone())
        assert row["last_error"] == "delivery_failed" and row["acknowledged_at"] is None
        assert "CANARY" not in caplog.text + json.dumps(dispatcher.snapshot()) + json.dumps(row)
        monkeypatch.setattr(security_events, "consume_local", original)
        with database.transaction() as connection:
            connection.execute("UPDATE security_delivery_obligations SET next_attempt_at=0")
        wait_for(lambda: pending(database) == 0)
        wait_for(lambda: dispatcher.snapshot()["last_delivery_at"] is not None)
    assert dispatcher.snapshot()["failed_cycles_since_start"] >= 1


def test_deferred_failed_delivery_stays_unhealthy_until_acknowledged(delivery_app, monkeypatch, caplog):
    database, dispatcher = delivery_app.state.database, delivery_app.state.security_dispatcher
    original = security_events.consume_local
    caplog.set_level(logging.INFO, logger=security_delivery.__name__)
    with database.transaction() as connection:
        security_events.record_event(connection, "editing_paused")

    def fail(connection, event):
        raise RuntimeError("PRIVATE_ADAPTER_SECRET_CANARY")

    monkeypatch.setattr(security_events, "consume_local", fail)
    with TestClient(delivery_app, base_url=ORIGIN):
        wait_for(lambda: dispatcher.snapshot()["failed_cycles_since_start"] >= 1)
        deferred_result = {"delivered": 0, "failed": 0, "pending": 1}
        wait_for(lambda: dispatcher.snapshot()["last_result"] == deferred_result)
        deferred_cycle = dispatcher.snapshot()["last_cycle_at"]
        wait_for(lambda: dispatcher.snapshot()["last_cycle_at"] != deferred_cycle)
        state = dispatcher.snapshot()
        assert state["last_result"] == deferred_result
        assert state["consecutive_failed_cycles"] > 0
        assert state["last_delivery_at"] is None
        assert "Automatic security-event delivery resumed" not in caplog.text
        assert caplog.text.count("Automatic security-event delivery failed") == 1
        with database.readonly_snapshot() as connection:
            row = dict(connection.execute("SELECT * FROM security_delivery_obligations").fetchone())
        assert row["attempts"] == 1 and row["last_error"] == "delivery_failed"
        assert row["acknowledged_at"] is None

        monkeypatch.setattr(security_events, "consume_local", original)
        with database.transaction() as connection:
            connection.execute("UPDATE security_delivery_obligations SET next_attempt_at=0")
        wait_for(lambda: pending(database) == 0)
        wait_for(lambda: dispatcher.snapshot()["consecutive_failed_cycles"] == 0)
        wait_for(lambda: "Automatic security-event delivery resumed" in caplog.text)
        recovered_cycle = dispatcher.snapshot()["last_cycle_at"]
        wait_for(lambda: dispatcher.snapshot()["last_cycle_at"] != recovered_cycle)
        assert dispatcher.snapshot()["last_delivery_at"] is not None
    assert caplog.text.count("Automatic security-event delivery resumed") == 1
    assert "CANARY" not in caplog.text


def test_new_worker_detects_persisted_failure_before_retry_is_due(delivery_app, monkeypatch, caplog):
    database = delivery_app.state.database
    with database.transaction() as connection:
        security_events.record_event(connection, "editing_paused")

    def fail(connection, event):
        raise RuntimeError("PRIVATE_ADAPTER_SECRET_CANARY")

    monkeypatch.setattr(security_events, "consume_local", fail)
    assert security_events.dispatch_pending(database) == {"delivered": 0, "failed": 1, "pending": 1}
    worker = security_delivery.SecurityEventDispatcher(database, interval=0.01)
    worker.start()
    try:
        wait_for(lambda: worker.snapshot()["last_cycle_at"] is not None)
        state = worker.snapshot()
        assert state["last_result"] == {"delivered": 0, "failed": 0, "pending": 1}
        assert state["consecutive_failed_cycles"] > 0
        assert state["last_delivery_at"] is None
    finally:
        worker.stop()
    with database.readonly_snapshot() as connection:
        assert connection.execute("SELECT attempts FROM security_delivery_obligations").fetchone()[0] == 1
    assert caplog.text.count("Automatic security-event delivery failed") == 1
    assert "Automatic security-event delivery resumed" not in caplog.text


def test_worker_failure_is_visible_without_exception_content_or_repeated_logs(delivery_app, monkeypatch, caplog):
    dispatcher = delivery_app.state.security_dispatcher

    def fail(*args, **kwargs):
        raise RuntimeError("PRIVATE_DATABASE_PATH_CANARY")

    monkeypatch.setattr(security_delivery, "dispatch_pending", fail)
    with TestClient(delivery_app, base_url=ORIGIN):
        wait_for(lambda: dispatcher.snapshot()["consecutive_failed_cycles"] >= 3)
        state = dispatcher.snapshot()
        assert state["last_cycle_at"] is not None and state["last_result"] is None
        assert state["last_delivery_at"] is None
    assert caplog.text.count("Automatic security-event delivery failed") == 1
    assert "CANARY" not in caplog.text + json.dumps(state)


def test_shutdown_waits_for_active_delivery_while_status_remains_nonblocking(delivery_app, monkeypatch):
    dispatcher = delivery_app.state.security_dispatcher
    entered, release, stopped = Event(), Event(), Event()

    def held_delivery(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return {"delivered": 0, "failed": 0, "pending": 0}

    monkeypatch.setattr(security_delivery, "dispatch_pending", held_delivery)
    dispatcher.start()
    assert entered.wait(5)
    stop_thread = Thread(target=lambda: (dispatcher.stop(), stopped.set()))
    stop_thread.start()
    try:
        assert not stopped.wait(0.05)
        # Simulates a protected timeline transaction while shutdown owns the
        # lifecycle lock and the delivery operation is still awaiting a lock.
        with delivery_app.state.database.transaction():
            started = time.monotonic()
            assert dispatcher.snapshot()["running"]
            assert time.monotonic() - started < 0.5
    finally:
        release.set()
        stop_thread.join(5)
    assert stopped.is_set() and not dispatcher.snapshot()["running"]


def test_dispatch_stops_between_events_and_preserves_untouched_obligations(delivery_app):
    database = delivery_app.state.database
    stopping = Event()
    with database.transaction() as connection:
        for _ in range(3):
            security_events.record_event(connection, "editing_paused")

    def deliver(event):
        with database.transaction() as connection:
            security_events.consume_local(connection, event)
        stopping.set()

    result = security_events.dispatch_pending(database, deliver=deliver, stop_requested=stopping.is_set)
    assert result == {"delivered": 1, "failed": 0, "pending": 2}
    with database.readonly_snapshot() as connection:
        assert sorted(row[0] for row in connection.execute("SELECT attempts FROM security_delivery_obligations")) == [0, 0, 1]


def test_worker_passes_bounded_batch_and_shutdown_signal(delivery_app, monkeypatch):
    database = delivery_app.state.database
    seen = []
    original = security_delivery.dispatch_pending

    def bounded(database, **kwargs):
        seen.append((kwargs["limit"], callable(kwargs["stop_requested"])))
        return original(database, **kwargs)

    monkeypatch.setattr(security_delivery, "dispatch_pending", bounded)
    worker = security_delivery.SecurityEventDispatcher(database, interval=0.01, batch_limit=2)
    with database.transaction() as connection:
        for _ in range(5):
            security_events.record_event(connection, "editing_paused")
    worker.start()
    try:
        wait_for(lambda: pending(database) == 0)
    finally:
        worker.stop()
    assert len(seen) >= 3 and all(value == (2, True) for value in seen)
