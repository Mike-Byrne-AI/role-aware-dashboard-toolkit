from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Barrier
import time

import pytest

from examples.record_workflows.actions import (
    ActionConflict, ActionDenied, ActionValidation, execute_change, normalize_reason,
)
from examples.record_workflows.service import WorkItemRules, WorkItems
from role_aware_dashboard_toolkit.access import AccessDenied, Identity


@pytest.fixture
def fixture(tmp_path):
    path = tmp_path / "synthetic.sqlite3"
    key = b"synthetic-example-key-for-tests!!"
    manager = Identity("synthetic-test", "manager", time.time() + 600)
    viewer = Identity("synthetic-test", "viewer", time.time() + 600)
    other = Identity("synthetic-test", "other-manager", time.time() + 600)
    service = WorkItems(path, identity_key=key)
    service.provision(manager, ["Manager"])
    service.provision(other, ["Manager"])
    service.provision(viewer, ["Viewer"])
    session = service.open_session(lambda: manager)
    service.change_freeze(session, "Manager", False, 0)
    item = service.create_item(label="Inspection", starts_at="2030-05-01T09:00:00+00:00")
    return service, session, manager, viewer, other, item, path, key


def _snapshot(path):
    with sqlite3.connect(path) as connection:
        return (
            connection.execute("SELECT * FROM items ORDER BY id").fetchall(),
            connection.execute("SELECT * FROM history ORDER BY id").fetchall(),
        )


def _move(service, session, item, **kwargs):
    return service.reschedule(
        session, "Manager", item["id"],
        expected_revision=kwargs.pop("expected_revision", item["revision"]),
        starts_at=kwargs.pop("starts_at", "2030-05-02T10:00:00+00:00"), **kwargs,
    )


def test_reschedule_complete_reopen_and_cancel_are_durable_and_audited(fixture):
    service, session, manager, _, _, item, path, key = fixture
    moved = _move(service, session, item, reason="  Site available  ")
    assert moved.changed and moved.before == item
    assert moved.after["revision"] == 1 and moved.reason == "Site available"
    completed = service.change_status(
        session, "Manager", item["id"], expected_revision=1, status="completed",
    )
    assert completed.after["status"] == "completed"
    service.change_status(session, "Manager", item["id"], expected_revision=2, status="scheduled")
    service.change_status(
        session, "Manager", item["id"], expected_revision=3, status="cancelled", reason="Not needed",
    )
    reopened = WorkItems(path, identity_key=key)
    fresh = reopened.open_session(lambda: manager)
    stored = reopened.read(fresh, "Manager", item["id"])
    assert stored["status"] == "cancelled" and stored["revision"] == 4
    events = reopened.audit_events(fresh, "Manager")
    assert len(events) == 4 and events[0]["before"] == item
    assert events[-1]["after"] == stored
    assert {event["actor"] for event in events} == {moved.actor}
    assert manager.subject not in json.dumps(events)


@pytest.mark.parametrize("mode", ["viewer", "forged_role", "revoked", "frozen", "expired", "switched", "closed"])
def test_denied_actions_have_no_record_or_history_effects(fixture, mode):
    service, session, manager, viewer, other, item, path, _ = fixture
    role = "Manager"
    if mode in {"viewer", "forged_role"}:
        session = service.open_session(lambda: viewer)
        role = "Viewer" if mode == "viewer" else "Manager"
    elif mode == "revoked":
        service.provision(manager, [])
    elif mode == "frozen":
        service.change_freeze(session, "Manager", True, 1)
    elif mode in {"expired", "switched"}:
        current = [manager]
        session = service.open_session(lambda: current[0])
        current[0] = replace(manager, expires_at=time.time() - 1) if mode == "expired" else other
    elif mode == "closed":
        session.close()
    before = _snapshot(path)
    with pytest.raises(AccessDenied):
        service.reschedule(session, role, item["id"], expected_revision=0, starts_at="2030-05-02T10:00:00Z")
    assert _snapshot(path) == before


def test_account_switch_during_validation_is_rejected_before_effect(fixture):
    service, _, manager, _, other, item, path, _ = fixture
    identities = iter([manager, manager, other])  # session binding, initial check, final check
    session = service.open_session(lambda: next(identities))
    before = _snapshot(path)
    with pytest.raises(AccessDenied):
        _move(service, session, item)
    assert _snapshot(path) == before


def test_noop_requires_current_authority_and_does_not_audit(fixture):
    service, session, manager, _, _, item, path, _ = fixture
    before = _snapshot(path)
    result = _move(service, session, item, starts_at=item["starts_at"])
    assert result.changed is False and result.before == result.after == item
    assert _snapshot(path) == before
    service.provision(manager, [])
    with pytest.raises(AccessDenied):
        _move(service, session, item, starts_at=item["starts_at"])
    assert _snapshot(path) == before


def test_stale_replay_rejected_even_when_values_match(fixture):
    service, session, _, _, _, item, path, _ = fixture
    result = _move(service, session, item)
    before = _snapshot(path)
    with pytest.raises(ActionConflict):
        _move(service, session, item, starts_at=result.after["starts_at"])
    assert _snapshot(path) == before


@pytest.mark.parametrize("revision", [True, False, -1, 0.0, "0", None, 9223372036854775807])
def test_invalid_revision_never_writes(fixture, revision):
    service, session, _, _, _, item, path, _ = fixture
    before = _snapshot(path)
    with pytest.raises(ActionValidation):
        _move(service, session, item, expected_revision=revision)
    assert _snapshot(path) == before


@pytest.mark.parametrize("date", ["2030-05-02", "2030-05-02T09:00:00", "invalid", True, "x" * 65])
def test_invalid_dates_never_write(fixture, date):
    service, session, _, _, _, item, path, _ = fixture
    before = _snapshot(path)
    with pytest.raises(ActionValidation):
        _move(service, session, item, starts_at=date)
    assert _snapshot(path) == before


@pytest.mark.parametrize("status,reason", [("cancelled", "  "), ("deleted", "why"), (None, "why"), ("completed", "\x00")])
def test_status_validation_never_writes(fixture, status, reason):
    service, session, _, _, _, item, path, _ = fixture
    before = _snapshot(path)
    with pytest.raises(ActionValidation):
        service.change_status(session, "Manager", item["id"], expected_revision=0, status=status, reason=reason)
    assert _snapshot(path) == before


def test_closed_status_requires_reopen_before_reschedule(fixture):
    service, session, _, _, _, item, path, _ = fixture
    service.change_status(session, "Manager", item["id"], expected_revision=0, status="completed")
    before = _snapshot(path)
    with pytest.raises(ActionValidation):
        _move(service, session, item, expected_revision=1)
    assert _snapshot(path) == before


def test_host_can_supply_domain_rules(fixture):
    service, session, manager, _, _, item, path, key = fixture
    rules = WorkItemRules(transitions=(("scheduled", "reviewed"),), reason_required_for=frozenset({"reviewed"}))
    service = WorkItems(path, identity_key=key, rules=rules)
    session = service.open_session(lambda: manager)
    with pytest.raises(ActionValidation):
        service.change_status(session, "Manager", item["id"], expected_revision=0, status="completed")
    result = service.change_status(
        session, "Manager", item["id"], expected_revision=0, status="reviewed", reason="Checked",
    )
    assert result.after["status"] == "reviewed"


def test_audit_failure_rolls_back_business_change(fixture):
    service, session, _, _, _, item, path, _ = fixture
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_audit BEFORE INSERT ON history "
            "BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END",
        )
    before = _snapshot(path)
    with pytest.raises(sqlite3.IntegrityError):
        _move(service, session, item)
    assert _snapshot(path) == before


def test_two_connections_cannot_overwrite_same_revision(fixture):
    service, session, _, _, _, item, path, _ = fixture
    gate = Barrier(2)

    def attempt(hour):
        gate.wait(timeout=10)
        try:
            return _move(service, session, item, starts_at=f"2030-05-02T{hour}:00:00+00:00").after
        except ActionConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, ["10", "11"]))
    assert results.count("conflict") == 1
    stored = service.read(session, "Manager", item["id"])
    assert stored in results and stored["revision"] == 1
    assert len(_snapshot(path)[1]) == 1


@pytest.fixture
def connection():
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("CREATE TABLE item(value TEXT, revision INTEGER)")
    connection.execute("INSERT INTO item VALUES ('before', 0)")
    connection.execute("CREATE TABLE history(value TEXT)")
    connection.execute("BEGIN IMMEDIATE")
    yield connection
    connection.close()


def _execute(connection, **changes):
    def save(record, revision):
        return connection.execute(
            "UPDATE item SET value=?,revision=? WHERE revision=?",
            (record["value"], record["revision"], revision),
        ).rowcount == 1
    options = dict(
        connection=connection, expected_revision=0, authorize=lambda: "actor",
        load=lambda: dict(zip(("value", "revision"), connection.execute("SELECT * FROM item").fetchone())),
        propose=lambda before: {"value": "after"}, save=save,
        audit=lambda result: connection.execute("INSERT INTO history VALUES (?)", (result.after["value"],)),
    )
    return execute_change(**{**options, **changes})


def test_savepoint_rolls_back_partial_audit_even_if_host_catches(connection):
    def broken_audit(result):
        connection.execute("INSERT INTO history VALUES ('partial')")
        raise RuntimeError("synthetic failure")
    with pytest.raises(RuntimeError, match="synthetic failure"):
        _execute(connection, audit=broken_audit)
    assert connection.in_transaction
    connection.commit()
    assert connection.execute("SELECT * FROM item").fetchall() == [("before", 0)]
    assert connection.execute("SELECT * FROM history").fetchall() == []


def test_helper_rejects_actor_switch_at_effect(connection):
    actors = iter(["first", "second"])
    with pytest.raises(ActionDenied):
        _execute(connection, authorize=lambda: next(actors))
    assert connection.execute("SELECT * FROM item").fetchall() == [("before", 0)]


def test_failed_compare_and_set_rolls_back_callback_write(connection):
    def failed_save(record, revision):
        connection.execute("UPDATE item SET value='partial'")
        return False
    with pytest.raises(ActionConflict):
        _execute(connection, save=failed_save)
    assert connection.execute("SELECT * FROM item").fetchall() == [("before", 0)]
    assert connection.execute("SELECT * FROM history").fetchall() == []


@pytest.mark.parametrize("changes", [{"revision": 100}, {"unknown": "value"}])
def test_helper_rejects_nonbusiness_proposals(connection, changes):
    with pytest.raises(ActionValidation):
        _execute(connection, propose=lambda before: changes)
    assert connection.execute("SELECT * FROM item").fetchall() == [("before", 0)]


def test_helper_requires_outer_transaction(connection):
    connection.rollback()
    with pytest.raises(RuntimeError, match="shared write transaction"):
        _execute(connection)


@pytest.mark.parametrize("value", ["x" * 501, 123, "bad\x00", "bad\r"])
def test_reason_rejects_unbounded_or_control_text(value):
    with pytest.raises(ActionValidation):
        normalize_reason(value)


def test_reason_preserves_plain_multiline_text():
    assert normalize_reason("  first\nsecond\tpart  ", required=True) == "first\nsecond\tpart"


def test_demo_runs_without_host_dependencies():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "examples.record_workflows.demo"], cwd=root,
        capture_output=True, text=True, timeout=20, check=True,
    )
    assert "persisted with 3 audit records" in result.stdout
