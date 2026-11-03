"""Transactional security receipts, bounded denial evidence and restart delivery."""

from tools.business_login_client import login_post

import importlib.util
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests import test_business_dashboard as dashboard_fixtures  # noqa: E402
from tests.test_business_dashboard import (  # noqa: E402
    ORIGIN, business_seed as business_seed, downgrade_enrollment_schema,
    business_admin as business_admin,
)
from business import app as business_app, db, security_events as events  # noqa: E402

enrolled_business = dashboard_fixtures.business


@pytest.fixture
def business(enrolled_business):
    # The shared seed keeps actual enrollment evidence. Isolate this module's
    # capacity, crash and delivery scenarios from that already-proven setup.
    with enrolled_business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM account_security WHERE lifecycle='active'").fetchone()[0] == 6
        assert connection.execute("SELECT COUNT(*) FROM enrollment_decisions").fetchone()[0] == 6
        connection.execute("DELETE FROM security_events")
    return enrolled_business


def _rows(business, table="security_events"):
    # Only fixed table names supplied by these tests.
    with business.db() as connection:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")]


def _downgrade_five(business):
    with business.raw_db() as connection:
        downgrade_enrollment_schema(connection)
        for table in ("session_predecessors", "security_sink_receipts", "security_outbox", "security_denial_budget", "security_events"):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version=5")


def _cli():
    path = Path(__file__).resolve().parents[1] / "examples/business_dashboard/dispatch_security_events.py"
    spec = importlib.util.spec_from_file_location("business_event_dispatch_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_success_event_and_obligation_share_mutation_transaction(business, business_admin):
    response = business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0})
    assert response.status_code == 200
    with business.db() as connection:
        assert connection.execute("SELECT frozen,freeze_revision FROM settings").fetchone()[:] == (1, 1)
        event = connection.execute("SELECT * FROM security_events WHERE code='editing_paused'").fetchone()
        assert event["actor"] == connection.execute("SELECT principal FROM users WHERE id='admin'").fetchone()[0]
        assert connection.execute("SELECT acknowledged_at FROM security_delivery_obligations WHERE event_id=?", (event["id"],)).fetchone()[0] is None


def test_required_event_failure_rolls_back_business_write_and_activity(business, business_admin, monkeypatch):
    with business.db() as connection:
        before = connection.execute("SELECT COUNT(*) FROM activity").fetchone()[0]

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic event failure")

    monkeypatch.setattr(business_app, "record_event", fail)
    response = business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0})
    assert response.status_code == 503
    with business.db() as connection:
        assert connection.execute("SELECT frozen,freeze_revision FROM settings").fetchone()[:] == (0, 0)
        assert connection.execute("SELECT COUNT(*) FROM activity").fetchone()[0] == before
        assert connection.execute("SELECT COUNT(*) FROM security_events WHERE code='editing_paused'").fetchone()[0] == 0
    # The failed action's refusal is observed independently, after rollback.
    assert any(row["outcome"] == "denied" for row in _rows(business))


def test_rollback_removes_event_and_delivery_obligation(business):
    with pytest.raises(RuntimeError):
        with business.db() as connection:
            events.record_event(connection, "editing_paused")
            connection.execute("UPDATE settings SET frozen=1")
            raise RuntimeError("synthetic rollback")
    assert _rows(business) == _rows(business, "security_delivery_obligations") == []
    with business.db() as connection:
        assert connection.execute("SELECT frozen FROM settings").fetchone()[0] == 0


def test_crash_after_commit_before_delivery_survives_restart_without_replaying_action(business):
    with business.db() as connection:
        connection.execute("UPDATE settings SET freeze_revision=freeze_revision+1")
        identifier = events.record_event(connection, "editing_paused")
    restarted = db.Database(business.directory)
    assert events.dispatch_pending(restarted) == {"delivered": 1, "failed": 0, "pending": 0}
    assert events.dispatch_pending(restarted) == {"delivered": 0, "failed": 0, "pending": 0}
    assert [row["event_id"] for row in _rows(business, "security_sink_receipts")] == [identifier]
    with business.db() as connection:
        assert connection.execute("SELECT freeze_revision FROM settings").fetchone()[0] == 1


def test_crash_after_delivery_before_ack_redelivers_with_idempotent_consumer(business):
    with business.db() as connection:
        identifier = events.record_event(connection, "editing_paused")

    def crash(event):
        raise RuntimeError("synthetic process termination")

    with pytest.raises(RuntimeError, match="termination"):
        events.dispatch_pending(business.app.state.database, after_delivery=crash)
    assert len(_rows(business, "security_sink_receipts")) == 1
    assert _rows(business, "security_delivery_obligations")[0]["acknowledged_at"] is None
    assert events.dispatch_pending(db.Database(business.directory))["delivered"] == 1
    assert [row["event_id"] for row in _rows(business, "security_sink_receipts")] == [identifier]
    assert _rows(business, "security_delivery_obligations")[0]["attempts"] == 2


@pytest.mark.parametrize("crash_boundary", ["after_commit", "after_delivery"])
def test_actual_process_exit_preserves_action_obligation_and_consumer_deduplication(business, crash_boundary):
    example = Path(__file__).resolve().parents[1] / "examples/business_dashboard"
    code = """
import os
import sys
sys.path.insert(0, sys.argv[1])
from business.db import Database
from business.security_events import dispatch_pending, record_event
database = Database(sys.argv[2])
with database.transaction() as connection:
    connection.execute("UPDATE settings SET freeze_revision=freeze_revision+1")
    record_event(connection, "editing_paused")
if sys.argv[3] == "after_commit":
    os._exit(73)
dispatch_pending(database, after_delivery=lambda event: os._exit(73))
raise AssertionError("Crash boundary was not reached")
"""
    result = subprocess.run([sys.executable, "-c", code, str(example), str(business.directory), crash_boundary],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 73, result.stderr
    assert result.stdout == result.stderr == ""
    assert len(_rows(business, "security_sink_receipts")) == (crash_boundary == "after_delivery")
    assert _rows(business, "security_delivery_obligations")[0]["acknowledged_at"] is None
    identifier = _rows(business)[0]["id"]
    restarted = db.Database(business.directory)
    assert events.dispatch_pending(restarted) == {"delivered": 1, "failed": 0, "pending": 0}
    assert events.dispatch_pending(restarted) == {"delivered": 0, "failed": 0, "pending": 0}
    assert [row["event_id"] for row in _rows(business, "security_sink_receipts")] == [identifier]
    with business.db() as connection:
        assert connection.execute("SELECT freeze_revision FROM settings").fetchone()[0] == 1


def test_delivery_failures_keep_pending_retry_and_do_not_leak_adapter_exception(business, caplog):
    with business.db() as connection:
        events.record_event(connection, "editing_paused")

    def unavailable(event):
        raise RuntimeError("SECRET_ADAPTER_CREDENTIAL_CANARY")

    result = events.dispatch_pending(business.app.state.database, deliver=unavailable)
    assert result == {"delivered": 0, "failed": 1, "pending": 1}
    outbox = _rows(business, "security_delivery_obligations")[0]
    assert outbox["last_error"] == "delivery_failed" and outbox["attempts"] == 1
    assert "SECRET_ADAPTER" not in caplog.text + json.dumps(outbox)
    assert events.dispatch_pending(business.app.state.database)["delivered"] == 0
    with business.db() as connection:
        connection.execute("UPDATE security_delivery_obligations SET next_attempt_at=0")
    assert events.dispatch_pending(db.Database(business.directory))["delivered"] == 1


def test_timeline_is_current_admin_only_bounded_and_nonsecret(business, business_admin):
    path = "/api/admin/security/events"
    assert business.client().get(path).status_code == 401
    employee = business.login("alex")
    assert employee.request("GET", path).status_code == 403
    response = business_admin.request("GET", path + "?limit=1")
    assert response.status_code == 200
    data = response.json()
    assert len(data["events"]) == 1 and data["next_before"] is not None
    assert data["events"][0]["sequence"] > business_admin.request(
        "GET", path + f"?limit=1&before={data['next_before']}",
    ).json()["events"][0]["sequence"]
    assert business_admin.request("GET", path + "?limit=101").status_code == 422
    serialized = json.dumps(data)
    assert all(password not in serialized for password in business.credentials.values())
    assert "token_hash" not in serialized and "username" not in serialized
    with business.db() as connection:
        connection.execute("UPDATE users SET active=0 WHERE id='admin'")
    assert business_admin.request("GET", path).status_code == 401


@pytest.mark.parametrize("cursor", [2**63, 10**100])
def test_out_of_range_timeline_cursor_returns_422_without_changing_authority_or_success_receipts(
    business, business_admin, cursor,
):
    def authority_digest():
        state = {table: _rows(business, table) for table in ("users", "sessions", "settings", "activity")}
        return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()

    before = authority_digest()
    successes = [row for row in _rows(business) if row["outcome"] == "succeeded"]
    response = business_admin.request("GET", f"/api/admin/security/events?before={cursor}")
    assert response.status_code == 422
    assert str(cursor) not in response.text
    assert authority_digest() == before
    assert [row for row in _rows(business) if row["outcome"] == "succeeded"] == successes
    # The refusal may create its separate bounded denial observation, as other
    # invalid requests do; it never changes business authority or success data.
    denied = [row for row in _rows(business) if row["outcome"] == "denied"]
    assert len(denied) == 1 and denied[0]["reason"] == "invalid_request"


def test_internal_timeline_rejects_oversized_cursor_and_accepts_largest_sqlite_integer(business, business_admin):
    before = _rows(business), _rows(business, "security_delivery_obligations")
    with business.db() as connection:
        with pytest.raises(ValueError, match="Invalid event page"):
            events.timeline(connection, before=2**63)
        result = events.timeline(connection, before=2**63 - 1)
    assert result["events"][0]["code"] == "login_succeeded"
    assert (_rows(business), _rows(business, "security_delivery_obligations")) == before


def test_dispatch_requires_csrf_admin_and_recent_verification(business, business_admin):
    path = "/api/admin/security/events/dispatch"
    assert business.client().post(path, headers={"Origin": ORIGIN}, json={}).status_code == 401
    assert business.login("alex").request("POST", path, json={}).status_code == 403
    assert business_admin.client.post(path, headers={"Origin": ORIGIN}, json={}).status_code == 403
    with business.db() as connection:
        connection.execute("UPDATE session_security SET verified_at=0")
    assert business_admin.request("POST", path, json={}).status_code == 403
    assert _rows(business, "security_sink_receipts") == []


def test_empty_dispatch_rechecks_authority_before_reading_queue(business, business_admin, monkeypatch):
    from business import security_event_routes

    events.dispatch_pending(business.app.state.database)
    original = security_event_routes.dispatch_pending

    def revoke_before_queue_read(database, **kwargs):
        with database.transaction() as connection:
            connection.execute("UPDATE users SET active=0 WHERE id='admin'")
        return original(database, **kwargs)

    monkeypatch.setattr(security_event_routes, "dispatch_pending", revoke_before_queue_read)
    response = business_admin.request("POST", "/api/admin/security/events/dispatch", json={})
    assert response.status_code == 401
    assert "pending" not in response.json()


def test_anonymous_passkey_refusals_are_authentication_events(business):
    response = business.client().post("/api/passkeys/login/verify", headers={"Origin": ORIGIN}, json={})
    assert response.status_code == 422
    assert _rows(business)[0]["code"] == "authentication_denied"


def test_denial_flood_is_fixed_bounded_across_restart_and_preserves_refusal(business, monkeypatch):
    monkeypatch.setattr(events, "DENIALS_PER_MINUTE", 3)
    monkeypatch.setattr(events.time, "time", lambda: 1900000000.0)
    recorder = business.app.state.security_event_recorder
    for _ in range(12):
        recorder.record("authentication_denied", "unauthenticated")
    assert len(_rows(business)) == 3
    assert recorder.snapshot()["denials_suppressed_since_start"] == 9
    restarted = events.DenialRecorder(db.Database(business.directory))
    restarted.record("authentication_denied", "unauthenticated")
    assert len(_rows(business)) == 3
    assert restarted.snapshot()["denials_suppressed_since_start"] == 1
    assert len(_rows(business, "security_denial_budget")) == 1


def test_anonymous_denial_flood_cannot_consume_required_action_capacity(business, business_admin, monkeypatch):
    monkeypatch.setattr(events, "MAX_EVENTS", 8)
    anonymous = business.client()
    for _ in range(12):
        assert anonymous.get("/api/admin/users").status_code == 401
    assert len([row for row in _rows(business) if row["outcome"] == "denied"]) == 2
    assert business.app.state.security_event_recorder.snapshot()["denials_suppressed_since_start"] == 10
    restarted = events.DenialRecorder(db.Database(business.directory))
    restarted.record("authorization_denied", "unauthenticated")
    assert restarted.snapshot()["denials_suppressed_since_start"] == 1
    assert business.login("alex").request("GET", "/api/messages").status_code == 200
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    rows = _rows(business)
    assert len(rows) == 5 and len([row for row in rows if row["outcome"] == "succeeded"]) == 3
    assert len(_rows(business, "security_delivery_obligations")) == 5  # No pending obligation was discarded.


def test_delivered_denial_observations_can_rotate_without_dropping_pending(business, monkeypatch):
    monkeypatch.setattr(events, "MAX_DENIAL_EVENTS", 1)
    recorder = business.app.state.security_event_recorder
    recorder.record("authorization_denied", "unauthenticated")
    first = _rows(business)[0]["id"]
    assert events.dispatch_pending(business.app.state.database)["delivered"] == 1
    recorder.record("authorization_denied", "forbidden")
    assert len(_rows(business)) == 1 and _rows(business)[0]["id"] != first
    assert len(_rows(business, "security_sink_receipts")) == 0
    assert _rows(business, "security_delivery_obligations")[0]["acknowledged_at"] is None


def _fill_normal_capacity(business):
    with business.db() as connection:
        for _ in range(events._normal_capacity()):
            events.record_event(connection, "editing_resumed")


@pytest.mark.parametrize("code", sorted(events.CONTAINMENT_CODES))
def test_employee_containment_names_cannot_spend_current_admin_reserve(business, monkeypatch, code):
    monkeypatch.setattr(events, "MAX_EVENTS", 8)
    _fill_normal_capacity(business)
    with business.db() as connection:
        principals = {row["id"]: row["principal"] for row in connection.execute("SELECT id,principal FROM users")}
    with pytest.raises(events.EventCapacityError), business.db() as connection:
        events.record_event(connection, code, actor=principals["alex"])
    assert len(_rows(business)) == 5
    with business.db() as connection:
        events.record_event(connection, code, actor=principals["admin"])
    assert len(_rows(business)) == len(_rows(business, "security_delivery_obligations")) == 6


@pytest.mark.parametrize("role,active", [("employee", 1), ("admin", 0)])
def test_reserve_checks_current_admin_role_and_active_state(business, monkeypatch, role, active):
    monkeypatch.setattr(events, "MAX_EVENTS", 8)
    _fill_normal_capacity(business)
    with business.db() as connection:
        principal = connection.execute("SELECT principal FROM users WHERE id='admin'").fetchone()[0]
        connection.execute("UPDATE users SET role=?,active=? WHERE id='admin'", (role, active))
    with pytest.raises(events.EventCapacityError), business.db() as connection:
        events.record_event(connection, "identity_verified", actor=principal)
    assert len(_rows(business)) == 5


@pytest.mark.parametrize("code", ["password_changed", "passkey_registered", "editing_resumed", "account_enabled", "mfa_key_rotated"])
def test_general_admin_security_events_do_not_spend_containment_reserve(business, monkeypatch, code):
    monkeypatch.setattr(events, "MAX_EVENTS", 8)
    _fill_normal_capacity(business)
    with business.db() as connection:
        principal = connection.execute("SELECT principal FROM users WHERE id='admin'").fetchone()[0]
    with pytest.raises(events.EventCapacityError), business.db() as connection:
        events.record_event(connection, code, actor=principal)
    assert len(_rows(business)) == 5


def test_employee_login_flood_leaves_stale_admin_reauthentication_and_containment_capacity(business, business_admin, monkeypatch):
    monkeypatch.setattr(events, "MAX_EVENTS", 20)
    employees = [business.login("alex") for _ in range(8)]
    assert len(_rows(business)) == 9
    policy = business_admin.request("GET", "/api/admin/security/events").json()["retention"]
    assert policy["normal_event_capacity"] == 9 and policy["containment_reserve"] == 3
    assert policy["employee_session_reserve"] == 8
    assert policy["reserve_eligibility"] == "current_active_admin_containment_only"
    blocked = login_post(business.client(), "/api/login", json=business.login_payload("alex"), headers={
        "Origin": ORIGIN, "X-Role": "admin", "X-User-ID": "admin",
    })
    assert blocked.status_code == 503 and len(_rows(business)) == 9
    assert employees[-1].request("POST", "/api/logout", json={}).status_code == 200
    assert employees[-1].request("GET", "/api/messages").status_code == 401
    with business.db() as connection:
        connection.execute("UPDATE session_security SET verified_at=0")
    # Invalid credentials do not reserve privileged capacity merely because an
    # existing session belongs to an administrator. Both factors still verify.
    assert business_admin.request("POST", "/api/security/reauthenticate", json={
        "current_password": "incorrect-disposable-password",
    }).status_code == 403
    assert business_admin.request("POST", "/api/security/reauthenticate", json={
        "current_password": business.credentials["admin"],
    }).status_code == 403
    assert len(_rows(business)) == 10
    verified = business_admin.request("POST", "/api/security/reauthenticate", json={
        "current_password": business.credentials["admin"], "otp": business.login_payload("admin")["otp"],
    })
    assert verified.status_code == 200
    business_admin.csrf = verified.json()["csrf"]
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": False, "revision": business.user_revision("alex")}).status_code == 200
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    assert len(_rows(business)) == len(_rows(business, "security_delivery_obligations")) == 13
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions WHERE user_id='alex'").fetchone()[0] == 0
        assert connection.execute("SELECT active FROM users WHERE id='alex'").fetchone()[0] == 0
    assert business_admin.request("POST", "/api/admin/security/events/dispatch", json={}).json() == {
        "delivered": 13, "failed": 0, "pending": 0,
    }
    assert business.login("blair").request("GET", "/api/messages").status_code == 200


@pytest.mark.parametrize("username,expected", [("admin", 200), ("alex", 503)])
def test_only_fully_verified_current_admin_passkeys_can_use_reserve(business, monkeypatch, username, expected):
    pytest.importorskip("webauthn")
    from tests.test_business_passkeys import enroll, finish_login, login_options

    owner = business.login(username)
    key, _ = enroll(owner)
    monkeypatch.setattr(events, "MAX_EVENTS", 8)
    with business.db() as connection:
        baseline = events._normal_capacity() - events._session_reserve(connection)
        for _ in range(baseline - connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]):
            events.record_event(connection, "editing_resumed")
    assert len(_rows(business)) == baseline
    client = business.client()
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"], change="signature")).status_code == 403
    assert len(_rows(business)) == baseline
    ceremony = login_options(client)
    response = finish_login(client, ceremony, key.assertion(ceremony["options"]))
    assert response.status_code == expected
    assert len(_rows(business)) == baseline + (username == "admin")
    with business.db() as connection:
        assert connection.execute("SELECT sign_count FROM passkey_credentials").fetchone()[0] == (username == "admin")
        count = connection.execute("SELECT COUNT(*) FROM security_events WHERE code='login_succeeded' AND method='passkey'").fetchone()[0]
        assert count == (username == "admin")


def test_all_employee_sessions_can_terminate_after_admin_reserve_is_used(business, business_admin, monkeypatch):
    monkeypatch.setattr(events, "MAX_EVENTS", 12)
    employees = [business.login(name) for name in ("alex", "alex", "blair", "blair")]
    identifiers = [next(row["id"] for row in actor.request("GET", "/api/security/sessions").json()["sessions"]
                        if row["current"]) for actor in employees]
    # Ordinary admission is full (five events plus four reserved terminations).
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    with business.db() as connection:
        principal = connection.execute("SELECT principal FROM users WHERE id='admin'").fetchone()[0]
        for _ in range(2):
            events.record_event(connection, "identity_verified", actor=principal)
        assert events._session_reserve(connection) == 4
    # Even the entire administrator reserve is now pending; no delivery occurs.
    assert len(_rows(business)) == 8
    for index, actor in enumerate(employees):
        path = "/api/logout" if index % 2 == 0 else f"/api/security/sessions/{identifiers[index]}/revoke"
        assert actor.request("POST", path, json={}).status_code == 200
        assert actor.request("GET", "/api/messages").status_code == 401
        with business.db() as connection:
            assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] + events._session_reserve(connection) == 12
    assert len(_rows(business)) == len(_rows(business, "security_delivery_obligations")) == 12
    assert all(row["acknowledged_at"] is None for row in _rows(business, "security_delivery_obligations"))
    assert login_post(business.client(), "/api/login", headers={"Origin": ORIGIN}, json=business.login_payload("casey")).status_code == 503


def test_termination_requires_owned_existing_session_and_rolls_back_failed_event(business, monkeypatch):
    business.login("alex")
    business.login("blair")
    monkeypatch.setattr(events, "MAX_EVENTS", 8)
    with business.db() as connection:
        principals = {row["id"]: row["principal"] for row in connection.execute("SELECT id,principal FROM users")}
        target = connection.execute("SELECT token_hash FROM sessions WHERE user_id='blair'").fetchone()[0]
        events.record_event(connection, "editing_resumed")
    before = _rows(business), _rows(business, "sessions")
    for hashed, actor in ((target, principals["alex"]), ("missing", principals["blair"])):
        with pytest.raises(ValueError, match="owned session"), business.db() as connection:
            events.terminate_own_session(connection, "session_revoked", hashed=hashed, actor=actor)
    with pytest.raises(ValueError, match="verified action"), business.db() as connection:
        events.terminate_own_session(connection, "identity_verified", hashed=target, actor=principals["blair"])
    assert (_rows(business), _rows(business, "sessions")) == before

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic required event failure")

    monkeypatch.setattr(events, "_record_event", fail)
    with pytest.raises(sqlite3.OperationalError), business.db() as connection:
        events.terminate_own_session(connection, "session_revoked", hashed=target, actor=principals["blair"])
    assert (_rows(business), _rows(business, "sessions")) == before


def test_expired_target_cannot_claim_slot_when_unrelated_session_expires_during_termination(business, monkeypatch):
    business.login("alex")
    business.login("blair")
    now = events.time.time()
    monkeypatch.setattr(events, "MAX_EVENTS", 8)
    with business.db() as connection:
        connection.execute("UPDATE sessions SET expires_at=? WHERE user_id='alex'", (now + 1,))
        connection.execute("UPDATE sessions SET expires_at=? WHERE user_id='blair'", (now - 1,))
        target = connection.execute("SELECT token_hash FROM sessions WHERE user_id='blair'").fetchone()[0]
        actor = connection.execute("SELECT principal FROM users WHERE id='blair'").fetchone()[0]
        for _ in range(2):
            events.record_event(connection, "editing_resumed")
    before = _rows(business), _rows(business, "sessions")
    moments = iter((now, now + 2))
    with monkeypatch.context() as patch:
        # Scope the two event timestamps to this module; the host clock
        # independently observes time at transaction entry.
        patch.setattr(events, "time", SimpleNamespace(time=lambda: next(moments)))
        with pytest.raises(events.EventCapacityError), business.db() as connection:
            events.terminate_own_session(connection, "session_revoked", hashed=target, actor=actor)
    assert (_rows(business), _rows(business, "sessions")) == before


@pytest.mark.parametrize("invalidity", ["expired", "idle", "absolute", "disabled"])
def test_unusable_employee_sessions_do_not_reserve_capacity(business, invalidity):
    business.login("alex")
    from business.security import IDLE_SECONDS, SESSION_SECONDS

    now = events.time.time()
    with business.db() as connection:
        assert events._session_reserve(connection, now=now) == 1
        if invalidity == "disabled":
            connection.execute("UPDATE users SET active=0 WHERE id='alex'")
        else:
            field, value = {"expired": ("expires_at", now), "idle": ("last_seen", now - IDLE_SECONDS),
                            "absolute": ("created_at", now - SESSION_SECONDS)}[invalidity]
            connection.execute(f"UPDATE sessions SET {field}=?", (value,))
        assert events._session_reserve(connection, now=now) == 0


def test_legacy_reservation_deficit_is_visible_and_requires_delivery_without_losing_pending(business, monkeypatch):
    actor = business.login("alex")
    business.login("blair")
    # Models a pre-upgrade backlog admitted without session earmarks.
    monkeypatch.setattr(events, "MAX_EVENTS", 3)
    with business.db() as connection:
        assert events.timeline(connection)["retention"]["reservation_deficit"] == 1
    assert actor.request("POST", "/api/logout", json={}).status_code == 503
    assert actor.request("GET", "/api/messages").status_code == 200
    assert len(_rows(business)) == len(_rows(business, "security_delivery_obligations")) == 2
    assert events.dispatch_pending(business.app.state.database)["delivered"] == 2
    assert actor.request("POST", "/api/logout", json={}).status_code == 200
    assert actor.request("GET", "/api/messages").status_code == 401


def test_denial_sink_failure_retains_original_response_and_visible_failure_counter(business, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("SECRET_DB_PATH_CANARY")

    monkeypatch.setattr(events, "record_event", fail)
    response = business.client().get("/api/admin/users")
    assert response.status_code == 401
    assert business.app.state.security_event_recorder.snapshot()["recording_failures_since_start"] == 1
    assert "SECRET_DB_PATH" not in response.text + caplog.text


def test_denied_login_never_persists_submitted_credentials_or_account_label(business, monkeypatch):
    from business import auth_routes

    monkeypatch.setattr(auth_routes, "dummy_password_check", lambda password: None)
    response = login_post(business.client(), "/api/login", headers={"Origin": ORIGIN}, json={
        "username": "UNVERIFIED_USERNAME_CANARY", "password": "SUBMITTED_PASSWORD_CANARY",
    })
    assert response.status_code == 401
    assert [row["code"] for row in _rows(business)] == ["authentication_denied"]
    assert _rows(business)[0]["actor"] is None
    assert events.dispatch_pending(business.app.state.database)["delivered"] == 1
    stored = json.dumps(_rows(business) + _rows(business, "security_sink_receipts"))
    assert "CANARY" not in stored and "username" not in stored and "password" not in stored


def test_fixed_fields_refuse_secret_content_and_unverified_identity(business):
    for kwargs in ({"code": "PASSWORD_CANARY"}, {"code": "editing_paused", "reason": "TOKEN_CANARY"},
                   {"code": "editing_paused", "actor": "admin@example.invalid"},
                   {"code": "editing_paused", "target": "SESSION_TOKEN_CANARY"}):
        with business.db() as connection, pytest.raises(ValueError):
            events.record_event(connection, **kwargs)
    assert _rows(business) == []


def test_retention_trims_delivered_only_and_capacity_recovery_allows_login(business, monkeypatch, capsys):
    monkeypatch.setattr(events, "MAX_EVENTS", 6)
    with business.db() as connection:
        principal = connection.execute("SELECT principal FROM users WHERE id='admin'").fetchone()[0]
        first = events.record_event(connection, "editing_paused", actor=principal)
        for _ in range(5):
            events.record_event(connection, "editing_paused", actor=principal)
    client = business.client()
    response = login_post(client, "/api/login", headers={"Origin": ORIGIN}, json=business.login_payload("alex"))
    assert response.status_code == 503
    assert len(_rows(business)) == 6
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert _cli().main(["--data-dir", str(business.directory), "--maintenance-confirmed"]) == 0
    output = capsys.readouterr().out
    assert output == "Local receipts delivered: 6; failed: 0; pending: 0.\n"
    assert business.login("alex").request("GET", "/api/messages").status_code == 200
    assert len(_rows(business)) == 2
    assert first not in {row["id"] for row in _rows(business)}
    assert len(_rows(business, "security_sink_receipts")) == 1


def test_age_retention_preserves_pending_obligations(business):
    old = events.time.time() - events.MAX_AGE_SECONDS - 60
    with business.db() as connection:
        delivered = events.record_event(connection, "editing_paused", now=old)
    assert events.dispatch_pending(business.app.state.database)["delivered"] == 1
    with business.db() as connection:
        pending = events.record_event(connection, "editing_resumed", now=old)
        recent = events.record_event(connection, "editing_paused")
    assert {row["id"] for row in _rows(business)} == {pending, recent}
    assert delivered not in {row["event_id"] for row in _rows(business, "security_sink_receipts")}


def test_offline_dispatch_requires_explicit_maintenance_assertion(business):
    with pytest.raises(SystemExit):
        _cli().main(["--data-dir", str(business.directory)])
    assert _rows(business, "security_sink_receipts") == []


def test_schema_five_requires_explicit_atomic_migration_preserving_business(business, monkeypatch):
    _downgrade_five(business)
    with business.raw_db() as connection:
        before = [tuple(row) for row in connection.execute("SELECT * FROM users ORDER BY id")]
    with pytest.raises(ValueError, match="explicit reviewed migration"):
        db.Database(business.directory)
    original = db._apply_event_migration

    def fail(connection):
        original(connection)
        raise sqlite3.OperationalError("synthetic event migration failure")

    with monkeypatch.context() as patch:
        patch.setattr(db, "_apply_event_migration", fail)
        with pytest.raises(ValueError):
            db.Database(business.directory, migrate=True)
    with business.raw_db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='security_events'").fetchone() is None
    db.Database(business.directory, migrate=True)
    with business.db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
        assert [tuple(row) for row in connection.execute("SELECT * FROM users ORDER BY id")] == before
        assert connection.execute("PRAGMA foreign_key_check").fetchone() is None
    assert _rows(business) == []
