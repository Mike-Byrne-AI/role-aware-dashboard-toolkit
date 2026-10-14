from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import json
import threading

import pytest

from role_aware_dashboard_toolkit.access_audit import bind_audit_identity
from role_aware_dashboard_toolkit.audit import AuditLog
from role_aware_dashboard_toolkit.sensitive_values import REDACTED_SECRET


USER_A = "a" * 64
USER_B = "b" * 64
SESSION_A = "1" * 32
SESSION_B = "2" * 32


def test_bound_actors_share_history_without_modifying_parent_identity():
    parent = AuditLog()
    first = bind_audit_identity(parent, USER_A, SESSION_A)
    second = bind_audit_identity(parent, USER_B, SESSION_B)
    first.log("first", user_id="spoofed@example.test", session_id="spoofed")
    second.log("second")
    parent.log("unbound")

    events = parent.all_events()
    assert [(event["user_id"], event["session_id"]) for event in events] == [
        (USER_A, SESSION_A), (USER_B, SESSION_B), ("", ""),
    ]
    assert first.all_events() == second.all_events() == events
    assert len(first) == len(second) == len(parent) == 3
    assert "user_id" not in vars(parent)
    assert "session_id" not in vars(parent)
    for name, value in (("user_id", USER_B), ("session_id", SESSION_B)):
        with pytest.raises(FrozenInstanceError):
            setattr(first, name, value)
    assert "spoofed" not in parent.export_jsonl()


def test_concurrent_browser_sessions_keep_each_event_attribution():
    parent = AuditLog()
    views = (
        bind_audit_identity(parent, USER_A, SESSION_A),
        bind_audit_identity(parent, USER_B, SESSION_B),
    )
    barrier = threading.Barrier(2)

    def write_events(index):
        barrier.wait(timeout=5)
        for count in range(40):
            views[index].log("concurrent", key=str(index), new_value=count)

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(write_events, range(2)))

    events = parent.all_events()
    assert len(events) == 80
    for index, expected in enumerate(((USER_A, SESSION_A), (USER_B, SESSION_B))):
        matching = [event for event in events if event["key"] == str(index)]
        assert len(matching) == 40
        assert {(event["user_id"], event["session_id"]) for event in matching} == {expected}


def test_nested_binding_replaces_only_the_new_views_identity():
    parent = AuditLog()
    first = bind_audit_identity(parent, USER_A, SESSION_A)
    rebound = bind_audit_identity(first, USER_B, SESSION_B)
    rebound.log("rebound")
    first.log("original")
    assert rebound._audit is parent
    assert [(event["user_id"], event["session_id"]) for event in parent.all_events()] == [
        (USER_B, SESSION_B), (USER_A, SESSION_A),
    ]


def test_convenience_methods_pin_identity_and_preserve_sensitive_redaction():
    parent = AuditLog()
    view = bind_audit_identity(parent, USER_A, SESSION_A)
    view.log_control_change("private", "old-canary", "new-canary", sensitive=True)
    view.log_control_change("api_token", "old-token", "new-token")
    view.log_profile_save("baseline", role="Admin", source="test")
    view.log_profile_load("baseline", role="Operator")
    view.log_role_switch("Viewer", "Admin")
    view.log_freeze(False, role="Admin")
    events = parent.all_events()

    assert [event["type"] for event in events] == [
        "control_change", "control_change", "profile_save", "profile_load",
        "role_switch", "freeze_toggle",
    ]
    assert {(event["user_id"], event["session_id"]) for event in events} == {
        (USER_A, SESSION_A),
    }
    assert [(event["old"], event["new"]) for event in events[:2]] == [
        (REDACTED_SECRET, REDACTED_SECRET), (REDACTED_SECRET, REDACTED_SECRET),
    ]
    assert events[2]["detail"] == events[3]["detail"] == "baseline"
    assert events[2]["role"] == "Admin"
    assert events[2]["source"] == "test"
    assert (events[4]["old"], events[4]["new"], events[4]["role"]) == (
        "Viewer", "Admin", "Admin",
    )
    assert events[5]["new"] is False
    exported = view.export_jsonl()
    assert "canary" not in exported
    assert "old-token" not in exported
    assert "new-token" not in exported


def test_view_delegates_existing_read_retention_and_clear_behavior():
    parent = AuditLog(max_events=10)
    view = bind_audit_identity(parent, USER_A, SESSION_A)
    for value in range(12):
        view.log_control_change("limit", value, value + 1, role="Admin")

    assert len(parent) == len(view) == 10
    assert view.recent(2) == parent.recent(2)
    assert view.filter_events(role="Admin", limit=2) == parent.filter_events(role="Admin", limit=2)
    assert view.replay_plan(limit=2) == parent.replay_plan(limit=2)
    assert view.export_jsonl() == parent.export_jsonl()
    copied = view.all_events()
    copied[0]["user_id"] = "changed"
    assert parent.all_events()[0]["user_id"] == USER_A
    assert view.clear(user_id="forged", session_id="forged") == 10
    # The clear leaves one record of itself in the shared view, with the bound actor.
    assert len(parent) == len(view) == 1
    [cleared] = parent.all_events()
    assert cleared["type"] == "audit_cleared"
    assert (cleared["user_id"], cleared["session_id"]) == (USER_A, SESSION_A)


def test_writer_lifecycle_delegates_to_shared_parent_and_persists_actor(tmp_path):
    path = tmp_path / "audit.jsonl"
    parent = AuditLog()
    view = bind_audit_identity(parent, USER_A, SESSION_A)
    assert view.start_writer(str(path), queue_size=3) is True
    try:
        assert view.writer_status() == parent.writer_status()
        assert view.writer_status()["writer_active"] is True
        assert view._writer_thread is parent._writer_thread
        view.log("persisted")
    finally:
        view.stop_writer(user_id="forged", session_id="forged")

    assert parent.writer_status()["writer_active"] is False
    assert view.writer_status() == parent.writer_status()
    saved = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    # start_writer/stop_writer record their own lifecycle events, and the view
    # pins its actor on those as it does for log.
    assert [event["type"] for event in saved] == [
        "audit_writer_start", "persisted", "audit_writer_stop",
    ]
    assert [(event["user_id"], event["session_id"]) for event in saved] == [(USER_A, SESSION_A)] * 3
    parent.dropped = 4
    assert view.dropped == 4


def test_delegated_writer_failures_keep_original_exception(monkeypatch):
    parent = AuditLog()
    view = bind_audit_identity(parent, USER_A, SESSION_A)
    error = OSError("writer unavailable")

    def fail_writer(**attribution):
        assert (attribution["user_id"], attribution["session_id"]) == (USER_A, SESSION_A)
        raise error

    monkeypatch.setattr(parent, "stop_writer", fail_writer)
    with pytest.raises(OSError) as caught:
        view.stop_writer()
    assert caught.value is error


@pytest.mark.parametrize("user_id", ["", "person@example.test", "token", "A" * 64, "a" * 63, None])
def test_binding_rejects_raw_or_malformed_principal_without_exposing_it(user_id):
    with pytest.raises(ValueError, match="opaque lowercase HMAC-SHA256") as caught:
        bind_audit_identity(AuditLog(), user_id, SESSION_A)
    if user_id:
        assert user_id not in str(caught.value)


@pytest.mark.parametrize("session_id", ["", "raw-session-token", "A" * 32, "1" * 31, None])
def test_binding_rejects_raw_or_malformed_session_without_exposing_it(session_id):
    with pytest.raises(ValueError, match="opaque lowercase UUID") as caught:
        bind_audit_identity(AuditLog(), USER_A, session_id)
    if session_id:
        assert session_id not in str(caught.value)
