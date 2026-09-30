"""Stale browser values must not reach records before controls are rendered."""
from __future__ import annotations

from copy import deepcopy

import pytest

from role_aware_dashboard_toolkit import ControlRegistry
from role_aware_dashboard_toolkit._ui_state import restore_unauthorized_control_state
from role_aware_dashboard_toolkit.security import SecurityContext
from tests.test_authenticated_ui import _healthy, _host

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _snapshot_consumer(host):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Review note", kind="text", key="review_note", default="Baseline")
        st.session_state["config"] = radt.DashboardConfig(
            title="Snapshot authorization", registry=registry, audit=host.audit,
            auth_mode="authenticated", access=host.policy,
            run_store=radt.InMemoryRunStore(), profile_store=radt.InMemoryProfileStore(),
            sections=radt.DashboardSections(
                profiles=False, audit_writer=False, audit_log=False,
                observability=False, plugin_details=False,
            ),
        )
    st.session_state["test_context"] = radt.render(st.session_state["config"])


def _bulk_consumer(host):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Visible note", kind="text", key="visible_note", default="Visible baseline")
        registry.register("Hidden note", kind="text", key="hidden_note", default="Hidden baseline", visible=False)
        profiles = radt.InMemoryProfileStore()
        profiles.save({
            "profile_id": "accepted", "role": "Admin",
            "values": {"visible_note": "Bulk visible", "hidden_note": "Bulk hidden"},
        })
        st.session_state["config"] = radt.DashboardConfig(
            registry=registry, audit=host.audit, auth_mode="authenticated", access=host.policy,
            profile_store=profiles,
            on_change=lambda *change: host.control_changes.append(change),
            sections=radt.DashboardSections(
                runbook=False, audit_writer=False, audit_log=False,
                observability=False, plugin_details=False,
            ),
        )
    st.session_state["test_context"] = radt.render(st.session_state["config"])


@pytest.mark.parametrize("action", ["start", "checkpoint"])
@pytest.mark.parametrize("authority_change", ["downgrade", "freeze"])
def test_stale_control_submission_cannot_enter_sidebar_run_snapshot(action, authority_change):
    host = _host()
    host.store.compare_and_set_freeze(False, 0, host.principal)
    app = _healthy(AppTest.from_function(_snapshot_consumer, args=(host,), default_timeout=15).run())
    _healthy(app.text_input(key="review_note").set_value("Accepted value").run())
    if action == "checkpoint":
        _healthy(app.button(key="_radt_run_start").click().run())
    config = app.session_state["config"]
    before = [config.run_store.load(run_id) for run_id in config.run_store.list_ids()]

    # Submit both a value from the previously enabled control and a native
    # action before the browser has rendered its downgraded/frozen UI.
    app.text_input(key="review_note").set_value("Unauthorized stale value")
    if authority_change == "downgrade":
        host.store.replace_grants(host.principal, ("Approver",))
    else:
        current = host.store.read_freeze()
        host.store.compare_and_set_freeze(True, current.revision, host.principal)
    action_key = "_radt_run_start" if action == "start" else "_radt_run_checkpoint"
    _healthy(app.button(key=action_key).click().run())

    assert app.session_state["review_note"] == "Accepted value"
    if authority_change == "freeze":
        assert [config.run_store.load(run_id) for run_id in config.run_store.list_ids()] == before
        current = host.store.read_freeze()
        host.store.compare_and_set_freeze(False, current.revision, host.principal)
        _healthy(app.run())
        _healthy(app.button(key=action_key).click().run())
    else:
        assert app.session_state["test_context"].role == "Approver"

    records = [config.run_store.load(run_id) for run_id in config.run_store.list_ids()]
    assert len(records) == 1
    record = records[0]
    controls = record["initial_controls"] if action == "start" else record["checkpoints"][-1]["controls"]
    assert controls["review_note"] == "Accepted value"
    assert not any(
        event["type"] == "control_change" and event["new"] == "Unauthorized stale value"
        for event in host.audit.all_events()
    )


def test_restore_uses_each_controls_live_permission_and_preserves_authorized_values():
    registry = ControlRegistry()
    registry.register("Allowed", kind="text", key="allowed", default="default", permission="can_edit")
    registry.register("Denied", kind="text", key="denied", default="default", permission="can_approve")
    state = {
        "allowed": "accepted new value", "denied": "forged value",
        "_radt_previous_control_values": {"allowed": "old value", "denied": "trusted value"},
        "unrelated": "retained",
    }
    calls = []
    ctx = SecurityContext(
        authenticated=True, perms={"can_edit": True, "can_approve": True},
        _authorize=lambda permission, write: calls.append((permission, write)) or permission == "can_edit",
    )
    restore_unauthorized_control_state(registry, state, ctx)
    assert state["allowed"] == "accepted new value"
    assert state["denied"] == "trusted value"
    assert state["unrelated"] == "retained"
    assert calls == [("can_edit", True), ("can_approve", True)]
    assert state["_radt_previous_control_values"] == {"allowed": "old value", "denied": "trusted value"}


@pytest.mark.parametrize("history", [None, {}, "malformed"])
def test_unseen_denied_control_uses_default_without_trusting_submitted_value(history):
    registry = ControlRegistry()
    registry.register("Hidden", kind="text", key="hidden", default="trusted default", visible=False)
    state = {"hidden": "untrusted", "_radt_previous_control_values": history}
    ctx = SecurityContext(authenticated=True, perms={}, _authorize=lambda *_: False)
    restore_unauthorized_control_state(registry, state, ctx)
    assert state["hidden"] == "trusted default"


def test_restored_values_do_not_alias_the_previous_snapshot():
    registry = ControlRegistry()
    registry.register("Choice", kind="select", key="choice", options=[["a"], ["b"]], default=["a"])
    state = {"choice": ["forged"], "_radt_previous_control_values": {"choice": ["a"]}}
    ctx = SecurityContext(authenticated=True, perms={}, _authorize=lambda *_: False)
    restore_unauthorized_control_state(registry, state, ctx)
    state["choice"].append("later mutation")
    assert state["_radt_previous_control_values"]["choice"] == ["a"]


def test_legacy_control_state_is_preserved():
    registry = ControlRegistry()
    registry.register("Value", kind="text", key="value", default="default")
    state = {"value": "current", "_radt_previous_control_values": {"value": "old"}}
    before = deepcopy(state)
    restore_unauthorized_control_state(registry, state, SecurityContext(controls_writable=False))
    assert state == before


@pytest.mark.parametrize("operation", ["profile", "replay"])
@pytest.mark.parametrize("reveal_after_freeze", [False, True])
def test_authorized_bulk_values_survive_freeze_and_keep_visible_change_callbacks(operation, reveal_after_freeze):
    from role_aware_dashboard_toolkit._ui_state import queue_replay
    from role_aware_dashboard_toolkit.replay import build_replay_packet_from_checkpoint

    host = _host()
    host.control_changes = []
    host.store.compare_and_set_freeze(False, 0, host.principal)
    app = _healthy(AppTest.from_function(_bulk_consumer, args=(host,), default_timeout=15).run())
    if operation == "profile":
        _healthy(app.selectbox(key="_radt_profile_choice").select("accepted").run())
        _healthy(app.button(key="_radt_profile_load").click().run())
    else:
        packet = build_replay_packet_from_checkpoint({
            "checkpoint_id": "bulk-checkpoint",
            "controls": {"visible_note": "Bulk visible", "hidden_note": "Bulk hidden"},
        })
        queue_replay(app.session_state, packet, "bulk-checkpoint")
        _healthy(app.run())

    assert app.session_state["hidden_note"] == "Bulk hidden"
    assert host.control_changes == [("visible_note", "Visible baseline", "Bulk visible")]
    _healthy(app.text_input(key="visible_note").set_value("Latest accepted edit").run())
    assert host.control_changes == [
        ("visible_note", "Visible baseline", "Bulk visible"),
        ("visible_note", "Bulk visible", "Latest accepted edit"),
    ]
    control_events = [event for event in host.audit.all_events() if event["type"] == "control_change"]
    assert [(event["key"], event["old"], event["new"]) for event in control_events] == host.control_changes

    # The hidden value has never produced a control widget. Later read-only
    # rendering must use the accepted bulk value, not a default or stale prior
    # widget value, and freezing must not create extra change callbacks/events.
    config = app.session_state["config"]
    config.registry.get("hidden_note").visible = reveal_after_freeze
    current = host.store.read_freeze()
    host.store.compare_and_set_freeze(True, current.revision, host.principal)
    _healthy(app.run())
    assert app.session_state["hidden_note"] == "Bulk hidden"
    assert app.session_state["visible_note"] == "Latest accepted edit"
    assert len(host.control_changes) == 2
    assert [event for event in host.audit.all_events() if event["type"] == "control_change"] == control_events
    if reveal_after_freeze:
        hidden = next(item for item in app.text_input if item.label == "Hidden note")
        assert hidden.disabled and hidden.value == "Bulk hidden"
