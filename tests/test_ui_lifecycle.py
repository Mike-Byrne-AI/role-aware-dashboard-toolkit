"""Real Streamlit lifecycle regressions for native controls and bulk operations."""
from __future__ import annotations

from copy import deepcopy

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _consumer():
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    from role_aware_dashboard_toolkit.security import BUILTIN_ROLES, RoleDef

    if "config" not in st.session_state:
        reg = radt.ControlRegistry()
        reg.register("Timeout", kind="slider", key="timeout", default=10.0,
                     min_value=1.0, max_value=60.0, step=1.0)
        reg.register("Workers", kind="number", key="workers", default=8,
                     min_value=1, max_value=40, step=1)
        reg.register("Track", kind="select", key="track", default="Stable",
                     options=["Stable", "Canary"])
        reg.register("Maintenance", kind="toggle", key="maintenance", default=False)
        reg.register("Message", kind="text", key="message", default="Ready")
        reg.register("Accent", kind="color", key="accent", default="#336699")
        reg.register("API token", kind="text", key="api_token", default="initial-secret",
                     sensitive=True)
        store = radt.InMemoryProfileStore()
        store.save({"profile_id": "partial", "role": "Admin", "values": {"workers": 20}})
        roles = {name: RoleDef(name, dict(role.perms))
                 for name, role in BUILTIN_ROLES.items()}
        roles["Blind operator"] = RoleDef(
            "Blind operator", {**roles["Operator"].perms, "can_view_metrics": False})
        st.session_state["config"] = radt.DashboardConfig(
            registry=reg, profile_store=store, run_store=radt.InMemoryRunStore(),
            custom_roles=roles, title="Lifecycle consumer",
            observability=radt.ObservabilityConfig(enabled=True))
    config = st.session_state["config"]

    def telemetry():
        if st.session_state.get("empty_telemetry"):
            return None
        if st.session_state.get("fail_telemetry"):
            raise RuntimeError("private path C:/private/token.json must not be displayed")
        count = st.session_state.get("sample_count", 0) + 1
        st.session_state["sample_count"] = count
        return {"ts": f"sample-{count}", "metrics": {"queue": 340, "bad": float("nan")},
                "health": {"checks": {"ready": True}}}

    config.observability.telemetry_hook = telemetry
    config.auth_hook = (
        (lambda: st.session_state["forced_role"])
        if st.session_state.get("forced_role") else None
    )
    radt.render(config)


@pytest.fixture
def app():
    return _healthy(AppTest.from_function(_consumer, default_timeout=15).run())


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


def _values(app):
    return {key: app.session_state[key]
            for key in app.session_state["config"].registry.keys()}


def _changed(app):
    app.slider(key="timeout").set_value(45.0)
    app.number_input(key="workers").set_value(24)
    app.selectbox(key="track").select("Canary")
    app.toggle(key="maintenance").set_value(True)
    app.text_input(key="message").set_value("Incident")
    app.color_picker(key="accent").set_value("#FF9900")
    app.text_input(key="_radt_sensitive_replacement__api_token").set_value("live-sensitive-value")
    return _healthy(app.button(key="_radt_sensitive_submit__api_token").click().run())


def _start(app):
    _healthy(app.button(key="_radt_run_start").click().run())
    return app.session_state["_radt_active_run_id"]


def _checkpoint(app):
    _healthy(app.button(key="_radt_run_checkpoint").click().run())
    config = app.session_state["config"]
    return config.run_store.load(app.session_state["_radt_active_run_id"])["checkpoints"][-1]


@pytest.mark.parametrize("action", ["start", "checkpoint", "end", "delete_profile"])
def test_early_sidebar_reruns_retain_every_control_kind_and_sensitive_value(app, action):
    if action in {"checkpoint", "end"}:
        _start(app)
    if action == "delete_profile":
        _healthy(app.selectbox(key="_radt_profile_choice").select("partial").run())
    _changed(app)
    before = _values(app)
    key = {"start": "_radt_run_start", "checkpoint": "_radt_run_checkpoint",
           "end": "_radt_run_end", "delete_profile": "_radt_profile_delete"}[action]
    _healthy(app.button(key=key).click().run())
    assert _values(app) == before
    assert app.number_input(key="workers").value == 24


@pytest.mark.parametrize("locked", [False, True])
def test_profile_merges_without_changing_role_or_sensitive_values(app, locked):
    _changed(app)
    if locked:
        app.session_state["forced_role"] = "Operator"
        _healthy(app.run())
    else:
        _healthy(app.selectbox(key="_radt_role").select("Operator").run())
    before = _values(app)
    _healthy(app.selectbox(key="_radt_profile_choice").select("partial").run())
    assert "_radt_active_profile_id" not in app.session_state
    _healthy(app.button(key="_radt_profile_load").click().run())
    assert _values(app) == {**before, "workers": 20}
    assert app.session_state["_radt_role"] == "Operator"
    assert not app.session_state["config"].custom_roles["Operator"].perms["can_manage_audit"]
    assert any("This preset updates only the settings it includes." in item.value for item in app.caption)
    assert app.session_state["_radt_active_profile_id"] == "partial"
    run_id = _start(app)
    run = app.session_state["config"].run_store.load(run_id)
    assert run["source_profile_id"] == "partial"
    assert run["active_profile_id"] == "partial"


def test_profile_permission_denial_applies_nothing_and_records_no_success(app):
    config = app.session_state["config"]
    config.registry.get("workers").permission = "can_manage_governance"
    _healthy(app.selectbox(key="_radt_role").select("Operator").run())
    _healthy(app.selectbox(key="_radt_profile_choice").select("partial").run())
    before = _values(app)
    _healthy(app.button(key="_radt_profile_load").click().run())
    assert _values(app) == before
    assert any("permission" in item.value for item in app.warning)
    assert "_radt_active_profile_id" not in app.session_state
    assert not any(e["type"] == "profile_load" for e in config.audit.all_events())


def test_replay_restores_all_nonsensitive_fields_once_after_widget_creation(app):
    _start(app)
    baseline = _checkpoint(app)
    _changed(app)
    _healthy(app.button(key="_radt_checkpoint_replay_btn").click().run())
    assert _values(app) == {**baseline["controls"], "api_token": "live-sensitive-value"}
    assert app.number_input(key="workers").value == 8
    events = app.session_state["config"].audit.all_events()
    assert len([e for e in events if e["type"] == "checkpoint_replay"]) == 1
    assert "_radt_pending_replay" not in app.session_state


@pytest.mark.parametrize("change", ["freeze", "role", "control_permission", "auth_failure"])
def test_deferred_replay_rechecks_current_authority_before_any_live_write(app, change):
    from role_aware_dashboard_toolkit._ui_state import queue_replay
    from role_aware_dashboard_toolkit.replay import build_replay_packet_from_checkpoint

    _start(app)
    baseline = _checkpoint(app)
    _changed(app)
    before = _values(app)
    queue_replay(app.session_state, build_replay_packet_from_checkpoint(baseline),
                 baseline["checkpoint_id"])
    if change == "freeze":
        app.toggle(key="_radt_writable").set_value(False)
    elif change == "role":
        app.selectbox(key="_radt_role").select("Viewer")
    elif change == "control_permission":
        app.session_state["config"].registry.get("workers").permission = "not_granted"
    else:
        app.session_state["forced_role"] = "unknown-role"
    _healthy(app.run())
    assert _values(app) == before
    assert not any(e["type"] == "checkpoint_replay"
                   for e in app.session_state["config"].audit.all_events())
    assert "_radt_pending_replay" not in app.session_state
    assert app.error if change == "auth_failure" else app.warning


def test_checkpoint_uses_exact_last_displayed_sample_and_timestamp(app):
    _start(app)
    observed = deepcopy(app.session_state["_radt_last_telemetry"])
    checkpoint = _checkpoint(app)
    assert checkpoint["telemetry_slice"] == observed
    assert observed["metrics"] == {"queue": 340.0}
    assert checkpoint["telemetry_slice"]["ts"] != app.session_state["_radt_last_telemetry"]["ts"]
    app.session_state["_radt_last_telemetry"]["health"]["checks"]["ready"] = False
    assert checkpoint["telemetry_slice"]["health"]["checks"]["ready"] is True


def test_telemetry_failure_is_visible_and_keeps_last_successful_displayed_sample(app):
    _start(app)
    observed = deepcopy(app.session_state["_radt_last_telemetry"])
    app.session_state["fail_telemetry"] = True
    _healthy(app.run())
    assert any("Telemetry sampling failed (RuntimeError)" in item.value for item in app.warning)
    assert not any("private/token" in item.value for item in app.warning)
    assert app.session_state["_radt_last_telemetry"] == observed
    assert _checkpoint(app)["telemetry_slice"] == observed


def test_hidden_metrics_are_not_sampled_or_copied_into_checkpoints(app):
    _start(app)
    count = app.session_state["sample_count"]
    _healthy(app.selectbox(key="_radt_role").select("Blind operator").run())
    assert app.session_state["sample_count"] == count
    assert _checkpoint(app)["telemetry_slice"] == {}
    assert app.session_state["sample_count"] == count


@pytest.mark.parametrize("operation", ["list_ids", "load", "save", "delete"])
@pytest.mark.parametrize("error_type", ["PermissionError", "StorePathSecurityError"])
def test_profile_store_failures_remain_visible_without_losing_live_state(app, operation, error_type):
    _changed(app)
    if operation in {"load", "delete"}:
        _healthy(app.selectbox(key="_radt_profile_choice").select("partial").run())
    config = app.session_state["config"]
    before = _values(app)
    events = deepcopy(config.audit.all_events())

    from role_aware_dashboard_toolkit.store_diagnostics import StorePathSecurityError

    failure = PermissionError if error_type == "PermissionError" else StorePathSecurityError

    def fail(*_args, **_kwargs):
        raise failure("private profile path C:/private/token.json")

    setattr(config.profile_store, operation, fail)
    if operation in {"save", "delete"}:
        app.button(key=f"_radt_profile_{operation}").click()
    _healthy(app.run())
    assert _values(app) == before
    assert config.audit.all_events() == events
    assert app.number_input(key="workers").value == 24
    assert any(f"Profile storage failed ({error_type})" in item.value for item in app.error)
    assert not any("private/token" in item.value for item in app.error)


@pytest.mark.parametrize("action", ["checkpoint", "end"])
def test_run_keeps_source_profile_and_updates_active_profile_at_capture(app, action):
    _healthy(app.selectbox(key="_radt_profile_choice").select("partial").run())
    _healthy(app.button(key="_radt_profile_load").click().run())
    run_id = _start(app)
    config = app.session_state["config"]
    config.profile_store.save({"profile_id": "recovery", "values": {"workers": 32}})
    _healthy(app.run())
    _healthy(app.selectbox(key="_radt_profile_choice").select("recovery").run())
    _healthy(app.button(key="_radt_profile_load").click().run())
    if action == "checkpoint":
        assert _checkpoint(app)["controls"]["workers"] == 32
    else:
        _healthy(app.button(key="_radt_run_end").click().run())
    recorded = config.run_store.load(run_id)
    assert recorded["source_profile_id"] == "partial"
    assert recorded["active_profile_id"] == "recovery"


def test_recovered_display_of_history_becomes_checkpoint_sample(app, monkeypatch):
    import streamlit as st

    _start(app)
    before = deepcopy(app.session_state["_radt_last_telemetry"])

    def fail_metric(*_args, **_kwargs):
        raise RuntimeError("synthetic metric renderer failure")

    with monkeypatch.context() as patch:
        patch.setattr(st, "metric", fail_metric)
        app.run()
    assert len(app.exception) == 1
    assert app.exception[0].message == "synthetic metric renderer failure"
    newest = deepcopy(app.session_state["_radt_observability_history"][-1])
    assert newest["ts"] != before["ts"]
    assert app.session_state["_radt_last_telemetry"] == before
    app.session_state["empty_telemetry"] = True
    _healthy(app.run())
    assert app.session_state["_radt_last_telemetry"] == newest
    assert _checkpoint(app)["telemetry_slice"] == newest
