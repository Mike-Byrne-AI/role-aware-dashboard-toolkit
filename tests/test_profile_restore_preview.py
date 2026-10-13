"""Effective profile previews preserve restore authority and sensitive values."""
from __future__ import annotations

from copy import deepcopy

import pytest

from role_aware_dashboard_toolkit import (
    ControlRegistry,
    DashboardConfig,
    InMemoryProfileStore,
    load_profile,
    make_security_context,
)
from role_aware_dashboard_toolkit._profile_preview import build_profile_restore_preview
from role_aware_dashboard_toolkit.sidebar import _render_profile_controls
from tests.test_role_aware_dashboard_toolkit import RecordingStreamlit


def _context(*, writable=True, **overrides):
    return make_security_context(
        "Planner", {"can_view_metrics": True, "can_load_profiles": True,
                    "can_edit_controls": True, **overrides},
        controls_writable=writable,
    )


def _registry():
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=2,
                      min_value=0, max_value=10, step=1)
    registry.register("Mode", kind="select", key="mode", default="safe",
                      options=["safe", "fast"])
    registry.register("Enabled", kind="toggle", key="enabled", default=False)
    registry.register("Note", kind="text", key="note", default="initial")
    registry.register("Color", kind="color", key="color", default="#123456")
    registry.register("Load", kind="slider", key="load", default=0.5,
                      min_value=0.0, max_value=1.0, step=0.1)
    return registry


def test_preview_matches_actual_sanitized_load_without_changing_inputs():
    registry = _registry()
    calls = []
    for control in registry.all():
        control.callback = lambda *_args: calls.append("callback")
    state = {"workers": 3, "mode": "fast", "enabled": False, "note": "live",
             "color": "#abcdef", "load": 0.9, "host_value": {"untouched": True}}
    profile = {"profile_id": "old", "values": {
        "workers": 100, "mode": "removed", "enabled": "yes", "note": 42,
        "color": "invalid", "load": -10,
    }}
    original_state, original_profile = deepcopy(state), deepcopy(profile)

    preview = build_profile_restore_preview(profile, registry, state, _context())

    assert state == original_state
    assert profile == original_profile
    assert calls == []
    store = InMemoryProfileStore()
    store.save(profile)
    expected = dict(state)
    loaded = load_profile("old", registry, expected, store=store)
    assert preview.corrected_count == loaded["corrected_values"] == 6
    assert not preview.blocked_reasons
    assert {row["Control"]: row["Effective"] for row in preview.rows} == {
        control.name: str(expected[control.key]) for control in registry.all()
    }
    assert preview.rows[0] == {
        "Control": "Workers", "Current": "3", "Saved": "100", "Effective": "10",
        "Result": "Restored; corrected",
    }


@pytest.mark.parametrize("saved,state", [
    ({"workers": 3}, {"workers": 3}),
    ({}, {"workers": 100}),
    ({}, {}),
])
def test_preview_checks_unchanged_restores_and_sanitation_only_permission(saved, state):
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=2,
                      min_value=0, max_value=10, step=1, permission="can_manage_workers")
    original_state = dict(state)
    preview = build_profile_restore_preview({"values": saved}, registry, state, _context())
    assert preview.blocked_reasons == ["Workers requires can_manage_workers."]
    if not saved:
        assert preview.rows[0]["Saved"] == "Not saved"
    assert state == original_state


def test_preview_accepts_absent_legacy_values_and_metadata_like_load():
    preview = build_profile_restore_preview(
        {"values": None, "control_meta": None}, _registry(), {"note": "retained"}, _context(),
    )
    assert preview.unknown_count == 0
    assert not preview.blocked_reasons
    assert next(row for row in preview.rows if row["Control"] == "Note")["Effective"] == "retained"


def test_preview_retains_missing_values_and_explains_frozen_and_missing_load_permission():
    preview = build_profile_restore_preview(
        {"values": {}}, _registry(), {"note": "retained"},
        _context(writable=False, can_load_profiles=False),
    )
    assert preview.blocked_reasons == ["Controls are frozen.", "Loading requires can_load_profiles."]
    assert preview.rows == []
    assert not preview.values_visible
    allowed = build_profile_restore_preview(
        {"values": {}}, _registry(), {"note": "retained"}, _context(),
    )
    row = next(row for row in allowed.rows if row["Control"] == "Note")
    assert row == {"Control": "Note", "Current": "retained", "Saved": "Not saved",
                   "Effective": "retained", "Result": "Current value retained"}


@pytest.mark.parametrize("permission", ["can_view_metrics", "can_load_profiles"])
def test_preview_does_not_disclose_values_without_both_view_and_load_permissions(permission):
    preview = build_profile_restore_preview(
        {"values": {"note": "stored-canary"}}, _registry(), {"note": "live-canary"},
        _context(**{permission: False}),
    )
    assert not preview.values_visible
    assert "canary" not in repr(preview)


def test_preview_hides_sensitive_unknown_historical_and_nested_secret_values():
    registry = _registry()
    registry.register("Credential", kind="text", key="credential", sensitive=True)
    profile = {"values": {
        "credential": "saved-secret-canary", "removed": "removed-secret-canary",
        "api_token": "unknown-secret-canary", "note": {"password": "nested-secret-canary"},
        "mode": "old-sensitive-canary",
    }, "control_meta": [{"key": "mode", "sensitive": True}]}
    preview = build_profile_restore_preview(
        profile, registry, {"credential": "live-secret-canary", "mode": "fast"}, _context(),
    )
    assert "canary" not in repr(preview)
    assert preview.unknown_count == 2
    assert preview.sensitive_omitted_count == 3
    rows = {row["Control"]: row for row in preview.rows}
    assert rows["Credential"]["Effective"] == "Hidden"
    assert rows["Mode"]["Saved"] == "Hidden"
    assert rows["Note"]["Effective"] == "Hidden"
    assert rows["Note"]["Saved"] == "Hidden"
    assert rows["Note"]["Result"] == "Sensitive value not restored"


def test_rendering_preview_does_not_write_stores_audit_controls_or_callbacks():
    class ReadOnlyStore(InMemoryProfileStore):
        def save(self, _profile):
            raise AssertionError("preview attempted to save")

        def delete(self, _profile_id):
            raise AssertionError("preview attempted to delete")

    store = ReadOnlyStore()
    store._profiles["saved"] = {"profile_id": "saved", "values": {"workers": 99}}
    calls = []
    registry = _registry()
    registry.get("workers").callback = lambda *_args: calls.append("callback")
    config = DashboardConfig(auth_mode="demo", registry=registry, profile_store=store,
                             on_change=lambda *_args: calls.append("global"))
    st = RecordingStreamlit()
    st.session_state.update({"_radt_profile_choice": "saved", "workers": 3})
    before = registry.snapshot(st.session_state)

    _render_profile_controls(st, config, _context(), store)

    assert registry.snapshot(st.session_state) == before
    assert calls == []
    assert config.audit.all_events() == []
    assert store.load("saved")["values"] == {"workers": 99}
    assert st.dataframe_payloads[0][0]["Effective"] == "10"
    assert "_radt_active_profile_id" not in st.session_state


@pytest.mark.parametrize("values", [42, True, "private-value-canary", ["private-key-canary"]])
@pytest.mark.parametrize("can_load", [False, True])
def test_selecting_malformed_profile_warns_without_crashing_or_exposing_contents(values, can_load):
    store = InMemoryProfileStore()
    profile = {"profile_id": "private-profile-canary", "values": values}
    store.save(profile)
    registry = _registry()
    config = DashboardConfig(auth_mode="demo", registry=registry, profile_store=store)
    st = RecordingStreamlit()
    st.session_state.update({"_radt_profile_choice": profile["profile_id"], "workers": 3})
    before = registry.snapshot(st.session_state)

    _render_profile_controls(
        st, config, _context(can_load_profiles=can_load, can_view_metrics=can_load), store,
    )

    assert st.messages["warning"] == ["Profile preview is unavailable: saved values are invalid."]
    assert "canary" not in repr(st.messages)
    assert st.dataframe_payloads == []
    assert registry.snapshot(st.session_state) == before
    assert config.audit.all_events() == []
    assert store.load(profile["profile_id"]) == profile


def test_preview_does_not_mask_unrelated_registry_errors(monkeypatch):
    registry = _registry()

    def failed_restore(*_args, **_kwargs):
        raise ValueError("registry failure")

    monkeypatch.setattr(registry, "restore", failed_restore)
    store = InMemoryProfileStore()
    store.save({"profile_id": "saved", "values": {"workers": 3}})
    st = RecordingStreamlit()
    st.session_state["_radt_profile_choice"] = "saved"
    with pytest.raises(ValueError, match="registry failure"):
        _render_profile_controls(st, DashboardConfig(auth_mode="demo", registry=registry), _context(), store)


def _preview_consumer():
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Workers", kind="number", key="workers", default=3,
                          min_value=0, max_value=10, step=1)
        store = radt.InMemoryProfileStore()
        store.save({"profile_id": "old", "values": {"workers": 25, "removed": "secret-canary"}})
        st.session_state["config"] = radt.DashboardConfig(
            auth_mode="demo",
            registry=registry, profile_store=store,
            sections=radt.DashboardSections(runbook=False, audit_writer=False,
                                           audit_log=False, plugin_details=False),
        )
    radt.render(st.session_state["config"])


def test_actual_sidebar_keeps_rendering_after_selecting_malformed_profile():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_preview_consumer).run()
    app.session_state["config"].profile_store.save({"profile_id": "corrupt", "values": 42})
    app.run()
    app.selectbox(key="_radt_profile_choice").select("corrupt").run()

    assert not app.exception
    assert app.session_state["workers"] == 3
    assert any("saved values are invalid" in item.value for item in app.warning)


def test_actual_sidebar_previews_then_rechecks_frozen_and_denied_load():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_preview_consumer).run()
    assert not app.exception
    app.selectbox(key="_radt_profile_choice").select("old").run()
    assert not app.exception
    assert list(app.dataframe[0].value["Current"]) == ["3"]
    assert list(app.dataframe[0].value["Saved"]) == ["25"]
    assert list(app.dataframe[0].value["Effective"]) == ["10"]
    assert app.session_state["workers"] == 3
    assert not app.session_state["config"].audit.all_events()
    assert "secret-canary" not in repr(app.dataframe[0].value)

    app.toggle(key="_radt_writable").set_value(False).run()
    assert not app.exception
    assert app.button(key="_radt_profile_load").disabled
    assert any("Controls are frozen" in item.value for item in app.warning)
    app.toggle(key="_radt_writable").set_value(True).run()
    app.session_state["config"].registry.get("workers").permission = "not_granted"
    app.button(key="_radt_profile_load").click().run()
    assert not app.exception
    assert app.session_state["workers"] == 3
    assert any("Workers requires not_granted" in item.value for item in app.warning)
    assert not any(event["type"] == "profile_load"
                   for event in app.session_state["config"].audit.all_events())

    app.session_state["config"].registry.get("workers").permission = "can_edit_controls"
    app.button(key="_radt_profile_load").click().run()
    assert not app.exception
    assert app.session_state["workers"] == 10
    assert len([event for event in app.session_state["config"].audit.all_events()
                if event["type"] == "profile_load"]) == 1
