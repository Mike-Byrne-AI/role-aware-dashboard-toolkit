"""Profile membership updates finish in one render without losing host widget state."""
from __future__ import annotations

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _consumer(audit_dir):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    def count(key):
        st.session_state[key] = st.session_state.get(key, 0) + 1

    def control_changed(*_args):
        count("control_calls")

    def setup(_context):
        count("setup_calls")

    def sidebar(context):
        count("sidebar_calls")
        context["st"].radio("Plugin menu", ["Overview", "Details"], key="plugin_menu")

    def panel(context):
        count("panel_calls")
        context["st"].text_input("Plugin note", value="initial", key="plugin_note")

    def sample():
        count("telemetry_calls")
        return {"metrics": {"capacity": 12}}

    count("script_calls")
    st.number_input("Host before", value=1, key="host_before")
    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Workers", kind="number", key="workers", default=2,
                          min_value=0, max_value=100, step=1, callback=control_changed)
        registry.register("Progress", kind="slider", key="progress", default=20,
                          min_value=0, max_value=100, step=1, callback=control_changed)
        registry.register("Priority", kind="select", key="priority", default="Normal",
                          options=["Normal", "High"], callback=control_changed)
        registry.register("Project", kind="text", key="project", default="Initial",
                          callback=control_changed)
        registry.register("Accepting", kind="toggle", key="accepting", default=True,
                          callback=control_changed)
        registry.register("Chart color", kind="color", key="chart_color", default="#336699",
                          callback=control_changed)
        profiles = radt.InMemoryProfileStore()
        profiles.save({"profile_id": "base", "values": {"workers": 3}, "source": "ui"})
        profiles.save({"profile_id": "other", "values": {"workers": 4}})
        plugins = radt.PluginRegistry()
        plugins.register(radt.DashboardPlugin(name="host-widgets", setup=setup,
                         render_sidebar=sidebar, render_panel=panel))
        st.session_state["config"] = radt.DashboardConfig(
            registry=registry, profile_store=profiles, plugins=plugins, audit_dir=audit_dir,
            sections=radt.DashboardSections(runbook=False, audit_writer=False,
                                           audit_log=False, plugin_details=False),
            observability=radt.ObservabilityConfig(enabled=True, telemetry_hook=sample,
                                                   show_summary=False),
        )
    st.session_state["ctx"] = radt.render(st.session_state["config"])
    st.number_input("Host after", value=1, key="host_after")
    count("completed_calls")


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


@pytest.fixture
def app(tmp_path):
    app = _healthy(AppTest.from_function(_consumer, args=(str(tmp_path / "audit"),),
                                        default_timeout=15).run())
    app.number_input(key="workers").set_value(18)
    app.slider(key="progress").set_value(70)
    app.selectbox(key="priority").select("High")
    app.text_input(key="project").set_value("Keep project")
    app.toggle(key="accepting").set_value(False)
    app.color_picker(key="chart_color").set_value("#CC5500")
    app.number_input(key="host_before").set_value(21)
    app.number_input(key="host_after").set_value(42)
    app.radio(key="plugin_menu").set_value("Details")
    app.text_input(key="plugin_note").set_value("Keep note")
    app.text_input(key="_radt_profile_name").set_value("new-plan")
    return _healthy(app.run())


def _values(app):
    return {key: app.session_state[key] for key in (
        "workers", "progress", "priority", "project", "accepting", "chart_color",
        "host_before", "host_after", "plugin_menu", "plugin_note", "_radt_profile_name",
    )}


def _counts(app):
    return {key: app.session_state[key] for key in (
        "script_calls", "completed_calls", "sidebar_calls", "panel_calls", "telemetry_calls",
    )}


def _assert_one_pass(app, counts, values, control_calls):
    assert _counts(app) == {key: value + 1 for key, value in counts.items()}
    assert _values(app) == values
    assert app.session_state["setup_calls"] == 1
    assert app.session_state["control_calls"] == control_calls
    assert app.number_input(key="host_after").value == 42
    assert app.radio(key="plugin_menu").value == "Details"
    assert app.text_input(key="plugin_note").value == "Keep note"


def _profile_events(app):
    return [event for event in app.session_state["config"].audit.all_events()
            if event["type"].startswith("profile_")]


@pytest.mark.parametrize("selection", ["(none)", "base"])
def test_save_immediately_refreshes_options_and_preserves_existing_selection(app, selection):
    _healthy(app.selectbox(key="_radt_profile_choice").select(selection).run())
    counts, values = _counts(app), _values(app)
    control_calls = app.session_state["control_calls"]
    _healthy(app.button(key="_radt_profile_save").click().run())
    assert app.selectbox(key="_radt_profile_choice").options == ["(none)", "base", "new-plan", "other"]
    assert app.selectbox(key="_radt_profile_choice").value == selection
    assert [toast.value for toast in app.get("toast")] == ["Saved profile: new-plan"]
    assert [event["type"] for event in _profile_events(app)] == ["profile_save"]
    saved = app.session_state["config"].profile_store.load("new-plan")
    assert saved["values"] == {key: values[key] for key in
                               ("workers", "progress", "priority", "project", "accepting", "chart_color")}
    assert saved["parent_profile_id"] == (selection if selection != "(none)" else "")
    _assert_one_pass(app, counts, values, control_calls)
    # The newly offered choice is usable immediately; no unrelated click is required.
    _healthy(app.selectbox(key="_radt_profile_choice").select("new-plan").run())
    assert app.selectbox(key="_radt_profile_choice").value == "new-plan"
    assert len(_profile_events(app)) == 1


def test_delete_refreshes_options_and_keeps_toast_host_widgets_and_single_dispatch(app):
    _healthy(app.selectbox(key="_radt_profile_choice").select("base").run())
    counts, values = _counts(app), _values(app)
    control_calls = app.session_state["control_calls"]
    _healthy(app.button(key="_radt_profile_delete").click().run())
    assert app.selectbox(key="_radt_profile_choice").options == ["(none)", "other"]
    assert app.selectbox(key="_radt_profile_choice").value == "(none)"
    assert [toast.value for toast in app.get("toast")] == ["Deleted profile: base"]
    assert [event["type"] for event in _profile_events(app)] == ["profile_delete"]
    assert app.session_state["config"].profile_store.load("base") is None
    _assert_one_pass(app, counts, values, control_calls)
    _healthy(app.run())
    assert _values(app) == values
    assert len(_profile_events(app)) == 1


@pytest.mark.parametrize("operation", ["save", "delete"])
def test_failed_write_keeps_profile_widgets_selection_and_no_success(app, operation):
    _healthy(app.selectbox(key="_radt_profile_choice").select("base").run())
    store = app.session_state["config"].profile_store

    def fail(*_args, **_kwargs):
        raise PermissionError("private-store-canary")

    setattr(store, operation, fail)
    counts, values = _counts(app), _values(app)
    control_calls = app.session_state["control_calls"]
    _healthy(app.button(key=f"_radt_profile_{operation}").click().run())
    assert "RADT-PROFILE-IO" in " ".join(item.value for item in app.error)
    assert "private-store-canary" not in " ".join(item.value for item in app.error)
    assert app.selectbox(key="_radt_profile_choice").options == ["(none)", "base", "other"]
    assert app.selectbox(key="_radt_profile_choice").value == "base"
    assert not app.get("toast")
    assert not _profile_events(app)
    _assert_one_pass(app, counts, values, control_calls)


@pytest.mark.parametrize("operation", ["save", "delete"])
def test_viewer_cannot_forge_profile_write_and_freeze_authority_is_preserved(app, operation, monkeypatch):
    _healthy(app.selectbox(key="_radt_profile_choice").select("base").run())
    _healthy(app.selectbox(key="_radt_role").select("Viewer").run())
    _healthy(app.toggle(key="_radt_writable").set_value(False).run())
    counts, values = _counts(app), _values(app)
    control_calls = app.session_state["control_calls"]
    assert app.button(key=f"_radt_profile_{operation}").disabled
    # Newer AppTest versions reject disabled-widget clicks at the client. Force
    # the server result while still drawing the real disabled widget to check
    # the toolkit's permission guard independently of that client protection.
    import streamlit as st
    original_button = st.button

    def forged_button(*args, **kwargs):
        clicked = original_button(*args, **kwargs)
        return True if kwargs.get("key") == f"_radt_profile_{operation}" else clicked

    monkeypatch.setattr(st, "button", forged_button)
    _healthy(app.run())
    assert app.session_state["ctx"].role == "Viewer"
    assert app.session_state["ctx"].controls_writable is False
    assert app.selectbox(key="_radt_profile_choice").options == ["(none)", "base", "other"]
    assert app.selectbox(key="_radt_profile_choice").value == "base"
    assert not app.get("toast")
    assert not _profile_events(app)
    _assert_one_pass(app, counts, values, control_calls)


def test_frozen_admin_save_still_refreshes_without_unfreezing_controls(app):
    _healthy(app.toggle(key="_radt_writable").set_value(False).run())
    counts, values = _counts(app), _values(app)
    control_calls = app.session_state["control_calls"]
    assert not app.button(key="_radt_profile_save").disabled
    assert app.button(key="_radt_profile_load").disabled
    _healthy(app.button(key="_radt_profile_save").click().run())
    assert "new-plan" in app.selectbox(key="_radt_profile_choice").options
    assert app.session_state["ctx"].controls_writable is False
    assert app.number_input(key="_radt_read_only_control__workers").disabled
    _assert_one_pass(app, counts, values, control_calls)



def test_failed_membership_read_after_save_keeps_inputs_and_reports_completed_write_once(app):
    _healthy(app.selectbox(key="_radt_profile_choice").select("base").run())
    store = app.session_state["config"].profile_store
    list_ids = store.list_ids
    attempts = []

    def list_until_saved():
        attempts.append("list")
        if store.load("new-plan") is not None:
            raise OSError("private-list-canary")
        return list_ids()

    store.list_ids = list_until_saved
    counts, values = _counts(app), _values(app)
    control_calls = app.session_state["control_calls"]
    _healthy(app.button(key="_radt_profile_save").click().run())
    assert attempts == ["list", "list"]
    assert store.load("new-plan") is not None
    assert app.selectbox(key="_radt_profile_choice").options == ["(none)", "base", "other"]
    assert app.selectbox(key="_radt_profile_choice").value == "base"
    assert [toast.value for toast in app.get("toast")] == ["Saved profile: new-plan"]
    assert [event["type"] for event in _profile_events(app)] == ["profile_save"]
    assert "RADT-PROFILE-IO" in " ".join(item.value for item in app.error)
    assert "private-list-canary" not in " ".join(item.value for item in app.error)
    _assert_one_pass(app, counts, values, control_calls)


def test_unsuccessful_delete_does_not_refresh_or_claim_success(app):
    _healthy(app.selectbox(key="_radt_profile_choice").select("base").run())
    store = app.session_state["config"].profile_store
    list_ids = store.list_ids
    attempts = []

    def list_counted():
        attempts.append("list")
        return list_ids()

    store.list_ids = list_counted
    store.delete = lambda _profile_id: False
    counts, values = _counts(app), _values(app)
    control_calls = app.session_state["control_calls"]
    _healthy(app.button(key="_radt_profile_delete").click().run())
    assert attempts == ["list"]
    assert app.selectbox(key="_radt_profile_choice").options == ["(none)", "base", "other"]
    assert app.selectbox(key="_radt_profile_choice").value == "base"
    assert any("Could not delete 'base'" in item.value for item in app.warning)
    assert not app.get("toast")
    assert not _profile_events(app)
    _assert_one_pass(app, counts, values, control_calls)
