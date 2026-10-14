"""Configuration and real Streamlit coverage for each dashboard surface."""
from dataclasses import FrozenInstanceError, asdict
from threading import Event
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit.sections import DashboardSections, section_visible
from tests.demo_role_helpers import start_as_admin


SECTION_NAMES = {
    "controls", "profiles", "runbook", "audit_writer", "audit_log", "observability",
    "plugin_details", "plugin_sidebar", "plugin_panels", "team_ops", "decisions",
    "operator_memory", "caseboard", "governance",
}


def test_default_sections_are_explicit_immutable_and_backward_compatible():
    sections = DashboardSections()
    assert asdict(sections) == dict.fromkeys(SECTION_NAMES, True)
    for name in SECTION_NAMES:
        assert section_visible(SimpleNamespace(), name)
        assert section_visible(SimpleNamespace(sections=None), name)
    with pytest.raises(FrozenInstanceError):
        sections.profiles = False
    with pytest.raises(TypeError, match="unexpected keyword"):
        DashboardSections(profile=False)
    with pytest.raises(ValueError, match="Unknown dashboard section"):
        section_visible(SimpleNamespace(), "profile")
    with pytest.raises(TypeError, match="DashboardSections"):
        section_visible(SimpleNamespace(sections={"profiles": False}), "profiles")


@pytest.mark.parametrize("value", [0, 1, None, "false", []])
def test_sections_reject_nonboolean_values(value):
    with pytest.raises(TypeError, match="DashboardSections.profiles must be bool"):
        DashboardSections(profiles=value)


def _consumer(audit_dir):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    from role_aware_dashboard_toolkit.caseboard import build_case_record
    from role_aware_dashboard_toolkit.case_store import InMemoryCaseStore
    from role_aware_dashboard_toolkit.decision_store import InMemoryDecisionStore
    from role_aware_dashboard_toolkit.governance_store import InMemoryGovernanceStore
    from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
    from role_aware_dashboard_toolkit.runs import build_run, append_checkpoint
    from role_aware_dashboard_toolkit.sections import DashboardSections
    from role_aware_dashboard_toolkit.team_store import InMemoryTeamStore

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Workers", kind="number", key="workers", default=8,
                          min_value=1, max_value=40, step=1)
        registry.register("API token", kind="text", key="api_token", sensitive=True,
                          default="synthetic-private-token")
        profiles = radt.InMemoryProfileStore()
        profiles.save({"profile_id": "shift", "values": {"workers": 20}})
        runs = radt.InMemoryRunStore()
        run = append_checkpoint(build_run({"workers": 8}), {"workers": 8})
        runs.save(run)
        cases = InMemoryCaseStore()
        cases.save(build_case_record("Synthetic review", linked_run_ids=[run["run_id"]]))
        plugins = radt.PluginRegistry()

        def setup(context):
            runtime = context["st"]
            runtime.session_state["plugin_setup_count"] = runtime.session_state.get("plugin_setup_count", 0) + 1

        def sidebar(context):
            runtime = context["st"]
            runtime.session_state["plugin_sidebar_count"] = runtime.session_state.get("plugin_sidebar_count", 0) + 1
            runtime.caption("Custom sidebar visible")
            if runtime.session_state.get("plugin_sidebar_failure"):
                raise RuntimeError("synthetic sidebar callback failure")

        def panel(context):
            runtime = context["st"]
            runtime.session_state["plugin_panel_count"] = runtime.session_state.get("plugin_panel_count", 0) + 1
            runtime.caption("Custom panel visible")

        plugins.register(radt.DashboardPlugin(name="section-consumer", setup=setup,
                         render_sidebar=sidebar, render_panel=panel))
        st.session_state["config"] = radt.DashboardConfig(
            auth_mode="demo",
            title="Section consumer", registry=registry, profile_store=profiles,
            run_store=runs, team_store=InMemoryTeamStore(),
            decision_store=InMemoryDecisionStore(), operator_memory_store=InMemoryOperatorMemoryStore(),
            case_store=cases, governance_store=InMemoryGovernanceStore(), plugins=plugins,
            audit_dir=audit_dir, observability=radt.ObservabilityConfig(enabled=True))
        st.session_state["_radt_active_run_id"] = run["run_id"]
        st.session_state["config"].audit.log("consumer_started")
    config = st.session_state["config"]
    config.sections = DashboardSections(**st.session_state.get("section_overrides", {}))
    config.auth_hook = (lambda: st.session_state["forced_role"]) if st.session_state.get("forced_role") else None

    def telemetry():
        st.session_state["sample_count"] = st.session_state.get("sample_count", 0) + 1
        return {"metrics": {"queue": 12}}

    config.observability.telemetry_hook = telemetry
    radt.render(config)


@pytest.fixture
def app(tmp_path):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = start_as_admin(AppTest.from_function(_consumer, args=(str(tmp_path),), default_timeout=15)).run()
    assert not app.exception, [item.message for item in app.exception]
    yield app
    app.session_state["config"].audit.stop_writer()


def _run(app):
    app.run()
    assert not app.exception, [item.message for item in app.exception]
    assert not any("_radt_audit_" in item.value and "default value" in item.value
                   for item in app.warning)
    return app


def _surfaces(app):
    headings = [item.value for item in app.subheader]
    expanders = [item.label for item in app.expander]
    captions = [item.value for item in app.caption]
    return {
        "controls": len([item for item in app.number_input if item.key == "workers"]),
        "profiles": headings.count("Profiles"),
        "runbook": expanders.count("Runbook"),
        "audit_writer": headings.count("Audit Logging"),
        "audit_log": expanders.count("Audit Log"),
        "observability": expanders.count("Observability"),
        "plugin_details": expanders.count("Plugins"),
        "plugin_sidebar": captions.count("Custom sidebar visible"),
        "plugin_panels": captions.count("Custom panel visible"),
        "team_ops": headings.count("Team Ops"),
        "decisions": headings.count("Decision Layer"),
        "operator_memory": headings.count("Incident Timeline"),
        "caseboard": headings.count("Caseboard"),
        "governance": headings.count("Governance"),
    }


@pytest.mark.parametrize("section", sorted(SECTION_NAMES))
def test_each_section_hides_its_real_surface_and_restores_defaults(app, section):
    before = _surfaces(app)
    assert all(before.values()), before
    assert before["team_ops"] == before["operator_memory"] == 2
    sample_count = app.session_state["sample_count"]
    sidebar_count = app.session_state["plugin_sidebar_count"]
    panel_count = app.session_state["plugin_panel_count"]
    app.session_state["section_overrides"] = {section: False}
    _run(app)
    expected = {**before, section: 0}
    if section == "runbook":
        expected.update(dict.fromkeys(["team_ops", "decisions", "operator_memory", "caseboard", "governance"], 0))
    assert _surfaces(app) == expected
    assert app.session_state["sample_count"] == sample_count + (section != "observability")
    assert app.session_state["plugin_sidebar_count"] == sidebar_count + (section != "plugin_sidebar")
    assert app.session_state["plugin_panel_count"] == panel_count + (section != "plugin_panels")
    assert app.session_state["plugin_setup_count"] == 1
    assert app.selectbox(key="_radt_role").value == "Admin"
    assert app.toggle(key="_radt_writable").value is True
    app.session_state["section_overrides"] = {}
    _run(app)
    assert _surfaces(app) == before


def test_hidden_controls_keep_values_and_do_not_grant_edit_permission(app):
    app.number_input(key="workers").set_value(24)
    app.text_input(key="_radt_sensitive_replacement__api_token").set_value("synthetic-live-token")
    app.button(key="_radt_sensitive_submit__api_token").click()
    _run(app)
    app.session_state["section_overrides"] = {"controls": False}
    _run(app)
    assert app.session_state["workers"] == 24
    assert app.session_state["api_token"] == "synthetic-live-token"
    app.selectbox(key="_radt_role").select("Viewer")
    _run(app)
    app.session_state["section_overrides"] = {}
    _run(app)
    assert app.session_state["workers"] == 24
    assert app.session_state["api_token"] == "synthetic-live-token"
    assert all(item.disabled for item in app.number_input if item.label == "Workers")
    assert not any(item.label == "Replace API token" for item in app.text_input)
    assert any(item.value == "API token: Hidden" for item in app.caption)


@pytest.mark.parametrize("denial", ["freeze", "auth"])
def test_hidden_sections_do_not_skip_pending_replay_authorization(app, denial):
    from role_aware_dashboard_toolkit._ui_state import queue_replay
    from role_aware_dashboard_toolkit.replay import build_replay_packet_from_checkpoint

    app.number_input(key="workers").set_value(24)
    _run(app)
    config = app.session_state["config"]
    run = config.run_store.load(app.session_state["_radt_active_run_id"])
    checkpoint = run["checkpoints"][-1]
    queue_replay(app.session_state, build_replay_packet_from_checkpoint(checkpoint), checkpoint["checkpoint_id"])
    app.session_state["section_overrides"] = dict.fromkeys(SECTION_NAMES, False)
    if denial == "freeze":
        app.toggle(key="_radt_writable").set_value(False)
    else:
        app.session_state["forced_role"] = "unknown-role"
    _run(app)
    assert app.session_state["workers"] == 24
    assert "_radt_pending_replay" not in app.session_state
    assert not any(event["type"] == "checkpoint_replay" for event in config.audit.all_events())
    assert app.error if denial == "auth" else app.warning


def test_hiding_plugin_details_keeps_callback_failures_visible(app):
    app.session_state["section_overrides"] = {"plugin_details": False}
    app.session_state["plugin_sidebar_failure"] = True
    _run(app)
    assert "Plugins" not in [item.label for item in app.expander]
    assert any("RADT-PLUGIN" in item.value and "RuntimeError" in item.value for item in app.warning)
    assert not any("synthetic sidebar callback failure" in item.value for item in app.warning)
    assert "Custom panel visible" in [item.value for item in app.caption]


def test_hidden_audit_writer_retains_thread_settings_and_errors(app, tmp_path, monkeypatch):
    audit_path = tmp_path / "custom-audit.jsonl"
    app.text_input(key="_radt_audit_path").set_value(str(audit_path))
    _run(app)
    app.toggle(key="_radt_audit_writer").set_value(True)
    _run(app)
    audit = app.session_state["config"].audit
    writer_thread = audit._writer_thread
    assert audit.writer_status()["writer_active"]
    assert audit.writer_status()["writer_path"] == str(audit_path)
    app.session_state["section_overrides"] = {"audit_writer": False}
    _run(app)
    assert not any(item.key == "_radt_audit_writer" for item in app.toggle)
    assert not any(item.key == "_radt_audit_path" for item in app.text_input)
    assert app.session_state["_radt_audit_writer"] is True
    assert app.session_state["_radt_audit_path"] == str(audit_path)
    assert audit._writer_thread is writer_thread
    app.button(key="_radt_run_checkpoint").click()
    _run(app)
    assert audit._writer_thread is writer_thread
    assert audit.writer_status()["writer_active"]

    recorded = Event()
    original_record = audit._record_writer_error

    def record_error(exc):
        result = original_record(exc)
        recorded.set()
        return result

    def fail_append(_event):
        raise PermissionError("cannot write C:/private/secret-audit.jsonl")

    monkeypatch.setattr(audit, "_record_writer_error", record_error)
    monkeypatch.setattr(audit._writer_store, "append", fail_append)
    audit.log("synthetic_failure_probe")
    assert recorded.wait(timeout=3), "The live writer did not consume the test event"
    _run(app)
    assert any("Audit writer error (PermissionError)" in item.value for item in app.error)
    assert not any("C:/private" in item.value or "secret-audit" in item.value for item in app.error)
    assert audit._writer_thread is writer_thread
    app.session_state["section_overrides"] = {}
    _run(app)
    assert app.toggle(key="_radt_audit_writer").value is True
    assert app.text_input(key="_radt_audit_path").value == str(audit_path)
    assert audit._writer_thread is writer_thread
    app.toggle(key="_radt_audit_writer").set_value(False)
    _run(app)
    assert not audit.writer_status()["writer_active"]
