"""Recovery guidance exercised through actual Streamlit reruns and plugin dispatch."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from role_aware_dashboard_toolkit import DashboardPlugin, PluginRegistry
from role_aware_dashboard_toolkit.diagnostics import build_diagnostic, diagnostic_text
from role_aware_dashboard_toolkit.plugins import PluginErrorRecord

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
PAYLOAD = "SECRET-DO-NOT-LEAK C:/private/credential.json"


def _consumer(audit_dir):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Protected count", kind="number", key="count", default=10,
                          min_value=0, max_value=100, step=1,
                          permission="can_manage_governance")
        registry.register("Message", kind="text", key="message", default="Ready")
        profiles = radt.InMemoryProfileStore()
        profiles.save({"profile_id": "saved", "values": {"count": 90, "message": "Restored"}})
        st.session_state["config"] = radt.DashboardConfig(
            title="Guidance consumer", registry=registry, profile_store=profiles,
            audit_dir=audit_dir, sections=radt.DashboardSections(plugin_details=False))
    st.session_state["ctx"] = radt.render(st.session_state["config"])


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


@pytest.fixture
def app(tmp_path):
    return _healthy(AppTest.from_function(
        _consumer, args=(str(tmp_path / "audit"),), default_timeout=15).run())


def _assert_help(app, code, capsys):
    messages = "\n".join(item.value for group in (app.error, app.warning, app.caption) for item in group)
    assert diagnostic_text(code) in messages
    assert "SECRET-DO-NOT-LEAK" not in messages
    assert "C:/private/credential.json" not in messages
    record = build_diagnostic(code)
    assert record["guide_command"] in messages
    # Resolve the command actually offered to the assistant, through the CLI.
    from role_aware_dashboard_toolkit.cli import main
    capsys.readouterr()
    assert main(["guide", record["guide_topic"], "--format", "json"]) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["ok"] is True
    assert response["result"]["topic"] == record["guide_topic"]
    assert response["result"]["content"]


def test_profile_permission_help_preserves_live_values_and_has_no_success(app, capsys):
    _healthy(app.selectbox(key="_radt_role").select("Operator").run())
    _healthy(app.selectbox(key="_radt_profile_choice").select("saved").run())
    before = {key: app.session_state[key] for key in ("count", "message")}
    _healthy(app.button(key="_radt_profile_load").click().run())
    _assert_help(app, "RADT-PERMISSION", capsys)
    assert {key: app.session_state[key] for key in before} == before
    assert app.session_state["ctx"].role == "Operator"
    assert not any(event["type"] == "profile_load"
                   for event in app.session_state["config"].audit.all_events())


@pytest.mark.parametrize("change", ["freeze", "role", "control_permission"])
def test_pending_replay_help_rechecks_current_authority(app, change, capsys):
    from role_aware_dashboard_toolkit._ui_state import queue_replay
    queue_replay(app.session_state, {"controls": {"count": 90, "message": "Replayed"}}, "checkpoint")
    if change == "freeze":
        app.toggle(key="_radt_writable").set_value(False)
    elif change == "role":
        app.selectbox(key="_radt_role").select("Viewer")
    else:
        app.session_state["config"].registry.get("count").permission = "not_granted"
    _healthy(app.run())
    _assert_help(app, "RADT-PERMISSION", capsys)
    assert app.session_state["count"] == 10
    assert app.session_state["message"] == "Ready"
    assert "_radt_pending_replay" not in app.session_state
    assert not any(event["type"] == "checkpoint_replay"
                   for event in app.session_state["config"].audit.all_events())


def test_immediate_replay_denial_points_to_permissions_without_staging(app, capsys):
    from role_aware_dashboard_toolkit import InMemoryRunStore
    app.session_state["config"].run_store = InMemoryRunStore()
    _healthy(app.run())
    _healthy(app.button(key="_radt_run_start").click().run())
    _healthy(app.button(key="_radt_run_checkpoint").click().run())
    _healthy(app.text_input(key="message").set_value("Keep this").run())
    _healthy(app.selectbox(key="_radt_role").select("Operator").run())
    _healthy(app.button(key="_radt_checkpoint_replay_btn").click().run())
    _assert_help(app, "RADT-PERMISSION", capsys)
    assert app.session_state["message"] == "Keep this"
    assert "_radt_pending_replay" not in app.session_state
    assert not any(event["type"] == "checkpoint_replay"
                   for event in app.session_state["config"].audit.all_events())


@pytest.mark.parametrize("stage", ["setup", "render_panel", "render_sidebar"])
def test_plugin_failure_help_reports_partial_effects_without_payload(app, stage, capsys):
    calls = []

    def fail(_context):
        calls.append(stage)
        raise RuntimeError(PAYLOAD)

    config = app.session_state["config"]
    config.plugins.register(DashboardPlugin(name="consumer-plugin", **{stage: fail}))
    _healthy(app.run())
    _assert_help(app, "RADT-PLUGIN", capsys)
    assert calls == [stage]
    assert app.session_state["count"] == 10
    assert "partial" in build_diagnostic("RADT-PLUGIN")["effect"]
    _healthy(app.run())
    assert calls == [stage, stage]  # Failed setup remains retryable; callbacks still dispatch.


def test_auth_failure_help_locks_ui_and_discards_pending_replay(app, capsys):
    from role_aware_dashboard_toolkit._ui_state import queue_replay
    calls = []

    def fail_auth():
        raise RuntimeError(PAYLOAD)

    config = app.session_state["config"]
    config.auth_hook = fail_auth
    config.plugins.register(DashboardPlugin(name="private-panel", render_panel=lambda ctx: calls.append(ctx)))
    queue_replay(app.session_state, {"controls": {"count": 90}}, "checkpoint")
    _healthy(app.run())
    _assert_help(app, "RADT-AUTH", capsys)
    assert app.session_state["ctx"].role == "Unauthenticated"
    assert app.session_state["ctx"].perms == {}
    assert app.session_state["ctx"].controls_writable is False
    assert "_radt_pending_replay" not in app.session_state
    assert app.session_state["count"] == 10
    assert not calls
    assert not app.number_input
    assert not app.selectbox


@pytest.mark.parametrize("operation", ["list_ids", "load", "save", "delete"])
def test_profile_io_help_keeps_live_controls_without_success(app, operation, capsys):
    if operation in {"load", "delete"}:
        _healthy(app.selectbox(key="_radt_profile_choice").select("saved").run())
    config = app.session_state["config"]
    events = config.audit.all_events()

    def fail(*_args, **_kwargs):
        raise PermissionError(PAYLOAD)

    setattr(config.profile_store, operation, fail)
    if operation in {"save", "delete"}:
        app.button(key=f"_radt_profile_{operation}").click()
    _healthy(app.run())
    _assert_help(app, "RADT-PROFILE-IO", capsys)
    assert app.session_state["count"] == 10
    assert app.session_state["message"] == "Ready"
    assert config.audit.all_events() == events


def test_unreadable_profile_record_help_does_not_echo_store_diagnostics(app):
    app.session_state["config"].profile_store.read_errors = [{"message": PAYLOAD, "path": PAYLOAD}]
    _healthy(app.run())
    warning = "\n".join(item.value for item in app.warning)
    assert "Profile storage has unreadable records." in warning
    assert build_diagnostic("RADT-PROFILE-IO")["guide_command"] in warning
    assert "SECRET-DO-NOT-LEAK" not in warning
    assert "C:/private/credential.json" not in warning
    assert app.session_state["count"] == 10


def test_successful_profile_load_does_not_inherit_historical_read_failure_claim(app):
    config = app.session_state["config"]
    config.profile_store.read_errors = [{"message": PAYLOAD, "path": PAYLOAD}]
    _healthy(app.selectbox(key="_radt_profile_choice").select("saved").run())
    assert app.session_state["count"] == 10
    _healthy(app.button(key="_radt_profile_load").click().run())
    assert app.session_state["count"] == 90
    assert app.session_state["message"] == "Restored"
    assert len([event for event in config.audit.all_events() if event["type"] == "profile_load"]) == 1
    assert config.profile_store.read_errors
    assert not app.error
    warning = "\n".join(item.value for item in app.warning)
    assert "Profile storage has unreadable records." in warning
    assert build_diagnostic("RADT-PROFILE-IO")["guide_command"] in warning
    assert "Live controls were preserved" not in warning
    assert "could not complete the requested operation" not in warning
    assert diagnostic_text("RADT-PROFILE-IO") not in warning
    assert "SECRET-DO-NOT-LEAK" not in warning
    assert "C:/private/credential.json" not in warning


def test_background_audit_error_help_does_not_echo_writer_payload(app, capsys):
    audit = app.session_state["config"].audit
    audit._writer_error_count = 1
    audit._last_writer_error = {"error_type": "PermissionError", "message": PAYLOAD}
    _healthy(app.run())
    _assert_help(app, "RADT-AUDIT-IO", capsys)
    assert audit.writer_status()["writer_error_count"] == 1


@pytest.mark.parametrize("stage", ["setup", "render_panel", "render_sidebar", "discover"])
def test_plugin_records_and_discovery_warnings_omit_payload(stage, monkeypatch):
    registry = PluginRegistry()

    class BrokenStringError(RuntimeError):
        def __str__(self):
            raise AssertionError("The third-party exception must never be stringified")

    def fail(*_args):
        raise BrokenStringError(PAYLOAD)

    if stage == "discover":
        class EntryPoint:
            name = "sample_ep"
            load = fail
        monkeypatch.setattr("role_aware_dashboard_toolkit.plugins._iter_entry_points",
                            lambda group: [EntryPoint()] if group.endswith("panels") else [])
        with pytest.warns(RuntimeWarning) as captured:
            registry.discover(allow_untrusted=True)
        records = registry.discovery_errors()
        assert "SECRET-DO-NOT-LEAK" not in str(captured[0].message)
        assert "RADT-PLUGIN" in str(captured[0].message)
    else:
        registry.register(DashboardPlugin(name="sample-plugin", **{stage: fail}))
        records = (registry.initialize({}) if stage == "setup" else
                   registry.render_panels({}) if stage == "render_panel" else registry.render_sidebar({}))
    assert len(records) == 1
    record = records[0]
    assert record.exception_type == "BrokenStringError"
    assert record.stage == stage
    serialized = json.dumps(record.to_dict()) + str(record)
    assert "SECRET-DO-NOT-LEAK" not in serialized
    assert "credential.json" not in serialized
    assert record.to_dict()["diagnostic"] == build_diagnostic("RADT-PLUGIN")
    record.diagnostic["effect"] = "mutated"
    assert record.diagnostic["effect"] == build_diagnostic("RADT-PLUGIN")["effect"]


def test_generated_plugin_identity_is_bounded_and_local_paths_are_redacted():
    registry = PluginRegistry()

    def fail(_context):
        raise RuntimeError(PAYLOAD)

    registry.register(DashboardPlugin(name="C:/private/plugin.py", render_panel=fail))
    registry.register(DashboardPlugin(name="long-" + "x" * 500, render_panel=fail))
    registry.register(DashboardPlugin(name="control-\x00\x1bcharacters", render_panel=fail))
    records = registry.render_panels({})
    assert all(len(record.plugin_name) <= 160 and len(record.source) <= 160 for record in records)
    assert "C:/private" not in json.dumps([record.to_dict() for record in records])
    assert all(record.plugin_name.isprintable() and record.source.isprintable() for record in records)
    # Existing positional constructor remains available to callers.
    record = PluginErrorRecord("name", "setup", "source", "RuntimeError", "caller-owned detail")
    assert record.message == "caller-owned detail"
    assert "caller-owned detail" not in str(record)
    assert "RADT-PLUGIN" in str(record)


def test_core_only_missing_streamlit_exception_has_usable_installed_help(tmp_path):
    package_root = Path(__file__).resolve().parents[1]
    environment = {**os.environ, "PYTHONPATH": str(package_root), "PYTHONDONTWRITEBYTECODE": "1"}
    code = """
import json
from role_aware_dashboard_toolkit import DashboardConfig, render
try:
    render(DashboardConfig())
except ModuleNotFoundError as exc:
    print(json.dumps({'message': str(exc), 'name': exc.name, 'diagnostic': exc.diagnostic}))
else:
    raise AssertionError('Expected missing optional Streamlit')
"""
    result = subprocess.run([sys.executable, "-B", "-S", "-c", code], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["name"] == "streamlit"
    assert payload["diagnostic"] == build_diagnostic("RADT-STREAMLIT")
    assert diagnostic_text("RADT-STREAMLIT") in payload["message"]
    assert result.stderr == ""
