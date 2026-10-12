"""Current sensitivity follows historical evidence through native output paths."""
from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import (
    AuditLog, ControlRegistry, InMemoryRunStore, append_checkpoint, build_run,
)
from role_aware_dashboard_toolkit._record_projection import (
    preserve_sensitivity_metadata, project_audit_events, project_record,
)
from role_aware_dashboard_toolkit._ui_state import protect_native_controls, stage_replay
from role_aware_dashboard_toolkit.dashboard_panels import render_audit_panel
from role_aware_dashboard_toolkit.decision_store import InMemoryDecisionStore
from role_aware_dashboard_toolkit.decisions import build_decision_case_from_run
from role_aware_dashboard_toolkit.runbook_panels import render_runbook_panel
from role_aware_dashboard_toolkit.observability import ObservabilityConfig, ObservabilityPanel
from role_aware_dashboard_toolkit.security import BUILTIN_ROLES, SecurityContext
from role_aware_dashboard_toolkit.team_ops import build_handoff_summary
from role_aware_dashboard_toolkit.team_store import InMemoryTeamStore
from tests.test_authenticated_ui import _healthy, _host
from tests.test_runbook_contract import _FakeContext, _FakeStreamlit, _runbook_config


MARKER = "SYNTHETIC-HISTORICAL-CONNECTION-CREDENTIAL"


def _registry(*, sensitive=True):
    registry = ControlRegistry()
    registry.register("Connection", kind="text", key="connection", default="", sensitive=sensitive)
    registry.register("Public setting", kind="text", key="public_setting", default="safe")
    return registry


def _context(role="Admin"):
    return SecurityContext(
        role=role, perms=dict(BUILTIN_ROLES[role].perms), authenticated=True,
        user_id="a" * 64, session_id="b" * 32,
        _authorize=lambda permission, writing: True,
    )


@pytest.mark.parametrize("historical", [False, True])
def test_projection_keeps_current_and_historical_sensitivity_across_record_shapes(historical):
    registry = _registry(sensitive=not historical)
    registry.register("Token count", kind="number", key="token_count", default=10, sensitive=False)
    value = {
        "control_meta": [{"key": "connection", "sensitive": historical, "default": MARKER}],
        "controls": {"connection": MARKER, "public_setting": "safe", "token_count": 10},
        "initial_controls": {"connection": MARKER},
        "summary": {"latest_controls": {"connection": MARKER}},
        "control_diff": {"connection": {"from": MARKER, "to": "other"}},
        "audit_slice": [{"type": "control_change", "key": "connection", "old": MARKER, "new": MARKER}],
        "recent_changes": [{"control": "connection", "new": MARKER}],
        "extension": {"safe": "kept", "nested": [{"password": MARKER}]},
    }
    before = deepcopy(value)

    projected = project_record(value, registry)

    assert MARKER not in json.dumps(projected)
    assert projected["controls"]["public_setting"] == "safe"
    assert projected["controls"]["token_count"] == 10
    assert projected["extension"]["safe"] == "kept"
    assert value == before


def test_projection_does_not_treat_a_control_name_as_record_structure():
    registry = ControlRegistry()
    registry.register("Private value", kind="text", key="controls", default=MARKER, sensitive=True)
    projected = project_record({"controls": {"controls": MARKER}, "source": "ui"}, registry)
    assert projected == {"controls": {"controls": "<redacted-secret>"}, "source": "ui"}


@pytest.mark.parametrize("event_type", [" CONTROL_CHANGE ", "malformed", "extension"])
def test_audit_keyed_values_are_protected_independently_of_type_normalization(event_type):
    event = {"type": event_type, "original_type": "control_change", "key": "connection",
             "old": MARKER, "new": MARKER}
    assert MARKER not in json.dumps(project_audit_events([event], _registry()))


def test_derived_sensitivity_metadata_is_minimal_detached_and_durable():
    source = {"control_meta": [{"key": "connection", "sensitive": True, "default": MARKER}]}
    record = {"summary": {"latest_controls": {"connection": MARKER}}}
    derived = preserve_sensitivity_metadata(record, source)
    assert derived["control_meta"] == [{"key": "connection", "sensitive": True}]
    assert MARKER not in json.dumps(project_record(derived, _registry(sensitive=False)))
    assert "control_meta" not in record


class _AuditCapture(_FakeStreamlit):
    def columns(self, count):
        return [_FakeContext(self) for _ in range(count if isinstance(count, int) else len(count))]

    def number_input(self, label, value=0, **kwargs):
        return value

    def download_button(self, label, data, filename, mime, **kwargs):
        self.events.append(("download", filename, data))

    def info(self, value):
        self.events.append(("info", str(value)))


def test_native_audit_downloads_timeline_and_replay_redact_without_rewriting_events():
    registry = _registry()
    audit = AuditLog()
    audit.log_control_change("connection", MARKER, MARKER)
    audit.log_control_change("public_setting", "old", "safe")
    before = audit.all_events()
    st = _AuditCapture()

    render_audit_panel(st, audit, _context("Viewer"), registry=registry)

    assert MARKER not in repr(st.events)
    downloads = {event[1]: event[2] for event in st.events if event[0] == "download"}
    assert set(downloads) == {"audit.csv", "audit.jsonl"}
    assert all("safe" in payload for payload in downloads.values())
    assert audit.all_events() == before
    assert MARKER in audit.export_jsonl(), "Raw host APIs retain stored evidence."
    assert MARKER not in json.dumps(project_audit_events(before, registry))


@pytest.mark.parametrize("nested", [False, True])
def test_native_observability_redacts_retained_nested_fields_and_empty_public_metric_fallback(nested):
    state = {}
    metrics = {"password": {"value": 7654321}, "throughput": 3} if nested else {"password": 7654321}
    sample = {"metrics": metrics, "labels": {"password": MARKER}}
    panel = ObservabilityPanel(ObservabilityConfig(telemetry_hook=lambda: sample), AuditLog(), state)
    st = _FakeStreamlit()
    panel.render(st)
    assert MARKER not in repr(st.events)
    assert "7654321" not in repr(st.events)
    assert state["_radt_last_telemetry"]["labels"]["password"] == MARKER
    if nested:
        assert state["_radt_last_telemetry"]["metrics"]["value"] == 7654321
        assert any(event[0] == "json" and event[1].get("latest") == {"throughput": 3}
                   for event in st.events)
    else:
        assert state["_radt_last_telemetry"]["metrics"]["password"] == 7654321


@pytest.mark.parametrize("role", ["Viewer", "Admin"])
@pytest.mark.parametrize("historical", [False, True])
def test_native_run_records_comparisons_packets_and_saved_summaries_redact(role, historical):
    registry = _registry(sensitive=not historical)
    run = build_run({"connection": MARKER, "public_setting": "first"}, run_id="first")
    run = append_checkpoint(run, {"connection": MARKER, "public_setting": "first"})
    run = append_checkpoint(run, {"connection": MARKER + "2", "public_setting": "second"})
    if historical:
        run["control_meta"] = [{"key": "connection", "sensitive": True}]
    other = append_checkpoint(build_run({"connection": MARKER}, run_id="second"), {"connection": MARKER})
    if historical:
        other["control_meta"] = deepcopy(run["control_meta"])
    runs = InMemoryRunStore()
    runs.save(run)
    runs.save(other)
    teams = InMemoryTeamStore()
    handoff = build_handoff_summary(run)
    decisions = InMemoryDecisionStore()
    decision = build_decision_case_from_run(run, checkpoint=run["checkpoints"][0])
    # Legacy derived records did not retain their source classification. The
    # native view must consult its already-authorized source evidence too.
    teams.save_handoff(handoff)
    decisions.save(decision)
    config = _runbook_config(runs, registry=registry, team_store=teams, decision_store=decisions)
    before = deepcopy((runs.load("first"), teams.list_handoffs(), decisions.list_by_run("first")))
    st = _FakeStreamlit(session_state={"_radt_selected_run_id": "first"})

    render_runbook_panel(st, config, _context(role))

    assert MARKER not in repr(st.events)
    assert "second" in repr(st.events), "Ordinary evidence remains available."
    outputs = [event[1] for event in st.events if event[0] == "json"]
    assert any("left_checkpoint_id" in output for output in outputs)
    assert any("left_run" in output for output in outputs)
    assert any("handoff_id" in output for output in outputs)
    assert any("decision_id" in output and "summary" in output for output in outputs)
    if role == "Admin":
        assert any("run_packet" in output for output in outputs)
        assert any(output.get("packet_type") == "checkpoint" for output in outputs)
        assert any(output.get("source_type") == "checkpoint" for output in outputs)
    assert (runs.load("first"), teams.list_handoffs(), decisions.list_by_run("first")) == before


@pytest.mark.parametrize("can_view_metrics", [False, True])
def test_native_checkpoint_and_saved_summary_metadata_require_control_value_read(can_view_metrics):
    registry = ControlRegistry()
    registry.register("Mode", kind="select", key="mode", default=MARKER, options=[MARKER], sensitive=False)
    run = append_checkpoint(build_run({"mode": MARKER}), {"mode": MARKER})
    run["control_meta"] = registry.export_metadata()
    run["checkpoints"][0]["control_meta"] = registry.export_metadata()
    runs = InMemoryRunStore()
    runs.save(run)
    handoff = build_handoff_summary(run)
    handoff["control_meta"] = registry.export_metadata()
    teams = InMemoryTeamStore()
    teams.save_handoff(handoff)
    config = _runbook_config(runs, registry=registry, team_store=teams)
    ctx = _context("Viewer")
    ctx.perms["can_view_metrics"] = can_view_metrics
    ctx.perms["can_view_audit"] = False
    before = deepcopy((runs.load(run["run_id"]), teams.list_handoffs()))
    st = _FakeStreamlit()

    render_runbook_panel(st, config, ctx)

    assert (MARKER in repr(st.events)) is can_view_metrics
    outputs = [event[1] for event in st.events if event[0] == "json"]
    checkpoint = next(output for output in outputs if output.get("checkpoint_id"))
    saved_handoff = next(output for output in outputs if output.get("handoff_id"))
    for view in (checkpoint, saved_handoff):
        assert "control_meta" in view
        assert ("default" in view["control_meta"][0]) is can_view_metrics
        assert ("options" in view["control_meta"][0]) is can_view_metrics
    assert (runs.load(run["run_id"]), teams.list_handoffs()) == before


@pytest.mark.parametrize("historical", [False, True])
def test_native_replay_omits_secret_values_before_text_coercion(historical):
    registry = _registry(sensitive=False)
    value = MARKER if historical else {"password": MARKER}
    packet = {"controls": {"connection": value, "public_setting": "updated"}}
    if historical:
        packet["control_meta"] = [{"key": "connection", "sensitive": True}]
    before = deepcopy(packet)
    state = {"connection": "retained", "public_setting": "safe"}

    staged, result = stage_replay(SimpleNamespace(registry=registry), state, _context(), packet)

    assert MARKER not in repr(staged)
    assert staged == {"public_setting": "updated"}
    assert result["touched_keys"] == ["public_setting"]
    assert state["connection"] == "retained"
    assert packet == before


def test_nested_control_classification_is_session_local_and_survives_text_coercion():
    class CustomRegistry(ControlRegistry):
        pass

    registry = CustomRegistry()
    registry.register("Connection", kind="text", key="connection", default="", sensitive=False)
    registry.register("Token count", kind="number", key="token_count", default=12, sensitive=False)
    registry.register("Region", kind="select", key="region", options=[{"region": "west"}])
    state = {"connection": {"password": MARKER}}
    view = protect_native_controls(registry, state)
    assert isinstance(view, CustomRegistry)
    assert view.get("connection").sensitive
    assert not registry.get("connection").sensitive
    assert not view.get("token_count").sensitive
    assert not view.get("region").sensitive
    state["connection"] = str(state["connection"])
    assert protect_native_controls(registry, state).get("connection").sensitive
    assert protect_native_controls(registry, {}).get("connection").sensitive is False
    from role_aware_dashboard_toolkit.streamlit_auth import clear_authenticated_state
    clear_authenticated_state(SimpleNamespace(session_state=state))
    assert state == {}


def _consumer(host):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    if "config" not in st.session_state:
        st.session_state["config"] = radt.DashboardConfig(
            registry=host.registry, audit=host.audit, access=host.policy,
            run_store=host.runs,
            observability=radt.ObservabilityConfig(enabled=True, telemetry_hook=lambda: {"metrics": {"throughput": 3}}),
            sections=radt.DashboardSections(profiles=False, audit_writer=False, plugin_details=False),
        )
    radt.render(st.session_state["config"])


def test_native_classification_change_hides_all_browser_outputs_and_preserves_evidence():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    host = _host(("Admin",))
    host.registry = _registry(sensitive=False)
    host.runs = InMemoryRunStore()
    host.store.compare_and_set_freeze(False, 0, host.principal)
    app = _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())
    _healthy(app.text_input(key="connection").set_value(MARKER).run())
    _healthy(app.button(key="_radt_run_start").click().run())
    _healthy(app.button(key="_radt_run_checkpoint").click().run())
    assert any(MARKER in item.value for item in app.json)
    host.registry.get("connection").sensitive = True
    host.store.replace_grants(host.principal, ("Viewer",))

    _healthy(app.run())

    outgoing = "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))
    assert MARKER not in outgoing
    assert any("Connection: Hidden" in item.value for item in app.caption)
    assert any(event.get("new") == MARKER for event in host.audit.all_events())
    assert MARKER in json.dumps(host.runs.load(host.runs.list_ids()[0]))


@pytest.mark.parametrize("kind", ["text", "select"])
def test_native_nested_secret_controls_never_serialize_values_or_options(kind):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    host = _host(("Admin",))
    host.registry = ControlRegistry()
    nested = {"settings": [{"password": MARKER}]}
    host.registry.register("Connection", kind=kind, key="connection", default=nested,
                           options=[nested] if kind == "select" else None, sensitive=False)
    host.registry.register("Token count", kind="number", key="token_count", default=12, sensitive=False)
    host.registry.register("Region", kind="select", key="region", options=[{"region": "west"}])
    host.runs = InMemoryRunStore()
    host.store.compare_and_set_freeze(False, 0, host.principal)
    app = _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())
    for _ in range(2):
        outgoing = "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))
        assert MARKER not in outgoing
        replacement = app.text_input(key="_radt_sensitive_replacement__connection")
        assert replacement.value == ""
        assert replacement.proto.type == replacement.proto.PASSWORD
        assert app.number_input(key="token_count").value == 12
        assert "west" in str(app.selectbox(key="region").options)
        _healthy(app.run())
    assert not host.registry.get("connection").sensitive
    _healthy(app.button(key="_radt_run_start").click().run())
    assert MARKER not in json.dumps(host.runs.load(host.runs.list_ids()[0]))
    host.store.replace_grants(host.principal, ("Viewer",))
    _healthy(app.run())
    assert any("Connection: Hidden" in item.value for item in app.caption)
    assert MARKER not in "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))
