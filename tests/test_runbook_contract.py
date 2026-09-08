from pathlib import Path
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import (
    AuditLog,
    ControlRegistry,
    FileRunStore,
    InMemoryRunStore,
    append_checkpoint,
    build_replay_packet_from_checkpoint,
    build_run,
    compare_checkpoints,
    compare_runs,
    end_run,
)
from role_aware_dashboard_toolkit.case_store import InMemoryCaseStore
from role_aware_dashboard_toolkit.checkpoints import build_checkpoint, build_dashboard_snapshot
from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.replay import apply_replay_packet
from role_aware_dashboard_toolkit.runbook_panels import render_runbook_panel, render_runbook_sidebar
from role_aware_dashboard_toolkit.runbook_panels_parts import shared as runbook_shared
from role_aware_dashboard_toolkit.runbook_panels_parts.caseboard import _render_caseboard_panel
from role_aware_dashboard_toolkit.runbook_panels_parts.operator_memory import _render_operator_memory_panel, _render_operator_memory_sidebar
from role_aware_dashboard_toolkit.security import BUILTIN_ROLES, make_security_context


class _FakeContext:
    def __init__(self, st):
        self._st = st

    def __enter__(self):
        return self._st

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeStreamlit:
    def __init__(self, *, button_returns=None, session_state=None):
        self.button_returns = dict(button_returns or {})
        self.events = []
        self.session_state = dict(session_state or {})

    def divider(self):
        self.events.append(("divider",))

    def expander(self, label, expanded=False):
        self.events.append(("expander", str(label), bool(expanded)))
        return _FakeContext(self)

    def caption(self, value):
        self.events.append(("caption", str(value)))

    def subheader(self, value):
        self.events.append(("subheader", str(value)))

    def json(self, value):
        self.events.append(("json", value))

    def write(self, value):
        self.events.append(("write", str(value)))

    def dataframe(self, value, **kwargs):
        self.events.append(("dataframe", value, dict(kwargs)))

    def columns(self, count):
        self.events.append(("columns", int(count)))
        return [_FakeContext(self) for _ in range(int(count))]

    def text_input(self, label, key=None, value="", **kwargs):
        if key and key not in self.session_state:
            self.session_state[key] = value
        result = self.session_state.get(key, value) if key else value
        self.events.append(("text_input", str(label), result, str(key or "")))
        return result

    def text_area(self, label, key=None, value="", **kwargs):
        if key and key not in self.session_state:
            self.session_state[key] = value
        result = self.session_state.get(key, value) if key else value
        self.events.append(("text_area", str(label), result, str(key or "")))
        return result

    def selectbox(self, label, options, index=0, key=None, **kwargs):
        values = list(options or [])
        current = self.session_state.get(key) if key else None
        if current not in values:
            current = values[index] if values else None
        if key:
            self.session_state[key] = current
        self.events.append(("selectbox", str(label), current, str(key or "")))
        return current

    def multiselect(self, label, options, default=None, key=None, **kwargs):
        values = list(options or [])
        current = self.session_state.get(key) if key else list(default or [])
        current = [item for item in list(current or []) if item in values]
        if key:
            self.session_state[key] = current
        self.events.append(("multiselect", str(label), current, str(key or "")))
        return current

    def button(self, label, key=None, disabled=False, **kwargs):
        self.events.append(("button", str(label), str(key or ""), bool(disabled)))
        if disabled:
            return False
        return bool(self.button_returns.get(key, self.button_returns.get(label, False)))

    def toast(self, value):
        self.events.append(("toast", str(value)))

    def rerun(self):
        self.events.append(("rerun",))


def _admin_ctx():
    role = BUILTIN_ROLES["Admin"]
    return make_security_context(role.name, dict(role.perms))


def _limited_ctx():
    return make_security_context(
        "Limited",
        {
            "can_edit_controls": False,
            "can_manage_runs": False,
            "can_approve_changes": False,
            "can_replay_runs": False,
            "can_comment_runs": False,
            "can_view_team_ops": False,
        },
    )


def _runbook_config(store, registry=None, **overrides):
    values = {
        "title": "Runbook Test",
        "version": "test-version",
        "runbook_title": "Runbook",
        "registry": registry or ControlRegistry(),
        "run_store": store,
        "audit": AuditLog(),
        "team_store": None,
        "decision_store": None,
        "operator_memory_store": None,
        "case_store": None,
        "governance_store": None,
        "timeline_title": "Incident Timeline",
        "caseboard_title": "Caseboard",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _event_labels(st, kind):
    return [event[1] for event in st.events if event and event[0] == kind]


def _button_event(st, key):
    return next(event for event in st.events if event[0] == "button" and event[2] == key)


def test_run_store_round_trip_and_status_flow():
    reg = ControlRegistry()
    reg.register("Temperature", kind="slider", key="temperature", default=0.7, min_value=0.0, max_value=2.0, step=0.1)
    reg.register("Mode", kind="select", key="mode", options=["fast", "safe"], default="safe")

    store = InMemoryRunStore()
    run = build_run(reg.snapshot({"temperature": 0.8, "mode": "safe"}), role="Operator", tags=["demo", "demo"])
    assert run["status"] == "active"
    assert run["tags"] == ["demo"]

    run = append_checkpoint(
        run,
        {"temperature": 0.9, "mode": "fast"},
        label="checkpoint 1",
        reason="raised temperature",
        approval_state="approved",
        role="Admin",
        telemetry={"latency_ms": 120},
    )
    assert run["last_checkpoint_id"]
    assert len(run["checkpoints"]) == 1

    store.save(run)
    loaded = store.load(run["run_id"])
    assert loaded is not None
    assert loaded["checkpoints"][0]["approval_state"] == "approved"

    finished = end_run(loaded, outcome="stable", status="completed")
    assert finished["status"] == "completed"
    assert finished["ended_at"]


def test_build_run_detaches_input_and_keeps_control_snapshots_independent():
    controls = {"policy": {"thresholds": [1, 2]}}

    run = build_run(controls, run_id="run-detached")
    controls["policy"]["thresholds"].append(3)
    run["latest_controls"]["policy"]["thresholds"].append(4)

    assert run["initial_controls"] == {"policy": {"thresholds": [1, 2]}}
    assert run["latest_controls"] == {"policy": {"thresholds": [1, 2, 4]}}


def test_build_checkpoint_detaches_controls_audit_and_telemetry():
    controls = {"policy": {"thresholds": [1, 2]}}
    audit_events = [{"details": {"result": "accepted"}}]
    telemetry = {"metrics": {"latency_ms": [10, 20]}}

    checkpoint = build_checkpoint(
        controls,
        checkpoint_id="checkpoint-detached",
        audit_events=audit_events,
        telemetry=telemetry,
    )
    controls["policy"]["thresholds"].append(3)
    audit_events[0]["details"]["result"] = "changed"
    telemetry["metrics"]["latency_ms"].append(30)
    checkpoint["controls"]["policy"]["thresholds"].append(4)

    assert controls == {"policy": {"thresholds": [1, 2, 3]}}
    assert checkpoint["controls"] == {"policy": {"thresholds": [1, 2, 4]}}
    assert checkpoint["audit_slice"] == [{"details": {"result": "accepted"}}]
    assert checkpoint["telemetry_slice"] == {"metrics": {"latency_ms": [10, 20]}}


def test_append_checkpoint_returns_a_record_detached_from_prior_versions():
    prior = build_run({"policy": {"thresholds": [1]}}, run_id="run-append-detached")
    controls = {"policy": {"thresholds": [2]}}
    audit_events = [{"details": {"result": "accepted"}}]

    updated = append_checkpoint(prior, controls, audit_events=audit_events)
    updated["initial_controls"]["policy"]["thresholds"].append(9)
    assert prior["initial_controls"] == {"policy": {"thresholds": [1]}}
    prior["initial_controls"]["policy"]["thresholds"].append(8)
    controls["policy"]["thresholds"].append(7)
    audit_events[0]["details"]["result"] = "changed"

    assert updated["initial_controls"] == {"policy": {"thresholds": [1, 9]}}
    assert updated["latest_controls"] == {"policy": {"thresholds": [2]}}
    assert updated["checkpoints"][0]["controls"] == {"policy": {"thresholds": [2]}}
    assert updated["checkpoints"][0]["audit_slice"] == [{"details": {"result": "accepted"}}]


def test_end_run_returns_a_record_detached_from_the_active_run():
    active = build_run({"policy": {"thresholds": [1]}}, run_id="run-end-detached")
    active = append_checkpoint(
        active,
        {"policy": {"thresholds": [2]}},
        audit_events=[{"details": {"result": "accepted"}}],
    )

    finished = end_run(active, outcome="stable")
    finished["checkpoints"][0]["audit_slice"][0]["details"]["result"] = "changed"
    active["latest_controls"]["policy"]["thresholds"].append(3)

    assert active["checkpoints"][0]["audit_slice"][0]["details"]["result"] == "accepted"
    assert finished["latest_controls"] == {"policy": {"thresholds": [2]}}


def test_dashboard_snapshot_detaches_visible_and_restore_control_values():
    controls = {
        "policy": {"thresholds": [1, 2]},
        "api_token": {"value": "secret"},
    }

    snapshot = build_dashboard_snapshot(controls, redact_keys=["api_token"])
    controls["policy"]["thresholds"].append(3)
    snapshot["controls"]["policy"]["thresholds"].append(4)

    assert controls["policy"] == {"thresholds": [1, 2, 3]}
    assert snapshot["controls"]["policy"] == {"thresholds": [1, 2, 4]}
    assert snapshot["restore_payload"]["controls"]["policy"] == {"thresholds": [1, 2]}
    assert "api_token" not in snapshot["restore_payload"]["controls"]


def test_file_run_store_direct_load_records_corrupt_json_read_errors(tmp_path):
    store = FileRunStore(str(tmp_path / "runs"))
    path = store.save(build_run({"mode": "safe"}, run_id="broken", role="Operator"))
    Path(path).write_text("{not json", encoding="utf-8")

    assert store.load("broken") is None
    assert store.read_errors
    assert store.read_errors[0]["path"].endswith(Path(path).name)
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"


def test_compare_and_replay_helpers_are_checkpoint_grounded():
    left = build_run({"temperature": 0.7, "mode": "safe"}, run_id="run_a", role="Operator")
    left = append_checkpoint(left, {"temperature": 0.8, "mode": "safe"}, label="A1", approval_state="proposed")

    right = build_run({"temperature": 0.7, "mode": "safe"}, run_id="run_b", role="Admin")
    right = append_checkpoint(right, {"temperature": 1.1, "mode": "fast"}, label="B1", approval_state="approved")

    run_cmp = compare_runs(left, right)
    assert "temperature" in run_cmp["control_diff"]
    assert run_cmp["left_run"]["run_id"] == "run_a"
    assert run_cmp["right_run"]["run_id"] == "run_b"

    checkpoint_cmp = compare_checkpoints(left["checkpoints"][0], right["checkpoints"][0])
    assert checkpoint_cmp["approval_transition"] == {"from": "proposed", "to": "approved"}
    assert checkpoint_cmp["control_diff"]["mode"]["to"] == "fast"

    reg = ControlRegistry()
    reg.register("Temperature", kind="slider", key="temperature", default=0.7, min_value=0.0, max_value=2.0, step=0.1)
    reg.register("Mode", kind="select", key="mode", options=["fast", "safe"], default="safe")
    session = {"temperature": 0.7, "mode": "safe"}
    packet = build_replay_packet_from_checkpoint(right["checkpoints"][0])
    applied = apply_replay_packet(packet, reg, session)
    assert applied["applied"] == 2
    assert session["temperature"] == 1.1
    assert session["mode"] == "fast"


def test_file_run_store_rejects_symlink_escape_records(tmp_path):
    store_dir = tmp_path / "runs"
    store_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"run_id": "escape"}', encoding="utf-8")
    link = store_dir / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    store = FileRunStore(str(store_dir))
    assert store.list_ids() == []
    assert store.read_errors
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"
    assert "symlinked store record" in store.read_errors[0]["message"]


def test_render_runbook_panel_empty_state_smoke():
    st = _FakeStreamlit()
    config = _runbook_config(InMemoryRunStore())

    render_runbook_panel(st, config, _admin_ctx())

    assert ("caption", "No runs recorded yet.") in st.events
    assert ("expander", "Runbook", False) in st.events


def test_render_table_uses_json_when_pandas_absent(monkeypatch):
    monkeypatch.setattr(runbook_shared, "pd", None)
    monkeypatch.setattr(runbook_shared, "PANDAS_AVAILABLE", False)
    st = _FakeStreamlit()

    runbook_shared._render_table(st, [{"run_id": "run-001"}])

    assert ("json", [{"run_id": "run-001"}]) in st.events
    assert not any(event[0] == "dataframe" for event in st.events)


def test_render_runbook_panel_populated_run_protocol_and_checkpoint_smoke():
    registry = ControlRegistry()
    registry.register("Temperature", kind="slider", key="temperature", default=0.7, min_value=0.0, max_value=2.0, step=0.1)
    registry.register("Mode", kind="select", key="mode", options=["safe", "fast"], default="safe")
    store = InMemoryRunStore()
    run = build_run(registry.snapshot({"temperature": 0.7, "mode": "safe"}), run_id="run-001", role="Operator")
    run = append_checkpoint(
        run,
        registry.snapshot({"temperature": 1.1, "mode": "fast"}),
        label="raise temperature",
        reason="exercise checkpoint timeline",
        approval_state="approved",
        role="Admin",
    )
    store.save(run)
    st = _FakeStreamlit(session_state={"_radt_selected_run_id": "run-001"})

    render_runbook_panel(st, _runbook_config(store, registry=registry), _admin_ctx())

    assert "Recent Runs" in _event_labels(st, "subheader")
    assert "Checkpoint Timeline" in _event_labels(st, "subheader")
    assert "Replay Preview" in _event_labels(st, "subheader")
    assert ("expander", "Protocol Preview", False) in st.events
    assert ("expander", "Checkpoint Packet", False) in st.events
    json_payloads = [event[1] for event in st.events if event and event[0] == "json"]
    assert any(isinstance(payload, dict) and {"run_packet", "ledger_summary"} <= set(payload) for payload in json_payloads)
    assert any(isinstance(payload, dict) and payload.get("source_type") == "checkpoint" for payload in json_payloads)


def test_edit_controls_does_not_imply_checkpoint_replay():
    registry = ControlRegistry()
    registry.register(
        "Mode",
        kind="select",
        key="mode",
        options=["safe", "fast"],
        default="safe",
    )
    store = InMemoryRunStore()
    run = build_run({"mode": "safe"}, run_id="run-no-replay")
    run = append_checkpoint(
        run,
        {"mode": "fast"},
        label="checkpoint",
    )
    store.save(run)
    st = _FakeStreamlit(
        button_returns={"_radt_checkpoint_replay_btn": True},
        session_state={"_radt_selected_run_id": run["run_id"]},
    )
    ctx = make_security_context(
        "Custom",
        {"can_edit_controls": True},
    )

    render_runbook_panel(st, _runbook_config(store, registry=registry), ctx)

    assert not any(
        event[0] == "button" and event[2] == "_radt_checkpoint_replay_btn"
        for event in st.events
    )


def test_render_runbook_sidebar_start_run_action_and_denied_state():
    registry = ControlRegistry()
    registry.register("Mode", kind="select", key="mode", options=["safe", "fast"], default="safe")
    registry.register("API Token", kind="text", key="api_token", default="")
    denied_store = InMemoryRunStore()
    denied_st = _FakeStreamlit(button_returns={"_radt_run_start": True}, session_state={"mode": "safe"})

    render_runbook_sidebar(denied_st, _runbook_config(denied_store, registry=registry), _limited_ctx())

    assert not any(event[0] == "button" for event in denied_st.events)
    assert denied_store.list_ids() == []

    store = InMemoryRunStore()
    st = _FakeStreamlit(
        button_returns={"_radt_run_start": True},
        session_state={"_radt_user_id": "operator-1", "_radt_run_notes": "start notes", "_radt_run_tags": "alpha, alpha, beta", "mode": "fast"},
    )
    st.session_state["api_token"] = "top-secret"
    config = _runbook_config(store, registry=registry)

    render_runbook_sidebar(st, config, _admin_ctx())

    run_ids = store.list_ids()
    assert len(run_ids) == 1
    started = store.load(run_ids[0])
    assert started["latest_controls"]["mode"] == "fast"
    assert "api_token" not in started["latest_controls"]
    assert started["tags"] == ["alpha", "beta"]
    assert st.session_state["_radt_active_run_id"] == started["run_id"]
    assert config.audit.recent(1)[0]["type"] == "run_start"
    assert ("rerun",) in st.events


def test_edit_controls_does_not_imply_run_management():
    registry = ControlRegistry()
    registry.register("Mode", kind="select", key="mode", options=["safe", "fast"], default="safe")
    store = InMemoryRunStore()
    st = _FakeStreamlit(
        button_returns={"_radt_run_start": True},
        session_state={"mode": "safe"},
    )
    ctx = make_security_context(
        "Custom",
        {"can_edit_controls": True},
    )

    render_runbook_sidebar(st, _runbook_config(store, registry=registry), ctx)

    assert not any(event[0] == "button" for event in st.events)
    assert store.list_ids() == []


def test_render_runbook_sidebar_checkpoint_action():
    registry = ControlRegistry()
    registry.register("Temperature", kind="slider", key="temperature", default=0.7, min_value=0.0, max_value=2.0, step=0.1)
    store = InMemoryRunStore()
    run = build_run(registry.snapshot({"temperature": 0.7}), run_id="run-checkpoint", role="Operator")
    store.save(run)
    st = _FakeStreamlit(
        button_returns={"_radt_run_checkpoint": True},
        session_state={
            "_radt_active_run_id": "run-checkpoint",
            "_radt_checkpoint_label": "manual check",
            "_radt_checkpoint_reason": "operator checkpoint",
            "_radt_user_id": "operator-1",
            "temperature": 1.2,
        },
    )
    config = _runbook_config(store, registry=registry)

    render_runbook_sidebar(st, config, _admin_ctx())

    updated = store.load("run-checkpoint")
    assert len(updated["checkpoints"]) == 1
    assert updated["checkpoints"][0]["label"] == "manual check"
    assert updated["checkpoints"][0]["controls"]["temperature"] == 1.2
    assert config.audit.recent(1)[0]["type"] == "checkpoint_create"
    assert ("rerun",) in st.events


def test_render_runbook_sidebar_end_run_action():
    registry = ControlRegistry()
    registry.register("Mode", kind="select", key="mode", options=["safe", "fast"], default="safe")
    store = InMemoryRunStore()
    run = build_run(registry.snapshot({"mode": "safe"}), run_id="run-end", role="Operator")
    store.save(run)
    st = _FakeStreamlit(
        button_returns={"_radt_run_end": True},
        session_state={"_radt_active_run_id": "run-end", "_radt_run_outcome": "stable", "_radt_run_notes": "closeout"},
    )
    config = _runbook_config(store, registry=registry)

    render_runbook_sidebar(st, config, _admin_ctx())

    finished = store.load("run-end")
    assert finished["status"] == "completed"
    assert finished["outcome"] == "stable"
    assert st.session_state["_radt_active_run_id"] == ""
    assert config.audit.recent(1)[0]["type"] == "run_end"
    assert ("rerun",) in st.events


def test_operator_memory_subpanel_render_and_save_paths():
    registry = ControlRegistry()
    registry.register("Mode", kind="select", key="mode", options=["safe", "fast"], default="safe")
    memory_store = InMemoryOperatorMemoryStore()
    run = build_run(registry.snapshot({"mode": "safe"}), run_id="run-memory", role="Operator")
    run = append_checkpoint(run, registry.snapshot({"mode": "fast"}), label="memory checkpoint", role="Admin")
    checkpoint = run["checkpoints"][0]
    config = _runbook_config(InMemoryRunStore(), registry=registry, operator_memory_store=memory_store)
    note_sidebar_st = _FakeStreamlit(
        button_returns={"_radt_operator_note_btn": True},
        session_state={
            "_radt_user_id": "operator-1",
            "_radt_operator_note_body": "Shift handoff note",
            "_radt_operator_note_type": "note",
            "_radt_incident_title": "Unexpected latency",
            "_radt_incident_summary": "Latency jumped during the run.",
            "_radt_incident_cause": "Load spike",
            "_radt_incident_severity": "high",
        },
    )
    incident_sidebar_st = _FakeStreamlit(
        button_returns={"_radt_operator_incident_btn": True},
        session_state={
            "_radt_user_id": "operator-1",
            "_radt_operator_note_body": "Shift handoff note",
            "_radt_operator_note_type": "note",
            "_radt_incident_title": "Unexpected latency",
            "_radt_incident_summary": "Latency jumped during the run.",
            "_radt_incident_cause": "Load spike",
            "_radt_incident_severity": "high",
        },
    )

    _render_operator_memory_sidebar(note_sidebar_st, config, _admin_ctx(), run)
    assert ("rerun",) in note_sidebar_st.events
    notes = memory_store.list_notes("run-memory", checkpoint_id=run["last_checkpoint_id"])
    incidents = memory_store.list_incidents("run-memory")
    assert len(notes) == 1
    assert len(incidents) == 0

    _render_operator_memory_sidebar(incident_sidebar_st, config, _admin_ctx(), run)
    assert ("rerun",) in incident_sidebar_st.events
    notes = memory_store.list_notes("run-memory", checkpoint_id=run["last_checkpoint_id"])
    incidents = memory_store.list_incidents("run-memory")
    assert len(notes) == 1
    assert notes[0]["body"] == "Shift handoff note"
    assert len(incidents) == 1
    assert incidents[0]["title"] == "Unexpected latency"
    assert {event["type"] for event in config.audit.recent(5)} >= {"operator_note", "incident_open"}

    panel_st = _FakeStreamlit(
        button_returns={f"_radt_save_narrative_{run['run_id']}": True},
        session_state={"_radt_user_id": "operator-1", "_radt_handoff_to": "next-shift"},
    )

    _render_operator_memory_panel(panel_st, config, _admin_ctx(), run, checkpoint)

    assert "Incident Timeline" in _event_labels(panel_st, "subheader")
    assert ("expander", "Timeline events", False) in panel_st.events
    assert ("expander", "Operator notes", False) in panel_st.events
    assert ("expander", "Incidents", False) in panel_st.events
    assert ("expander", "Narrative handoff packet", False) in panel_st.events
    narratives = memory_store.list_narratives("run-memory", checkpoint_id=run["last_checkpoint_id"])
    assert len(narratives) == 1
    assert config.audit.recent(1)[0]["type"] == "narrative_handoff_save"


def test_caseboard_subpanel_create_and_render_paths():
    registry = ControlRegistry()
    registry.register("Mode", kind="select", key="mode", options=["safe", "fast"], default="safe")
    case_store = InMemoryCaseStore()
    memory_store = InMemoryOperatorMemoryStore()
    run = build_run(registry.snapshot({"mode": "safe"}), run_id="run-case", role="Operator")
    config = _runbook_config(
        InMemoryRunStore(),
        registry=registry,
        operator_memory_store=memory_store,
        case_store=case_store,
    )
    create_st = _FakeStreamlit(
        button_returns={"_radt_case_create_btn": True},
        session_state={
            "_radt_user_id": "operator-1",
            "_radt_case_title": "Release blocker",
            "_radt_case_summary": "Investigate the release blocker.",
            "_radt_case_priority": "high",
            "_radt_case_run_ids": ["run-case"],
            "_radt_case_note_body": "Finding captured from the run.",
        },
    )

    _render_caseboard_panel(create_st, config, _admin_ctx(), [run], run)

    cases = case_store.list_cases()
    assert len(cases) == 1
    assert cases[0]["title"] == "Release blocker"
    assert cases[0]["linked_run_ids"] == ["run-case"]
    assert config.audit.recent(1)[0]["type"] == "case_create"

    render_st = _FakeStreamlit(session_state={"_radt_selected_case_id": cases[0]["case_id"]})
    _render_caseboard_panel(render_st, config, _admin_ctx(), [run], run)

    assert "Caseboard" in _event_labels(render_st, "subheader")
    assert ("expander", "Cases", False) in render_st.events
    assert ("expander", "Case record", False) in render_st.events
    assert any(
        isinstance(payload, dict) and payload.get("case_count") == 1
        for payload in [event[1] for event in render_st.events if event and event[0] == "json"]
    )
