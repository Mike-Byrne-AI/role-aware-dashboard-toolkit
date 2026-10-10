"""Malformed stored/imported records fail before consumer state is changed."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit import approvals, caseboard, decisions, governance
from role_aware_dashboard_toolkit import operator_memory, team_ops
from role_aware_dashboard_toolkit.observability import coerce_telemetry_sample
from role_aware_dashboard_toolkit.packets import build_profile_packet
from role_aware_dashboard_toolkit.packet_core import VALID_PACKET_TYPES
from role_aware_dashboard_toolkit.protocol.catalog import get_protocol_schema_version
from role_aware_dashboard_toolkit.profiles import _InvalidProfileError
from role_aware_dashboard_toolkit.validators import VALID_RECORD_TYPES, validate_record


def _registry():
    registry = radt.ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=3,
                      min_value=0, max_value=10, step=1)
    registry.register("Secret", kind="text", key="secret", sensitive=True)
    return registry


def _records():
    run = radt.append_checkpoint(radt.build_run({"workers": 3}), {"workers": 5})
    case = caseboard.build_case_record("Review", linked_run_ids=[run["run_id"]])
    return {
        "profile": radt.build_profile("saved", _registry(), {"workers": 3}),
        "run": run,
        "checkpoint": run["checkpoints"][0],
        "approval": approvals.build_approval_record("proposed"),
        "audit_event": radt.AuditLog().log("review"),
        "telemetry_sample": coerce_telemetry_sample({"latency": 3}),
        "replay_packet": radt.build_replay_packet_from_checkpoint(run["checkpoints"][0]),
        "diff_packet": {"schema_version": 1, "diff_type": "controls", "source_ids": [], "diff": {}},
        "packet": radt.build_run_packet(run),
        "ledger": radt.build_run_ledger(run),
        "comment": team_ops.build_team_comment("Review", run_id=run["run_id"]),
        "assignment": team_ops.build_review_assignment(run["run_id"]),
        "signoff": team_ops.build_signoff_record(run["run_id"], "approved"),
        "handoff": team_ops.build_handoff_summary(run),
        "decision": decisions.build_decision_case(run),
        "operator_note": operator_memory.build_operator_note("Review", run_id=run["run_id"]),
        "incident": operator_memory.build_incident_record(run["run_id"], "Review"),
        "incident_timeline": operator_memory.build_incident_timeline(run),
        "narrative_handoff": operator_memory.build_narrative_handoff_packet(run),
        "case": case,
        "governance": governance.build_governance_record(case),
    }


@pytest.mark.parametrize("record_type", VALID_RECORD_TYPES)
def test_each_declared_record_builder_validates_and_rejects_non_records(record_type):
    assert validate_record(record_type, _records()[record_type])["ok"]
    for invalid in (None, 42, True, "record", [], [1]):
        result = validate_record(record_type, invalid)
        assert not result["ok"]
        assert result["errors"]


def _schema_field_cases():
    cases = []
    for path in sorted((Path(__file__).parents[1] / "schemas").glob("*.schema.json")):
        record_type = {"replay": "replay_packet"}.get(path.name.split(".")[0], path.name.split(".")[0])
        schema = json.loads(path.read_text(encoding="utf-8"))
        for field, definition in schema["properties"].items():
            expected = definition.get("type")
            if expected:
                cases.append(pytest.param(record_type, field, expected, id=f"{record_type}-{field}"))
    return cases


@pytest.mark.parametrize("record_type,field,expected", _schema_field_cases())
def test_runtime_rejects_wrong_types_in_declared_json_schema_fields(record_type, field, expected):
    # The published schemas are independent of the runtime's field-shape table.
    samples = {"integer": 42, "string": "canary", "array": [], "object": {}}
    for wrong_type, value in samples.items():
        if wrong_type == expected:
            continue
        record = deepcopy(_records()[record_type])
        record[field] = value
        result = validate_record(record_type, record)
        assert not result["ok"], (record_type, field, wrong_type)
        assert any(field in error for error in result["errors"])
    record = deepcopy(_records()[record_type])
    record[field] = None
    assert not validate_record(record_type, record)["ok"]


@pytest.mark.parametrize("record_type,field", [
    ("profile", "values"), ("profile", "control_meta"), ("profile", "extra"),
    ("run", "initial_controls"), ("run", "latest_controls"),
    ("decision", "history"), ("governance", "policy_checks"), ("case", "history"),
])
@pytest.mark.parametrize("invalid", [None, 42, True, "private-canary"])
def test_core_shapes_fail_structurally_without_conversion_crashes(record_type, field, invalid):
    record = _records()[record_type]
    record[field] = invalid
    result = validate_record(record_type, record)
    assert not result["ok"]
    assert any(field in error for error in result["errors"])


@pytest.mark.parametrize("record_type,field", [
    ("profile", "control_meta"), ("run", "checkpoints"),
    ("checkpoint", "audit_slice"), ("decision", "history"),
    ("governance", "policy_checks"), ("case", "history"),
    ("incident_timeline", "events"), ("ledger", "entries"),
])
def test_record_lists_reject_scalar_members(record_type, field):
    record = _records()[record_type]
    record[field] = [42]
    result = validate_record(record_type, record)
    assert not result["ok"]
    assert any(f"{field}[0]" in error for error in result["errors"])


def test_nested_checkpoint_controls_are_checked_by_record_and_packet_boundaries():
    run = _records()["run"]
    run["checkpoints"][0]["controls"] = 42
    assert not validate_record("run", run)["ok"]
    with pytest.raises(ValueError, match="controls"):
        radt.export_packet_json(radt.build_run_packet(run))


@pytest.mark.parametrize("nested_type,field", [("approval", "state"), ("approval", "ts"),
                                              ("audit_event", "type"), ("audit_event", "ts"),
                                              ("audit_event", "source")])
def test_nested_known_records_check_present_scalar_fields(nested_type, field):
    run = _records()["run"]
    checkpoint = run["checkpoints"][0]
    if nested_type == "approval":
        checkpoint["approval"][field] = 42
    else:
        checkpoint["audit_slice"] = [{field: 42}]
    assert not validate_record("run", run)["ok"]
    with pytest.raises(ValueError, match=field):
        radt.export_packet_json(radt.build_run_packet(run))


@pytest.mark.parametrize("field,invalid", [
    ("values", 42), ("values", [["workers", 8]]), ("values", "canary"),
    ("extra", [1]), ("diff_from_parent", False), ("control_meta", [42]),
])
def test_profile_load_validates_before_any_mutation_and_reports_safe_errors(field, invalid):
    registry = _registry()
    store = radt.InMemoryProfileStore()
    profile = radt.build_profile("saved", registry, {"workers": 8})
    profile[field] = invalid
    store.save(profile)
    before_record = store.load("saved")
    state = {"workers": 3, "secret": "live-secret", "other": "retained"}
    before = deepcopy(state)
    with pytest.raises(_InvalidProfileError) as caught:
        radt.load_profile("saved", registry, state, store=store)
    assert state == before
    assert store.load("saved") == before_record
    assert caught.value.errors
    assert "canary" not in str(caught.value)
    assert "live-secret" not in str(caught.value.errors)


@pytest.mark.parametrize("profile", [{}, {"values": {"workers": 8}},
                                   {"schema_version": 1, "values": {"workers": 8}},
                                   {"values": None, "control_meta": None, "extra": None}])
def test_native_profile_loading_retains_legacy_missing_and_null_metadata(profile):
    store = radt.InMemoryProfileStore()
    store.save({**profile, "profile_id": "legacy"})
    state = {"workers": 3, "secret": "live-secret"}
    assert radt.load_profile("legacy", _registry(), state, store=store) is not None
    assert state["workers"] == ((profile.get("values") or {}).get("workers", 3))
    assert state["secret"] == "live-secret"


def test_sanitation_failure_is_atomic_for_direct_profile_callers(monkeypatch):
    registry = _registry()
    store = radt.InMemoryProfileStore()
    store.save({"profile_id": "saved", "values": {"workers": 8}})
    state = {"workers": 3, "secret": "live-secret"}
    def failed_sanitize(staged):
        raise ValueError("unexpected registry failure")
    monkeypatch.setattr(registry, "sanitize_session_state", failed_sanitize)
    with pytest.raises(ValueError, match="unexpected registry failure"):
        radt.load_profile("saved", registry, state, store=store)
    assert state == {"workers": 3, "secret": "live-secret"}


def test_malformed_profile_packet_is_rejected_on_import_and_export():
    profile = _records()["profile"]
    profile["values"] = 42
    packet = build_profile_packet(profile)
    with pytest.raises(ValueError, match="values"):
        radt.export_packet_json(packet)
    with pytest.raises(ValueError, match="values"):
        radt.load_packet_json(json.dumps(packet))
    # Partial legacy envelopes and application-owned extension fields still work.
    radt.export_packet_json(radt.build_packet("run", {"schema_version": 1}))
    radt.export_packet_json(radt.build_packet("x_custom", {"schema_version": 1, "values": 42}))


@pytest.mark.parametrize("packet_type", VALID_PACKET_TYPES)
def test_each_builtin_packet_retains_partial_envelope_compatibility(packet_type):
    payload = {"schema_version": get_protocol_schema_version(packet_type)}
    packet = radt.build_packet(packet_type, payload)
    assert validate_record("packet", packet)["ok"]
    assert radt.load_packet_json(radt.export_packet_json(packet))["payload"] == payload
    # A partial envelope does not make its payload a complete current record.
    if packet_type in VALID_RECORD_TYPES:
        assert not validate_record(packet_type, payload)["ok"]


def test_api_rejects_malformed_profile_reads_and_activation_without_success_events(monkeypatch):
    pytest.importorskip("fastapi")
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "test-only-key")
    store = radt.InMemoryProfileStore()
    store.save({"profile_id": "bad", "values": 42})
    audit = radt.AuditLog()
    client = TestClient(radt.create_app(_registry(), profile_store=store, audit=audit, api_role="Admin"))
    headers = {"X-API-Key": "test-only-key"}
    before = client.get("/controls", headers=headers).json()
    for response in (client.get("/profiles/bad", headers=headers),
                     client.post("/profiles/bad/activate", headers=headers)):
        assert response.status_code == 422
        assert response.json() == {"detail": "Stored profile fields are invalid."}
    assert client.get("/controls", headers=headers).json() == before
    assert not audit.all_events()


def _invalid_profile_consumer():
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Workers", kind="number", key="workers", default=3,
                          min_value=0, max_value=10, step=1)
        profiles = radt.InMemoryProfileStore()
        profiles.save({"profile_id": "saved", "values": {"workers": 8}})
        st.session_state["config"] = radt.DashboardConfig(
            registry=registry, profile_store=profiles,
            sections=radt.DashboardSections(runbook=False, audit_writer=False,
                                           audit_log=False, plugin_details=False))
    radt.render(st.session_state["config"])


def _corrupt_after_preflight(monkeypatch, store):
    before = store.load("saved")
    parent = {"profile_id": "saved", "values": 42}
    store.save(parent)
    original_load = store.load
    reads = []
    def changing_load(profile_id):
        reads.append(profile_id)
        # The sidebar's disabled-state preflight sees the earlier valid version;
        # the action must validate its own later read before any mutation.
        return deepcopy(before) if len(reads) == 1 else original_load(profile_id)
    monkeypatch.setattr(store, "load", changing_load)
    return parent


def test_native_load_rechecks_saved_data_after_successful_preview(monkeypatch):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_invalid_profile_consumer).run()
    app.selectbox(key="_radt_profile_choice").select("saved").run()
    assert not app.exception
    config = app.session_state["config"]
    _corrupt_after_preflight(monkeypatch, config.profile_store)
    app.button(key="_radt_profile_load").click().run()
    assert not app.exception
    assert app.session_state["workers"] == 3
    assert any("Profile storage failed" in item.value for item in app.error)
    assert not any(event["type"] == "profile_load" for event in config.audit.all_events())
    assert "_radt_active_profile_id" not in app.session_state


def test_native_save_rechecks_selected_parent_before_building_or_writing_child(monkeypatch):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_invalid_profile_consumer).run()
    app.selectbox(key="_radt_profile_choice").select("saved").run()
    app.text_input(key="_radt_profile_name").set_value("child").run()
    config = app.session_state["config"]
    parent = _corrupt_after_preflight(monkeypatch, config.profile_store)
    before_events = config.audit.all_events()
    app.button(key="_radt_profile_save").click().run()
    assert not app.exception
    assert app.session_state["workers"] == 3
    assert any("Profile storage failed" in item.value for item in app.error)
    assert config.audit.all_events() == before_events
    assert config.profile_store.list_ids() == ["saved"]
    assert config.profile_store.load("saved") == parent
    assert config.profile_store.load("child") is None


def test_known_invalid_selection_disables_save_and_load_but_preserves_authorized_delete():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_invalid_profile_consumer).run()
    config = app.session_state["config"]
    config.profile_store.save({"profile_id": "saved", "values": 42})
    app.selectbox(key="_radt_profile_choice").select("saved").run()
    assert not app.exception
    assert app.button(key="_radt_profile_save").disabled
    assert app.button(key="_radt_profile_load").disabled
    assert not app.button(key="_radt_profile_delete").disabled
    assert any("saved values are invalid" in item.value for item in app.warning)
    app.button(key="_radt_profile_delete").click().run()
    assert not app.exception
    assert config.profile_store.list_ids() == []
    assert app.session_state["workers"] == 3


def test_governance_schema_matches_existing_approval_requirement_mapping():
    schema = json.loads((Path(__file__).parents[1] / "schemas/governance.schema.json").read_text())
    assert schema["properties"]["approval_requirements"]["type"] == "object"
    assert isinstance(_records()["governance"]["approval_requirements"], dict)
