"""Validators accept native builders and reject unsafe imported nested records."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.decision_store import FileDecisionStore, InMemoryDecisionStore
from role_aware_dashboard_toolkit.decisions import build_decision_case_from_run
from role_aware_dashboard_toolkit.governance import build_governance_record, governance_summary
from role_aware_dashboard_toolkit.governance_store import FileGovernanceStore, InMemoryGovernanceStore
from role_aware_dashboard_toolkit.runbook_panels_parts.review_models import build_decision_panel_preview
from role_aware_dashboard_toolkit.team_ops import build_review_assignment
from role_aware_dashboard_toolkit.validators import validate_record


def _run(approval_state="proposed"):
    return radt.append_checkpoint(radt.build_run({"workers": 1}), {"workers": 2},
                                  approval_state=approval_state)


@pytest.mark.parametrize("approval_state", ["frozen", "replay_only", "proposed"])
@pytest.mark.parametrize("file_backed", [False, True])
def test_native_decisions_with_blockers_validate_after_store_roundtrip(tmp_path, approval_state, file_backed):
    run = _run(approval_state)
    assignment = build_review_assignment(run["run_id"], status="in_review")
    decision = build_decision_case_from_run(run, assignments=[assignment])
    assert decision["blockers"]
    store = FileDecisionStore(str(tmp_path)) if file_backed else InMemoryDecisionStore()
    store.save(decision)
    loaded = store.load(decision["decision_id"])
    assert loaded == decision
    assert validate_record("decision", loaded)["ok"]
    loaded["blockers"] = ["invalid scalar blocker"]
    result = validate_record("decision", loaded)
    assert not result["ok"]
    assert "blockers[0] must be a mapping." in result["errors"]


@pytest.mark.parametrize("path,value", [
    (("approval_state",), "invented"),
    (("approval", "state"), "invented"),
    (("approval", "state"), "Missing required field: bait"),
    (("schema_version",), 999),
    (("approval", "schema_version"), 999),
])
def test_imported_runs_reject_invalid_nested_checkpoint_semantics(path, value):
    run = _run()
    target = run["checkpoints"][0]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    original = deepcopy(run)
    result = validate_record("run", run)
    assert not result["ok"]
    assert any("checkpoints[0]." in error for error in result["errors"])
    packet = radt.build_run_packet(run)
    with pytest.raises(ValueError, match="checkpoints"):
        radt.export_packet_json(packet)
    with pytest.raises(ValueError, match="checkpoints"):
        radt.load_packet_json(json.dumps(packet))
    assert run == original


def test_valid_imported_run_can_build_the_native_decision_preview():
    run = _run("frozen")
    imported = radt.load_packet_json(radt.export_packet_json(radt.build_run_packet(run)))["payload"]
    assert validate_record("run", imported)["ok"]
    preview = build_decision_panel_preview(
        SimpleNamespace(decision_store=InMemoryDecisionStore()), imported,
        imported["checkpoints"][0], actor="synthetic", role="Admin",
    )
    assert preview["decision"]["state"] == "frozen"
    assert validate_record("decision", preview["decision"])["ok"]


def test_full_run_requires_nested_metadata_but_partial_packets_remain_supported():
    run = _run()
    run["checkpoints"] = [{"controls": {"workers": 2}, "approval": {"state": "approved"}}]
    result = validate_record("run", run)
    assert not result["ok"]
    assert "checkpoints[0].Missing required field: checkpoint_id" in result["errors"]
    assert "checkpoints[0].approval.Missing required field: ts" in result["errors"]
    packet = radt.build_run_packet(run)
    assert radt.load_packet_json(radt.export_packet_json(packet))["payload"] == run


def test_builder_runs_retain_support_for_partial_external_audit_rows():
    run = radt.append_checkpoint(radt.build_run({"workers": 1}), {"workers": 2},
                                  audit_events=[{"type": "external_review", "detail": "Synthetic event"}])
    assert validate_record("run", run)["ok"]
    packet = radt.build_run_packet(run)
    assert radt.load_packet_json(radt.export_packet_json(packet))["payload"] == run


@pytest.mark.parametrize("field", ["blocker_count", "warning_count"])
@pytest.mark.parametrize("invalid", ["not-a-number", [], {}, True, None, 1.5])
@pytest.mark.parametrize("file_backed", [False, True])
def test_governance_summary_counters_are_validated_after_store_roundtrip(tmp_path, field, invalid, file_backed):
    record = build_governance_record(build_case_record("Synthetic review"))
    record[field] = invalid
    store = FileGovernanceStore(str(tmp_path)) if file_backed else InMemoryGovernanceStore()
    store.save(record)
    result = validate_record("governance", store.load(record["governance_id"]))
    assert not result["ok"]
    assert f"Field '{field}' must be an integer." in result["errors"]


@pytest.mark.parametrize("field", ["required_roles", "missing_roles", "satisfied_roles"])
@pytest.mark.parametrize("invalid", [42, "Approver", {}, None, [42], [None]])
def test_governance_summary_role_lists_reject_malformed_values(field, invalid):
    record = build_governance_record(build_case_record("Synthetic review"))
    record["approval_requirements"][field] = invalid
    result = validate_record("governance", record)
    assert not result["ok"]
    assert any("approval_requirements." in error and field in error for error in result["errors"])


@pytest.mark.parametrize("omit_optional", [False, True])
def test_governance_summary_accepts_valid_and_legacy_optional_fields(omit_optional):
    record = build_governance_record(build_case_record("Synthetic review"))
    if omit_optional:
        record.pop("blocker_count")
        record.pop("warning_count")
        record["approval_requirements"] = {"custom_extension": {"anything": 42}}
    record["approval_requirements"]["schema_version"] = "host-extension-v1"
    assert validate_record("governance", record)["ok"]
    summary = governance_summary(record)
    assert isinstance(summary["blocker_count"], int)
    assert isinstance(summary["required_roles"], list)


def test_full_run_nested_validation_handles_circular_caller_mappings():
    run = _run()
    run["checkpoints"][0]["approval"] = run
    result = validate_record("run", run)
    assert not result["ok"]
    assert any("circular" in error for error in result["errors"])
