"""Imported evidence is rejected before malformed fields change its meaning."""
from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.governance import build_governance_record, derive_governance_state
from role_aware_dashboard_toolkit.ledger import reconstruct_controls_from_ledger
from role_aware_dashboard_toolkit.validators import validate_packet, validate_record


def _run():
    return radt.append_checkpoint(radt.build_run({"workers": 1}), {"workers": 2})


def _skewed_ledger():
    run = radt.append_checkpoint(_run(), {"workers": 3})
    run["started_at"] = "2026-01-01T00:00:00+00:00"
    run["checkpoints"][0]["ts"] = "2026-01-03T00:00:00+00:00"
    run["checkpoints"][1]["ts"] = "2026-01-02T00:00:00+00:00"
    return radt.build_run_ledger(run)


def _schema_errors(record_type, record):
    path = Path(__file__).parents[1] / "schemas" / f"{record_type}.schema.json"
    return list(Draft202012Validator(json.loads(path.read_text())).iter_errors(record))


@pytest.mark.parametrize("field,invalid", [
    ("source_sequence", True), ("source_sequence", -1), ("source_sequence", None),
    ("source_sequence", "1"), ("source_sequence", 1.5), ("source_sequence", {}),
    ("entry_type", {}), ("entry_type", ""), ("entry_type", "invented"),
    ("controls", []), ("controls_diff", 42), ("telemetry", "invalid"),
    ("audit_event", []), ("audit_count", True), ("entry_id", 42),
    ("approval_state", []), ("ts", None),
])
def test_malformed_ledger_entries_fail_record_schema_and_packet_boundaries(field, invalid):
    ledger = _skewed_ledger()
    ledger["entries"][0][field] = invalid
    original = deepcopy(ledger)
    result = validate_record("ledger", ledger)
    assert not result["ok"]
    assert any("entries[0]" in error and field in error for error in result["errors"])
    assert _schema_errors("ledger", ledger)
    packet = radt.build_ledger_packet(ledger)
    with pytest.raises(ValueError, match="entries"):
        radt.export_packet_json(packet)
    with pytest.raises(ValueError, match="entries"):
        radt.load_packet_json(json.dumps(packet))
    assert ledger == original


def test_complete_ledger_sequences_preserve_source_controls_across_clock_skew():
    ledger = _skewed_ledger()
    assert [entry["source_sequence"] for entry in ledger["entries"]] == [0, 2, 1]
    assert validate_record("ledger", ledger)["ok"]
    assert not _schema_errors("ledger", ledger)
    imported = radt.load_packet_json(radt.export_packet_json(radt.build_ledger_packet(ledger)))["payload"]
    assert reconstruct_controls_from_ledger(imported) == ledger["latest_controls"] == {"workers": 3}


@pytest.mark.parametrize("mode", ["absent", "incomplete", "duplicate"])
def test_legacy_valid_sequence_metadata_retains_list_order(mode):
    ledger = _skewed_ledger()
    if mode == "absent":
        for entry in ledger["entries"]:
            entry.pop("source_sequence")
    elif mode == "incomplete":
        ledger["entries"][0].pop("source_sequence")
    else:
        ledger["entries"][0]["source_sequence"] = ledger["entries"][1]["source_sequence"]
    assert validate_record("ledger", ledger)["ok"]
    assert not _schema_errors("ledger", ledger)
    imported = radt.load_packet_json(radt.export_packet_json(radt.build_ledger_packet(ledger)))["payload"]
    assert reconstruct_controls_from_ledger(imported) == {"workers": 2}


def test_partial_ledger_entries_and_application_fields_remain_supported():
    payload = {"schema_version": 1, "entries": [{"controls": {"workers": 2},
                                                "schema_version": "application-v1"}]}
    packet = radt.build_packet("ledger", payload)
    assert radt.load_packet_json(radt.export_packet_json(packet))["payload"] == payload


def _governance():
    return build_governance_record(build_case_record("Synthetic review"))


@pytest.mark.parametrize("field,invalid", [
    ("blocker", "false"), ("blocker", 0), ("blocker", 1), ("blocker", None),
    ("blocker", []), ("blocker", {}), ("check_id", 42), ("title", []),
    ("detail", False), ("result", ""), ("result", None), ("result", 0),
    ("result", False), ("required_roles", "Approver"), ("required_roles", [42]),
    ("refs", []),
])
def test_governance_policy_field_types_match_published_nested_schema(field, invalid):
    record = _governance()
    record["policy_checks"][0][field] = invalid
    result = validate_record("governance", record)
    assert not result["ok"]
    assert any("policy_checks[0]" in error and field in error for error in result["errors"])
    assert _schema_errors("governance", record)


@pytest.mark.parametrize("field", ["check_id", "title", "result"])
def test_governance_policy_checks_require_declared_metadata(field):
    record = _governance()
    record["policy_checks"][0].pop(field)
    result = validate_record("governance", record)
    assert not result["ok"]
    assert f"policy_checks[0].Missing required field: {field}" in result["errors"]
    assert _schema_errors("governance", record)


@pytest.mark.parametrize("blocker,expected_state", [(False, "admissible"), (True, "blocked")])
def test_validated_governance_booleans_keep_their_actual_policy_meaning(blocker, expected_state):
    record = _governance()
    record["policy_checks"] = [{"check_id": "test", "title": "Review", "result": "fail",
                                "blocker": blocker}]
    assert validate_record("governance", record)["ok"]
    assert not _schema_errors("governance", record)
    assert derive_governance_state(policy_checks=record["policy_checks"]) == expected_state


def test_legacy_policy_checks_can_omit_optional_fields_and_keep_extensions():
    record = _governance()
    record["policy_checks"] = [{"check_id": "test", "title": "Review", "result": "pass",
                                "schema_version": "application-v1"}]
    assert validate_record("governance", record)["ok"]
    assert not _schema_errors("governance", record)


@pytest.mark.parametrize("path", [("approval_state",), ("approval", "state")])
@pytest.mark.parametrize("invalid", ["", " ", None, False, 0, {}, []])
def test_present_invalid_approval_states_fail_full_runs_and_partial_packets(path, invalid):
    run = _run()
    target = run["checkpoints"][0]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    assert not validate_record("run", run)["ok"]
    packet = radt.build_run_packet(run)
    with pytest.raises(ValueError, match="approval"):
        radt.export_packet_json(packet)
    with pytest.raises(ValueError, match="approval"):
        radt.load_packet_json(json.dumps(packet))


@pytest.mark.parametrize("field", ["state", "escalation_level"])
def test_governance_present_empty_enums_are_invalid(field):
    record = _governance()
    record[field] = ""
    assert not validate_record("governance", record)["ok"]
    assert _schema_errors("governance", record)


def test_omitted_states_remain_accepted_in_partial_packet_payloads():
    payload = {"schema_version": 1, "checkpoints": [{"controls": {}, "approval": {}}]}
    packet = radt.build_packet("run", payload)
    assert radt.load_packet_json(radt.export_packet_json(packet))["payload"] == payload
    assert not validate_record("run", payload)["ok"]


@pytest.mark.parametrize("version", ["\u00b2", "1" * 5000])
def test_malformed_schema_strings_return_structured_packet_errors(version):
    packet = radt.build_run_packet(_run())
    packet["payload_schema_version"] = version
    result = validate_packet(packet)
    assert not result["ok"]
    assert any("payload_schema_version" in error for error in result["errors"])
    with pytest.raises(ValueError, match="payload_schema_version"):
        radt.load_packet_json(json.dumps(packet))


@pytest.mark.parametrize("version", [1, "1", " 1 ", "\u0661"])
def test_existing_integer_and_convertible_version_strings_remain_supported(version):
    packet = radt.build_run_packet(_run())
    packet["payload_schema_version"] = version
    assert validate_packet(packet)["ok"]
