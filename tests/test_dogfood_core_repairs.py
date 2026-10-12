"""Consumer regressions for packet boundaries and trustworthy evidence snapshots."""

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator
import pytest

import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit.ledger import (
    ledger_summary,
    reconstruct_controls_from_entries,
    reconstruct_controls_from_ledger,
)
from role_aware_dashboard_toolkit.validators import validate_packet


@pytest.mark.parametrize(
    "packet_type",
    ["x_bad/type", "x_" + "a" * 63, "x_has-dash", "x_has space", "1invalid", "", "custom"],
)
def test_packet_identifier_rules_match_for_build_import_validation_and_export(packet_type):
    with pytest.raises(ValueError, match="packet_type"):
        radt.build_packet(packet_type, {"schema_version": 1})

    packet = radt.build_packet("x_valid", {"schema_version": 1})
    packet["packet_type"] = packet_type
    assert validate_packet(packet)["ok"] is False
    with pytest.raises(ValueError, match="packet_type"):
        radt.load_packet_json(json.dumps(packet))
    with pytest.raises(ValueError, match="packet_type"):
        radt.export_packet_json(packet)


@pytest.mark.parametrize("packet_type", [" X_Custom_42 ", " RUN ", "x_" + "a" * 62])
def test_packet_type_canonicalization_is_consistent_without_mutating_input(packet_type):
    expected = packet_type.strip().lower()
    packet = radt.build_packet(packet_type, {"schema_version": 1})
    assert packet["packet_type"] == expected
    packet["packet_type"] = packet_type
    original = deepcopy(packet)
    assert validate_packet(packet)["ok"] is True
    assert radt.load_packet_json(json.dumps(packet))["packet_type"] == expected
    assert json.loads(radt.export_packet_json(packet))["packet_type"] == expected
    assert packet == original


def _checkpoint_entries(ledger):
    return [entry for entry in ledger["entries"] if entry["entry_type"] == "checkpoint"]


def test_ledger_chronology_and_reconstruction_survive_offsets_skew_and_older_audit():
    run = radt.build_run({"workers": 1}, run_id="offset-evidence")
    run["started_at"] = "2026-09-10T09:00:00+00:00"
    run = radt.append_checkpoint(
        run,
        {"workers": 8},
        approval_state="approved",
        audit_events=[{
            "ts": "2026-09-10T12:01:00+02:00",
            "type": "control_change",
            "key": "workers",
            "old": 1,
            "new": 4,
        }],
    )
    run["checkpoints"][0]["ts"] = "2026-09-10T10:02:00+00:00"
    # This checkpoint was appended later despite a clock ten minutes behind.
    run = radt.append_checkpoint(run, {"workers": 20}, approval_state="rejected")
    run["checkpoints"][1]["ts"] = "2026-09-10T09:52:00+00:00"
    ledger = radt.build_run_ledger(run)

    instants = [
        datetime.fromisoformat(entry["ts"]).astimezone(timezone.utc)
        for entry in ledger["entries"]
    ]
    assert instants == sorted(instants)
    assert [entry["source_sequence"] for entry in ledger["entries"]] == [0, 3, 2, 1]
    assert ledger["latest_controls"] == run["latest_controls"] == {"workers": 20}
    assert reconstruct_controls_from_ledger(ledger) == run["latest_controls"]
    later_checkpoint = next(entry for entry in _checkpoint_entries(ledger) if entry["controls"]["workers"] == 20)
    assert later_checkpoint["controls_diff"] == {"workers": {"from": 8, "to": 20}}
    assert ledger["latest_approval_state"] == "rejected"
    assert ledger_summary(ledger)["latest_approval_state"] == "rejected"

    exported = radt.load_packet_json(radt.export_packet_json(radt.build_ledger_packet(ledger)))
    assert reconstruct_controls_from_ledger(exported["payload"]) == {"workers": 20}


def test_equal_instants_and_naive_utc_timestamps_keep_source_order():
    run = radt.build_run({"workers": 1})
    run["started_at"] = "2026-09-10T10:00:00Z"
    run = radt.append_checkpoint(
        run, {"workers": 8},
        audit_events=[{"ts": "2026-09-10T05:00:00-05:00", "type": "control_change"}],
    )
    run["checkpoints"][0]["ts"] = "2026-09-10T10:00:00"
    run = radt.end_run(run)
    run["ended_at"] = "2026-09-10T12:00:00+02:00"
    ledger = radt.build_run_ledger(run)
    assert [entry["source_sequence"] for entry in ledger["entries"]] == [0, 1, 2, 3]
    assert [entry["ts"] for entry in ledger["entries"]] == [
        "2026-09-10T10:00:00Z", "2026-09-10T10:00:00",
        "2026-09-10T05:00:00-05:00", "2026-09-10T12:00:00+02:00",
    ]


def test_undated_or_invalid_ledger_entries_remain_visible_in_stable_source_order():
    run = radt.build_run({"workers": 1})
    run["started_at"] = ""
    run = radt.append_checkpoint(run, {"workers": 8}, audit_events=[{"ts": "", "type": "note"}])
    run["checkpoints"][0]["ts"] = "not-an-instant"
    run = radt.end_run(run)
    run["ended_at"] = "2026-09-10T10:00:00+00:00"
    ledger = radt.build_run_ledger(run)
    assert [entry["source_sequence"] for entry in ledger["entries"]] == [3, 0, 1, 2]
    assert [entry["ts"] for entry in ledger["entries"]] == [
        "2026-09-10T10:00:00+00:00", "", "not-an-instant", "",
    ]
    assert reconstruct_controls_from_ledger(ledger) == {"workers": 8}


@pytest.mark.parametrize("status", ["completed", "aborted"])
def test_run_lifecycle_never_changes_checkpoint_approval(status):
    run = radt.append_checkpoint(radt.build_run({}), {"workers": 4}, approval_state="rejected")
    ledger = radt.build_run_ledger(radt.end_run(run, status=status))
    assert ledger["run_status"] == status
    assert ledger["latest_approval_state"] == "rejected"
    assert all(
        entry["approval_state"] == ""
        for entry in ledger["entries"]
        if entry["entry_type"] in {"run_started", "run_ended"}
    )
    empty = radt.build_run_ledger(radt.end_run(radt.build_run({}), status=status))
    assert empty["latest_approval_state"] == ""


def test_ledger_and_reconstructed_nested_values_are_detached_from_source():
    run = radt.build_run({"route": {"weights": [10, 90]}})
    run = radt.append_checkpoint(
        run, {"route": {"weights": [90, 10]}},
        telemetry={"queue": {"samples": [420, 300]}},
        audit_events=[{"type": "control_change", "new": {"weights": [70, 30]}}],
    )
    original = deepcopy(run)
    ledger = radt.build_run_ledger(run)
    checkpoint = _checkpoint_entries(ledger)[0]
    checkpoint["telemetry"]["queue"]["samples"][0] = 0
    checkpoint["controls"]["route"]["weights"][0] = 0
    audit = next(entry for entry in ledger["entries"] if entry["entry_type"] == "audit_event")
    audit["audit_event"]["new"]["weights"][0] = 0
    assert run == original

    reconstructed = reconstruct_controls_from_ledger(ledger)
    reconstructed["route"]["weights"][1] = 0
    assert checkpoint["controls"]["route"]["weights"] == [0, 10]


def test_profile_snapshot_detaches_metadata_values_and_parent_diffs():
    registry = radt.ControlRegistry()
    options = [{"weights": [10, 90]}, {"weights": [90, 10]}]
    registry.register("Route", kind="select", key="route", options=options, default=options[0])
    state = {"route": options[1]}
    extra = {"incident": {"tags": ["overload"]}}
    parent = {"route": options[0]}
    profile = radt.build_profile(
        "mitigation", registry, state, extra=extra,
        parent_profile_id="baseline", parent_values=parent,
    )
    before = deepcopy(profile)
    options[0]["weights"][0] = 0
    state["route"]["weights"][0] = 0
    extra["incident"]["tags"].append("recovered")
    assert profile == before


@pytest.mark.parametrize("ended", [False, True])
def test_empty_checkpoint_snapshot_clears_controls(ended):
    run = radt.append_checkpoint(radt.build_run({"workers": 1}), {})
    if ended:
        run = radt.end_run(run)
    ledger = radt.build_run_ledger(run)
    assert ledger["latest_controls"] == run["latest_controls"] == {}
    assert reconstruct_controls_from_ledger(ledger) == {}


@pytest.mark.parametrize(
    "sequences", [None, [2, 2], [2, None], [2, -1], [2, True], [2, {}]],
)
def test_legacy_or_incomplete_sequence_metadata_uses_existing_entry_order(sequences):
    entries = [
        {"entry_type": "checkpoint", "controls": {"workers": 8}},
        {"entry_type": "checkpoint", "controls": {"workers": 20}},
    ]
    if sequences is not None:
        for entry, sequence in zip(entries, sequences):
            entry["source_sequence"] = sequence
    assert reconstruct_controls_from_entries(entries) == {"workers": 20}


def test_z_timestamps_work_when_parser_requires_python310_explicit_offsets(monkeypatch):
    import role_aware_dashboard_toolkit.ledger as ledger_module

    class ExplicitOffsetDatetime(datetime):
        @classmethod
        def fromisoformat(cls, text):
            if text.endswith("Z"):
                raise ValueError("Python 3.10 requires an explicit offset")
            return super().fromisoformat(text)

    monkeypatch.setattr(ledger_module, "datetime", ExplicitOffsetDatetime)
    run = radt.build_run({"workers": 1})
    run["started_at"] = "2026-09-10T09:00:00Z"
    run = radt.append_checkpoint(run, {"workers": 8})
    run["checkpoints"][0]["ts"] = "2026-09-10T10:00:00+00:00"
    ledger = radt.build_run_ledger(run)
    assert [entry["entry_type"] for entry in ledger["entries"]] == ["run_started", "checkpoint"]


@pytest.mark.parametrize("exception_type", [ImportError, ValueError])
def test_packet_registry_import_failures_are_visible_and_path_redacted(monkeypatch, exception_type):
    import builtins

    packet = radt.build_packet("run", {"schema_version": 1})
    original_import = builtins.__import__

    def failing_import(name, *args, **kwargs):
        if name == "packet_core":
            raise exception_type(r"broken registry at C:\Users\Demo\private\packet_core.py")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", failing_import)
    result = validate_packet(packet)
    assert result["ok"] is False
    errors = "; ".join(result["errors"])
    assert "Failed to import packet type registry" in errors
    assert exception_type.__name__ in errors
    assert "Users" not in errors
    assert "<redacted-local-path>" in errors


def _read_protocol_schema(name):
    return json.loads(
        (Path(__file__).resolve().parents[1] / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8")
    )


def test_packet_schema_declares_the_same_canonical_type_contract_as_runtime():
    from role_aware_dashboard_toolkit.packet_core import VALID_PACKET_TYPES

    packet_type = _read_protocol_schema("packet")["properties"]["packet_type"]
    assert packet_type["type"] == "string"
    assert packet_type["minLength"] == 1
    assert packet_type["maxLength"] == 64
    assert set(packet_type["anyOf"][0]["enum"]) == set(VALID_PACKET_TYPES)
    assert packet_type["anyOf"][1]["pattern"] == "^x_"
    for valid in [*VALID_PACKET_TYPES, "x_custom", "x_" + "a" * 62]:
        assert re.search(packet_type["pattern"], valid)
    for invalid in ["", "x_bad/type", "x_" + "a" * 63, "Run", " run", "run ", "x_note\n"]:
        assert not re.search(packet_type["pattern"], invalid)


def test_ledger_schema_keeps_source_sequence_optional_and_nonnegative():
    item = _read_protocol_schema("ledger")["properties"]["entries"]["items"]
    assert item["type"] == "object"
    assert "source_sequence" not in item.get("required", [])
    sequence = item["properties"]["source_sequence"]
    assert sequence["type"] == "integer"
    assert sequence["minimum"] == 0
    assert "legacy" in sequence["description"]


@pytest.fixture
def protocol_schema_validator():
    return Draft202012Validator


@pytest.mark.parametrize("packet_type", ["run", "x_custom", "x_" + "a" * 62])
def test_serialized_packets_pass_json_schema(protocol_schema_validator, packet_type):
    schema = _read_protocol_schema("packet")
    protocol_schema_validator.check_schema(schema)
    packet = radt.build_packet(packet_type, {"schema_version": 1})
    serialized = json.loads(radt.export_packet_json(packet))
    protocol_schema_validator(schema).validate(serialized)


@pytest.mark.parametrize(
    "packet_type", ["x_bad/type", "x_" + "a" * 63, "Run", " run", "run ", "x_note\n", "custom"],
)
def test_packet_json_schema_rejects_invalid_or_noncanonical_types(protocol_schema_validator, packet_type):
    packet = radt.build_packet("run", {"schema_version": 1})
    packet["packet_type"] = packet_type
    validator = protocol_schema_validator(_read_protocol_schema("packet"))
    assert list(validator.iter_errors(packet))


def test_json_schema_accepts_new_and_legacy_ledger_sequences(protocol_schema_validator):
    schema = _read_protocol_schema("ledger")
    protocol_schema_validator.check_schema(schema)
    validator = protocol_schema_validator(schema)
    ledger = radt.build_run_ledger(radt.append_checkpoint(radt.build_run({}), {"workers": 4}))
    validator.validate(ledger)
    for entry in ledger["entries"]:
        entry.pop("source_sequence")
    validator.validate(ledger)


@pytest.mark.parametrize("sequence", [-1, True, "1", 1.5, None])
def test_ledger_json_schema_rejects_invalid_sequence_values(protocol_schema_validator, sequence):
    ledger = radt.build_run_ledger(radt.build_run({}))
    ledger["entries"][0]["source_sequence"] = sequence
    validator = protocol_schema_validator(_read_protocol_schema("ledger"))
    assert list(validator.iter_errors(ledger))
