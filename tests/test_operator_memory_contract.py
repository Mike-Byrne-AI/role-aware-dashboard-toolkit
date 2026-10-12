import json
from pathlib import Path
from uuid import uuid4

import pytest

import role_aware_dashboard_toolkit as radt
import role_aware_dashboard_toolkit.decisions as decisions
import role_aware_dashboard_toolkit.operator_memory_store as operator_memory_store
import role_aware_dashboard_toolkit.operator_memory as operator_memory_module
import role_aware_dashboard_toolkit.operator_memory_normalization as operator_memory_normalization_module
from role_aware_dashboard_toolkit.access import Identity, principal_id
from role_aware_dashboard_toolkit.access_audit import bind_audit_identity
from role_aware_dashboard_toolkit.validators import validate_incident_record, validate_incident_timeline_record, validate_narrative_handoff_record, validate_operator_note_record
from role_aware_dashboard_toolkit.store_diagnostics import StorePathSecurityError



def test_operator_note_incident_timeline_and_narrative_validate():
    run = radt.build_run({"temperature": 0.7, "mode": "safe"}, run_id="run_ops", role="Operator")
    run = radt.append_checkpoint(run, {"temperature": 1.0, "mode": "safe"}, label="cp1", approval_state="proposed")
    checkpoint = run["checkpoints"][-1]
    decision = decisions.build_decision_case_from_run(run, checkpoint=checkpoint)

    note = operator_memory_module.build_operator_note(
        "Raised temperature after watching latency trend.",
        run_id=run["run_id"],
        checkpoint_id=checkpoint["checkpoint_id"],
        decision_id=decision["decision_id"],
        actor="mike",
        role="Operator",
        importance="high",
    )
    incident = operator_memory_module.build_incident_record(
        run["run_id"],
        "Latency spike",
        checkpoint_id=checkpoint["checkpoint_id"],
        decision_id=decision["decision_id"],
        actor="mike",
        role="Operator",
        severity="high",
        summary="Latency crossed the watch threshold.",
        suspected_cause="Raised temperature",
    )
    timeline = operator_memory_module.build_incident_timeline(
        run,
        decisions=[decision],
        notes=[note],
        incidents=[incident],
        telemetry_history=[
            {
                "ts": "2026-04-05T12:00:00Z",
                "source": "example",
                "metrics": {"latency_ms": 640, "risk_score": 0.82},
                "health": {"status": "watch"},
            }
        ],
    )
    narrative = operator_memory_module.build_narrative_handoff_packet(
        run,
        timeline=timeline,
        decisions=[decision],
        incidents=[incident],
        handoff_to="night-shift",
        actor="mike",
        role="Operator",
    )

    assert validate_operator_note_record(note)["ok"] is True
    assert validate_incident_record(incident)["ok"] is True
    assert validate_incident_timeline_record(timeline)["ok"] is True
    assert validate_narrative_handoff_record(narrative)["ok"] is True
    assert timeline["summary"]["telemetry_alert_count"] >= 1
    assert narrative["summary"]["descriptive_only"] is True
    assert "does not prove causation" in narrative["summary"]["disclaimer"]



def test_inmemory_operator_memory_store_filters_by_run_checkpoint_and_decision():
    store = operator_memory_store.InMemoryOperatorMemoryStore()
    note_a = operator_memory_module.build_operator_note("A", run_id="run_a", checkpoint_id="cp_a", decision_id="dec_a")
    note_b = operator_memory_module.build_operator_note("B", run_id="run_b", checkpoint_id="cp_b", decision_id="dec_b")
    incident = operator_memory_module.build_incident_record("run_a", "Issue A", checkpoint_id="cp_a", decision_id="dec_a")
    narrative = operator_memory_module.build_narrative_handoff_packet({"run_id": "run_a", "last_checkpoint_id": "cp_a"}, handoff_to="ops")

    store.save_note(note_a)
    store.save_note(note_b)
    store.save_incident(incident)
    store.save_narrative(narrative)

    assert len(store.list_notes("run_a")) == 1
    assert store.list_notes("run_a", checkpoint_id="cp_a")[0]["body"] == "A"
    assert store.list_notes("run_a", checkpoint_id="cp_a", decision_id="dec_a")[0]["note_id"] == note_a["note_id"]
    assert store.list_incidents("run_a")[0]["title"] == "Issue A"
    assert store.list_narratives("run_a")[0]["handoff_to"] == "ops"



def test_incident_timeline_preserves_authenticated_audit_actor():
    identity = Identity("https://issuer.example", "test-subject", 2_000_000_000)
    actor = principal_id(identity, b"test-only-fixed-key-32-bytes-long!!")
    audit = bind_audit_identity(radt.AuditLog(), actor, uuid4().hex)
    audit.log("freeze_toggle", new_value=True, role="Admin")

    timeline = operator_memory_module.build_incident_timeline(
        radt.build_run({}, run_id="run_a"), audit_events=audit.recent(),
    )

    event = next(item for item in timeline["events"] if item["event_type"] == "audit_event")
    assert audit.recent()[0]["user_id"] == actor
    assert event["actor"] == actor
    assert event["role"] == "Admin"
    assert validate_incident_timeline_record(timeline)["ok"] is True


@pytest.mark.parametrize("attribution,expected", [
    ({"actor": "legacy-actor"}, "legacy-actor"),
    ({"user_id": "", "actor": "legacy-actor"}, "legacy-actor"),
    ({"user_id": "current-actor", "actor": "legacy-actor"}, "current-actor"),
])
def test_incident_timeline_audit_actor_uses_legacy_fallback(attribution, expected):
    timeline = operator_memory_module.build_incident_timeline(
        {}, audit_events=[{"type": "note", **attribution}],
    )

    assert timeline["events"][0]["actor"] == expected


def test_file_operator_memory_store_uses_hashed_writes_and_lists_manual_records(tmp_path):
    store_dir = tmp_path / "operator_memory"
    store = operator_memory_store.FileOperatorMemoryStore(str(store_dir))
    left_note = operator_memory_module.build_operator_note("left", run_id="run_a", note_id="note/a")
    right_note = operator_memory_module.build_operator_note("right", run_id="run_a", note_id="note:a")

    left_path = Path(store.save_note(left_note))
    right_path = Path(store.save_note(right_note))

    assert left_path != right_path
    assert left_path.name.startswith("notea-")
    assert right_path.name.startswith("notea-")
    note_ids = {item["note_id"] for item in store.list_notes("run_a")}
    assert {"note/a", "note:a"}.issubset(note_ids)

    legacy_id = "legacy/note"
    legacy_path = store_dir / "notes" / "legacynote.json"
    legacy_path.write_text(json.dumps({"note_id": legacy_id, "run_id": "run_a", "body": "legacy"}), encoding="utf-8")
    note_ids = {item["note_id"] for item in store.list_notes("run_a")}
    assert legacy_id in note_ids


def test_file_operator_memory_store_rejects_symlinked_collection_dir(tmp_path):
    store_dir = tmp_path / "operator_memory"
    store = operator_memory_store.FileOperatorMemoryStore(str(store_dir))
    outside = tmp_path / "outside_notes"
    outside.mkdir()
    notes_dir = store_dir / "notes"
    notes_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        notes_dir.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    record = operator_memory_module.build_operator_note("body", run_id="run_a", note_id="blocked")
    with pytest.raises(StorePathSecurityError):
        store.save_note(record)

    assert store.list_notes("run_a") == []
    assert store.read_errors
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"


def test_validate_incident_record_catches_bad_severity():
    incident = operator_memory_module.build_incident_record("run_bad", "Bad severity")
    incident["severity"] = "urgent"
    result = validate_incident_record(incident)
    assert result["ok"] is False
    assert any("Invalid incident severity" in error for error in result["errors"])


def test_operator_memory_uses_shared_incident_severity_constants():
    assert operator_memory_module.VALID_INCIDENT_SEVERITIES is operator_memory_normalization_module.VALID_INCIDENT_SEVERITIES
