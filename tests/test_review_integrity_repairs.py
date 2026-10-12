"""Regression proofs for store completeness and native governance scope."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import append_checkpoint, build_run
from role_aware_dashboard_toolkit._evidence_reads import EvidenceUnavailable, read_evidence
from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.decision_store import InMemoryDecisionStore
from role_aware_dashboard_toolkit.governance_store import InMemoryGovernanceStore
from role_aware_dashboard_toolkit.operator_memory import build_incident_record
from role_aware_dashboard_toolkit.operator_memory_store import FileOperatorMemoryStore, InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.profile_store import FileProfileStore
from role_aware_dashboard_toolkit.run_store import FileRunStore
from role_aware_dashboard_toolkit.runbook_panels_parts.review_models import (
    build_decision_panel_preview,
    build_governance_panel_preview,
)
from role_aware_dashboard_toolkit.team_store import FileTeamStore


@pytest.mark.parametrize("store_class", [FileProfileStore, FileRunStore])
@pytest.mark.parametrize("operation", ["list", "load"])
def test_existing_file_cannot_serve_as_empty_record_store(tmp_path, store_class, operation):
    root = tmp_path / "records"
    root.write_text("not a directory", encoding="utf-8")
    store = store_class(str(root))
    result = store.list_ids() if operation == "list" else store.load("missing")
    assert not result
    assert store.read_errors
    assert str(tmp_path) not in repr(store.read_errors)


@pytest.mark.parametrize("store_class,method,subdir,record_type", [
    (FileTeamStore, "list_signoffs", "signoffs", "signoff"),
    (FileOperatorMemoryStore, "list_incidents", "incidents", "incident"),
])
@pytest.mark.parametrize("invalid_part", ["root", "collection", "record"])
def test_invalid_existing_collection_paths_are_failed_evidence(
    tmp_path, store_class, method, subdir, record_type, invalid_part,
):
    root = tmp_path / "records"
    if invalid_part == "root":
        root.write_text("not a directory", encoding="utf-8")
    elif invalid_part == "collection":
        root.mkdir()
        (root / subdir).write_text("not a directory", encoding="utf-8")
    else:
        (root / subdir / "invalid.json").mkdir(parents=True)
    store = store_class(str(root))
    result = read_evidence(store, method, record_type=record_type)
    assert result.status == "failed"
    assert store.read_errors
    assert str(tmp_path) not in repr(store.read_errors)


@pytest.mark.parametrize("operation", ["list", "load"])
def test_existing_nonregular_record_is_diagnosed(tmp_path, operation):
    store = FileRunStore(str(tmp_path))
    path = Path(store.save(build_run({}, run_id="run")))
    path.unlink()
    path.mkdir()
    result = store.list_ids() if operation == "list" else store.load("run")
    assert not result
    assert store.read_errors


def test_invalid_signoff_store_blocks_decision_preview_and_can_recover(tmp_path):
    (tmp_path / "signoffs").write_text("not a directory", encoding="utf-8")
    config = SimpleNamespace(team_store=FileTeamStore(str(tmp_path)), decision_store=InMemoryDecisionStore())
    run = append_checkpoint(build_run({}, run_id="run"), {}, approval_state="approved")
    with pytest.raises(EvidenceUnavailable):
        build_decision_panel_preview(config, run, run["checkpoints"][-1], actor="", role="Admin")
    (tmp_path / "signoffs").unlink()
    (tmp_path / "signoffs").mkdir()
    preview = build_decision_panel_preview(config, run, run["checkpoints"][-1], actor="", role="Admin")
    assert preview["decision"]["state"] == "approved"
    assert config.team_store.read_errors  # Historical diagnostics do not block a recovered read.


@pytest.mark.parametrize("scope", ["none", "run", "checkpoint", "incident"])
def test_governance_incidents_follow_additive_case_scope(scope):
    run = append_checkpoint(build_run({}, run_id="A"), {})
    run = append_checkpoint(run, {})
    first, second = run["checkpoints"]
    memory = InMemoryOperatorMemoryStore()
    config = SimpleNamespace(governance_store=InMemoryGovernanceStore(), operator_memory_store=memory)
    case = build_case_record("Case")
    if scope == "run":
        case["linked_run_ids"] = ["A"]
    elif scope == "checkpoint":
        case["linked_checkpoint_ids"] = [first["checkpoint_id"]]
    unrelated = build_incident_record("B", "Unrelated", severity="critical")
    memory.save_incident(unrelated)
    if scope == "incident":
        case["linked_incident_ids"] = [unrelated["incident_id"]]

    def preview():
        return build_governance_panel_preview(config, case, actor="", role="Admin", runs=[run])["governance"]

    initial_state = "blocked" if scope == "incident" else "needs_review" if scope == "none" else "admissible"
    initial = preview()
    assert initial["state"] == initial_state
    if scope in {"run", "checkpoint"}:
        linkage = next(check for check in initial["policy_checks"] if check["check_id"] == "evidence_linkage")
        assert linkage["result"] == "pass"
        assert initial["blocked_actions"] == []
    if scope not in {"run", "checkpoint"}:
        return
    memory.save_incident(build_incident_record("A", "Other checkpoint", severity="critical",
                                              checkpoint_id=second["checkpoint_id"]))
    assert preview()["state"] == ("blocked" if scope == "run" else initial_state)
    memory.save_incident(build_incident_record("A", "Linked checkpoint", severity="critical",
                                              checkpoint_id=first["checkpoint_id"]))
    assert preview()["state"] == "blocked"
    harmless = build_incident_record("B", "Resolved", severity="low", status="closed")
    memory.save_incident(harmless)
    case["linked_incident_ids"] = [harmless["incident_id"]]
    assert preview()["state"] == "blocked"  # An explicit link cannot hide scoped evidence.
