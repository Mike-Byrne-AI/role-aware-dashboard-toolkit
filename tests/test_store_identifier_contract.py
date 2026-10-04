"""Successful writes yield identities usable for later list/load/delete calls."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit.profile_store import FileProfileStore, InMemoryProfileStore
from role_aware_dashboard_toolkit.run_store import FileRunStore, InMemoryRunStore
from role_aware_dashboard_toolkit.decision_store import FileDecisionStore, InMemoryDecisionStore
from role_aware_dashboard_toolkit.case_store import FileCaseStore, InMemoryCaseStore
from role_aware_dashboard_toolkit.governance_store import FileGovernanceStore, InMemoryGovernanceStore
from role_aware_dashboard_toolkit.team_store import FileTeamStore, InMemoryTeamStore
from role_aware_dashboard_toolkit.operator_memory_store import FileOperatorMemoryStore, InMemoryOperatorMemoryStore


RECORD_STORES = [
    ("profile_id", FileProfileStore, InMemoryProfileStore),
    ("run_id", FileRunStore, InMemoryRunStore),
    ("decision_id", FileDecisionStore, InMemoryDecisionStore),
    ("case_id", FileCaseStore, InMemoryCaseStore),
    ("governance_id", FileGovernanceStore, InMemoryGovernanceStore),
]


@pytest.mark.parametrize("field,file_class,memory_class", RECORD_STORES)
@pytest.mark.parametrize("file_backed", [False, True])
@pytest.mark.parametrize("identifier,canonical", [(" spaced ", "spaced"), ("  审查/α  ", "审查/α"), (" ", "default")])
def test_saved_listed_and_loaded_record_ids_agree(tmp_path, field, file_class, memory_class,
                                               file_backed, identifier, canonical):
    store = file_class(str(tmp_path)) if file_backed else memory_class()
    record = {field: identifier, "nested": {"value": "retained"}}
    original = deepcopy(record)
    saved = store.save(record)
    assert record == original
    assert store.list_ids() == [canonical]
    assert store.load(store.list_ids()[0]) == {**record, field: canonical}
    assert store.load(identifier) == store.load(canonical)
    loaded = store.load(canonical)
    loaded["nested"]["value"] = "detached"
    assert store.load(canonical)["nested"] == {"value": "retained"}
    if file_backed:
        assert json.loads(Path(saved).read_text(encoding="utf-8"))[field] == canonical
        assert Path(store.resolve_path(identifier)) == Path(saved)
    if hasattr(store, "delete"):
        assert store.delete(identifier)
        assert store.list_ids() == []


@pytest.mark.parametrize("field,file_class,memory_class", RECORD_STORES)
def test_existing_trimmed_filename_with_untrimmed_payload_remains_readable_without_rewrite(
    tmp_path, field, file_class, memory_class,
):
    store = file_class(str(tmp_path))
    path = Path(store.save({field: "legacy", "nested": {"kept": True}}))
    legacy = json.dumps({field: " legacy ", "nested": {"kept": True}}).encode()
    path.write_bytes(legacy)
    assert store.list_ids() == ["legacy"]
    assert store.load(" legacy ") == {field: "legacy", "nested": {"kept": True}}
    assert store.load("legacy") is not None
    assert path.read_bytes() == legacy
    assert len(list(tmp_path.glob("*.json"))) == 1


COLLECTION_STORES = [
    ("comment_id", "save_comment", "list_comments", FileTeamStore, InMemoryTeamStore),
    ("assignment_id", "save_assignment", "list_assignments", FileTeamStore, InMemoryTeamStore),
    ("signoff_id", "save_signoff", "list_signoffs", FileTeamStore, InMemoryTeamStore),
    ("handoff_id", "save_handoff", "list_handoffs", FileTeamStore, InMemoryTeamStore),
    ("note_id", "save_note", "list_notes", FileOperatorMemoryStore, InMemoryOperatorMemoryStore),
    ("incident_id", "save_incident", "list_incidents", FileOperatorMemoryStore, InMemoryOperatorMemoryStore),
    ("narrative_id", "save_narrative", "list_narratives", FileOperatorMemoryStore, InMemoryOperatorMemoryStore),
]


@pytest.mark.parametrize("field,save_method,list_method,file_class,memory_class", COLLECTION_STORES)
@pytest.mark.parametrize("file_backed", [False, True])
def test_collection_primary_ids_follow_the_same_policy_without_rewriting_references(
    tmp_path, field, save_method, list_method, file_class, memory_class, file_backed,
):
    store = file_class(str(tmp_path)) if file_backed else memory_class()
    record = {field: " spaced ", "run_id": " external reference "}
    original = dict(record)
    saved = getattr(store, save_method)(record)
    assert record == original
    assert getattr(store, list_method)() == [{field: "spaced", "run_id": " external reference "}]
    if file_backed:
        path = Path(saved)
        assert json.loads(path.read_text(encoding="utf-8"))[field] == "spaced"
        legacy = json.dumps(original).encode()
        path.write_bytes(legacy)
        assert getattr(store, list_method)()[0][field] == "spaced"
        assert path.read_bytes() == legacy


@pytest.mark.parametrize("field,file_class,memory_class", RECORD_STORES)
def test_alias_write_uses_existing_canonical_identity(tmp_path, field, file_class, memory_class):
    for store in (file_class(str(tmp_path)), memory_class()):
        store.save({field: " name ", "version": 1})
        store.save({field: "name", "version": 2})
        assert store.list_ids() == ["name"]
        assert store.load(" name ")["version"] == 2
    assert len(list(tmp_path.glob("*.json"))) == 1
