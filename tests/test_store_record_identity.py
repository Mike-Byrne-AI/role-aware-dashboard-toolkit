"""A record file is trusted only for the id it holds.

The 40-bit filename digest is unchanged (a longer one would orphan existing
stores); reads and writes verify the record id instead.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit.operator_memory_store import FileOperatorMemoryStore
from role_aware_dashboard_toolkit.profile_store import FileProfileStore
from role_aware_dashboard_toolkit.run_store import FileRunStore
from role_aware_dashboard_toolkit.store_diagnostics import StorePathSecurityError, hashed_store_filename

# Found by the review's birthday search: same sanitized prefix, same 10-hex digest.
COLLIDING = ("ops$#;$:!", "ops+$&$#$")


def test_the_colliding_pair_really_shares_a_filename():
    assert hashed_store_filename(COLLIDING[0]) == hashed_store_filename(COLLIDING[1])
    assert COLLIDING[0] != COLLIDING[1]


def test_load_refuses_a_file_holding_another_id(tmp_path):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "alpha", "values": {"limit": 10}})
    store.save({"profile_id": "beta", "values": {"limit": 20}})
    # An operator restores beta from the wrong backup file.
    shutil.copyfile(store.resolve_path("alpha"), store.resolve_path("beta"))

    reader = FileProfileStore(str(tmp_path))
    assert reader.load("beta") is None
    assert [error["error_type"] for error in reader.read_errors] == ["StorePathSecurityError"]
    assert "record id does not match" in reader.read_errors[0]["message"]
    assert reader.load("alpha")["values"] == {"limit": 10}


def test_listing_skips_a_record_stored_under_another_ids_filename(tmp_path):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "alpha", "values": {"limit": 10}})
    store.save({"profile_id": "beta", "values": {"limit": 20}})
    shutil.copyfile(store.resolve_path("alpha"), store.resolve_path("beta"))

    reader = FileProfileStore(str(tmp_path))
    assert reader.list_ids() == ["alpha"]
    assert len(reader.read_errors) == 1


def test_colliding_id_cannot_overwrite_or_be_read_as_the_other(tmp_path):
    first, second = COLLIDING
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": first, "values": {"limit": 1}})
    with pytest.raises(StorePathSecurityError, match="holds a different record id"):
        store.save({"profile_id": second, "values": {"limit": 999}})
    assert store.load(first)["values"] == {"limit": 1}
    assert store.load(second) is None


def test_a_crafted_collision_file_is_not_returned_for_the_other_id(tmp_path):
    first, second = COLLIDING
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": second, "values": {"limit": 999}})
    reader = FileProfileStore(str(tmp_path))
    assert reader.load(first) is None
    assert "record id does not match" in reader.read_errors[0]["message"]


def test_rewriting_the_same_record_is_still_allowed(tmp_path):
    store = FileRunStore(str(tmp_path))
    store.save({"run_id": "run-1", "values": {"x": 1}})
    store.save({"run_id": "run-1", "values": {"x": 2}})
    assert store.load("run-1")["values"] == {"x": 2}


def test_untrimmed_legacy_id_still_matches_its_canonical_file(tmp_path):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "ops", "values": {}})
    path = Path(store.resolve_path("ops"))
    record = json.loads(path.read_text(encoding="utf-8"))
    record["profile_id"] = "  ops  "
    path.write_text(json.dumps(record), encoding="utf-8")
    reader = FileProfileStore(str(tmp_path))
    assert reader.load("ops")["profile_id"] == "ops"
    assert reader.list_ids() == ["ops"]
    store.save({"profile_id": "ops", "values": {"v": 1}})
    assert reader.read_errors == []


def test_collection_save_refuses_a_file_holding_another_id(tmp_path):
    store = FileOperatorMemoryStore(str(tmp_path))
    first_path = Path(store.save_note({"note_id": "n1", "run_id": "r", "body": "one"}))
    second_path = first_path.parent / f"{hashed_store_filename('n2')}.json"
    shutil.copyfile(first_path, second_path)  # n1's content under n2's name
    with pytest.raises(StorePathSecurityError, match="holds a different record id"):
        store.save_note({"note_id": "n2", "run_id": "r", "body": "two"})
    assert json.loads(second_path.read_text(encoding="utf-8"))["note_id"] == "n1"


def test_delete_refuses_a_file_holding_another_id(tmp_path):
    first, second = COLLIDING
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": first, "values": {"limit": 1}})
    with pytest.raises(StorePathSecurityError, match="holds a different record id"):
        store.delete(second)
    assert store.load(first)["values"] == {"limit": 1}
    assert store.delete(first) is True
