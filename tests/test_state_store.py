"""Live state survives restart and refuses conflicting or invalid replacements."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier

import pytest

from role_aware_dashboard_toolkit import state_store
from role_aware_dashboard_toolkit.state_store import (
    InMemoryStateStore,
    SQLiteStateStore,
    StateConflict,
    StateSnapshot,
    StateStoreError,
)


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryStateStore()
    return SQLiteStateStore.create(tmp_path / "state.sqlite3")


def test_state_replacements_are_revisioned_and_reject_stale_writers(store):
    assert store.read() == StateSnapshot({}, 0)
    first = store.compare_and_set({"workers": 3, "mode": "review"}, 0)
    assert first == StateSnapshot({"workers": 3, "mode": "review"}, 1)
    with pytest.raises(StateConflict):
        store.compare_and_set({"workers": 99}, 0)
    assert store.read() == first
    assert store.compare_and_set({"workers": 4}, 1) == StateSnapshot({"workers": 4}, 2)


def test_reads_inputs_and_returned_snapshots_do_not_alias_stored_values(store):
    values = {"nested": {"items": [1, 2]}}
    saved = store.compare_and_set(values, 0)
    values["nested"]["items"].append(3)
    saved.values["nested"]["items"].append(4)
    read = store.read()
    assert read.values == {"nested": {"items": [1, 2]}}
    read.values["nested"]["items"].clear()
    assert store.read().values == {"nested": {"items": [1, 2]}}


def test_snapshot_representation_does_not_expose_control_values(store):
    saved = store.compare_and_set({"private_label": "synthetic-confidential-value"}, 0)
    assert repr(saved) == "StateSnapshot(revision=1)"


@pytest.mark.parametrize("values", [
    None, [], {1: "numeric key"}, {"nested": {False: 1}}, {"items": [{1: 2}]},
    {"nan": float("nan")}, {"infinite": float("inf")}, {"bytes": b"invalid"},
])
def test_invalid_state_cannot_replace_a_good_snapshot(store, values):
    saved = store.compare_and_set({"retained": True}, 0)
    with pytest.raises(ValueError):
        store.compare_and_set(values, saved.revision)
    assert store.read() == saved


def test_circular_values_are_refused_without_a_partial_write(store):
    values = {"nested": []}
    values["nested"].append(values)
    with pytest.raises(ValueError):
        store.compare_and_set(values, 0)
    assert store.read() == StateSnapshot({}, 0)


@pytest.mark.parametrize("revision", [True, False, -1, 0.0, "0", None, 2**63 - 1, 2**63])
def test_invalid_revision_does_not_change_state(store, revision):
    with pytest.raises(ValueError):
        store.compare_and_set({"changed": True}, revision)
    assert store.read() == StateSnapshot({}, 0)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_competing_writers_cannot_silently_overwrite_one_another(tmp_path, backend):
    if backend == "sqlite":
        path = tmp_path / "state.sqlite3"
        first = SQLiteStateStore.create(path)
        second = SQLiteStateStore(path)
    else:
        first = second = InMemoryStateStore()
    barrier = Barrier(2)

    def write(store, value):
        snapshot = store.read()
        barrier.wait(timeout=5)
        try:
            return store.compare_and_set({"winner": value}, snapshot.revision)
        except StateConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(write, first, "first"), pool.submit(write, second, "second")]
        results = [future.result(timeout=10) for future in futures]
    assert results.count("conflict") == 1
    assert first.read() == second.read()
    assert first.read() in results
    assert first.read().revision == 1


def test_sqlite_restart_and_separate_process_preserve_values_and_conflicts(tmp_path):
    path = tmp_path / "state.sqlite3"
    first = SQLiteStateStore.create(path, values={"workers": 2})
    first.compare_and_set({"workers": 3}, 0)
    code = """
import sys
from role_aware_dashboard_toolkit.state_store import SQLiteStateStore, StateConflict
store = SQLiteStateStore(sys.argv[1])
assert store.read().values == {"workers": 3}
assert store.read().revision == 1
try:
    store.compare_and_set({"workers": 99}, 0)
except StateConflict:
    pass
else:
    raise AssertionError("stale process unexpectedly wrote state")
store.compare_and_set({"workers": 4}, 1)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert first.read() == SQLiteStateStore(path).read() == StateSnapshot({"workers": 4}, 2)


def test_creation_never_overwrites_or_implicitly_recreates_storage(tmp_path):
    path = tmp_path / "state.sqlite3"
    with pytest.raises(StateStoreError):
        SQLiteStateStore(path)
    assert not path.exists()
    first = SQLiteStateStore.create(path, values={"retained": True})
    before = path.read_bytes()
    with pytest.raises(StateStoreError):
        SQLiteStateStore.create(path, values={"replacement": True})
    assert path.read_bytes() == before
    assert first.read().values == {"retained": True}
    path.unlink()
    with pytest.raises(StateStoreError):
        first.compare_and_set({"replacement": True}, 0)
    assert not path.exists()


def test_invalid_initial_values_do_not_create_a_file(tmp_path):
    path = tmp_path / "state.sqlite3"
    with pytest.raises(ValueError):
        SQLiteStateStore.create(path, values={"value": float("nan")})
    assert not path.exists()


@pytest.mark.parametrize("corruption", [
    "UPDATE control_state SET values_json = '[]'",
    "UPDATE control_state SET values_json = '{\"value\": NaN}'",
    "UPDATE control_state SET values_json = '{\"value\": 1e9999}'",
    "UPDATE control_state SET values_json = '{invalid'",
    "UPDATE control_state SET revision = 0.5",
    "DELETE FROM control_state",
    "PRAGMA user_version = 2",
    "CREATE TABLE unexpected (value TEXT)",
])
def test_corrupt_existing_storage_fails_closed_without_repair(tmp_path, corruption):
    path = tmp_path / "state.sqlite3"
    store = SQLiteStateStore.create(path)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(corruption)
    before = path.read_bytes()
    with pytest.raises(StateStoreError):
        store.read()
    with pytest.raises(StateStoreError):
        store.compare_and_set({"replacement": True}, 0)
    with pytest.raises(StateStoreError):
        SQLiteStateStore(path)
    assert path.read_bytes() == before


def test_failed_commit_rolls_back_values_and_revision(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    store = SQLiteStateStore.create(path, values={"retained": True})
    connect = sqlite3.connect

    class FailedCommit:
        def __init__(self, *args, **kwargs):
            self.connection = connect(*args, **kwargs)

        def execute(self, *args, **kwargs):
            return self.connection.execute(*args, **kwargs)

        def commit(self):
            raise sqlite3.OperationalError("synthetic commit failure")

        def close(self):
            self.connection.close()

    with monkeypatch.context() as patch:
        patch.setattr(state_store.sqlite3, "connect", FailedCommit)
        with pytest.raises(StateStoreError):
            store.compare_and_set({"replacement": True}, 0)
    assert store.read() == StateSnapshot({"retained": True}, 0)


def test_symlinked_database_is_refused(tmp_path):
    path = tmp_path / "state.sqlite3"
    SQLiteStateStore.create(path)
    link = tmp_path / "linked.sqlite3"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(StateStoreError):
        SQLiteStateStore(link)
