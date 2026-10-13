"""A record replaced by another writer during a read is re-read, not reported missing."""
from __future__ import annotations

import os
from pathlib import Path

from role_aware_dashboard_toolkit import store_diagnostics
from role_aware_dashboard_toolkit.profile_store import FileProfileStore


def _racing_open(monkeypatch, target: Path, replace_times: int, root: Path):
    real_open = os.open
    replaced: list[int] = []

    def racing_open(path, flags, *args, **kwargs):
        if Path(path) == target and len(replaced) < replace_times:
            # Another writer atomically replaces the record after the reader
            # validated it and before the reader opens it.
            replaced.append(len(replaced))
            FileProfileStore(str(root)).save(
                {"profile_id": "ops", "values": {"v": 100 + len(replaced)}}
            )
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(store_diagnostics.os, "open", racing_open)
    return replaced


def test_load_rereads_a_record_replaced_between_check_and_open(tmp_path, monkeypatch):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "ops", "values": {"v": 1}})
    target = Path(store.resolve_path("ops"))
    reader = FileProfileStore(str(tmp_path))
    replaced = _racing_open(monkeypatch, target, 1, tmp_path)

    loaded = reader.load("ops")

    assert replaced == [0]
    assert loaded is not None and loaded["values"] == {"v": 101}
    assert reader.read_errors == []


def test_listing_rereads_a_record_replaced_during_the_scan(tmp_path, monkeypatch):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "ops", "values": {"v": 1}})
    target = Path(store.resolve_path("ops"))
    reader = FileProfileStore(str(tmp_path))
    _racing_open(monkeypatch, target, 2, tmp_path)

    assert reader.list_ids() == ["ops"]
    assert reader.read_errors == []


def test_a_record_that_keeps_changing_is_still_diagnosed(tmp_path, monkeypatch):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "ops", "values": {"v": 1}})
    target = Path(store.resolve_path("ops"))
    reader = FileProfileStore(str(tmp_path))
    _racing_open(monkeypatch, target, 10_000, tmp_path)

    assert reader.load("ops") is None
    assert [error["error_type"] for error in reader.read_errors] == ["StorePathSecurityError"]
    assert "changed between validation and read" in reader.read_errors[0]["message"]
