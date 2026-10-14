"""Record writes are flushed to disk, and crash-orphaned temp files are swept."""
from __future__ import annotations

import os
import stat
import time

import pytest

from role_aware_dashboard_toolkit import store_diagnostics
from role_aware_dashboard_toolkit.profile_store import FileProfileStore


@pytest.fixture(autouse=True)
def _fresh_sweep_schedule(monkeypatch):
    monkeypatch.setattr(store_diagnostics, "_TEMP_SWEEP_LAST_RUN", {}, raising=False)


def test_record_write_fsyncs_the_file_and_its_directory(tmp_path, monkeypatch):
    synced: list[str] = []
    real_fsync = os.fsync

    def spy_fsync(fd):
        synced.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        return real_fsync(fd)

    monkeypatch.setattr(store_diagnostics.os, "fsync", spy_fsync)
    FileProfileStore(str(tmp_path)).save({"profile_id": "ops", "values": {"v": 1}})
    assert "file" in synced
    if os.name != "nt":
        assert synced.index("dir") > synced.index("file")


def test_failed_file_fsync_fails_the_write_and_keeps_the_old_record(tmp_path, monkeypatch):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "ops", "values": {"v": "old"}})

    def failing_fsync(_fd):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(store_diagnostics.os, "fsync", failing_fsync)
    with pytest.raises(OSError):
        store.save({"profile_id": "ops", "values": {"v": "new"}})
    monkeypatch.undo()
    assert store.load("ops")["values"] == {"v": "old"}
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".radt-record-")]


def _age(path, seconds):
    old = time.time() - seconds
    os.utime(path, (old, old))


def test_a_write_sweeps_stale_temp_files_of_the_store_prefix_only(tmp_path):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "seed", "values": {}})
    stale = tmp_path / ".radt-record-crashed.tmp"
    stale.write_text('{"profile_id": "ops", "values": {"secret": "x"}}', encoding="utf-8")
    _age(stale, 3600)
    fresh = tmp_path / ".radt-record-inflight.tmp"
    fresh.write_text("{}", encoding="utf-8")
    other = tmp_path / ".other-tool.tmp"
    other.write_text("keep", encoding="utf-8")
    _age(other, 3600)
    unrelated = tmp_path / "radt-record-no-dot.tmp"
    unrelated.write_text("keep", encoding="utf-8")
    _age(unrelated, 3600)

    store_diagnostics._TEMP_SWEEP_LAST_RUN.clear()  # the restarted process's first write
    store.save({"profile_id": "ops", "values": {"v": 1}})

    assert not stale.exists()
    assert fresh.exists() and other.exists() and unrelated.exists()


def test_sweep_runs_at_most_once_per_interval_per_directory(tmp_path):
    store = FileProfileStore(str(tmp_path))
    store.save({"profile_id": "seed", "values": {}})
    stale = tmp_path / ".radt-record-crashed.tmp"
    stale.write_text("{}", encoding="utf-8")
    _age(stale, 3600)
    store.save({"profile_id": "ops", "values": {"v": 1}})
    assert stale.exists()  # swept again only after the interval


def test_sweep_never_follows_a_symlinked_temp_name(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    store_dir = tmp_path / "store"
    store = FileProfileStore(str(store_dir))
    store.save({"profile_id": "seed", "values": {}})
    link = store_dir / ".radt-record-link.tmp"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")
    if os.utime in os.supports_follow_symlinks:
        old = time.time() - 3600
        os.utime(link, (old, old), follow_symlinks=False)

    store_diagnostics._TEMP_SWEEP_LAST_RUN.clear()
    store.save({"profile_id": "ops", "values": {"v": 1}})

    assert outside.read_text(encoding="utf-8") == "keep"
    assert link.is_symlink()
