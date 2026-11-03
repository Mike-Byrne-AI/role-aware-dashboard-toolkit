"""Independent audit stores cannot interleave records inside one process."""
from concurrent.futures import ThreadPoolExecutor
import gc
import json
import os
from pathlib import Path
from threading import Barrier, Event, current_thread
import weakref

import pytest

from role_aware_dashboard_toolkit.audit_store import FileAuditStore
from role_aware_dashboard_toolkit import store_diagnostics


def test_separate_stores_wait_through_short_write_and_tail_recovery(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    (tmp_path / "child").mkdir()
    alias = tmp_path / "child" / ".." / "audit.jsonl"
    first, second = FileAuditStore(str(path)), FileAuditStore(str(alias))
    prefix_written, second_waiting, second_wrote = Event(), Event(), Event()
    coordinator = store_diagnostics._store_append_lock(path)
    actual_lock = coordinator.lock
    writer_names = {}
    writes = []
    actual_write = store_diagnostics.os.write

    class ObservedLock:
        def __enter__(self):
            if current_thread().name == writer_names.get("second"):
                # Signal the actual lock attempt, not a scheduling delay. The
                # first writer remains paused with an incomplete JSON record.
                second_waiting.set()
            actual_lock.acquire()

        def __exit__(self, *_args):
            actual_lock.release()

    coordinator.lock = ObservedLock()

    def short_write(fd, payload):
        name = current_thread().name
        if name == writer_names.get("first") and not prefix_written.is_set():
            written = actual_write(fd, bytes(payload)[:-3])
            writes.append("first-prefix")
            prefix_written.set()
            assert second_waiting.wait(timeout=5), "second appender did not attempt the shared lock"
            assert not second_wrote.is_set(), "a second record reached an incomplete first record"
            return written
        if name == writer_names.get("second"):
            second_wrote.set()
            writes.append("second")
        else:
            writes.append("first-tail")
        return actual_write(fd, payload)

    monkeypatch.setattr(store_diagnostics.os, "write", short_write)

    def append(store, label):
        writer_names[label] = current_thread().name
        store.append({"type": label, "detail": "caf\u00e9"})

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(append, first, "first")
        assert prefix_written.wait(timeout=5)
        two = pool.submit(append, second, "second")
        one.result(timeout=10)
        two.result(timeout=10)

    assert writes == ["first-prefix", "first-tail", "second"]
    assert [json.loads(line)["type"] for line in path.read_text(encoding="utf-8").splitlines()] == ["first", "second"]
    assert first.read_errors == second.read_errors == []


def test_different_audit_paths_can_append_concurrently(tmp_path, monkeypatch):
    paths = [tmp_path / "first.jsonl", tmp_path / "second.jsonl"]
    stores = [FileAuditStore(str(path)) for path in paths]
    entered = Barrier(2)
    actual_write = store_diagnostics._write_all_store_bytes

    def competing_write(fd, payload):
        # A process-wide append lock would prevent the second independent file
        # from entering and fail this bounded rendezvous.
        entered.wait(timeout=5)
        actual_write(fd, payload)

    monkeypatch.setattr(store_diagnostics, "_write_all_store_bytes", competing_write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(store.append, {"type": str(index)}) for index, store in enumerate(stores)]
        for future in futures:
            future.result(timeout=10)
    assert [json.loads(path.read_text(encoding="utf-8"))["type"] for path in paths] == ["0", "1"]


def test_idle_path_locks_are_released_after_success_or_failure(tmp_path, monkeypatch):
    paths = [tmp_path / f"audit-{index}.jsonl" for index in range(20)]
    references = []
    actual_lock_for = store_diagnostics._store_append_lock

    def remember_lock(path):
        coordinator = actual_lock_for(path)
        references.append(weakref.ref(coordinator))
        return coordinator

    monkeypatch.setattr(store_diagnostics, "_store_append_lock", remember_lock)
    for path in paths:
        FileAuditStore(str(path)).append({"type": "written"})

    def fail_write(*_args):
        raise OSError("synthetic append failure")

    with monkeypatch.context() as patch:
        patch.setattr(store_diagnostics, "_write_all_store_bytes", fail_write)
        with pytest.raises(OSError, match="synthetic append failure"):
            FileAuditStore(str(paths[0])).append({"type": "failed"})
    # The failed append's lock must also release so a later writer can proceed.
    FileAuditStore(str(paths[0])).append({"type": "after-failure"})
    gc.collect()
    assert all(reference() is None for reference in references)
    for path in paths:
        key = os.path.normcase(str(Path(path).resolve(strict=False)))
        assert key not in store_diagnostics._STORE_APPEND_LOCKS
    assert [event["type"] for event in FileAuditStore(str(paths[0])).read_all()] == ["written", "after-failure"]
