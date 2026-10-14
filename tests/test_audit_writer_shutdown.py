"""Queued audit events reach disk at interpreter exit and when a log is dropped."""
from __future__ import annotations

import gc
import json
import subprocess
import sys
import textwrap
import threading
import time
import weakref
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import AuditLog

REPO_ROOT = Path(__file__).resolve().parents[1]

_EXIT_CHILD = textwrap.dedent(
    """
    import sys
    import role_aware_dashboard_toolkit as radt
    import role_aware_dashboard_toolkit.audit as audit_module

    # This checks drain correctness on slow filesystems. The blocked-append
    # tests below independently enforce the shutdown deadline.
    audit_module._WRITER_STOP_TIMEOUT_SECONDS = 15

    audit = radt.AuditLog()
    audit.start_writer(sys.argv[1])
    for index in range(int(sys.argv[2])):
        audit.log("evt", detail=str(index))
    # No stop_writer(): a normal interpreter exit right after the last event.
    """
)


def _types(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [json.loads(line)["type"] for line in path.read_text(encoding="utf-8").splitlines()]


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_normal_exit_drains_queued_events(tmp_path):
    for trial, count in enumerate((1, 300)):
        path = tmp_path / f"exit-{trial}.jsonl"
        subprocess.run(
            [sys.executable, "-B", "-c", _EXIT_CHILD, str(path), str(count)],
            check=True, cwd=REPO_ROOT, timeout=60,
        )
        types = _types(path)
        assert types.count("evt") == count, (count, types.count("evt"))
        assert types[0] == "audit_writer_start"
        assert types[-1] == "audit_writer_stop"


def test_exit_stop_record_names_the_exit_source(tmp_path):
    path = tmp_path / "exit.jsonl"
    subprocess.run(
        [sys.executable, "-B", "-c", _EXIT_CHILD, str(path), "1"],
        check=True, cwd=REPO_ROOT, timeout=60,
    )
    last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert (last["type"], last["source"]) == ("audit_writer_stop", "atexit")


def test_stop_writer_unregisters_the_exit_drain(tmp_path):
    child = textwrap.dedent(
        """
        import atexit, sys
        import role_aware_dashboard_toolkit as radt

        audit = radt.AuditLog()
        audit.start_writer(sys.argv[1])
        audit.stop_writer()
        audit.log("after_stop")
        """
    )
    path = tmp_path / "stopped.jsonl"
    subprocess.run([sys.executable, "-B", "-c", child, str(path)], check=True, cwd=REPO_ROOT, timeout=60)
    assert _types(path) == ["audit_writer_start", "audit_writer_stop"]


def test_dropped_logs_stop_their_writer_threads_after_draining(tmp_path):
    logs = [AuditLog() for _ in range(20)]
    for index, audit in enumerate(logs):
        audit.start_writer(str(tmp_path / f"dropped-{index}.jsonl"))
        audit.log("before_drop", detail=str(index))
    threads = [audit._writer_thread for audit in logs]
    refs = [weakref.ref(audit) for audit in logs]
    del audit, logs
    gc.collect()

    assert all(ref() is None for ref in refs), "a writer thread kept its AuditLog alive"
    assert _wait_for(lambda: not any(thread.is_alive() for thread in threads))
    for index in range(20):
        assert "before_drop" in _types(tmp_path / f"dropped-{index}.jsonl")


def test_restarted_writer_does_not_leave_the_old_thread_running(tmp_path):
    audit = AuditLog()
    audit.start_writer(str(tmp_path / "first.jsonl"))
    first = audit._writer_thread
    audit.start_writer(str(tmp_path / "second.jsonl"))
    try:
        assert not first.is_alive()
        assert audit._writer_thread.is_alive()
    finally:
        audit.stop_writer()


@pytest.mark.parametrize("at_exit", [False, True], ids=["explicit-stop", "exit-drain"])
def test_final_stop_append_obeys_timeout_and_retains_writer(tmp_path, monkeypatch, caplog, at_exit):
    import role_aware_dashboard_toolkit.audit as audit_module

    monkeypatch.setattr(audit_module, "_WRITER_STOP_TIMEOUT_SECONDS", 0.4)
    path = tmp_path / "audit.jsonl"
    audit = AuditLog()
    audit.start_writer(str(path))
    writer = audit._writer_thread
    store = audit._writer_store
    original_append = store.append
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    errors = []

    def blocked_stop_append(event):
        if event["type"] == "audit_writer_stop":
            entered.set()
            assert release.wait(10), "test did not release the final append"
        original_append(event)

    monkeypatch.setattr(store, "append", blocked_stop_append)

    def stop():
        try:
            if at_exit:
                audit_module._drain_writer_at_exit(weakref.ref(audit), writer, audit._writer_stop)
            else:
                audit.stop_writer(role="Admin", source="ui", user_id="original-user", session_id="original-session")
        except Exception as exc:
            errors.append(exc)
        finally:
            finished.set()

    caller = threading.Thread(target=stop, daemon=True)
    caller.start()
    try:
        assert entered.wait(3), "writer did not reach its final append"
        assert finished.wait(1.5), "final append bypassed the writer shutdown timeout"
        if at_exit:
            assert not errors
            assert "could not be drained at exit" in caplog.text
        else:
            assert len(errors) == 1 and isinstance(errors[0], TimeoutError)
        assert audit._writer_thread is writer and writer.is_alive()
        assert audit._writer_store is store
        assert audit.writer_status()["last_writer_error"]["error_type"] == "TimeoutError"

        # Retrying or moving a still-owned writer cannot overlap its final write.
        with pytest.raises(TimeoutError):
            audit.start_writer(str(tmp_path / "replacement.jsonl"), user_id="replacement-user")
        with pytest.raises(TimeoutError):
            audit.stop_writer(user_id="retry-user")
        stops = [event for event in audit.all_events() if event["type"] == "audit_writer_stop"]
        assert len(stops) == 1
        assert stops[0]["source"] == ("atexit" if at_exit else "ui")
        assert stops[0]["user_id"] == ("" if at_exit else "original-user")
        assert stops[0]["session_id"] == ("" if at_exit else "original-session")
        assert not (tmp_path / "replacement.jsonl").exists()
    finally:
        release.set()
        caller.join(3)
        writer.join(3)
        audit.stop_writer(user_id="cleanup-user")

    persisted = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [event["type"] for event in persisted] == ["audit_writer_start", "audit_writer_stop"]
    assert persisted[-1] == stops[0]
    assert audit.writer_status()["writer_active"] is False

    replacement = tmp_path / "replacement.jsonl"
    audit.start_writer(str(replacement))
    audit.stop_writer()
    assert _types(replacement) == ["audit_writer_start", "audit_writer_stop"]


def test_full_queue_drains_before_stop_request_without_dropping_it(tmp_path, monkeypatch):
    import role_aware_dashboard_toolkit.audit as audit_module

    monkeypatch.setattr(audit_module, "_WRITER_STOP_TIMEOUT_SECONDS", 0.1)
    path = tmp_path / "full.jsonl"
    audit = AuditLog()
    audit.start_writer(str(path), queue_size=1)
    assert _wait_for(lambda: _types(path) == ["audit_writer_start"])
    writer = audit._writer_thread
    store = audit._writer_store
    original_append = store.append
    entered = threading.Event()
    release = threading.Event()

    def blocked_append(event):
        if event["type"] == "inflight":
            entered.set()
            assert release.wait(10), "test did not release the queued append"
        original_append(event)

    monkeypatch.setattr(store, "append", blocked_append)
    try:
        audit.log("inflight")
        assert entered.wait(3)
        audit.log("queued")
        with pytest.raises(TimeoutError):
            audit.stop_writer(user_id="first-user")
        assert audit.writer_status()["queued_events"] == 1
        assert audit.writer_status()["dropped_events"] == 0
        # Subsequent memory-only events cannot be persisted after the stop line.
        audit.log("after_stop_request")
    finally:
        release.set()
        writer.join(3)
        audit.stop_writer(user_id="retry-user")

    persisted = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [event["type"] for event in persisted] == [
        "audit_writer_start", "inflight", "queued", "audit_writer_stop",
    ]
    assert persisted[-1]["user_id"] == "first-user"
    assert audit.writer_status()["dropped_events"] == 0


def test_dropped_log_during_final_append_does_not_keep_owner_alive(tmp_path, monkeypatch):
    import role_aware_dashboard_toolkit.audit as audit_module

    monkeypatch.setattr(audit_module, "_WRITER_STOP_TIMEOUT_SECONDS", 0.4)
    path = tmp_path / "collected.jsonl"
    audit = AuditLog()
    audit.start_writer(str(path))
    writer = audit._writer_thread
    store = audit._writer_store
    original_append = store.append
    entered = threading.Event()
    release = threading.Event()

    def blocked_append(event):
        if event["type"] == "audit_writer_stop":
            entered.set()
            assert release.wait(10), "test did not release the final append"
        original_append(event)

    monkeypatch.setattr(store, "append", blocked_append)
    try:
        with pytest.raises(TimeoutError):
            audit.stop_writer()
        assert entered.wait(3)
        owner = weakref.ref(audit)
        del audit
        gc.collect()
        assert owner() is None, "final append retained its AuditLog"
    finally:
        release.set()
        writer.join(3)
    assert not writer.is_alive()
    assert _types(path) == ["audit_writer_start", "audit_writer_stop"]
