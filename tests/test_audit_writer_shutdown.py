"""Queued audit events reach disk at interpreter exit and when a log is dropped."""
from __future__ import annotations

import gc
import json
import subprocess
import sys
import textwrap
import time
import weakref
from pathlib import Path

from role_aware_dashboard_toolkit import AuditLog

REPO_ROOT = Path(__file__).resolve().parents[1]

_EXIT_CHILD = textwrap.dedent(
    """
    import sys
    import role_aware_dashboard_toolkit as radt

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
