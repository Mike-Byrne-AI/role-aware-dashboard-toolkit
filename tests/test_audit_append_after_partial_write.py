"""An append after a torn audit line starts on a fresh line and stays readable."""
from __future__ import annotations

import errno
import os

import pytest

from role_aware_dashboard_toolkit import FileAuditStore
from role_aware_dashboard_toolkit import store_diagnostics


def _event(event_type: str, detail: str = "") -> dict:
    return {
        "schema_version": 1, "ts": "2026-10-13T00:00:00+00:00",
        "type": event_type, "source": "ui", "detail": detail,
    }


def test_append_after_a_short_failed_write_is_readable(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    store = FileAuditStore(str(path))
    store.append(_event("e1"))
    real_write = os.write
    calls = []

    def short_then_full_disk(fd, data):
        calls.append(len(data))
        if len(calls) == 1:
            return real_write(fd, bytes(data[:40]))
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(store_diagnostics.os, "write", short_then_full_disk)
        with pytest.raises(OSError):
            store.append(_event("e2", "x" * 200))

    store.append(_event("e3"))  # space is back

    reader = FileAuditStore(str(path))
    assert [row["type"] for row in reader.read_all()] == ["e1", "e3"]
    # The torn e2 line is diagnosed as its own line, not merged with e3.
    assert len(reader.read_errors) == 1
    assert reader.read_errors[0]["message"].startswith("line 2:")


def test_append_after_a_crash_torn_tail_is_readable(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = FileAuditStore(str(path))
    store.append(_event("e1"))
    with open(path, "ab") as handle:  # a process died mid-append
        handle.write(b'{"schema_version": 1, "type": "e2", "detail": "xx')
    store.append(_event("e3"))
    reader = FileAuditStore(str(path))
    assert [row["type"] for row in reader.read_all()] == ["e1", "e3"]
    assert len(reader.read_errors) == 1


def test_healthy_appends_add_no_blank_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = FileAuditStore(str(path))
    for index in range(3):
        store.append(_event(f"e{index}"))
    raw = path.read_bytes()
    assert raw.count(b"\n") == 3
    assert b"\n\n" not in raw.replace(b"\r\n", b"\n")
