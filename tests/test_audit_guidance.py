"""Audit writer diagnostics preserve lifecycle without exposing exception payloads."""
from __future__ import annotations

import importlib
import json
import logging

import pytest

from role_aware_dashboard_toolkit import AuditLog
from role_aware_dashboard_toolkit.diagnostics import diagnostic_text


def _error(hostile):
    class UnprintableError(RuntimeError):
        def __str__(self):
            raise AssertionError("exception formatting must not be invoked")

    error_type = UnprintableError if hostile else RuntimeError
    return error_type("writer-secret-canary at C:/private/audit.jsonl")


@pytest.mark.parametrize("hostile", [False, True])
def test_actual_background_writer_failure_preserves_status_and_hides_exception(hostile, monkeypatch, caplog):
    audit_module = importlib.import_module("role_aware_dashboard_toolkit.audit")
    error = _error(hostile)
    attempted = []

    class BrokenStore:
        def __init__(self, _path):
            pass

        def append(self, event):
            attempted.append(event)
            raise error

    monkeypatch.setattr(audit_module, "FileAuditStore", BrokenStore)
    audit = AuditLog()
    with caplog.at_level(logging.WARNING, logger=audit_module.__name__):
        audit.start_writer("synthetic-audit.jsonl")
        event = audit.log("control_change", key="workers", old_value=1, new_value=2)
        # The real thread drains the queued event before a successful bounded stop.
        audit.stop_writer()
    assert attempted == [event]
    assert audit.all_events() == [event]
    status = audit.writer_status()
    assert not status["writer_active"]
    assert status["queued_events"] == 0
    assert status["writer_error_count"] == 1
    assert status["last_writer_error"] == {
        "error_type": type(error).__name__,
        "exception_type": type(error).__name__,
        "message": diagnostic_text("RADT-AUDIT-IO"),
    }
    combined = json.dumps(status) + caplog.text
    assert "writer-secret-canary" not in combined
    assert "private/audit" not in combined
    assert "exception formatting" not in combined


@pytest.mark.parametrize("hostile", [False, True])
def test_writer_liveness_logging_uses_fixed_guidance_without_formatting_exception(hostile, caplog):
    error = _error(hostile)

    class UnknownLiveness:
        def is_alive(self):
            raise error

    audit = AuditLog()
    thread = UnknownLiveness()
    audit._writer_thread = thread
    with caplog.at_level(logging.WARNING, logger="role_aware_dashboard_toolkit.audit"):
        audit._rollback_failed_writer_start_locked(thread)
    assert audit._writer_thread is thread
    assert audit._writer_stop.is_set()
    assert "retaining ownership" in caplog.text
    assert type(error).__name__ in caplog.text
    assert diagnostic_text("RADT-AUDIT-IO") in caplog.text
    assert "writer-secret-canary" not in caplog.text
    assert "private/audit" not in caplog.text
    assert "exception formatting" not in caplog.text
