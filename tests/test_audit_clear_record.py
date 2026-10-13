"""Clearing the in-memory audit view leaves an attributed record of the clear."""
from __future__ import annotations

import importlib
import json

from role_aware_dashboard_toolkit import AuditLog, make_security_context
from role_aware_dashboard_toolkit.access_audit import bind_audit_identity
from tests.test_role_aware_dashboard_toolkit import RecordingStreamlit

_PRINCIPAL = "c" * 64
_SESSION = "d" * 32


class _ClearClickStreamlit(RecordingStreamlit):
    def button(self, _label, *, key=None, disabled=False, **_kwargs):
        return key in {"_radt_audit_clear_btn", "_radt_audit_clear"} and not disabled


def test_clear_records_the_count_in_memory_and_on_disk(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog()
    audit.start_writer(str(path))
    for index in range(3):
        audit.log("evt", detail=str(index))
    cleared = audit.clear(role="Admin", source="ui")
    audit.stop_writer()

    assert cleared == 4  # the start record and three events
    memory = audit.all_events()
    assert [event["type"] for event in memory] == ["audit_cleared", "audit_writer_stop"]
    assert (memory[0]["old"], memory[0]["new"], memory[0]["role"], memory[0]["source"]) == (
        4, 0, "Admin", "ui",
    )
    disk = [json.loads(line)["type"] for line in path.read_text(encoding="utf-8").splitlines()]
    assert disk == [
        "audit_writer_start", "evt", "evt", "evt", "audit_cleared", "audit_writer_stop",
    ]


def test_clear_of_an_empty_view_is_still_recorded():
    audit = AuditLog()
    assert audit.clear() == 0
    assert [(event["type"], event["old"], event["source"]) for event in audit.all_events()] == [
        ("audit_cleared", 0, "host"),
    ]


def test_panel_clear_records_the_operator(monkeypatch):
    dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
    monkeypatch.setattr(dashboard_panels, "PANDAS_AVAILABLE", False)
    audit = AuditLog()
    audit.log_control_change("temperature", 0.7, 0.9, role="Operator")
    ctx = make_security_context("Admin", {"can_manage_audit": True, "can_view_audit": True})

    dashboard_panels.render_audit_panel(_ClearClickStreamlit(), audit, ctx)

    events = audit.all_events()
    assert [(e["type"], e["old"], e["role"], e["source"]) for e in events] == [
        ("audit_cleared", 1, "Admin", "ui"),
    ]


def test_panel_clear_through_a_bound_view_records_the_actor(monkeypatch):
    dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
    monkeypatch.setattr(dashboard_panels, "PANDAS_AVAILABLE", False)
    parent = AuditLog()
    view = bind_audit_identity(parent, _PRINCIPAL, _SESSION)
    ctx = make_security_context("Admin", {"can_manage_audit": True, "can_view_audit": True})

    dashboard_panels.render_audit_panel(_ClearClickStreamlit(), view, ctx)

    [record] = parent.all_events()
    assert (record["type"], record["user_id"], record["session_id"]) == (
        "audit_cleared", _PRINCIPAL, _SESSION,
    )
