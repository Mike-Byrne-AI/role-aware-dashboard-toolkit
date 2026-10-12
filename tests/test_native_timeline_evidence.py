"""Run narratives summarize captured evidence without borrowing a session's past."""
from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, append_checkpoint, build_run
from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.security import SecurityContext


AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _consumer(host):
    import streamlit as st
    from role_aware_dashboard_toolkit.runbook_panels_parts.operator_memory import _render_operator_memory_panel

    st.session_state["_radt_observability_history"] = host.live_history
    _render_operator_memory_panel(st, host.config, host.ctx, host.run, host.run["checkpoints"][-1])


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


def _host(*, captured=True, can_view_audit=True, can_view_metrics=True):
    audit = AuditLog()
    audit.log("run_end", detail="unrelated-live-run", role="Admin")
    event = {
        "ts": "2026-10-01T09:15:00+00:00", "type": "control_change",
        "key": "workers", "old": 1, "new": 2, "detail": "captured audit context",
    }
    sample = {
        "ts": "2026-10-01T09:20:00+00:00", "metrics": {"latency_ms": 750},
        "health": {"status": "degraded"},
    }
    run = build_run({}, run_id="historical-run")
    for index in range(2):
        # Checkpoints commonly retain overlapping audit history and the same
        # last displayed telemetry sample; these are not additional events.
        run = append_checkpoint(
            run, {}, audit_events=[event] if captured else [],
            telemetry=sample if captured else {}, label=f"checkpoint-{index}",
        )
        run["checkpoints"][-1]["ts"] = f"2026-10-01T09:{30 + index}:00+00:00"
    run.update(started_at="2026-10-01T09:00:00+00:00",
               ended_at="2026-10-01T10:00:00+00:00", status="completed")
    config = SimpleNamespace(
        audit=audit, registry=ControlRegistry(), operator_memory_store=InMemoryOperatorMemoryStore(),
    )
    ctx = SecurityContext(role="Reviewer", perms={
        "can_view_team_ops": True, "can_export_packets": True, "can_manage_runs": True,
        "can_view_audit": can_view_audit, "can_view_metrics": can_view_metrics,
    })
    return SimpleNamespace(config=config, ctx=ctx, run=run, live_history=[{
        "ts": "2026-10-12T10:00:00+00:00", "metrics": {"risk_score": 0.99},
        "health": {"status": "critical"},
    }])


def _narrative(app):
    return next(record for item in app.json
                if (record := json.loads(item.value)).get("event_type") == "narrative_handoff")


@pytest.mark.parametrize("captured", [True, False])
def test_narrative_preview_and_save_use_only_selected_run_captured_context(captured):
    host = _host(captured=captured)
    originals = deepcopy((host.run, host.live_history, host.config.audit.all_events()))
    app = _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())

    preview = _narrative(app)
    assert "unrelated-live-run" not in str(preview)
    assert "risk_score=0.99" not in str(preview)
    events = preview["highlights"]
    assert sum(item["event_type"] == "audit_event" for item in events) == int(captured)
    assert sum(item["event_type"] == "telemetry_alert" for item in events) == int(captured)
    if captured:
        assert "captured audit context" in str(events)
        assert "latency_ms=750.0" in str(events)
    _healthy(app.button(key="_radt_save_narrative_historical-run").click().run())

    saved = host.config.operator_memory_store.list_narratives("historical-run")
    assert len(saved) == 1
    assert saved[0]["highlights"] == preview["highlights"]
    assert saved[0]["summary"] == preview["summary"]
    assert host.run == originals[0] and host.live_history == originals[1]
    assert host.config.audit.all_events()[:-1] == originals[2]


@pytest.mark.parametrize("audit_allowed,metrics_allowed", [(False, True), (True, False), (False, False)])
def test_captured_timeline_context_keeps_read_permissions(audit_allowed, metrics_allowed):
    host = _host(can_view_audit=audit_allowed, can_view_metrics=metrics_allowed)
    app = _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())
    events = _narrative(app)["highlights"]
    assert any(item["event_type"] == "audit_event" for item in events) is audit_allowed
    assert any(item["event_type"] == "telemetry_alert" for item in events) is metrics_allowed
    assert ("captured audit context" in str(events)) is audit_allowed
    assert ("latency_ms=750.0" in str(events)) is metrics_allowed


def test_captured_telemetry_is_projected_before_building_timeline_strings():
    host = _host()
    # Secret-name projection also applies before values are embedded in a
    # telemetry alert's text. The original captured record stays untouched.
    host.run["checkpoints"][0]["telemetry_slice"]["health"]["status"] = {
        "password": "CAPTURED-SECRET-CANARY",
    }
    before = deepcopy(host.run)

    app = _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())

    narrative = str(_narrative(app)).casefold()
    assert "captured-secret-canary" not in narrative
    assert "<redacted-secret>" in narrative
    _healthy(app.button(key="_radt_save_narrative_historical-run").click().run())
    saved = str(host.config.operator_memory_store.list_narratives("historical-run")).casefold()
    assert "captured-secret-canary" not in saved
    assert "<redacted-secret>" in saved
    assert host.run == before
