"""Operator text in the incident timeline narrative renders as plain text."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, append_checkpoint, build_run
from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.security import SecurityContext

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

MARKDOWN = "![beacon](https://tracker.example/b.png) [Reset access](https://phish.example/) **urgent**"


def _consumer(host):
    import streamlit as st
    from role_aware_dashboard_toolkit.runbook_panels_parts.operator_memory import _render_operator_memory_panel

    _render_operator_memory_panel(st, host.config, host.ctx, host.run, host.run["checkpoints"][-1])


def _host():
    run = append_checkpoint(build_run({}, run_id="run-1"), {}, label=MARKDOWN)
    run["checkpoints"][-1]["ts"] = "2026-10-01T09:30:00+00:00"
    run.update(started_at="2026-10-01T09:00:00+00:00")
    config = SimpleNamespace(
        audit=AuditLog(), registry=ControlRegistry(), operator_memory_store=InMemoryOperatorMemoryStore(),
    )
    ctx = SecurityContext(role="Reviewer", perms={"can_view_team_ops": True})
    return SimpleNamespace(config=config, ctx=ctx, run=run)


def test_timeline_narrative_does_not_render_operator_text_as_markdown():
    app = AppTest.from_function(_consumer, args=(_host(),), default_timeout=15).run()
    assert not app.exception, [item.message for item in app.exception]

    narratives = [element.value for element in app.text if "Latest timeline event" in element.value]
    assert len(narratives) == 1
    assert MARKDOWN in narratives[0]
    assert not any("tracker.example" in element.value or "phish.example" in element.value
                   for element in app.markdown)
