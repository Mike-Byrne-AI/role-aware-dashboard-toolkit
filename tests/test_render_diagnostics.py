"""Real rendering proof for diagnostic privacy, retained samples, and audit tables."""
from __future__ import annotations

from copy import deepcopy
import json
import logging

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _telemetry_consumer(initial_mode="success"):
    import streamlit as st
    from role_aware_dashboard_toolkit import AuditLog
    from role_aware_dashboard_toolkit.observability import ObservabilityConfig, ObservabilityPanel

    st.session_state.setdefault("mode", initial_mode)

    def sample():
        st.session_state["attempts"] = st.session_state.get("attempts", 0) + 1
        if st.session_state["mode"] == "failed":
            raise RuntimeError("raw-secret-canary at C:/private/telemetry.json")
        if st.session_state["mode"] == "empty":
            return None
        return {"ts": "2026-09-10T12:34:56+00:00", "metrics": {"queue": 12}}

    panel = ObservabilityPanel(
        ObservabilityConfig(enabled=True, telemetry_hook=sample, show_summary=False),
        AuditLog(), st.session_state,
    )
    panel.render(st)


def _callback_consumer(callback_kind):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    def fail(*_args):
        st.session_state["callback_calls"] = st.session_state.get("callback_calls", 0) + 1
        raise RuntimeError("raw-secret-canary at C:/private/callback.json")

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Workers", kind="number", key="workers", default=2,
                          min_value=1, max_value=10, step=1,
                          callback=fail if callback_kind == "control" else None)
        st.session_state["config"] = radt.DashboardConfig(
            auth_mode="demo",
            registry=registry, on_change=fail if callback_kind == "global" else None,
        )
    radt.render(st.session_state["config"])


def _audit_consumer():
    import streamlit as st
    from role_aware_dashboard_toolkit import AuditLog
    from role_aware_dashboard_toolkit.dashboard_panels import render_audit_panel

    if "audit" not in st.session_state:
        audit = AuditLog()
        changes = [
            ("workers", 1, 2),
            ("enabled", True, False),
            ("priority", "Steady", "Urgent"),
            ("options", {"size": 1, "api_token": "nested-secret-canary"}, {"size": 2}),
            ("optional", None, "configured"),
        ]
        for key, old, new in changes:
            audit.log_control_change(key, old, new, role="Admin")
        audit.log_control_change("credential", "old-secret-canary", "new-secret-canary",
                                 sensitive=True, role="Admin")
        st.session_state["audit"] = audit
        st.session_state["original_events"] = audit.all_events()
    render_audit_panel(st, st.session_state["audit"])


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


@pytest.mark.parametrize("mode", ["failed", "empty"])
def test_retained_telemetry_is_explicitly_old_and_keeps_original_timestamp(mode):
    from role_aware_dashboard_toolkit.diagnostics import build_diagnostic

    app = _healthy(AppTest.from_function(_telemetry_consumer).run())
    prior = deepcopy(app.session_state["_radt_last_telemetry"])
    app.session_state["mode"] = mode
    _healthy(app.run())
    assert app.session_state["_radt_last_telemetry"] == prior
    assert len(app.session_state["_radt_observability_history"]) == 1
    assert app.session_state["attempts"] == 2  # Hook effects have not been rolled back.
    captions = "\n".join(item.value for item in app.caption)
    assert f"retained sample from {prior['ts']}" in captions
    assert "no new sample was collected" in captions
    assert app.metric[0].value == "12.0"
    warnings = "\n".join(item.value for item in app.warning)
    if mode == "failed":
        diagnostic = build_diagnostic("RADT-TELEMETRY")
        assert "Telemetry sampling failed (RuntimeError)" in warnings
        assert diagnostic["code"] in warnings
        assert diagnostic["guide_command"] in warnings
        assert diagnostic["effect"] in warnings
    else:
        assert not warnings
    assert "raw-secret-canary" not in warnings
    assert "private/telemetry" not in warnings


@pytest.mark.parametrize("mode", ["failed", "empty"])
def test_missing_first_sample_does_not_claim_a_retained_sample(mode):
    app = _healthy(AppTest.from_function(_telemetry_consumer, args=(mode,)).run())
    assert "_radt_last_telemetry" not in app.session_state
    assert not app.metric
    assert any("No telemetry samples yet" in item.value for item in app.caption)
    assert not any("Showing the retained sample" in item.value for item in app.caption)


@pytest.mark.parametrize("callback_kind", ["control", "global"])
def test_callback_diagnostic_hides_raw_exception_and_preserves_completed_effects(callback_kind):
    from role_aware_dashboard_toolkit.diagnostics import build_diagnostic

    app = _healthy(AppTest.from_function(_callback_consumer, args=(callback_kind,)).run())
    _healthy(app.number_input(key="workers").set_value(5).run())
    assert app.number_input(key="workers").value == 5
    assert app.session_state["callback_calls"] == 1
    audit = app.session_state["config"].audit
    events = audit.all_events()
    changed = [event for event in events if event["type"] == "control_change"]
    assert changed[-1]["new"] == 5
    errors = [event for event in events if event["type"] == "callback_error"]
    assert len(errors) == 1
    diagnostic = build_diagnostic("RADT-CALLBACK")
    visible = "\n".join(item.value for item in app.error)
    assert diagnostic["code"] in visible
    assert diagnostic["effect"] in visible
    assert diagnostic["guide_command"] in visible
    assert "RuntimeError" in visible
    assert diagnostic["code"] in errors[0]["detail"]
    combined = visible + audit.export_jsonl()
    assert "raw-secret-canary" not in combined
    assert "private/callback" not in combined


def test_mixed_audit_cells_render_without_arrow_fallback_or_raw_record_mutation(caplog, monkeypatch):
    pandas = pytest.importorskip("pandas")
    arrow = pytest.importorskip("pyarrow")
    logger = logging.getLogger("streamlit.dataframe_util")
    monkeypatch.setattr(logger, "propagate", True)
    with caplog.at_level(logging.INFO, logger=logger.name):
        app = _healthy(AppTest.from_function(_audit_consumer).run())
    assert not any("Serialization of dataframe to Arrow" in record.getMessage()
                   for record in caplog.records)
    assert not any(record.exc_info for record in caplog.records
                   if record.name == logger.name)
    assert len(app.dataframe) == 1
    display = app.dataframe[0].value
    table = arrow.Table.from_pandas(display, preserve_index=False)
    # pandas 3 uses Arrow's large-string storage for the same text values.
    for column in ("old", "new"):
        assert table.schema.field(column).type in (arrow.string(), arrow.large_string())
    assert list(display["new"][:3]) == ["2", "False", "Urgent"]
    assert "'size': 2" in display["new"][3]
    assert pandas.isna(display["old"][4])
    assert table["old"][4].as_py() is None
    audit = app.session_state["audit"]
    events = audit.all_events()
    assert events == app.session_state["original_events"]
    assert [type(event["old"]) for event in events[:4]] == [int, bool, str, dict]
    exported = [json.loads(line) for line in audit.export_jsonl().splitlines()]
    assert exported == events
    assert exported[3]["old"]["size"] == 1
    assert exported[3]["old"]["api_token"] != "nested-secret-canary"
    visible = display.to_json() + "".join(item.value for item in app.json)
    for secret in ("nested-secret-canary", "old-secret-canary", "new-secret-canary"):
        assert secret not in visible
        assert secret not in audit.export_jsonl()
    # The underlying mixed values still reproduce the Arrow incompatibility.
    with pytest.raises((arrow.ArrowInvalid, arrow.ArrowTypeError)):
        arrow.Table.from_pandas(pandas.DataFrame(events), preserve_index=False)
