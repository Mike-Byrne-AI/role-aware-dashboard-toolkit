"""Native runbook reads distinguish unavailable evidence from absent records."""
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import FileRunStore, InMemoryRunStore, append_checkpoint, build_run
from role_aware_dashboard_toolkit.runbook_panels import render_runbook_panel, render_runbook_sidebar
from role_aware_dashboard_toolkit.store_diagnostics import StorePathSecurityError
from tests.test_runbook_contract import _FakeStreamlit, _admin_ctx, _limited_ctx, _runbook_config
from tests.demo_role_helpers import start_as_admin


class _RunbookUI(_FakeStreamlit):
    def warning(self, value):
        self.events.append(("warning", str(value)))


def _messages(ui, kind):
    return [event[1] for event in ui.events if event[0] == kind]


def _corrupt_run(store, run_id="active"):
    path = Path(store.save(build_run({}, run_id=run_id)))
    path.write_text('{"private-marker": not-json}', encoding="utf-8")
    return path


def test_unreadable_active_run_preserves_selection_and_blocks_mutations(tmp_path):
    store = FileRunStore(str(tmp_path))
    path = _corrupt_run(store)
    before = path.read_bytes()
    config = _runbook_config(store)
    ui = _RunbookUI(
        session_state={"_radt_active_run_id": "active", "_radt_run_notes": "draft"},
        button_returns={"_radt_run_start": True, "_radt_run_checkpoint": True, "_radt_run_end": True},
    )

    render_runbook_sidebar(ui, config, _admin_ctx())

    assert ui.session_state["_radt_active_run_id"] == "active"
    assert ui.session_state["_radt_run_notes"] == "draft"
    assert path.read_bytes() == before
    assert len(store.read_errors) == 1
    assert not config.audit.all_events()
    assert not any(event[0] == "button" for event in ui.events)
    assert "No active run." not in _messages(ui, "caption")
    warnings = _messages(ui, "warning")
    assert len(warnings) == 1
    assert "selection is preserved" in warnings[0]
    assert "guide runs" in warnings[0]
    assert str(tmp_path) not in warnings[0]
    assert "private-marker" not in warnings[0]


def test_missing_active_run_still_clears_selection_after_historical_read_error(tmp_path):
    store = FileRunStore(str(tmp_path))
    _corrupt_run(store, "unrelated")
    assert store.load("unrelated") is None
    assert store.read_errors
    ui = _RunbookUI(session_state={"_radt_active_run_id": "missing"})

    render_runbook_sidebar(ui, _runbook_config(store), _admin_ctx())

    assert ui.session_state["_radt_active_run_id"] == ""
    assert not _messages(ui, "warning")
    assert "No active run." in _messages(ui, "caption")
    assert any(event[0] == "button" and event[2] == "_radt_run_start" for event in ui.events)
    assert len(store.read_errors) == 1


@pytest.mark.parametrize("fault", ["status", "checkpoint", "approval"])
def test_invalid_run_shapes_block_native_use_without_rewriting_evidence(tmp_path, fault):
    store = FileRunStore(str(tmp_path))
    invalid = append_checkpoint(build_run({}, run_id="active"), {})
    if fault == "status":
        invalid["status"] = "PRIVATE-INVALID-STATUS"
    elif fault == "checkpoint":
        invalid["checkpoints"] = [None]
    else:
        invalid["checkpoints"][0]["approval_state"] = "PRIVATE-INVALID-APPROVAL"
    path = Path(store.save(invalid))
    before = path.read_bytes()
    store.save(build_run({}, run_id="healthy"))
    config = _runbook_config(store)
    ui = _RunbookUI(
        session_state={"_radt_active_run_id": "active"},
        button_returns={"_radt_run_checkpoint": True, "_radt_run_end": True},
    )

    render_runbook_sidebar(ui, config, _admin_ctx())
    render_runbook_panel(ui, config, _admin_ctx())

    assert ui.session_state["_radt_active_run_id"] == "active"
    assert ui.session_state["_radt_selected_run_id"] == "healthy"
    assert _messages(ui, "warning")
    assert "PRIVATE-INVALID" not in repr(ui.events)
    assert not config.audit.all_events()
    assert path.read_bytes() == before
    assert not store.read_errors, "Valid JSON can still be invalid review evidence."

    store.save(build_run({}, run_id="active"))
    recovered = _RunbookUI(session_state={"_radt_active_run_id": "active"})
    render_runbook_sidebar(recovered, config, _admin_ctx())
    assert not _messages(recovered, "warning")
    assert any(event[0] == "button" and event[2] == "_radt_run_checkpoint" for event in recovered.events)


@pytest.mark.parametrize("keep_healthy", [False, True])
def test_history_warns_about_corrupt_records_and_keeps_readable_runs(tmp_path, keep_healthy):
    store = FileRunStore(str(tmp_path))
    _corrupt_run(store, "corrupt")
    if keep_healthy:
        store.save(build_run({}, run_id="healthy"))
    ui = _RunbookUI()

    render_runbook_panel(ui, _runbook_config(store), _admin_ctx())

    warnings = _messages(ui, "warning")
    assert len(warnings) == 1
    assert "could not be read completely" in warnings[0]
    assert "private-marker" not in warnings[0]
    assert str(tmp_path) not in warnings[0]
    assert "No runs recorded yet." not in _messages(ui, "caption")
    if keep_healthy:
        assert ui.session_state["_radt_selected_run_id"] == "healthy"
    else:
        assert not any(event[0] == "selectbox" for event in ui.events)


class _ReadFailureStore(InMemoryRunStore):
    def __init__(self, operation, error_type):
        super().__init__()
        self.operation = operation
        self.error_type = error_type

    def load(self, run_id):
        if self.operation == "load" and run_id == "active":
            raise self.error_type("private-token=C:/private/run.json")
        return super().load(run_id)

    def list_ids(self):
        if self.operation == "list_ids":
            raise self.error_type("private-token=C:/private/run.json")
        return super().list_ids()


@pytest.mark.parametrize("error_type", [PermissionError, ValueError, StorePathSecurityError])
@pytest.mark.parametrize("operation", ["load", "list_ids"])
def test_expected_store_exceptions_are_visible_without_payloads(operation, error_type):
    store = _ReadFailureStore(operation, error_type)
    store.save(build_run({}, run_id="active"))
    store.save(build_run({}, run_id="healthy"))
    config = _runbook_config(store)
    ui = _RunbookUI(session_state={"_radt_active_run_id": "active"})

    render_runbook_sidebar(ui, config, _admin_ctx())
    render_runbook_panel(ui, config, _admin_ctx())

    warnings = _messages(ui, "warning")
    assert warnings
    assert all("private-token" not in warning and "C:/private" not in warning for warning in warnings)
    assert ui.session_state["_radt_active_run_id"] == "active"
    assert not config.audit.all_events()
    if operation == "load":
        assert ui.session_state["_radt_selected_run_id"] == "healthy"
    assert "No runs recorded yet." not in _messages(ui, "caption")


@pytest.mark.parametrize("keep_healthy", [False, True])
def test_new_load_diagnostic_after_listing_is_visible(keep_healthy):
    class InterruptedLoadStore(InMemoryRunStore):
        read_errors = []

        def load(self, run_id):
            if run_id == "active":
                self.read_errors.append({"message": "private-token"})
                return None
            return super().load(run_id)

    store = InterruptedLoadStore()
    for run_id in (("active", "healthy") if keep_healthy else ("active",)):
        store.save(build_run({}, run_id=run_id))
    ui = _RunbookUI()

    render_runbook_panel(ui, _runbook_config(store), _admin_ctx())

    if keep_healthy:
        assert ui.session_state["_radt_selected_run_id"] == "healthy"
    else:
        assert not any(event[0] == "selectbox" for event in ui.events)
        assert not _messages(ui, "caption")
    assert len(_messages(ui, "warning")) == 1
    assert "private-token" not in _messages(ui, "warning")[0]


def test_denied_runbook_access_does_not_read_or_report_store_errors():
    class NoReads:
        def __getattr__(self, _name):
            pytest.fail("denied runbook must not access its store")

    ui = _RunbookUI(session_state={"_radt_active_run_id": "active"})
    config = _runbook_config(NoReads())
    render_runbook_sidebar(ui, config, _limited_ctx())
    render_runbook_panel(ui, config, _limited_ctx())
    assert ui.events == []
    assert ui.session_state["_radt_active_run_id"] == "active"


def test_streamlit_corrupted_active_run_preserves_drafts_and_recovers(tmp_path):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    store = FileRunStore(str(tmp_path))
    active = build_run({"workers": 4}, run_id="active")
    path = Path(store.save(active))
    store.save(build_run({}, run_id="healthy"))
    source = f'''
import streamlit as st
import role_aware_dashboard_toolkit as r
from role_aware_dashboard_toolkit.team_store import InMemoryTeamStore
from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
if "config" not in st.session_state:
    registry = r.ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=4,
                      min_value=1, max_value=20, step=1)
    st.session_state["config"] = r.DashboardConfig(
        auth_mode="demo", registry=registry, run_store=r.FileRunStore({str(tmp_path)!r}),
        team_store=InMemoryTeamStore(), operator_memory_store=InMemoryOperatorMemoryStore(),
        profile_store=r.InMemoryProfileStore(), sections=r.DashboardSections(audit_writer=False))
    st.session_state["_radt_active_run_id"] = "active"
r.render(st.session_state["config"])
'''
    app = start_as_admin(AppTest.from_string(source, default_timeout=20)).run()
    assert not app.exception
    app.text_input(key="_radt_run_notes").set_value("retained draft").run()
    app.number_input(key="workers").set_value(8).run()
    text_drafts = {
        "_radt_team_comment_body": "unsaved comment", "_radt_review_assignee": "reviewer",
        "_radt_review_assignee_role": "Reviewer", "_radt_review_title": "unsaved review",
        "_radt_handoff_to": "next operator", "_radt_handoff_role": "Operator",
        "_radt_incident_title": "unsaved incident", "_radt_incident_summary": "unsaved summary",
        "_radt_incident_cause": "unsaved cause",
    }
    for key, value in text_drafts.items():
        app.text_input(key=key).set_value(value)
    app.text_area(key="_radt_operator_note_body").set_value("unsaved note")
    app.selectbox(key="_radt_operator_note_type").select("annotation")
    app.selectbox(key="_radt_incident_severity").select("high")
    app.run()
    assert not app.exception
    all_drafts = {
        **text_drafts, "_radt_operator_note_body": "unsaved note",
        "_radt_operator_note_type": "annotation", "_radt_incident_severity": "high",
    }
    # A submitted child action cannot use an unreadable run or replay on recovery.
    app.button(key="_radt_team_comment_btn").click()
    path.write_text('{"private-marker": not-json}', encoding="utf-8")

    app.run()

    assert not app.exception
    assert app.session_state["_radt_active_run_id"] == "active"
    assert app.text_input(key="_radt_run_notes").value == "retained draft"
    assert app.number_input(key="workers").value == 8
    assert app.selectbox(key="_radt_selected_run_id").value == "healthy"
    assert app.warning
    assert all("private-marker" not in item.value and str(tmp_path) not in item.value for item in app.warning)
    assert not any(button.key in {"_radt_run_start", "_radt_run_checkpoint", "_radt_run_end"}
                   for button in app.button)
    assert not any(button.key in {"_radt_team_comment_btn", "_radt_assign_review_btn",
                                 "_radt_signoff_btn", "_radt_handoff_btn",
                                 "_radt_operator_note_btn", "_radt_operator_incident_btn"}
                   for button in app.button)
    assert not any("No runs recorded yet." in item.value for item in app.caption)
    assert {key: app.session_state[key] for key in all_drafts} == all_drafts
    app.run()
    assert not app.exception
    assert {key: app.session_state[key] for key in all_drafts} == all_drafts
    retained_store = app.session_state["config"].run_store
    old_errors = retained_store.read_errors
    assert old_errors
    store.save(active)

    app.run()

    assert not app.exception
    assert not app.warning
    assert retained_store.read_errors == old_errors
    assert app.session_state["_radt_active_run_id"] == "active"
    assert app.text_input(key="_radt_run_notes").value == "retained draft"
    assert {key: app.text_input(key=key).value for key in text_drafts} == text_drafts
    assert app.text_area(key="_radt_operator_note_body").value == "unsaved note"
    assert app.selectbox(key="_radt_operator_note_type").value == "annotation"
    assert app.selectbox(key="_radt_incident_severity").value == "high"
    config = app.session_state["config"]
    assert config.team_store.list_comments("active") == []
    assert config.team_store.list_assignments("active") == []
    assert config.team_store.list_signoffs("active") == []
    assert config.team_store.list_handoffs("active") == []
    assert config.operator_memory_store.list_notes("active") == []
    assert config.operator_memory_store.list_incidents("active") == []
    assert not app.button(key="_radt_run_checkpoint").disabled
    app.button(key="_radt_run_checkpoint").click().run()
    assert not app.exception
    assert len(store.load("active")["checkpoints"]) == 1
    assert store.load("active")["latest_controls"] == {"workers": 8}
    assert [event["type"] for event in app.session_state["config"].audit.all_events()].count("checkpoint_create") == 1
