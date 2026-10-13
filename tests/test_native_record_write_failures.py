"""Native record writes keep the app usable when persistence is uncertain."""
from copy import deepcopy

import pytest

from role_aware_dashboard_toolkit import (
    ControlRegistry, DashboardConfig, DashboardSections, InMemoryProfileStore,
    InMemoryRunStore, append_checkpoint, build_run,
)
from role_aware_dashboard_toolkit.case_store import InMemoryCaseStore
from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.decision_store import InMemoryDecisionStore
from role_aware_dashboard_toolkit.governance_store import InMemoryGovernanceStore
from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.team_store import InMemoryTeamStore
from tests.demo_role_helpers import start_as_admin

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _consumer(config, active_run_id):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    st.session_state.setdefault("_radt_active_run_id", active_run_id)
    radt.render(config)
    st.text_input("Host draft", key="host_draft")


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


def _app(*, active=True):
    registry = ControlRegistry()
    registry.register("Workers", key="workers", kind="number", default=2,
                      min_value=0, max_value=100, step=1)
    run_store = InMemoryRunStore()
    run = append_checkpoint(build_run({"workers": 2}, run_id="run-one"), {"workers": 2})
    run_store.save(run)
    cases = InMemoryCaseStore()
    cases.save(build_case_record("Existing case", case_id="case-one", linked_run_ids=["run-one"]))
    config = DashboardConfig(
        registry=registry, profile_store=InMemoryProfileStore(), run_store=run_store,
        team_store=InMemoryTeamStore(), operator_memory_store=InMemoryOperatorMemoryStore(),
        decision_store=InMemoryDecisionStore(), case_store=cases,
        governance_store=InMemoryGovernanceStore(),
        sections=DashboardSections(audit_writer=False, plugin_details=False),
    )
    app = _healthy(start_as_admin(AppTest.from_function(
        _consumer, args=(config, "run-one" if active else ""), default_timeout=15,
    )).run())
    for widget in app.text_input:
        if widget.key != "_radt_profile_name":
            widget.set_value("Retained draft")
    for widget in app.text_area:
        widget.set_value("Retained draft")
    app.number_input(key="workers").set_value(19)
    return _healthy(app.run()), config


_WRITES = [
    ("run_store", "save", "_radt_run_start"),
    ("run_store", "save", "_radt_run_checkpoint"),
    ("run_store", "save", "_radt_run_end"),
    ("team_store", "save_comment", "_radt_team_comment_btn"),
    ("team_store", "save_assignment", "_radt_assign_review_btn"),
    ("team_store", "save_signoff", "_radt_signoff_btn"),
    ("team_store", "save_handoff", "_radt_handoff_btn"),
    ("operator_memory_store", "save_note", "_radt_operator_note_btn"),
    ("operator_memory_store", "save_incident", "_radt_operator_incident_btn"),
    ("operator_memory_store", "save_narrative", "_radt_save_narrative_run-one"),
    ("case_store", "save", "_radt_case_create_btn"),
    ("case_store", "save", "_radt_reopen_case_case-one"),
    ("case_store", "save", "_radt_close_case_case-one"),
    ("case_store", "save", "_radt_case_append_note_case-one"),
    ("decision_store", "save", "_radt_decision_save::"),
    ("governance_store", "save", "_radt_governance_save::case-one"),
]


@pytest.mark.parametrize("store_name,method,button_key", _WRITES)
def test_failed_record_write_keeps_widgets_drafts_and_no_success(
    monkeypatch, store_name, method, button_key,
):
    app, config = _app(active=button_key != "_radt_run_start")
    attempts = []
    store = getattr(config, store_name)
    before_store = deepcopy(vars(store))
    before_audit = config.audit.all_events()
    before_active = app.session_state["_radt_active_run_id"]
    drafts = {widget.key: widget.value for widget in [*app.text_input, *app.text_area]}

    def fail(record):
        attempts.append(record)
        raise PermissionError("C:/private/private-store-canary.json")

    monkeypatch.setattr(store, method, fail)
    button = next(widget for widget in app.button if widget.key.startswith(button_key))
    _healthy(button.click().run())

    assert len(attempts) == 1
    assert {key: value for key, value in vars(store).items() if key != method} == before_store
    assert config.audit.all_events() == before_audit
    assert app.session_state["_radt_active_run_id"] == before_active
    assert app.number_input(key="workers").value == 19
    assert {widget.key: widget.value for widget in [*app.text_input, *app.text_area]} == drafts
    assert not app.get("toast")
    assert any("could not confirm this save" in item.value for item in app.warning)
    visible = "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))
    assert "private-store-canary" not in visible
    _healthy(app.run())
    assert len(attempts) == 1, "An unrelated rerun must not retry a failed write."


def test_store_committed_before_error_is_reported_as_uncertain_and_not_retried(monkeypatch):
    app, config = _app(active=False)
    original_save = config.run_store.save
    before_audit = config.audit.all_events()
    attempts = []

    def commit_then_fail(record):
        attempts.append(record["run_id"])
        original_save(record)
        raise RuntimeError("private-provider-canary")

    monkeypatch.setattr(config.run_store, "save", commit_then_fail)
    _healthy(app.button(key="_radt_run_start").click().run())
    assert len(config.run_store.list_ids()) == 2
    assert config.audit.all_events() == before_audit
    assert app.session_state["_radt_active_run_id"] == ""
    assert not app.get("toast")
    assert any("may have completed partially" in item.value for item in app.warning)
    _healthy(app.run())
    assert len(attempts) == 1
    assert len(config.run_store.list_ids()) == 2
