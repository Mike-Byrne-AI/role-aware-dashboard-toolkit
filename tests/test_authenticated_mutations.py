"""Exercise native write boundaries after UI state and current grants diverge."""
from __future__ import annotations

import json

import pytest

from role_aware_dashboard_toolkit import InMemoryRunStore, append_checkpoint, build_run
from role_aware_dashboard_toolkit.access_audit import bind_audit_identity
from role_aware_dashboard_toolkit.case_store import InMemoryCaseStore
from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.decision_store import InMemoryDecisionStore
from role_aware_dashboard_toolkit.governance_store import InMemoryGovernanceStore
from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.runbook_panels import render_runbook_sidebar
from role_aware_dashboard_toolkit.runbook_panels_parts.caseboard import _render_caseboard_panel
from role_aware_dashboard_toolkit.runbook_panels_parts.decisions import _render_decision_panel
from role_aware_dashboard_toolkit.runbook_panels_parts.governance import _render_governance_panel
from role_aware_dashboard_toolkit.runbook_panels_parts.operator_memory import (
    _render_operator_memory_panel,
    _render_operator_memory_sidebar,
)
from role_aware_dashboard_toolkit.runbook_panels_parts.team_ops import _render_team_ops_sidebar
from role_aware_dashboard_toolkit.security import BUILTIN_ROLES, SecurityContext
from role_aware_dashboard_toolkit.team_store import InMemoryTeamStore
from tests.test_runbook_contract import _FakeStreamlit, _runbook_config


USER_ID = "a" * 64
SESSION_ID = "1" * 32
ACTIONS = (
    "run_start", "run_checkpoint", "run_end", "team_comment", "review_assign",
    "signoff", "handoff", "operator_note", "incident", "narrative",
    "case_create", "case_reopen", "case_close", "case_note", "decision", "governance",
)


class _ActionStreamlit(_FakeStreamlit):
    def __init__(self, target, state, *, on_click=None):
        super().__init__(session_state=state)
        self.target = target
        self.on_click = on_click
        self.clicked = False

    def button(self, label, key=None, disabled=False, **kwargs):
        self.events.append(("button", str(label), str(key or ""), bool(disabled)))
        if key != self.target:
            return False
        self.clicked = True
        if self.on_click:
            self.on_click()
        # Deliberately return a forged click even when UI state was disabled.
        return True


def _scenario(action):
    run = append_checkpoint(build_run({}, run_id="run_test"), {}, label="baseline")
    checkpoint = run["checkpoints"][-1]
    config = _runbook_config(
        InMemoryRunStore(),
        team_store=InMemoryTeamStore(),
        operator_memory_store=InMemoryOperatorMemoryStore(),
        case_store=InMemoryCaseStore(),
        decision_store=InMemoryDecisionStore(),
        governance_store=InMemoryGovernanceStore(),
    )
    config.run_store.save(run)
    config.case_store.save(build_case_record(
        "Existing case", case_id="case_test", linked_run_ids=[run["run_id"]],
        state="closed" if action == "case_reopen" else "open",
    ))
    config.audit = bind_audit_identity(config.audit, USER_ID, SESSION_ID)
    state = {
        "_radt_active_run_id": "" if action == "run_start" else run["run_id"],
        "_radt_selected_case_id": "case_test",
        "_radt_user_id": "spoofed-actor@example.test",
        "_radt_session_id": "spoofed-session",
        "_radt_team_comment_body": "A review comment",
        "_radt_review_assignee": "reviewer",
        "_radt_operator_note_body": "An operator note",
        "_radt_incident_title": "A test incident",
        "_radt_case_title": "A new case",
        "_radt_case_note_body": "A finding",
    }
    targets = {
        "run_start": "_radt_run_start",
        "run_checkpoint": "_radt_run_checkpoint",
        "run_end": "_radt_run_end",
        "team_comment": "_radt_team_comment_btn",
        "review_assign": "_radt_assign_review_btn",
        "signoff": "_radt_signoff_btn",
        "handoff": "_radt_handoff_btn",
        "operator_note": "_radt_operator_note_btn",
        "incident": "_radt_operator_incident_btn",
        "narrative": f"_radt_save_narrative_{run['run_id']}",
        "case_create": "_radt_case_create_btn",
        "case_reopen": "_radt_reopen_case_case_test",
        "case_close": "_radt_close_case_case_test",
        "case_note": "_radt_case_append_note_case_test",
        "decision": f"_radt_decision_save::{run['run_id']}::{checkpoint['checkpoint_id']}",
        "governance": "_radt_governance_save::case_test",
    }

    def render(st, ctx):
        if action.startswith("run_"):
            render_runbook_sidebar(st, config, ctx)
        elif action in {"team_comment", "review_assign", "signoff", "handoff"}:
            _render_team_ops_sidebar(st, config, ctx, run)
        elif action in {"operator_note", "incident"}:
            _render_operator_memory_sidebar(st, config, ctx, run)
        elif action == "narrative":
            _render_operator_memory_panel(st, config, ctx, run, checkpoint)
        elif action.startswith("case_"):
            _render_caseboard_panel(st, config, ctx, [run], run)
        elif action == "decision":
            _render_decision_panel(st, config, ctx, run, checkpoint)
        else:
            _render_governance_panel(st, config, ctx, [run])

    return config, state, targets[action], render


def _snapshot(config):
    return {
        "runs": [config.run_store.load(run_id) for run_id in config.run_store.list_ids()],
        "comments": config.team_store.list_comments(),
        "assignments": config.team_store.list_assignments(),
        "signoffs": config.team_store.list_signoffs(),
        "handoffs": config.team_store.list_handoffs(),
        "notes": config.operator_memory_store.list_notes(),
        "incidents": config.operator_memory_store.list_incidents(),
        "narratives": config.operator_memory_store.list_narratives(),
        "cases": config.case_store.list_cases(),
        "decisions": config.decision_store.list_by_run("run_test"),
        "governance": config.governance_store.list_records(),
        "audit": config.audit.all_events(),
    }


def _authenticated_context(authorize):
    return SecurityContext(
        role="Admin", perms=dict(BUILTIN_ROLES["Admin"].perms),
        authenticated=True, user_id=USER_ID, session_id=SESSION_ID,
        _authorize=authorize,
    )


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("boundary", ["frozen", "revoked_on_click"])
def test_native_writes_obey_shared_freeze_and_recheck_current_grants(action, boundary):
    config, state, target, render = _scenario(action)
    current = {"allowed": True}

    def authorize(permission, writing):
        return current["allowed"] and not (boundary == "frozen" and writing)

    def revoke():
        current["allowed"] = False

    st = _ActionStreamlit(target, state, on_click=revoke if boundary == "revoked_on_click" else None)
    before = _snapshot(config)
    render(st, _authenticated_context(authorize))

    assert _snapshot(config) == before
    assert not any(event[0] in {"toast", "rerun"} for event in st.events)
    if boundary == "revoked_on_click":
        assert st.clicked, "The test must reach the enabled action before revocation."


@pytest.mark.parametrize("action", ACTIONS)
def test_authorized_native_writes_succeed_and_use_principal_not_session_actor(action):
    config, state, target, render = _scenario(action)
    before = _snapshot(config)
    st = _ActionStreamlit(target, state)
    render(st, _authenticated_context(lambda permission, writing: True))
    after = _snapshot(config)

    assert st.clicked
    assert after != before
    persisted = json.dumps(after)
    assert USER_ID in persisted
    assert "spoofed-actor" not in persisted
    assert "spoofed-session" not in persisted
    if action == "run_start":
        new_runs = [run for run in after["runs"] if run["run_id"] != "run_test"]
        assert new_runs[0]["actor"] == USER_ID
        assert new_runs[0]["session_id"] == SESSION_ID


@pytest.mark.parametrize("action", ACTIONS)
def test_legacy_record_permissions_keep_existing_session_freeze_behavior(action):
    config, state, target, render = _scenario(action)
    ctx = SecurityContext(
        role="Admin", perms=dict(BUILTIN_ROLES["Admin"].perms), controls_writable=False,
    )
    before = _snapshot(config)
    st = _ActionStreamlit(target, state)
    render(st, ctx)
    assert st.clicked
    assert _snapshot(config) != before


def test_checkpoint_approval_is_rechecked_after_click():
    config, state, target, render = _scenario("run_checkpoint")
    current = {"approve": True}

    def authorize(permission, writing):
        return permission != "can_approve_changes" or current["approve"]

    def revoke_approval():
        current["approve"] = False

    st = _ActionStreamlit(target, state, on_click=revoke_approval)
    render(st, _authenticated_context(authorize))
    checkpoints = config.run_store.load("run_test")["checkpoints"]
    assert len(checkpoints) == 2
    assert checkpoints[-1]["approval_state"] == "proposed"
