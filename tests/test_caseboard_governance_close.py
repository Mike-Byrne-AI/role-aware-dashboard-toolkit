"""The native Close case button honours governance's close_case block."""
from __future__ import annotations

import pytest

from role_aware_dashboard_toolkit import InMemoryRunStore, append_checkpoint, build_run
from role_aware_dashboard_toolkit.case_store import InMemoryCaseStore
from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.governance_store import InMemoryGovernanceStore
from role_aware_dashboard_toolkit.operator_memory import build_incident_record
from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.runbook_panels_parts.caseboard import _render_caseboard_panel
from role_aware_dashboard_toolkit.security import BUILTIN_ROLES, SecurityContext
from tests.test_runbook_contract import _FakeStreamlit, _runbook_config

CLOSE_KEY = "_radt_close_case_case_a"


class _ForgingStreamlit(_FakeStreamlit):
    """Return a click for the target button even when it is rendered disabled."""

    def __init__(self, target, state):
        super().__init__(session_state=state)
        self.target = target

    def button(self, label, key=None, disabled=False, **kwargs):
        self.events.append(("button", str(label), str(key or ""), bool(disabled)))
        return key == self.target


def _scenario(*, incident_status="open", severity="critical", governance=True):
    run = append_checkpoint(build_run({}, run_id="run_a"), {}, label="baseline")
    config = _runbook_config(
        InMemoryRunStore(),
        operator_memory_store=InMemoryOperatorMemoryStore(),
        case_store=InMemoryCaseStore(),
        governance_store=InMemoryGovernanceStore() if governance else None,
    )
    config.run_store.save(run)
    config.operator_memory_store.save_incident(build_incident_record(
        "run_a", "Sev1 outage", severity=severity, status=incident_status, actor="u", role="Operator",
    ))
    incident_id = config.operator_memory_store.list_incidents()[0]["incident_id"]
    config.case_store.save(build_case_record(
        "Outage", case_id="case_a", linked_run_ids=["run_a"], linked_incident_ids=[incident_id],
    ))
    return config, run


def _context(role="Operator", perms=None):
    granted = dict(perms if perms is not None else BUILTIN_ROLES[role].perms)
    return SecurityContext(
        role=role, perms=granted, authenticated=True, user_id="a" * 64, session_id="1" * 32,
        _authorize=lambda permission, writing: bool(granted.get(permission)),
    )


def _render(config, run, ctx):
    st = _ForgingStreamlit(CLOSE_KEY, {"_radt_selected_case_id": "case_a"})
    _render_caseboard_panel(st, config, ctx, [run], run)
    button = next(event for event in st.events if event[0] == "button" and event[2] == CLOSE_KEY)
    return st, button


def _case_state(config):
    return config.case_store.list_cases()[0]["state"]


@pytest.mark.parametrize("role", ["Operator", "Admin"])
def test_close_is_disabled_and_refused_while_governance_blocks_it(role):
    config, run = _scenario()

    st, button = _render(config, run, _context(role))

    assert button[3] is True, "the Close case button must render disabled"
    assert _case_state(config) == "open"
    assert not any(event[0] in {"toast", "rerun"} for event in st.events)
    assert not any(event.get("type") == "case_close" for event in config.audit.all_events())
    captions = [event[1] for event in st.events if event[0] == "caption"]
    assert any("Governance blocks closing this case" in text and "open incidents: 1" in text for text in captions)


def test_close_works_when_governance_allows_it():
    config, run = _scenario(incident_status="closed", severity="low")

    st, button = _render(config, run, _context())

    assert button[3] is False
    assert _case_state(config) == "closed"
    assert ("rerun",) in st.events


def test_close_fails_closed_when_governance_cannot_be_evaluated():
    perms = {"can_manage_runs": True, "can_view_team_ops": True, "can_view_decisions": True,
             "can_view_governance": False}
    config, run = _scenario(incident_status="closed", severity="low")

    st, button = _render(config, run, _context("Closer", perms))

    assert button[3] is True
    assert _case_state(config) == "open"
    captions = [event[1] for event in st.events if event[0] == "caption"]
    assert any("governance could not be evaluated" in text for text in captions)


def test_close_stays_blocked_until_a_critical_case_has_its_signoffs():
    # A critical incident keeps the case critical after it is resolved, so
    # governance still requires Approver and Admin signoffs before closing.
    config, run = _scenario(incident_status="closed")

    st, button = _render(config, run, _context("Admin"))

    assert button[3] is True
    assert _case_state(config) == "open"
    captions = [event[1] for event in st.events if event[0] == "caption"]
    assert any("missing signoff roles: Approver, Admin" in text for text in captions)


def test_close_without_a_governance_store_keeps_its_previous_behavior():
    config, run = _scenario(governance=False)

    st, button = _render(config, run, _context())

    assert button[3] is False
    assert _case_state(config) == "closed"


def test_an_unexpected_governance_error_refuses_close_without_breaking_the_caseboard(monkeypatch):
    def broken_preview(*_args, **_kwargs):
        raise RuntimeError("store exploded at /srv/private/governance.db")

    monkeypatch.setattr(
        "role_aware_dashboard_toolkit.runbook_panels_parts.caseboard.build_governance_panel_preview",
        broken_preview,
    )
    config, run = _scenario(incident_status="closed", severity="low")

    st, button = _render(config, run, _context())

    assert button[3] is True
    assert _case_state(config) == "open"
    captions = [event[1] for event in st.events if event[0] == "caption"]
    assert any("governance could not be evaluated" in text for text in captions)
    assert not any("/srv/private" in str(event) for event in st.events)
    assert any(event[0] == "button" and event[1] == "Append finding to selected case" for event in st.events)


_CLOSER = {"can_manage_runs": True, "can_view_team_ops": True, "can_view_decisions": True,
           "can_view_governance": True}


@pytest.mark.parametrize("missing", [None, "can_view_decisions", "can_view_governance"])
def test_a_custom_role_needs_decision_and_governance_views_to_close(missing):
    # Listed under Changed (BREAKING): with a governance store, closing reads
    # decision-derived governance evidence, so a custom role that could close
    # cases in 0.1.0 with can_manage_runs alone now needs both view grants.
    perms = {name: name != missing for name in _CLOSER}
    config, run = _scenario(incident_status="closed", severity="low")

    _st, button = _render(config, run, _context("Closer", perms))

    assert button[3] is (missing is not None)
    assert _case_state(config) == ("open" if missing else "closed")
