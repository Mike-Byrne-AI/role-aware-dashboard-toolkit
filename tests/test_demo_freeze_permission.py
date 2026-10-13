"""In demo mode only a role with can_manage_freeze can change Controls Writable."""
from __future__ import annotations

from role_aware_dashboard_toolkit import DashboardConfig, DashboardSections
from role_aware_dashboard_toolkit.sidebar import render_sidebar
from tests.test_role_aware_dashboard_toolkit import FakeStreamlit


class _ToggleRecorder(FakeStreamlit):
    def __init__(self):
        super().__init__()
        self.toggles = {}

    def toggle(self, label, value=False, key=None, disabled=False, **kwargs):
        self.toggles[key] = {"disabled": disabled}
        return super().toggle(label, value=value, key=key, disabled=disabled, **kwargs)


def _config(role):
    return DashboardConfig(
        auth_hook=lambda: role,
        sections=DashboardSections(audit_writer=False, profiles=False, runbook=False),
    )


def _freeze_events(config):
    return [event for event in config.audit.all_events() if event["type"] == "freeze_toggle"]


def test_role_without_manage_freeze_sees_a_disabled_toggle_and_cannot_freeze():
    fake_st = _ToggleRecorder()
    config = _config("Operator")
    assert render_sidebar(fake_st, config).ctx.controls_writable is True
    assert fake_st.toggles["_radt_writable"]["disabled"] is True

    fake_st.session_state["_radt_writable"] = False  # a disabled widget cannot send this
    result = render_sidebar(fake_st, config)

    assert result.ctx.controls_writable is True
    assert fake_st.session_state["_radt_writable"] is True
    assert _freeze_events(config) == []


def test_role_with_manage_freeze_can_freeze_and_unfreeze():
    fake_st = _ToggleRecorder()
    config = _config("Admin")
    render_sidebar(fake_st, config)
    assert fake_st.toggles["_radt_writable"]["disabled"] is False

    fake_st.session_state["_radt_writable"] = False
    assert render_sidebar(fake_st, config).ctx.controls_writable is False
    fake_st.session_state["_radt_writable"] = True
    assert render_sidebar(fake_st, config).ctx.controls_writable is True
    assert [(e["new"], e["role"]) for e in _freeze_events(config)] == [(False, "Admin"), (True, "Admin")]


def test_a_freeze_set_by_a_manager_holds_for_a_role_that_cannot_lift_it():
    fake_st = _ToggleRecorder()
    render_sidebar(fake_st, _config("Admin"))
    fake_st.session_state["_radt_writable"] = False
    render_sidebar(fake_st, _config("Admin"))

    viewer = _config("Viewer")
    fake_st.session_state["_radt_writable"] = True  # forged unfreeze
    assert render_sidebar(fake_st, viewer).ctx.controls_writable is False
    assert fake_st.toggles["_radt_writable"]["disabled"] is True
