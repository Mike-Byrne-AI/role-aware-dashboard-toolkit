"""Demo mode starts a new session in its least-privileged role."""
from __future__ import annotations

from role_aware_dashboard_toolkit import DashboardConfig, DashboardSections, RoleDef
from role_aware_dashboard_toolkit.sidebar import render_sidebar
from tests.test_role_aware_dashboard_toolkit import FakeStreamlit


def _config(**kwargs):
    return DashboardConfig(
        sections=DashboardSections(audit_writer=False, profiles=False, runbook=False), **kwargs,
    )


def test_new_demo_session_starts_as_viewer():
    fake_st = FakeStreamlit()
    result = render_sidebar(fake_st, _config())
    assert result.ctx.role == "Viewer"
    assert fake_st.session_state["_radt_role"] == "Viewer"


def test_custom_roles_start_in_the_role_with_fewest_grants():
    roles = {
        "Lead": RoleDef(name="Lead", perms={"can_edit_controls": True, "can_view_audit": True}),
        "Guest": RoleDef(name="Guest", perms={"can_view_metrics": True, "can_edit_controls": False}),
    }
    fake_st = FakeStreamlit()
    assert render_sidebar(fake_st, _config(custom_roles=roles)).ctx.role == "Guest"


def test_an_unknown_selected_role_falls_back_to_the_least_privileged_role():
    fake_st = FakeStreamlit()
    fake_st.session_state["_radt_role"] = "Removed"
    assert render_sidebar(fake_st, _config()).ctx.role == "Viewer"


def test_a_selected_role_is_kept():
    fake_st = FakeStreamlit()
    fake_st.session_state["_radt_role"] = "Admin"
    assert render_sidebar(fake_st, _config()).ctx.role == "Admin"
