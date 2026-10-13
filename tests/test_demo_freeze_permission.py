"""In demo mode only a role with can_manage_freeze can change Controls Writable."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re

import pytest

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


_REPO = Path(__file__).resolve().parents[1]
_WALKTHROUGHS = {
    "starter": "role_aware_dashboard_toolkit/resources/starter",
    "studio_dispatch": "examples/studio_dispatch",
}


@pytest.mark.parametrize("name", sorted(_WALKTHROUGHS))
def test_walkthroughs_freeze_controls_as_a_role_that_can(name):
    # The starter told a Planner to turn Controls Writable off, which only a
    # can_manage_freeze role can do since demo freeze became a permission.
    pytest.importorskip("streamlit")
    from role_aware_dashboard_toolkit.security import BUILTIN_ROLES, get_role

    folder = _REPO / _WALKTHROUGHS[name]
    spec = importlib.util.spec_from_file_location(f"walkthrough_{name}", folder / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    custom_roles = module.build_roles()
    role_names = set(BUILTIN_ROLES) | set(custom_roles)

    text = " ".join((folder / "README.md").read_text(encoding="utf-8").split())
    sentences = [s for s in re.split(r"(?<=\.)\s", text) if "Controls Writable" in s and "off" in s]
    assert sentences, "the walkthrough no longer freezes controls"
    for sentence in sentences:
        named = [role for role in role_names if re.search(rf"\b{re.escape(role)}\b", sentence)]
        assert any(get_role(role, custom_roles).perms.get("can_manage_freeze") is True for role in named), sentence
