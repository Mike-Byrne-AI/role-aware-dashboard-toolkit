"""A page render never changes the audit writer; only an explicit toggle does."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import AuditLog, DashboardConfig, DashboardSections, RoleDef
from role_aware_dashboard_toolkit.access_audit import bind_audit_identity
from role_aware_dashboard_toolkit.security import get_role, make_security_context
from role_aware_dashboard_toolkit.sidebar import _render_audit_writer_controls, render_sidebar
from tests.test_role_aware_dashboard_toolkit import FakeStreamlit

_PRINCIPAL = "a" * 64
_SESSION = "b" * 32


def _disk(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _types(path: Path) -> list[str]:
    return [event["type"] for event in _disk(path)]


def _wait_for(predicate, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _ctx(role: str):
    return make_security_context(role, dict(get_role(role).perms))


# --- AuditLog: every start and stop is an audit record ---------------------


def test_writer_start_and_stop_are_recorded_on_disk(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog()
    audit.start_writer(str(path), role="Admin", source="ui")
    audit.start_writer(str(path), role="Admin", source="ui")  # already running: no record
    audit.log("between")
    audit.stop_writer(role="Admin", source="ui")
    audit.stop_writer(role="Admin", source="ui")  # nothing running: no record

    events = _disk(path)
    assert [event["type"] for event in events] == [
        "audit_writer_start", "between", "audit_writer_stop",
    ]
    assert events[0]["role"] == "Admin" and events[0]["source"] == "ui"
    assert events[-1]["role"] == "Admin" and events[-1]["source"] == "ui"
    assert [event["type"] for event in audit.all_events()] == [
        "audit_writer_start", "between", "audit_writer_stop",
    ]


def test_writer_move_records_stop_in_old_file_and_start_in_new_file(tmp_path):
    first, second = tmp_path / "first.jsonl", tmp_path / "second.jsonl"
    audit = AuditLog()
    audit.start_writer(str(first))
    audit.start_writer(str(second))
    audit.stop_writer()
    assert _types(first) == ["audit_writer_start", "audit_writer_stop"]
    assert _types(second) == ["audit_writer_start", "audit_writer_stop"]


def test_host_writer_lifecycle_defaults_to_host_source(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog()
    audit.start_writer(str(path))
    audit.stop_writer()
    assert [(event["type"], event["source"]) for event in _disk(path)] == [
        ("audit_writer_start", "host"), ("audit_writer_stop", "host"),
    ]


# --- Sidebar: a render does not stop or start a writer ---------------------


@pytest.mark.parametrize("form_visible", [True, False])
@pytest.mark.parametrize("role", ["Admin", "Operator", "Viewer"])
def test_render_keeps_host_started_writer(tmp_path, role, form_visible):
    audit_root = tmp_path / "audit"
    path = audit_root / "audit.jsonl"
    audit = AuditLog()
    audit.start_writer(str(path))
    fake_st = FakeStreamlit()
    config = DashboardConfig(
        audit=audit, audit_dir=str(audit_root), auth_hook=lambda: role,
        sections=DashboardSections(audit_writer=form_visible),
    )
    try:
        render_sidebar(fake_st, config)
        render_sidebar(fake_st, config)
        assert audit.writer_status()["writer_active"] is True
        audit.log("after_render", role=role)
    finally:
        audit.stop_writer()
    assert "after_render" in _types(path)
    if form_visible:
        # Every role sees the live state, including roles that cannot change it.
        assert fake_st.session_state["_radt_audit_writer"] is True


def test_toggle_reflects_live_writer_before_any_interaction(tmp_path):
    audit_root = tmp_path / "audit"
    audit = AuditLog()
    audit.start_writer(str(audit_root / "audit.jsonl"))
    fake_st = FakeStreamlit()
    try:
        _render_audit_writer_controls(fake_st, DashboardConfig(audit=audit, audit_dir=str(audit_root)), _ctx("Admin"))
        assert fake_st.session_state["_radt_audit_writer"] is True
        audit.stop_writer()
        _render_audit_writer_controls(fake_st, DashboardConfig(audit=audit, audit_dir=str(audit_root)), _ctx("Admin"))
        assert fake_st.session_state["_radt_audit_writer"] is False
    finally:
        audit.stop_writer()


def test_explicit_toggle_changes_start_and_stop_with_attribution(tmp_path):
    audit_root = tmp_path / "audit"
    path = audit_root / "audit.jsonl"
    audit = AuditLog()
    fake_st = FakeStreamlit()
    config = DashboardConfig(audit=audit, audit_dir=str(audit_root))
    ctx = _ctx("Admin")
    _render_audit_writer_controls(fake_st, config, ctx)
    assert audit.writer_status()["writer_active"] is False

    fake_st.session_state["_radt_audit_writer"] = True  # operator turns it on
    _render_audit_writer_controls(fake_st, config, ctx)
    assert audit.writer_status()["writer_active"] is True
    _render_audit_writer_controls(fake_st, config, ctx)  # plain rerun: no change
    assert audit.writer_status()["writer_active"] is True

    fake_st.session_state["_radt_audit_writer"] = False  # operator turns it off
    _render_audit_writer_controls(fake_st, config, ctx)
    assert audit.writer_status()["writer_active"] is False
    events = _disk(path)
    assert [(e["type"], e["role"], e["source"]) for e in events] == [
        ("audit_writer_start", "Admin", "ui"), ("audit_writer_stop", "Admin", "ui"),
    ]


def test_lifecycle_records_carry_bound_identity(tmp_path):
    audit_root = tmp_path / "audit"
    path = audit_root / "audit.jsonl"
    parent = AuditLog()
    fake_st = FakeStreamlit()
    config = DashboardConfig(audit=bind_audit_identity(parent, _PRINCIPAL, _SESSION), audit_dir=str(audit_root))
    ctx = _ctx("Admin")
    _render_audit_writer_controls(fake_st, config, ctx)
    fake_st.session_state["_radt_audit_writer"] = True
    _render_audit_writer_controls(fake_st, config, ctx)
    fake_st.session_state["_radt_audit_writer"] = False
    _render_audit_writer_controls(fake_st, config, ctx)
    events = _disk(path)
    assert [e["type"] for e in events] == ["audit_writer_start", "audit_writer_stop"]
    assert {(e["user_id"], e["session_id"]) for e in events} == {(_PRINCIPAL, _SESSION)}


def test_forged_toggle_from_role_without_manage_audit_is_ignored_and_resynced(tmp_path):
    audit_root = tmp_path / "audit"
    audit = AuditLog()
    audit.start_writer(str(audit_root / "audit.jsonl"))
    fake_st = FakeStreamlit()
    config = DashboardConfig(audit=audit, audit_dir=str(audit_root))
    try:
        _render_audit_writer_controls(fake_st, config, _ctx("Operator"))
        fake_st.session_state["_radt_audit_writer"] = False  # a disabled widget cannot send this
        _render_audit_writer_controls(fake_st, config, _ctx("Operator"))
        assert audit.writer_status()["writer_active"] is True
        assert fake_st.session_state["_radt_audit_writer"] is True
    finally:
        audit.stop_writer()


def test_path_edit_moves_an_active_writer_and_a_bad_path_keeps_it(tmp_path):
    audit_root = tmp_path / "audit"
    first, second = audit_root / "first.jsonl", audit_root / "second.jsonl"
    audit = AuditLog()
    fake_st = FakeStreamlit()
    config = DashboardConfig(audit=audit, audit_dir=str(audit_root))
    ctx = _ctx("Admin")
    fake_st.session_state["_radt_audit_path"] = str(first)
    _render_audit_writer_controls(fake_st, config, ctx)
    fake_st.session_state["_radt_audit_writer"] = True
    _render_audit_writer_controls(fake_st, config, ctx)
    try:
        fake_st.session_state["_radt_audit_path"] = str(second)
        _render_audit_writer_controls(fake_st, config, ctx)
        assert audit.writer_status()["writer_path"] == str(second)

        fake_st.session_state["_radt_audit_path"] = str(tmp_path / "outside.jsonl")
        _render_audit_writer_controls(fake_st, config, ctx)
        assert audit.writer_status()["writer_active"] is True
        assert audit.writer_status()["writer_path"] == str(second)
        assert len(fake_st.messages["error"]) == 1
        assert "within configured audit directory" in fake_st.messages["error"][0]
        _render_audit_writer_controls(fake_st, config, ctx)  # unchanged bad path: no repeat
        assert len(fake_st.messages["error"]) == 1
    finally:
        audit.stop_writer()
    assert _types(first) == ["audit_writer_start", "audit_writer_stop"]
    assert _types(second) == ["audit_writer_start", "audit_writer_stop"]


def test_failed_start_shows_the_toggle_off(tmp_path):
    audit_root = tmp_path / "audit"
    audit = AuditLog()
    fake_st = FakeStreamlit()
    config = DashboardConfig(audit=audit, audit_dir=str(audit_root))
    ctx = _ctx("Admin")
    fake_st.session_state["_radt_audit_path"] = str(tmp_path / "outside.jsonl")
    fake_st.session_state["_radt_audit_writer"] = True
    _render_audit_writer_controls(fake_st, config, ctx)
    assert audit.writer_status()["writer_active"] is False
    assert fake_st.session_state["_radt_audit_writer"] is False


# --- Real Streamlit sessions: every role's events reach disk ---------------


def _session_app(audit, audit_dir, role, *, host_starts_writer=False, show_form=True):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    from role_aware_dashboard_toolkit.sections import DashboardSections

    if "audit" not in st.session_state:
        session_audit = audit if audit is not None else radt.AuditLog()
        if host_starts_writer:
            session_audit.start_writer(audit_dir + "/audit.jsonl")
        st.session_state["audit"] = session_audit
    registry = radt.ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=8, min_value=1, max_value=40, step=1)
    config = radt.DashboardConfig(
        title="t", registry=registry, audit=st.session_state["audit"], audit_dir=audit_dir,
        auth_mode="demo", sections=DashboardSections(
            audit_writer=show_form, runbook=False, plugin_details=False,
        ),
    )
    config.auth_hook = lambda: role
    radt.render(config)


def _app(*args, **kwargs):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_session_app, args=args, kwargs=kwargs, default_timeout=20).run()
    assert not app.exception, [item.message for item in app.exception]
    return app


def _change(app, value):
    app.number_input(key="workers").set_value(value).run()
    assert not app.exception, [item.message for item in app.exception]


def _control_changes(path: Path) -> list[tuple[str, int]]:
    return [(e["role"], e["new"]) for e in _disk(path) if e["type"] == "control_change"]


@pytest.mark.parametrize("show_form", [True, False])
def test_shared_log_with_host_writer_persists_every_role(tmp_path, show_form):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog()
    audit.start_writer(str(path))
    try:
        admin = _app(audit, str(tmp_path), "Admin", show_form=show_form)
        operator = _app(audit, str(tmp_path), "Operator", show_form=show_form)
        viewer = _app(audit, str(tmp_path), "Viewer", show_form=show_form)
        second_admin = _app(audit, str(tmp_path), "Admin", show_form=show_form)
        _change(admin, 11)
        _change(operator, 22)
        viewer.run()
        second_admin.run()
        _change(operator, 33)
        assert audit.writer_status()["writer_active"] is True
        if show_form:
            assert operator.toggle(key="_radt_audit_writer").value is True
    finally:
        audit.stop_writer()
    assert _control_changes(path) == [("Admin", 11), ("Operator", 22), ("Operator", 33)]


def test_shared_log_toggle_route_survives_a_second_admin(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog()
    try:
        admin = _app(audit, str(tmp_path), "Admin")
        admin.toggle(key="_radt_audit_writer").set_value(True).run()
        _change(admin, 11)
        operator = _app(audit, str(tmp_path), "Operator")
        _change(operator, 22)
        _app(audit, str(tmp_path), "Admin")  # a second Admin opens the page
        _change(operator, 33)
        _change(admin, 12)
        _change(operator, 34)
        assert operator.toggle(key="_radt_audit_writer").value is True
    finally:
        audit.stop_writer()
    assert _control_changes(path) == [
        ("Admin", 11), ("Operator", 22), ("Operator", 33), ("Admin", 12), ("Operator", 34),
    ]
    assert _types(path).count("audit_writer_start") == 1


def test_per_session_logs_with_host_writers_persist_every_role(tmp_path):
    path = tmp_path / "audit.jsonl"
    apps = [
        _app(None, str(tmp_path), role, host_starts_writer=True)
        for role in ("Admin", "Operator", "Admin")
    ]
    try:
        _change(apps[0], 11)
        _change(apps[1], 22)
        apps[2].run()
        _change(apps[1], 33)
        _change(apps[0], 12)
        _change(apps[2], 13)
    finally:
        for app in apps:
            app.session_state["audit"].stop_writer()
    assert sorted(_control_changes(path)) == sorted([
        ("Admin", 11), ("Operator", 22), ("Operator", 33), ("Admin", 12), ("Admin", 13),
    ])


def test_custom_role_without_manage_audit_cannot_stop_a_writer(tmp_path):
    audit_root = tmp_path / "audit"
    audit = AuditLog()
    audit.start_writer(str(audit_root / "audit.jsonl"))
    fake_st = FakeStreamlit()
    fake_st.session_state["_radt_audit_writer"] = False
    config = DashboardConfig(
        audit=audit, audit_dir=str(audit_root),
        custom_roles={"Locked": RoleDef(name="Locked", perms={"can_view_audit": True})},
        auth_hook=lambda: "Locked",
    )
    try:
        render_sidebar(fake_st, config)
        assert audit.writer_status()["writer_active"] is True
    finally:
        audit.stop_writer()
