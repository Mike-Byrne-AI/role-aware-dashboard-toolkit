"""Native profile inputs survive hidden sections without host-owned private keys."""
from __future__ import annotations

import time

import pytest

from role_aware_dashboard_toolkit import ControlRegistry, DashboardConfig, InMemoryProfileStore
from role_aware_dashboard_toolkit.access import Identity, principal_id
from tests.test_authenticated_ui import _healthy, _host

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _consumer(host):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    from role_aware_dashboard_toolkit.dashboard import prepare_access

    if host.config.auth_mode == "authenticated":
        prepare_access(host.config)
    page = st.radio("Page", ["Controls", "Other"], key="page")
    host.config.sections = radt.DashboardSections(
        controls=page == "Controls", profiles=page == "Controls",
        runbook=False, audit_writer=False, audit_log=False, observability=False,
        plugin_details=False,
    )
    radt.render(host.config)


def _app(*, authenticated=True):
    host = _host()
    host.store.compare_and_set_freeze(False, 0, host.principal)
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=8,
                      min_value=1, max_value=40, step=1)
    profiles = InMemoryProfileStore()
    profiles.save({"profile_id": "baseline", "values": {"workers": 20}})
    host.config = DashboardConfig(
        registry=registry, profile_store=profiles, audit=host.audit,
        access=host.policy if authenticated else None,
    )
    app = _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())
    _healthy(app.selectbox(key="_radt_profile_choice").select("baseline").run())
    _healthy(app.button(key="_radt_profile_load").click().run())
    _healthy(app.number_input(key="workers").set_value(23).run())
    _healthy(app.text_input(key="_radt_profile_name").set_value("Next shift draft").run())
    return app, host


def _hide(app):
    _healthy(app.radio(key="page").set_value("Other").run())
    for _ in range(3):
        _healthy(app.run())
    assert all(widget.key != "_radt_profile_choice" for widget in app.selectbox)
    assert all(widget.key != "_radt_profile_name" for widget in app.text_input)


def _show(app):
    _healthy(app.radio(key="page").set_value("Controls").run())


def _assert_retained(app, *, choice="baseline"):
    assert app.selectbox(key="_radt_profile_choice").value == choice
    assert app.text_input(key="_radt_profile_name").value == "Next shift draft"
    assert app.session_state["_radt_active_profile_id"] == "baseline"
    assert app.session_state["workers"] == 23
    assert next(widget for widget in app.number_input if widget.label == "Workers").value == 23


@pytest.mark.parametrize("authenticated", [False, True])
def test_profile_selection_and_draft_survive_repeated_hidden_reruns(authenticated):
    app, host = _app(authenticated=authenticated)
    events = host.audit.all_events()
    for _ in range(2):
        _hide(app)
        _show(app)
        _assert_retained(app)
    assert host.audit.all_events() == events
    assert host.config.profile_store.list_ids() == ["baseline"]


def test_profile_removed_while_hidden_resets_selection_without_losing_draft_or_live_values():
    app, host = _app()
    _hide(app)
    assert host.config.profile_store.delete("baseline")
    _healthy(app.run())
    _show(app)
    _assert_retained(app, choice="(none)")
    assert app.selectbox(key="_radt_profile_choice").options == ["(none)"]


@pytest.mark.parametrize("change", ["role", "freeze"])
def test_retained_profile_inputs_do_not_bypass_current_role_or_freeze(change, monkeypatch):
    app, host = _app()
    _hide(app)
    store = host.config.profile_store
    original_list, original_load = store.list_ids, store.load
    reads = []

    def tracked_list():
        reads.append("list")
        return original_list()

    def tracked_load(profile_id):
        reads.append("load")
        return original_load(profile_id)

    monkeypatch.setattr(store, "list_ids", tracked_list)
    monkeypatch.setattr(store, "load", tracked_load)
    if change == "role":
        host.store.replace_grants(host.principal, ("Viewer",))
    else:
        freeze = host.store.read_freeze()
        host.store.compare_and_set_freeze(True, freeze.revision, host.principal)
    _healthy(app.run())
    _show(app)
    assert next(widget for widget in app.number_input if widget.label == "Workers").disabled
    events = host.audit.all_events()
    if change == "role":
        assert not reads
        for key in ("_radt_profile_choice", "_radt_profile_name", "_radt_active_profile_id"):
            assert key not in app.session_state
        assert not any(widget.key == "_radt_profile_choice" for widget in app.selectbox)
        assert not any(widget.key == "_radt_profile_name" for widget in app.text_input)
        assert not any(widget.key in {"_radt_profile_load", "_radt_profile_save", "_radt_profile_delete"}
                       for widget in app.button)
    else:
        _assert_retained(app)
        for key in ("_radt_profile_load", "_radt_profile_save", "_radt_profile_delete"):
            assert app.button(key=key).disabled
    _healthy(app.run())
    if change == "role":
        assert not reads
        assert app.session_state["workers"] == 23
    else:
        _assert_retained(app)
    assert host.audit.all_events() == events
    assert original_list() == ["baseline"]
    assert original_load("baseline")["values"] == {"workers": 20}
    if change == "role":
        host.store.replace_grants(host.principal, ("Admin",))
    else:
        freeze = host.store.read_freeze()
        host.store.compare_and_set_freeze(False, freeze.revision, host.principal)
    _healthy(app.run())
    if change == "role":
        # Regranting access cannot resurrect metadata cleared on revocation.
        assert app.selectbox(key="_radt_profile_choice").value == "(none)"
        assert app.text_input(key="_radt_profile_name").value == "my_profile"
        _healthy(app.selectbox(key="_radt_profile_choice").select("baseline").run())
    _healthy(app.button(key="_radt_profile_load").click().run())
    assert app.number_input(key="workers").value == 20
    assert app.selectbox(key="_radt_profile_choice").value == "baseline"
    expected_name = "my_profile" if change == "role" else "Next shift draft"
    assert app.text_input(key="_radt_profile_name").value == expected_name


@pytest.mark.parametrize("hidden", [False, True])
def test_principal_change_clears_profile_inputs_and_live_values(hidden):
    app, host = _app()
    previous_session = app.session_state["_radt_authenticated_session"]
    if hidden:
        _hide(app)
    host.identity = Identity("https://provider.invalid", "second-account", time.time() + 3600)
    next_principal = principal_id(host.identity, host.key)
    host.store.replace_grants(next_principal, ("Admin",))
    _healthy(app.run())
    assert app.session_state["_radt_authenticated_principal"] == next_principal
    assert app.session_state["_radt_authenticated_session"] != previous_session
    assert app.selectbox(key="_radt_profile_choice").value == "(none)"
    assert app.text_input(key="_radt_profile_name").value == "my_profile"
    assert app.number_input(key="workers").value == 8
    assert "_radt_active_profile_id" not in app.session_state
