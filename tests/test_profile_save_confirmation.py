"""Profile replacement consent is tied to the reviewed draft and live authority."""

from copy import deepcopy

import pytest

from role_aware_dashboard_toolkit import InMemoryProfileStore
from tests.test_authenticated_ui import _host
from tests.test_profile_menu_refresh import _consumer, _healthy, _profile_events
from tests.demo_role_helpers import start_as_admin


AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
CONFIRM = "_radt_profile_replace_confirm"
CANCEL = "_radt_profile_replace_cancel"


@pytest.fixture
def app(tmp_path):
    app = _healthy(start_as_admin(AppTest.from_function(
        _consumer, args=(str(tmp_path / "audit"),), default_timeout=15,
    )).run())
    app.number_input(key="workers").set_value(18)
    app.text_input(key="_radt_profile_name").set_value("  base  ")
    return _healthy(app.run())


def _stage(app):
    _healthy(app.button(key="_radt_profile_save").click().run())
    assert app.button(key=CONFIRM).label == "Replace saved profile"
    assert app.button(key=CANCEL).label == "Cancel replacement"
    return app


def test_existing_name_requires_explicit_confirmation_then_saves_once(app):
    store = app.session_state["config"].profile_store
    original = deepcopy(store.load("base"))
    events = deepcopy(_profile_events(app))

    _stage(app)

    assert store.load("base") == original
    assert _profile_events(app) == events
    assert not app.get("toast")
    _healthy(app.button(key=CONFIRM).click().run())
    assert store.load("base")["values"]["workers"] == 18
    assert store.list_ids() == ["base", "other"]
    assert [event["type"] for event in _profile_events(app)] == ["profile_save"]
    assert [toast.value for toast in app.get("toast")] == ["Saved profile: base"]
    assert not any(button.key == CONFIRM for button in app.button)
    assert not app.button(key="_radt_profile_save").disabled

    saved = deepcopy(store.load("base"))
    _healthy(app.run())
    assert store.load("base") == saved
    assert len(_profile_events(app)) == 1
    assert not any(button.key == CONFIRM for button in app.button)


def test_cancel_replacement_preserves_original_and_draft(app):
    store = app.session_state["config"].profile_store
    original = deepcopy(store.load("base"))
    _stage(app)

    _healthy(app.button(key=CANCEL).click().run())

    assert store.load("base") == original
    assert app.number_input(key="workers").value == 18
    assert not _profile_events(app)
    assert not app.get("toast")
    assert not any(button.key == CONFIRM for button in app.button)
    assert not app.button(key="_radt_profile_save").disabled


def test_save_and_confirm_in_one_submission_only_restages_the_review(app):
    store = app.session_state["config"].profile_store
    original = deepcopy(store.load("base"))
    _stage(app)
    app.button(key="_radt_profile_save").click()

    _healthy(app.button(key=CONFIRM).click().run())

    assert store.load("base") == original
    assert not _profile_events(app)
    assert not app.get("toast")
    assert app.button(key=CONFIRM).label == "Replace saved profile"

    _healthy(app.button(key=CONFIRM).click().run())
    assert store.load("base")["values"]["workers"] == 18
    assert [event["type"] for event in _profile_events(app)] == ["profile_save"]


@pytest.mark.parametrize("changed", ["name", "selection", "draft", "role"])
def test_same_submission_change_cannot_confirm_an_old_review(app, changed):
    store = app.session_state["config"].profile_store
    originals = {name: deepcopy(store.load(name)) for name in store.list_ids()}
    _stage(app)
    confirm = app.button(key=CONFIRM)
    if changed == "name":
        app.text_input(key="_radt_profile_name").set_value("other")
    elif changed == "selection":
        app.selectbox(key="_radt_profile_choice").select("other")
    elif changed == "draft":
        app.number_input(key="workers").set_value(31)
    else:
        app.selectbox(key="_radt_role").select("Viewer")

    _healthy(confirm.click().run())

    assert {name: store.load(name) for name in store.list_ids()} == originals
    assert not _profile_events(app)
    assert not app.get("toast")
    assert not any(button.key == CONFIRM and not button.disabled for button in app.button)


@pytest.mark.parametrize("change", ["replaced", "deleted"])
def test_confirmation_rereads_target_and_preserves_concurrent_changes(app, change):
    store = app.session_state["config"].profile_store
    _stage(app)
    if change == "replaced":
        store.save({"profile_id": "base", "values": {"workers": 77}, "source": "another-session"})
    else:
        store.delete("base")
    expected = deepcopy(store.load("base"))

    _healthy(app.button(key=CONFIRM).click().run())

    assert store.load("base") == expected
    assert not _profile_events(app)
    assert not app.get("toast")
    assert not any(button.key == CONFIRM and not button.disabled for button in app.button)


def test_read_only_role_disables_profile_name_input(app):
    _healthy(app.selectbox(key="_radt_role").select("Viewer").run())
    assert app.text_input(key="_radt_profile_name").disabled
    assert app.button(key="_radt_profile_save").disabled


def _authenticated_consumer(host):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Workers", kind="number", key="workers", default=18,
                          min_value=0, max_value=100, step=1)
        st.session_state["config"] = radt.DashboardConfig(
            registry=registry, audit=host.audit, profile_store=host.profiles,
            auth_mode="authenticated", access=host.policy,
            sections=radt.DashboardSections(runbook=False, audit_writer=False,
                                           audit_log=False, observability=False),
        )
    radt.render(st.session_state["config"])


@pytest.mark.parametrize("boundary", ["revoke", "freeze"])
def test_confirmation_rechecks_authority_at_the_actual_button_boundary(monkeypatch, boundary):
    import streamlit as st

    host = _host()
    host.store.compare_and_set_freeze(False, 0, host.principal)
    host.profiles = InMemoryProfileStore()
    host.profiles.save({"profile_id": "base", "values": {"workers": 3}})
    original = deepcopy(host.profiles.load("base"))
    app = _healthy(AppTest.from_function(
        _authenticated_consumer, args=(host,), default_timeout=15,
    ).run())
    _healthy(app.text_input(key="_radt_profile_name").set_value("base").run())
    _stage(app)
    original_button = st.button
    changed = []

    def change_authority_before_returning_click(*args, **kwargs):
        clicked = original_button(*args, **kwargs)
        if kwargs.get("key") == CONFIRM and clicked:
            if boundary == "revoke":
                host.store.replace_grants(host.principal, ())
            else:
                freeze = host.store.read_freeze()
                host.store.compare_and_set_freeze(True, freeze.revision, host.principal)
            changed.append(boundary)
        return clicked

    monkeypatch.setattr(st, "button", change_authority_before_returning_click)
    _healthy(app.button(key=CONFIRM).click().run())

    assert changed == [boundary]
    assert host.profiles.load("base") == original
    assert not [event for event in host.audit.all_events() if event["type"] == "profile_save"]
    assert not app.get("toast")
    assert not any(button.key == CONFIRM and not button.disabled for button in app.button)
    if boundary == "revoke":
        assert not any(field.key == "_radt_profile_name" for field in app.text_input)
        assert "_radt_profile_name" not in app.session_state
    else:
        assert app.text_input(key="_radt_profile_name").disabled


def test_confirmation_rechecks_authority_after_parent_store_read(monkeypatch):
    import streamlit as st

    host = _host()
    host.store.compare_and_set_freeze(False, 0, host.principal)
    host.profiles = InMemoryProfileStore()
    host.profiles.save({"profile_id": "base", "values": {"workers": 3}})
    host.profiles.save({"profile_id": "parent", "values": {"workers": 7}})
    original = deepcopy(host.profiles.load("base"))
    app = _healthy(AppTest.from_function(
        _authenticated_consumer, args=(host,), default_timeout=15,
    ).run())
    app.selectbox(key="_radt_profile_choice").select("parent")
    _healthy(app.text_input(key="_radt_profile_name").set_value("base").run())
    _stage(app)
    original_button = st.button
    original_load = host.profiles.load
    armed = []
    revoked = []

    def arm_on_confirmation(*args, **kwargs):
        clicked = original_button(*args, **kwargs)
        if kwargs.get("key") == CONFIRM and clicked:
            armed.append(True)
        return clicked

    def revoke_during_parent_read(profile_id):
        saved = original_load(profile_id)
        if armed and not revoked and profile_id == "parent":
            host.store.replace_grants(host.principal, ())
            revoked.append(profile_id)
        return saved

    monkeypatch.setattr(st, "button", arm_on_confirmation)
    monkeypatch.setattr(host.profiles, "load", revoke_during_parent_read)
    _healthy(app.button(key=CONFIRM).click().run())

    assert revoked == ["parent"]
    assert original_load("base") == original
    assert not [event for event in host.audit.all_events() if event["type"] == "profile_save"]
    assert not app.get("toast")
    assert not any(button.key == CONFIRM for button in app.button)
