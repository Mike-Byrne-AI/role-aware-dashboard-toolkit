"""Profile metadata must not turn a zero-permission role into a store reader."""
from __future__ import annotations

from types import SimpleNamespace
import time

import pytest

from role_aware_dashboard_toolkit import AuditLog, InMemoryProfileStore
from role_aware_dashboard_toolkit.access import AccessPolicy, Identity, InMemoryAccessStore, principal_id
from role_aware_dashboard_toolkit.security import RoleDef

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

PROFILE = "PRIVATE-PROFILE-CANARY"
SOURCE = "PRIVATE-SOURCE-CANARY"
KEY = b"synthetic-profile-metadata-test-key"


class ObservedProfiles(InMemoryProfileStore):
    def __init__(self):
        super().__init__()
        self.reads = []
        self.after_read = lambda operation: None

    def list_ids(self):
        result = super().list_ids()
        self.reads.append("list")
        self.after_read("list")
        return result

    def load(self, profile_id):
        result = super().load(profile_id)
        self.reads.append("load")
        self.after_read("load")
        return result


def _host(role="Admin"):
    identity = Identity("https://metadata.invalid", "synthetic-user", time.time() + 600)
    roles = {
        "Guest": RoleDef("Guest", {}),
        "Saver": RoleDef("Saver", {"can_save_profiles": True, "can_view_metrics": True}),
        "Reader": RoleDef("Reader", {"can_load_profiles": True, "can_view_metrics": True}),
    }
    store = InMemoryAccessStore(allowed_roles=("Admin", *roles))
    principal = principal_id(identity, KEY)
    store.replace_grants(principal, (role,))
    store.compare_and_set_freeze(False, 0, principal)
    profiles = ObservedProfiles()
    profiles.save({"profile_id": PROFILE, "source": SOURCE, "values": {"workers": 3}})
    return SimpleNamespace(
        policy=AccessPolicy(lambda: identity, store, KEY), store=store,
        principal=principal, profiles=profiles, roles=roles, audit=AuditLog(),
    )


def _consumer(host):
    import role_aware_dashboard_toolkit as radt

    registry = radt.ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=9,
                      min_value=0, max_value=100, step=1)
    radt.render(radt.DashboardConfig(
        registry=registry, access=host.policy, custom_roles=host.roles,
        profile_store=host.profiles, audit=host.audit,
        sections=radt.DashboardSections(
            runbook=False, audit_writer=False, audit_log=False, observability=False,
            plugin_details=False, plugin_sidebar=False, plugin_panels=False,
            team_ops=False, decisions=False, operator_memory=False,
            caseboard=False, governance=False,
        ),
    ))


def _healthy(app):
    assert not app.exception, [error.message for error in app.exception]
    return app


def _app(host):
    return _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())


def _assert_no_profiles(app):
    assert not any(element.key.startswith("_radt_profile_") for element in
                   [*app.selectbox, *app.text_input, *app.button] if element.key)
    visible = "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))
    assert PROFILE not in visible and SOURCE not in visible
    assert not app.dataframe


@pytest.mark.parametrize("default_store", [False, True])
def test_zero_permission_role_does_not_construct_or_read_profile_store(monkeypatch, default_store):
    from role_aware_dashboard_toolkit import sidebar

    host = _host("Guest")
    store = host.profiles
    if default_store:
        host.profiles = None

    def unexpected_store(_path):
        pytest.fail("Denied role constructed a profile store")

    monkeypatch.setattr(sidebar, "FileProfileStore", unexpected_store)
    app = _app(host)
    assert store.reads == []
    _assert_no_profiles(app)


def test_role_downgrade_discards_previous_profile_selection_and_pending_values():
    host = _host()
    app = _app(host)
    _healthy(app.selectbox(key="_radt_profile_choice").select(PROFILE).run())
    _healthy(app.text_input(key="_radt_profile_name").set_value(PROFILE).run())
    _healthy(app.button(key="_radt_profile_save").click().run())
    assert "_radt_profile_replace_pending" in app.session_state
    app.session_state["_radt_active_profile_id"] = PROFILE
    before_reads = list(host.profiles.reads)
    host.store.replace_grants(host.principal, ("Guest",))
    _healthy(app.run())
    assert host.profiles.reads == before_reads
    for key in ("_radt_profile_replace_pending", "_radt_profile_choice",
                "_radt_profile_name", "_radt_active_profile_id"):
        assert key not in app.session_state
    _assert_no_profiles(app)


@pytest.mark.parametrize("operation,occurrence", [("list", 1), ("load", 1), ("load", 2)])
def test_revocation_during_profile_read_does_not_publish_returned_metadata(operation, occurrence):
    host = _host()
    app = _app(host)
    if operation == "load":
        app.selectbox(key="_radt_profile_choice").select(PROFILE)
    seen = []

    def revoke_at_boundary(actual):
        if actual == operation:
            seen.append(actual)
            if len(seen) == occurrence:
                host.store.replace_grants(host.principal, ("Guest",))

    host.profiles.after_read = revoke_at_boundary
    _healthy(app.run())
    assert len(seen) == occurrence
    _assert_no_profiles(app)
    assert "_radt_profile_choice" not in app.session_state


@pytest.mark.parametrize("role,values_visible", [("Reader", True), ("Saver", False)])
def test_profile_metadata_management_and_value_preview_have_distinct_permissions(role, values_visible):
    host = _host(role)
    app = _app(host)
    assert PROFILE in app.selectbox(key="_radt_profile_choice").options
    _healthy(app.selectbox(key="_radt_profile_choice").select(PROFILE).run())
    assert any(SOURCE in caption.value for caption in app.caption)
    assert bool(app.dataframe) is values_visible
    assert app.button(key="_radt_profile_load").disabled is (role != "Reader")
    assert app.button(key="_radt_profile_save").disabled is (role != "Saver")


def test_save_only_manager_can_create_replace_and_delete_without_loading_values():
    host = _host("Saver")
    app = _app(host)
    _healthy(app.text_input(key="_radt_profile_name").set_value("new-profile").run())
    _healthy(app.button(key="_radt_profile_save").click().run())
    assert host.profiles.load("new-profile")["values"]["workers"] == 9
    _healthy(app.text_input(key="_radt_profile_name").set_value(PROFILE).run())
    _healthy(app.button(key="_radt_profile_save").click().run())
    _healthy(app.button(key="_radt_profile_replace_confirm").click().run())
    assert host.profiles.load(PROFILE)["values"]["workers"] == 9
    _healthy(app.selectbox(key="_radt_profile_choice").select(PROFILE).run())
    assert not app.dataframe
    assert app.button(key="_radt_profile_load").disabled
    _healthy(app.button(key="_radt_profile_delete").click().run())
    assert host.profiles.load(PROFILE) is None


def test_load_permission_lost_during_restore_cannot_apply_values_despite_retained_metadata_access(monkeypatch):
    import streamlit as st

    host = _host("Reader")
    host.roles["Reader"].perms.update(can_save_profiles=True, can_edit_controls=True)
    app = _app(host)
    _healthy(app.selectbox(key="_radt_profile_choice").select(PROFILE).run())
    before = app.session_state["workers"]
    original_button = st.button
    armed = []

    def arm_load(*args, **kwargs):
        clicked = original_button(*args, **kwargs)
        if kwargs.get("key") == "_radt_profile_load" and clicked:
            armed.append(True)
        return clicked

    def remove_load_permission(operation):
        if armed and operation == "load":
            host.roles["Reader"].perms["can_load_profiles"] = False

    monkeypatch.setattr(st, "button", arm_load)
    host.profiles.after_read = remove_load_permission
    _healthy(app.button(key="_radt_profile_load").click().run())
    assert armed
    assert app.session_state["workers"] == before
    assert not any(event["type"] == "profile_load" for event in host.audit.all_events())
    assert any("Load denied" in warning.value for warning in app.warning)
    assert not app.dataframe


@pytest.mark.parametrize("revoked_permission", ["can_load_profiles", "can_view_metrics"])
def test_preview_rechecks_value_visibility_after_later_permission_checks_during_build(monkeypatch, revoked_permission):
    from role_aware_dashboard_toolkit import sidebar

    host = _host("Reader")
    host.roles["Reader"].perms.update(can_save_profiles=True, can_edit_controls=True)
    armed = []
    previews = []

    class RevokeDuringPreview(AccessPolicy):
        def authorize(self, principal, role, permission, custom_roles=None, *, write=False):
            allowed = super().authorize(principal, role, permission, custom_roles, write=write)
            # The builder checks field edit permission after it has calculated
            # values_visible. Preserve save permission, so metadata stays valid.
            if armed and permission == "can_edit_controls":
                host.roles["Reader"].perms[revoked_permission] = False
            return allowed

    host.policy = RevokeDuringPreview(host.policy.identity_resolver, host.store, KEY)
    app = _app(host)
    original_build = sidebar.build_profile_restore_preview

    def build_with_revocation(*args, **kwargs):
        armed.append(True)
        try:
            preview = original_build(*args, **kwargs)
            previews.append(preview)
            return preview
        finally:
            armed.clear()

    monkeypatch.setattr(sidebar, "build_profile_restore_preview", build_with_revocation)
    _healthy(app.selectbox(key="_radt_profile_choice").select(PROFILE).run())

    assert len(previews) == 1
    assert previews[0].values_visible is True
    assert previews[0].rows[0]["Saved"] == "3"
    assert not app.dataframe
    assert any("Values require permission" in caption.value for caption in app.caption)
    assert any(SOURCE in caption.value for caption in app.caption)
    assert host.roles["Reader"].perms["can_save_profiles"] is True
    assert host.roles["Reader"].perms[revoked_permission] is False
