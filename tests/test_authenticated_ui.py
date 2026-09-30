"""Real Streamlit authentication, account changes and shared freeze callbacks."""
from __future__ import annotations

from types import SimpleNamespace
import time

import pytest

from role_aware_dashboard_toolkit import AuditLog
from role_aware_dashboard_toolkit.access import (
    AccessPolicy, AccessStoreError, Identity, InMemoryAccessStore, principal_id,
)
from role_aware_dashboard_toolkit.security import SecurityContext, can_mutate, can_write, has_perm

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _consumer(host):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    if "config" not in st.session_state:
        host.builds += 1
        registry = radt.ControlRegistry()
        registry.register("Review note", kind="text", key="review_note", default="Initial")
        plugins = radt.PluginRegistry()

        def setup(context):
            host.calls.append(("setup", context["ctx"].user_id))

        def panel(context):
            host.calls.append(("source_panel", context["ctx"].user_id))
            context["st"].write("Private experiment source")

        plugins.register(radt.DashboardPlugin("private-source", setup=setup, render_panel=panel))
        st.session_state["resource"] = object()
        st.session_state["config"] = radt.DashboardConfig(
            title="Authenticated UI test", registry=registry, audit=host.audit,
            auth_mode="authenticated", access=host.policy, plugins=plugins,
            profile_store=radt.InMemoryProfileStore(),
            sections=radt.DashboardSections(
                profiles=False, runbook=False, audit_writer=False,
                audit_log=False, observability=False, plugin_details=False,
            ),
        )
    for key, value in host.patch_state.items():
        st.session_state[key] = value
    host.patch_state.clear()
    ctx = radt.render(st.session_state["config"])
    st.session_state["test_context"] = ctx


def _host(roles=("Admin",), *, store=None, subject="operator-one"):
    host = SimpleNamespace(
        identity=Identity("https://provider.invalid", subject, time.time() + 3600),
        audit=AuditLog(), calls=[], builds=0, patch_state={},
    )
    host.store = store if store is not None else InMemoryAccessStore()
    host.key = b"test-only-identity-key-material-32bytes"
    host.principal = principal_id(host.identity, host.key)
    host.store.replace_grants(host.principal, roles)
    host.policy = AccessPolicy(lambda: host.identity, host.store, host.key)
    return host


def _prepared_consumer(host):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    from role_aware_dashboard_toolkit.access import AccessDenied
    from role_aware_dashboard_toolkit.dashboard import prepare_access

    config = radt.DashboardConfig(auth_mode="authenticated", access=host.policy, audit=host.audit)
    try:
        ctx = prepare_access(config)
    except AccessDenied:
        return
    host.calls.append(("protected_host_read", ctx.user_id))
    st.session_state["protected_host_resource"] = object()
    st.session_state["test_context"] = ctx
    st.write("Protected host data")


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


def _app(host):
    return _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())


def test_authenticated_initial_render_restarts_then_runs_protected_plugins():
    host = _host()
    app = _app(host)
    ctx = app.session_state["test_context"]
    assert ctx.authenticated and ctx.user_id == host.principal
    assert ctx.role == "Admin" and not ctx.controls_writable
    assert host.calls == [("setup", host.principal), ("source_panel", host.principal)]
    assert len(ctx.session_id) == 32
    assert app.toggle(key="_radt_shared_frozen").value is True
    assert not app.toggle(key="_radt_shared_frozen").disabled


@pytest.mark.parametrize("identity_state", ["unknown", "signed_out", "expired"])
def test_unassigned_or_invalid_identity_stops_before_setup_and_source_panels(identity_state):
    host = _host(roles=())
    if identity_state == "signed_out":
        host.identity = None
    elif identity_state == "expired":
        host.identity = Identity("https://provider.invalid", "operator-one", time.time() - 10)
    app = _app(host)
    assert host.calls == []
    assert len(app.error) == 1
    assert app.session_state["test_context"].role == "Unauthenticated"
    assert not app.selectbox
    assert not app.toggle
    assert not app.text_input
    assert not any(item.value == "Private experiment source" for item in app.markdown)


def test_chooser_contains_only_assigned_roles_and_ignores_forged_admin_state():
    host = _host(("Viewer", "Operator"))
    app = _app(host)
    chooser = app.selectbox(key="_radt_role")
    assert chooser.options == ["Viewer", "Operator"]
    _healthy(chooser.select("Operator").run())
    assert app.session_state["test_context"].role == "Operator"
    # Inject after AppTest serializes the legal selectbox choices, before the
    # dashboard checks its mutable session state.
    host.patch_state["_radt_role"] = "Admin"
    _healthy(app.run())
    assert app.session_state["test_context"].role == "Viewer"
    assert app.selectbox(key="_radt_role").options == ["Viewer", "Operator"]
    assert app.toggle(key="_radt_shared_frozen").disabled
    assert all(event.get("new") != "Admin" for event in host.audit.all_events())


def test_account_change_rebuilds_resources_and_discards_deferred_writes():
    host = _host()
    app = _app(host)
    old_resource = app.session_state["resource"]
    old_session = app.session_state["test_context"].session_id
    app.session_state["_private_evidence"] = "previous account data"
    app.session_state["_radt_pending_replay"] = {"invalid": "must be discarded"}
    host.identity = Identity("https://provider.invalid", "second-account", time.time() + 3600)
    second_principal = principal_id(host.identity, host.key)
    host.store.replace_grants(second_principal, ("Viewer",))
    calls_before = len(host.calls)
    _healthy(app.run())

    assert app.session_state["resource"] is not old_resource
    assert "_private_evidence" not in app.session_state
    assert "_radt_pending_replay" not in app.session_state
    ctx = app.session_state["test_context"]
    assert ctx.user_id == second_principal and ctx.role == "Viewer"
    assert ctx.session_id != old_session
    assert all(principal == second_principal for _, principal in host.calls[calls_before:])


def test_revoked_selected_role_falls_back_to_remaining_grant_and_discards_replay():
    host = _host(("Admin", "Viewer"))
    app = _app(host)
    app.session_state["_radt_pending_replay"] = {"invalid": "must be discarded"}
    host.store.replace_grants(host.principal, ("Viewer",))
    _healthy(app.run())
    assert app.session_state["test_context"].role == "Viewer"
    assert "_radt_pending_replay" not in app.session_state
    assert not app.selectbox
    assert app.toggle(key="_radt_shared_frozen").disabled
    host.store.replace_grants(host.principal, ())
    calls_before = list(host.calls)
    _healthy(app.run())
    assert host.calls == calls_before
    assert len(app.error) == 1
    assert app.session_state["test_context"].role == "Unauthenticated"
    assert "resource" not in app.session_state


def test_admin_freeze_callback_is_shared_across_sessions_and_audit_is_bound():
    host = _host()
    first = _app(host)
    second = _app(host)
    first_session = first.session_state["test_context"].session_id
    second_session = second.session_state["test_context"].session_id
    assert first_session != second_session
    _healthy(first.toggle(key="_radt_shared_frozen").set_value(False).run())
    assert host.store.read_freeze().frozen is False
    _healthy(second.run())
    assert second.toggle(key="_radt_shared_frozen").value is False
    assert not second.text_input(key="review_note").disabled
    _healthy(second.toggle(key="_radt_shared_frozen").set_value(True).run())
    _healthy(first.run())
    assert first.toggle(key="_radt_shared_frozen").value is True
    assert next(item for item in first.text_input if item.label == "Review note").disabled
    events = [event for event in host.audit.all_events() if event["type"] == "shared_freeze_changed"]
    assert [(event["new"], event["session_id"]) for event in events] == [
        (False, first_session), (True, second_session),
    ]
    assert {event["user_id"] for event in events} == {host.principal}
    assert "operator-one" not in host.audit.export_jsonl()
    assert "user_id" not in vars(host.audit)


def test_stale_admin_freeze_callback_cannot_overwrite_newer_server_revision():
    host = _host()
    first = _app(host)
    stale = _app(host)
    _healthy(first.toggle(key="_radt_shared_frozen").set_value(False).run())
    _healthy(first.toggle(key="_radt_shared_frozen").set_value(True).run())
    before = host.store.read_freeze()
    _healthy(stale.toggle(key="_radt_shared_frozen").set_value(False).run())
    assert host.store.read_freeze() == before
    assert stale.toggle(key="_radt_shared_frozen").value is True
    assert any("superseded" in item.value for item in stale.warning)
    events = [event for event in host.audit.all_events() if event["type"] == "shared_freeze_changed"]
    assert len(events) == 2


def test_viewer_forged_toggle_callback_cannot_change_shared_freeze():
    host = _host(("Viewer",))
    app = _app(host)
    before = host.store.read_freeze()
    assert app.toggle(key="_radt_shared_frozen").disabled
    _healthy(app.toggle(key="_radt_shared_frozen").set_value(False).run())
    assert host.store.read_freeze() == before
    assert app.toggle(key="_radt_shared_frozen").value is True
    assert not any(event["type"] == "shared_freeze_changed" for event in host.audit.all_events())


def test_freeze_store_failure_removes_protected_content_and_stale_authority(monkeypatch):
    host = _host()
    app = _app(host)
    previous_context = app.session_state["test_context"]
    calls_before = list(host.calls)

    def unavailable():
        raise AccessStoreError()

    monkeypatch.setattr(host.store, "read_freeze", unavailable)
    _healthy(app.run())
    assert host.calls == calls_before
    assert len(app.error) == 1
    assert app.session_state["test_context"].role == "Unauthenticated"
    assert not app.text_input
    assert not previous_context._authorize("can_edit_controls", True)


def test_freeze_callback_rechecks_revoked_admin_before_app_rerun():
    host = _host()
    app = _app(host)
    before = host.store.read_freeze()
    host.store.replace_grants(host.principal, ("Viewer",))
    _healthy(app.toggle(key="_radt_shared_frozen").set_value(False).run())
    assert host.store.read_freeze() == before
    assert app.session_state["test_context"].role == "Viewer"
    assert not any(event["type"] == "shared_freeze_changed" for event in host.audit.all_events())


def test_missing_access_configuration_never_falls_back_to_demo_picker():
    host = _host()
    host.policy = None
    app = _app(host)
    assert len(app.error) == 1
    assert host.calls == []
    assert not app.selectbox
    assert app.session_state["test_context"].role == "Unauthenticated"


def test_prepare_access_guards_host_reads_and_discards_revoked_resources():
    host = _host()
    app = _healthy(AppTest.from_function(_prepared_consumer, args=(host,), default_timeout=15).run())
    assert host.calls == [("protected_host_read", host.principal)]
    assert "protected_host_resource" in app.session_state
    host.store.replace_grants(host.principal, ())
    _healthy(app.run())
    assert host.calls == [("protected_host_read", host.principal)]
    assert "protected_host_resource" not in app.session_state
    assert not app.markdown
    assert len(app.error) == 1


def test_role_change_discards_replay_created_under_another_assigned_role():
    from role_aware_dashboard_toolkit import build_checkpoint_packet
    from role_aware_dashboard_toolkit._ui_state import queue_replay

    host = _host(("Admin", "Operator"))
    app = _app(host)
    _healthy(app.toggle(key="_radt_shared_frozen").set_value(False).run())
    queue_replay(app.session_state, build_checkpoint_packet({}), "old-role-checkpoint")
    _healthy(app.selectbox(key="_radt_role").select("Operator").run())
    assert "_radt_pending_replay" not in app.session_state
    assert app.session_state["test_context"].role == "Operator"
    assert any("active role has changed" in item.value for item in app.warning)
    assert not any(event["type"] == "checkpoint_replay" for event in host.audit.all_events())


@pytest.mark.parametrize("failure", ["exception", "malformed"])
def test_untrusted_store_failure_is_safe_denial_before_protected_setup(monkeypatch, failure):
    host = _host()
    app = _app(host)
    calls_before = list(host.calls)

    def failed_read():
        if failure == "exception":
            raise OSError("private-store-path-and-token-canary")
        return None

    monkeypatch.setattr(host.store, "read_freeze", failed_read)
    _healthy(app.run())
    assert host.calls == calls_before
    assert len(app.error) == 1
    assert "private-store-path-and-token-canary" not in app.error[0].value
    assert not app.toggle
    assert app.session_state["test_context"].role == "Unauthenticated"


@pytest.mark.parametrize("check", [has_perm, can_write, can_mutate])
def test_authenticated_missing_permission_mapping_cannot_use_permissive_default(check):
    authorization_calls = []
    ctx = SecurityContext(
        role="Admin", perms=None, authenticated=True,
        _authorize=lambda *args: authorization_calls.append(args) or True,
    )
    assert check(ctx, "can_edit_controls", default=True) is False
    assert authorization_calls == []


@pytest.mark.parametrize("check", [has_perm, can_write, can_mutate])
@pytest.mark.parametrize("perms", [{}, {"can_edit_controls": False}])
def test_absent_or_denied_permission_does_not_reach_live_authorization(check, perms):
    authorization_calls = []
    ctx = SecurityContext(
        role="Admin", perms=perms, authenticated=True,
        _authorize=lambda *args: authorization_calls.append(args) or True,
    )
    assert check(ctx, "can_edit_controls") is False
    assert authorization_calls == []


@pytest.mark.parametrize("perms", [[], "Admin", False])
def test_malformed_permission_mapping_never_authorizes(perms):
    authorization_calls = []
    ctx = SecurityContext(
        role="Admin", perms=perms, authenticated=True,
        _authorize=lambda *args: authorization_calls.append(args) or True,
    )
    assert can_write(ctx, "can_edit_controls", default=True) is False
    assert can_mutate(ctx, "can_edit_controls", default=True) is False
    # has_perm retains its documented type-error contract for malformed maps.
    with pytest.raises(TypeError, match="must be a mapping"):
        has_perm(ctx, "can_edit_controls", default=True)
    assert authorization_calls == []


@pytest.mark.parametrize("check", [has_perm, can_write, can_mutate])
def test_authenticated_permission_snapshot_without_live_authorizer_cannot_grant_access(check):
    ctx = SecurityContext(role="Admin", perms={"can_edit_controls": True}, authenticated=True)
    assert check(ctx, "can_edit_controls", default=True) is False
