"""A denied authenticated dashboard cannot enable permissive host defaults."""
from __future__ import annotations

import time

import pytest

from role_aware_dashboard_toolkit.access import AccessStoreError, Identity
from role_aware_dashboard_toolkit.security import (
    SecurityContext, can_mutate, can_write, has_perm, make_security_context,
)
from tests.test_authenticated_ui import AppTest, _healthy, _host


def _consumer(host, late_failure=None):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    from role_aware_dashboard_toolkit.security import can_mutate

    plugins = radt.PluginRegistry()
    if late_failure:
        def setup(context):
            # The first render gate succeeds; authority disappears before the
            # sidebar's independent access check during the same render.
            assert radt.has_perm(context["ctx"], "can_view_metrics")
            host.calls.append("authorized_setup")
            if late_failure == "revoked":
                host.store.replace_grants(host.principal, ())
            else:
                def unavailable():
                    raise AccessStoreError()
                host.store.read_freeze = unavailable

        plugins.register(radt.DashboardPlugin("revoke-during-setup", setup=setup))
    ctx = radt.render(radt.DashboardConfig(
        auth_mode="authenticated", access=host.policy, plugins=plugins,
        sections=radt.DashboardSections(
            profiles=False, runbook=False, audit_writer=False, audit_log=False,
            observability=False, plugin_details=False,
        ),
    ))
    st.session_state["returned_context"] = ctx
    if radt.has_perm(ctx, "host_private_read", default=True):
        st.write("Protected host payload")
    if can_mutate(ctx, "host_private_write", default=True):
        host.calls.append("protected_host_write")


def _assert_denied(app, host, expected_calls):
    ctx = app.session_state["returned_context"]
    assert ctx.role == "Unauthenticated"
    assert ctx.authenticated is False
    assert not any(item.value == "Protected host payload" for item in app.markdown)
    assert host.calls == expected_calls
    for check in (has_perm, can_write, can_mutate):
        assert check(ctx, "host_private_access", default=True) is False
        assert check(ctx, "host_private_access") is False


@pytest.mark.parametrize("failure", ["unassigned", "signed_out", "expired", "missing_policy"])
def test_early_authenticated_denial_blocks_permissive_host_defaults(failure):
    host = _host(roles=())
    if failure == "signed_out":
        host.identity = None
    elif failure == "expired":
        host.identity = Identity("https://provider.invalid", "operator-one", time.time() - 10)
    elif failure == "missing_policy":
        host.policy = None
    app = _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())
    _assert_denied(app, host, [])


@pytest.mark.parametrize("failure", ["revoked", "unavailable"])
def test_sidebar_authenticated_denial_blocks_permissive_host_defaults(failure):
    host = _host()
    app = _healthy(AppTest.from_function(
        _consumer, args=(host, failure), default_timeout=15,
    ).run())
    _assert_denied(app, host, ["authorized_setup"])


def test_legacy_context_defaults_are_preserved():
    ctx = make_security_context("Viewer", controls_writable=False)
    assert has_perm(ctx, "legacy_read", default=True) is True
    assert can_mutate(ctx, "legacy_write", default=True) is True
    assert can_write(ctx, "legacy_control", default=True) is False


@pytest.mark.parametrize("authenticated", [False, True])
@pytest.mark.parametrize("writable", [False, True])
@pytest.mark.parametrize("perms", [{}, {"host_private_access": True}])
def test_reserved_denial_role_overrides_defaults_and_conflicting_fields(authenticated, writable, perms):
    authorization_calls = []
    ctx = SecurityContext(
        role="Unauthenticated", perms=perms, authenticated=authenticated,
        controls_writable=writable,
        _authorize=lambda *args: authorization_calls.append(args) or True,
    )
    for check in (has_perm, can_write, can_mutate):
        assert check(ctx, "host_private_access", default=True) is False
        assert check(ctx, "host_private_access") is False
    assert authorization_calls == []
