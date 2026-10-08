"""Recovery messages distinguish ordinary sign-in from unconfirmed access."""

import time

import pytest

from role_aware_dashboard_toolkit.access import AccessPolicy
from tests import test_auth_sign_in_lifecycle
from tests.test_auth_sign_in_lifecycle import (
    KEY,
    _app,
    _assert_private_state_cleared,
    _healthy,
    _seed_stale_resources,
)


host = test_auth_sign_in_lifecycle.host


def _assert_ordinary_sign_in(app):
    assert not app.error
    assert not app.warning
    assert [item.value for item in app.info] == ["Sign in to open this dashboard."]
    assert app.button(key="_radt_sign_in").label == "Sign in"
    assert not app.metric and not app.number_input


def test_ordinary_signed_out_page_has_one_neutral_prompt_and_working_login(host):
    host.claims = {"is_logged_in": False}
    app = _app(host)
    _assert_ordinary_sign_in(app)
    _seed_stale_resources(app)

    _healthy(app.button(key="_radt_sign_in").click().run())

    _assert_ordinary_sign_in(app)
    _assert_private_state_cleared(app.session_state)
    assert host.calls == [("login", "synthetic-provider")]
    assert host.resource_reads == 0
    _healthy(app.run())
    _assert_ordinary_sign_in(app)
    assert host.calls == [("login", "synthetic-provider")]


@pytest.mark.parametrize("reason", ["unassigned", "revoked", "expired"])
def test_unconfirmed_access_explains_sign_out_and_fresh_login_recovery(host, reason):
    if reason != "unassigned":
        host.store.replace_grants(host.principal, ("Admin",))
    app = _app(host)
    if reason != "unassigned":
        assert app.metric
        _seed_stale_resources(app)
        if reason == "revoked":
            host.store.replace_grants(host.principal, ())
        else:
            host.claims["exp"] = time.time() - 1
        _healthy(app.run())

    assert [item.value for item in app.error] == ["Dashboard access could not be confirmed."]
    assert any("Sign out, then sign in again" in item.value for item in app.warning)
    assert any("administrator" in item.value for item in app.warning)
    assert not app.metric and not app.number_input
    _assert_private_state_cleared(app.session_state)
    reads_before = host.resource_reads

    _healthy(app.button(key="_radt_sign_out").click().run())
    assert host.calls == [("logout",)]
    _healthy(app.run())

    _assert_ordinary_sign_in(app)
    _assert_private_state_cleared(app.session_state)
    assert host.resource_reads == reads_before
    _healthy(app.button(key="_radt_sign_in").click().run())
    assert host.calls == [("logout",), ("login", "synthetic-provider")]


def test_custom_resolver_outage_is_not_mislabeled_as_ordinary_signed_out(host):
    host.claims = {"is_logged_in": False}

    def unavailable():
        raise RuntimeError("synthetic-private-resolver-detail")

    host.policy = AccessPolicy(unavailable, host.store, KEY)
    app = _app(host)

    assert [item.value for item in app.error] == ["Dashboard access could not be confirmed."]
    assert "synthetic-private-resolver-detail" not in repr(app.error)
    assert host.resource_reads == 0
    assert not app.metric and not app.number_input


def test_unreadable_provider_status_keeps_error_and_safe_sign_in_recovery(host, monkeypatch):
    from streamlit import user_info

    def unavailable():
        raise RuntimeError("synthetic-private-provider-detail")

    monkeypatch.setattr(user_info, "_get_user_info", unavailable)
    app = _app(host)

    assert [item.value for item in app.error] == ["Dashboard access could not be confirmed."]
    assert any("Sign-in status could not be read" in item.value for item in app.warning)
    assert "synthetic-private-provider-detail" not in repr(app.error)
    assert "synthetic-private-provider-detail" not in repr(app.warning)
    assert host.resource_reads == 0
    assert not app.metric and not app.number_input
    _healthy(app.button(key="_radt_sign_in").click().run())
    assert host.calls == [("login", "synthetic-provider")]


def test_normal_logout_returns_to_neutral_sign_in_without_stale_denial(host):
    host.store.replace_grants(host.principal, ("Admin",))
    app = _app(host)
    assert app.metric

    _healthy(app.button(key="_authenticated_pulse_sign_out").click().run())
    _healthy(app.run())

    _assert_ordinary_sign_in(app)
    _assert_private_state_cleared(app.session_state)
    assert host.calls == [("logout",)]


@pytest.mark.parametrize("restored_role", ["Admin", "Operator"])
def test_recovery_sign_out_survives_grant_restoration_before_click(host, restored_role):
    host.store.replace_grants(host.principal, ("Operator",))
    app = _app(host)
    host.store.replace_grants(host.principal, ())
    _healthy(app.run())
    assert app.button(key="_radt_sign_out").label == "Sign out"
    reads_before = host.resource_reads

    # Authority can reappear between rendering denial and receiving its button
    # event. The recovery action must execute before the access gate reruns.
    host.store.replace_grants(host.principal, (restored_role,))
    _seed_stale_resources(app)
    _healthy(app.button(key="_radt_sign_out").click().run())

    assert host.calls == [("logout",)]
    assert host.resource_reads == reads_before
    _assert_private_state_cleared(app.session_state)
    assert not app.metric and not app.number_input
    _healthy(app.run())
    _assert_ordinary_sign_in(app)
    _healthy(app.run())
    assert host.calls == [("logout",)]


def test_failed_recovery_sign_out_stops_before_newly_restored_access(host, monkeypatch):
    import streamlit as st

    app = _app(host)
    host.store.replace_grants(host.principal, ("Admin",))
    _seed_stale_resources(app)

    def unavailable():
        _assert_private_state_cleared(st.session_state)
        host.calls.append(("logout",))
        raise RuntimeError("synthetic-private-provider-detail")

    monkeypatch.setattr(st, "logout", unavailable)
    _healthy(app.button(key="_radt_sign_out").click().run())

    assert host.calls == [("logout",)]
    assert host.resource_reads == 0
    assert not app.metric and not app.number_input
    assert any("Sign-out is unavailable" in item.value for item in app.error)
    assert "synthetic-private-provider-detail" not in repr(app.error)
    _assert_private_state_cleared(app.session_state)
