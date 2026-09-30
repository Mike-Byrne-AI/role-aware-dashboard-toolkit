"""Actual Streamlit button events must survive denial until login/logout reads them.

These tests run the packaged authenticated starter. Only provider claims and
the external redirect calls are synthetic; widget reruns and the access gate
are Streamlit's real implementations.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit.access import (
    AccessPolicy,
    Identity,
    InMemoryAccessStore,
    principal_id,
)
from role_aware_dashboard_toolkit.streamlit_auth import StreamlitIdentityResolver

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
ISSUER = "https://synthetic-issuer.example.test"
AUDIENCE = "synthetic-client"
SUBJECT = "synthetic-account"
KEY = b"synthetic-sign-in-lifecycle-key-32bytes"
PRIVATE_KEYS = (
    "_authenticated_pulse_resources",
    "synthetic_private_host_resource",
    "_radt_pending_replay",
    "_radt_authenticated_control_values",
    "_radt_role",
)


def _run_starter(host):
    host.starter.main()


def _healthy(app):
    assert not app.exception, [error.message for error in app.exception]
    return app


def _assert_private_state_cleared(state):
    for key in PRIVATE_KEYS:
        assert key not in state, f"Denied access retained {key}"


@pytest.fixture
def host(monkeypatch):
    import streamlit as st
    from streamlit import user_info
    from role_aware_dashboard_toolkit import dashboard

    path = Path(__file__).resolve().parents[1] / (
        "role_aware_dashboard_toolkit/resources/authenticated_starter/app.py"
    )
    spec = importlib.util.spec_from_file_location("synthetic_login_lifecycle_starter", path)
    starter = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(starter)
    now = time.time()
    host = SimpleNamespace(
        starter=starter,
        claims={
            "is_logged_in": True,
            "iss": ISSUER,
            "sub": SUBJECT,
            "aud": AUDIENCE,
            "iat": now - 60,
            "exp": now + 600,
        },
        calls=[],
        resource_reads=0,
        store=InMemoryAccessStore(),
    )
    host.principal = principal_id(Identity(ISSUER, SUBJECT, now + 600), KEY)
    host.policy = AccessPolicy(
        StreamlitIdentityResolver(trusted_issuer=ISSUER, expected_audience=AUDIENCE),
        host.store,
        KEY,
    )
    original_resources = starter.session_resources

    def session_resources(initial_audit):
        host.resource_reads += 1
        return original_resources(initial_audit)

    def login(provider=None):
        _assert_private_state_cleared(st.session_state)
        host.calls.append(("login", provider))

    def logout():
        _assert_private_state_cleared(st.session_state)
        host.calls.append(("logout",))
        host.claims = {"is_logged_in": False}

    monkeypatch.setattr(user_info, "_get_user_info", lambda: host.claims)
    monkeypatch.setattr(dashboard, "st", st)
    monkeypatch.setattr(starter, "build_access_policy", lambda: host.policy)
    monkeypatch.setattr(starter, "session_resources", session_resources)
    monkeypatch.setattr(st, "login", login)
    monkeypatch.setattr(st, "logout", logout)
    monkeypatch.setenv("RADT_OIDC_PROVIDER", "synthetic-provider")
    return host


def _app(host):
    return _healthy(AppTest.from_function(_run_starter, args=(host,), default_timeout=15).run())


def _seed_stale_resources(app):
    app.session_state["synthetic_private_host_resource"] = {"private": "synthetic-only"}
    app.session_state["_authenticated_pulse_resources"] = {"private": "synthetic-only"}
    app.session_state["_radt_pending_replay"] = {"queued_write": "synthetic-only"}
    app.session_state["_radt_authenticated_control_values"] = {"weekly_target": 999}
    app.session_state["_radt_role"] = "Admin"


def test_anonymous_sign_in_click_survives_denial_reset_and_calls_streamlit_login(host):
    host.claims = {"is_logged_in": False}
    app = _app(host)
    assert app.button(key="_radt_sign_in").label == "Sign in"
    assert not host.calls
    _seed_stale_resources(app)

    _healthy(app.button(key="_radt_sign_in").click().run())

    assert host.calls == [("login", "synthetic-provider")]
    assert host.resource_reads == 0
    _assert_private_state_cleared(app.session_state)
    assert not app.metric and not app.number_input
    # Button triggers remain one-shot; preserving them must not repeat login.
    _healthy(app.run())
    assert host.calls == [("login", "synthetic-provider")]


@pytest.mark.parametrize("reason", ["unassigned", "expired"])
def test_denied_signed_in_account_can_click_sign_out_without_loading_private_data(host, reason):
    if reason == "expired":
        host.store.replace_grants(host.principal, ("Admin",))
        host.claims["exp"] = time.time() - 1
    app = _app(host)
    assert app.button(key="_radt_sign_out").label == "Sign out"
    _seed_stale_resources(app)

    _healthy(app.button(key="_radt_sign_out").click().run())

    assert host.calls == [("logout",)]
    assert host.resource_reads == 0
    _assert_private_state_cleared(app.session_state)
    assert not app.metric and not app.number_input
    _healthy(app.run())
    assert app.button(key="_radt_sign_in").label == "Sign in"
    assert host.calls == [("logout",)]


@pytest.mark.parametrize("reason", ["revoked", "expired", "signed_out"])
def test_account_losing_access_discards_resources_and_pending_writes_but_recovery_works(host, reason):
    host.store.replace_grants(host.principal, ("Admin",))
    app = _app(host)
    assert host.resource_reads == 1
    assert app.metric
    assert "_authenticated_pulse_resources" in app.session_state
    _seed_stale_resources(app)
    if reason == "revoked":
        host.store.replace_grants(host.principal, ())
    elif reason == "expired":
        host.claims["exp"] = time.time() - 1
    else:
        host.claims = {"is_logged_in": False}

    _healthy(app.run())

    assert host.resource_reads == 1
    _assert_private_state_cleared(app.session_state)
    assert not app.metric and not app.number_input
    key = "_radt_sign_in" if reason == "signed_out" else "_radt_sign_out"
    _healthy(app.button(key=key).click().run())
    assert host.calls == (
        [("login", "synthetic-provider")] if reason == "signed_out" else [("logout",)]
    )
    assert host.resource_reads == 1
    _assert_private_state_cleared(app.session_state)
