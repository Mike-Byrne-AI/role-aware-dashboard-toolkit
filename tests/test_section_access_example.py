"""Crash tests for section reads, admin actions, and actual Streamlit navigation.

The identity adapter below is trusted synthetic test infrastructure. It does not
claim to exercise provider login, signatures, TLS, or deployment permissions.
"""
from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from examples.section_access import app as example
from examples.section_access.policy import (
    build_roles,
    read_section,
    run_admin_action,
    visible_sections,
)
from role_aware_dashboard_toolkit.access import (
    AccessDenied,
    AccessPolicy,
    AccessStoreError,
    Identity,
    InMemoryAccessStore,
    principal_id,
)
from role_aware_dashboard_toolkit.security import SecurityContext
from role_aware_dashboard_toolkit.streamlit_auth import (
    StreamlitIdentityResolver,
    _SIGN_OUT_PENDING,
)

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
EXPECTED_SECTIONS = {
    "Admin": ("A", "B", "C"),
    "AOnly": ("A",),
    "AB": ("A", "B"),
    "COnly": ("C",),
}
KEY = b"synthetic-section-access-test-key" * 2
ISSUER = "https://section-test.invalid"


def _host(roles=("Admin",), *, frozen=False, store=None):
    host = SimpleNamespace(
        identity=Identity(ISSUER, "synthetic-account", time.time() + 3600),
        patch_state={}, reads=[],
    )
    host.store = store if store is not None else InMemoryAccessStore(
        allowed_roles=EXPECTED_SECTIONS,
    )
    host.principal = principal_id(host.identity, KEY)
    host.store.replace_grants(host.principal, roles)
    if not frozen and host.store.read_freeze().frozen:
        host.store.compare_and_set_freeze(
            False, host.store.read_freeze().revision, host.principal,
        )
    host.policy = AccessPolicy(lambda: host.identity, host.store, KEY)
    return host


def _context(host, role):
    # Mirror prepare_access's captured identity and role. Mutable display fields
    # on this snapshot must never override the policy bound to this closure.
    roles = build_roles()
    principal = host.principal
    return SecurityContext(
        role=role, perms=dict(roles[role].perms), authenticated=True,
        controls_writable=not host.store.read_freeze().frozen,
        user_id=principal,
        _authorize=lambda permission, write: host.policy.authorize(
            principal, role, permission, roles, write=write,
        ),
    )


def _consumer(host):
    import streamlit as st
    from examples.section_access.app import main

    for key, value in host.patch_state.items():
        st.session_state[key] = value
    host.patch_state.clear()
    main(access=host.policy)


def _production_consumer():
    from examples.section_access.app import main

    main()


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


def _app(host, monkeypatch):
    original = example.load_synthetic_section

    def recording_loader(section):
        host.reads.append(section)
        return original(section)

    monkeypatch.setattr(example, "load_synthetic_section", recording_loader)
    return _healthy(AppTest.from_function(
        _consumer, args=(host,), default_timeout=15,
    ).run())


@pytest.fixture
def oidc_host(monkeypatch):
    import streamlit as st
    from streamlit import user_info

    host = _host()
    now = time.time()
    host.claims = {
        "is_logged_in": True, "iss": ISSUER, "sub": "synthetic-account",
        "aud": "section-test-client", "iat": now - 60, "exp": now + 600,
    }
    host.policy = AccessPolicy(
        StreamlitIdentityResolver(
            trusted_issuer=ISSUER, expected_audience="section-test-client",
        ),
        host.store, KEY,
    )
    host.logout_calls = 0
    host.logout_fails = False

    def logout():
        assert "private_previous_account_canary" not in st.session_state
        assert "_radt_pending_replay" not in st.session_state
        assert "section_access_admin_runs" not in st.session_state
        host.logout_calls += 1
        if host.logout_fails:
            raise RuntimeError("synthetic-private-provider-detail")
        host.claims = {"is_logged_in": False}

    monkeypatch.setattr(user_info, "_get_user_info", lambda: host.claims)
    monkeypatch.setattr(st, "logout", logout)
    return host


def _seed_private_sign_out_state(app):
    app.session_state["private_previous_account_canary"] = "must disappear"
    app.session_state["_radt_pending_replay"] = {"queued_write": "synthetic-only"}
    app.session_state["section_access_admin_runs"] = 3


def _assert_sign_out_stopped_private_work(app, host, previous_reads):
    assert host.reads == previous_reads
    assert not app.metric and not app.radio
    for key in (
        "private_previous_account_canary", "_radt_pending_replay",
        "section_access_admin_runs", "_radt_role",
    ):
        assert key not in app.session_state


def test_failed_sign_out_remains_denied_on_rerun_and_supports_recovery(oidc_host, monkeypatch):
    host = oidc_host
    app = _app(host, monkeypatch)
    assert app.metric
    previous_reads = list(host.reads)
    _seed_private_sign_out_state(app)
    host.logout_fails = True

    _healthy(app.button(key="section_access_sign_out").click().run())

    assert host.logout_calls == 1
    assert any("Sign-out is unavailable" in item.value for item in app.error)
    assert "synthetic-private-provider-detail" not in repr(app.error)
    _assert_sign_out_stopped_private_work(app, host, previous_reads)
    for _ in range(2):
        _healthy(app.run())
        _assert_sign_out_stopped_private_work(app, host, previous_reads)
        assert app.session_state[_SIGN_OUT_PENDING] is True
        assert app.button(key="_radt_sign_out").label == "Sign out"
        assert host.logout_calls == 1

    host.logout_fails = False
    _healthy(app.button(key="_radt_sign_out").click().run())
    _healthy(app.run())
    _assert_sign_out_stopped_private_work(app, host, previous_reads)
    assert host.logout_calls == 2
    assert app.button(key="_radt_sign_in").label == "Sign in"
    assert _SIGN_OUT_PENDING not in app.session_state


@pytest.mark.parametrize("access_change", ("none", "revoked", "expired"))
def test_sign_out_click_runs_before_rechecking_access_and_stops_reads(
    oidc_host, monkeypatch, access_change,
):
    host = oidc_host
    app = _app(host, monkeypatch)
    assert app.metric
    previous_reads = list(host.reads)
    _seed_private_sign_out_state(app)
    if access_change == "revoked":
        host.store.replace_grants(host.principal, ())
    elif access_change == "expired":
        host.claims["exp"] = time.time() - 1

    _healthy(app.button(key="section_access_sign_out").click().run())

    assert host.logout_calls == 1
    _assert_sign_out_stopped_private_work(app, host, previous_reads)
    _healthy(app.run())
    _assert_sign_out_stopped_private_work(app, host, previous_reads)
    assert app.button(key="_radt_sign_in").label == "Sign in"
    assert host.logout_calls == 1


@pytest.mark.parametrize("role,sections", EXPECTED_SECTIONS.items())
def test_real_navigation_only_loads_and_displays_assigned_sections(role, sections, monkeypatch):
    host = _host((role,))
    app = _app(host, monkeypatch)
    assert not app.error
    assert app.radio(key="section_access_section").options == list(sections)
    assert app.toggle(key="_radt_shared_frozen").disabled is (role != "Admin")
    # A single assigned role provides no self-service role selector.
    assert not [widget for widget in app.selectbox if widget.key == "_radt_role"]
    for section in sections:
        _healthy(app.radio(key="section_access_section").set_value(section).run())
        rendered = [item.value for item in app.subheader if item.value.startswith("Section ")]
        assert rendered == [f"Section {section}"]
        assert host.reads[-1] == section
    assert set(host.reads) == set(sections)
    actions = [button for button in app.button if button.key == "section_access_admin_action"]
    if role == "Admin":
        assert len(actions) == 1 and not actions[0].disabled
    else:
        assert not actions or all(button.disabled for button in actions)


@pytest.mark.parametrize("role,sections", EXPECTED_SECTIONS.items())
@pytest.mark.parametrize("section", ("A", "B", "C"))
def test_direct_reads_enforce_full_assignment_matrix_before_loader(role, sections, section):
    host = _host((role,))
    ctx = _context(host, role)
    loader = Mock(return_value={"private": section})
    assert visible_sections(ctx) == sections
    if section in sections:
        assert read_section(ctx, section, loader) == {"private": section}
        loader.assert_called_once_with(section)
    else:
        with pytest.raises(AccessDenied):
            read_section(ctx, section, loader)
        loader.assert_not_called()


@pytest.mark.parametrize("role", EXPECTED_SECTIONS)
@pytest.mark.parametrize("frozen", (False, True))
def test_direct_admin_callback_requires_live_admin_and_unfrozen_store(role, frozen):
    host = _host((role,), frozen=frozen)
    ctx = _context(host, role)
    action = Mock(return_value="synthetic-action-completed")
    if role == "Admin" and not frozen:
        assert run_admin_action(ctx, action) == "synthetic-action-completed"
        action.assert_called_once_with()
    else:
        with pytest.raises(AccessDenied):
            run_admin_action(ctx, action)
        action.assert_not_called()


@pytest.mark.parametrize("section", ("D", "a", "../C", "", None))
def test_unknown_section_is_denied_before_loader_even_for_admin(section):
    ctx = _context(_host(), "Admin")
    loader = Mock()
    with pytest.raises(AccessDenied):
        read_section(ctx, section, loader)
    loader.assert_not_called()


@pytest.mark.parametrize("authenticated", (False, True))
def test_demo_or_fabricated_permission_snapshot_cannot_read_or_write(authenticated):
    ctx = SecurityContext(
        role="Admin", perms=dict(build_roles()["Admin"].perms),
        authenticated=authenticated, controls_writable=True,
    )
    loader, action = Mock(), Mock()
    assert visible_sections(ctx) == ()
    with pytest.raises(AccessDenied):
        read_section(ctx, "C", loader)
    with pytest.raises(AccessDenied):
        run_admin_action(ctx, action)
    loader.assert_not_called()
    action.assert_not_called()


def test_forged_context_role_and_permissions_do_not_override_bound_policy():
    host = _host(("AOnly",))
    ctx = _context(host, "AOnly")
    ctx.role = "Admin"
    ctx.perms = dict(build_roles()["Admin"].perms)
    ctx.controls_writable = True
    loader, action = Mock(), Mock()
    assert visible_sections(ctx) == ("A",)
    with pytest.raises(AccessDenied):
        read_section(ctx, "C", loader)
    with pytest.raises(AccessDenied):
        run_admin_action(ctx, action)
    loader.assert_not_called()
    action.assert_not_called()


@pytest.mark.parametrize("failure", ("revoked", "expired", "signed_out", "account_changed", "store_failed"))
def test_stale_admin_context_loses_authority_at_actual_read_and_action_boundary(failure, monkeypatch):
    host = _host()
    ctx = _context(host, "Admin")
    loader, action = Mock(), Mock()
    assert read_section(ctx, "C", loader) is loader.return_value
    loader.reset_mock()
    if failure == "revoked":
        host.store.replace_grants(host.principal, ("AOnly",))
    elif failure == "expired":
        host.identity = Identity(ISSUER, "synthetic-account", time.time() - 1)
    elif failure == "signed_out":
        host.identity = None
    elif failure == "account_changed":
        host.identity = Identity(ISSUER, "other-account", time.time() + 3600)
        host.store.replace_grants(principal_id(host.identity, KEY), ("Admin",))
    else:
        monkeypatch.setattr(host.store, "read_grants", Mock(side_effect=AccessStoreError()))
    assert visible_sections(ctx) == ()
    with pytest.raises(AccessDenied):
        read_section(ctx, "C", loader)
    with pytest.raises(AccessDenied):
        run_admin_action(ctx, action)
    loader.assert_not_called()
    action.assert_not_called()


def test_live_freeze_blocks_old_writable_context_but_keeps_authorized_reads():
    host = _host()
    ctx = _context(host, "Admin")
    host.store.compare_and_set_freeze(True, host.store.read_freeze().revision, host.principal)
    assert ctx.controls_writable is True
    action, loader = Mock(), Mock()
    with pytest.raises(AccessDenied):
        run_admin_action(ctx, action)
    action.assert_not_called()
    assert read_section(ctx, "B", loader) is loader.return_value
    loader.assert_called_once_with("B")


def test_forged_session_role_navigation_and_permissions_cannot_reveal_other_sections(monkeypatch):
    host = _host(("AOnly",))
    app = _app(host, monkeypatch)
    host.patch_state.update({
        "_radt_role": "Admin", "_radt_writable": True,
        "_radt_shared_frozen": False, "section_access_section": "C",
        "_radt_permissions": dict(build_roles()["Admin"].perms),
    })
    _healthy(app.run())
    assert not app.error
    assert app.radio(key="section_access_section").options == ["A"]
    assert app.radio(key="section_access_section").value == "A"
    assert app.session_state["_radt_role"] == "AOnly"
    assert set(host.reads) == {"A"}
    assert "Section C" not in [item.value for item in app.subheader]


def test_assigned_role_switch_uses_selected_role_without_combining_grants(monkeypatch):
    host = _host(("AB", "COnly"))
    app = _app(host, monkeypatch)
    assert app.selectbox(key="_radt_role").options == ["AB", "COnly"]
    assert app.radio(key="section_access_section").options == ["A", "B"]
    _healthy(app.radio(key="section_access_section").set_value("B").run())
    reads_before = len(host.reads)
    _healthy(app.selectbox(key="_radt_role").select("COnly").run())
    assert app.radio(key="section_access_section").options == ["C"]
    assert host.reads[reads_before:] == ["C"]
    assert "Section B" not in [item.value for item in app.subheader]
    host.patch_state["_radt_role"] = "Admin"
    _healthy(app.run())
    assert app.session_state["_radt_role"] == "AB"
    assert app.radio(key="section_access_section").options == ["A", "B"]


@pytest.mark.parametrize("identity_state", ("unassigned", "signed_out", "expired"))
def test_unassigned_and_invalid_accounts_stop_before_loading_sections(identity_state, monkeypatch):
    host = _host(())
    if identity_state == "signed_out":
        host.identity = None
    elif identity_state == "expired":
        host.identity = Identity(ISSUER, "synthetic-account", time.time() - 1)
    app = _app(host, monkeypatch)
    assert host.reads == []
    assert app.error
    assert not app.radio
    assert not app.metric
    assert not [item for item in app.subheader if item.value.startswith("Section ")]


def test_revocation_replaces_visible_section_then_removes_all_protected_content(monkeypatch):
    host = _host()
    app = _app(host, monkeypatch)
    _healthy(app.radio(key="section_access_section").set_value("C").run())
    host.store.replace_grants(host.principal, ("AOnly",))
    reads_before = len(host.reads)
    _healthy(app.run())
    assert host.reads[reads_before:] == ["A"]
    assert app.radio(key="section_access_section").options == ["A"]
    assert "Section C" not in [item.value for item in app.subheader]
    host.store.replace_grants(host.principal, ())
    reads_before = list(host.reads)
    _healthy(app.run())
    assert host.reads == reads_before
    assert not app.radio and not app.metric
    assert app.error


def test_account_switch_discards_previous_account_state_and_uses_new_grants(monkeypatch):
    host = _host()
    app = _app(host, monkeypatch)
    _healthy(app.radio(key="section_access_section").set_value("B").run())
    app.session_state["private_previous_account_canary"] = "must disappear"
    old_session = app.session_state["_radt_authenticated_session"]
    host.identity = Identity(ISSUER, "c-only-account", time.time() + 3600)
    host.store.replace_grants(principal_id(host.identity, KEY), ("COnly",))
    reads_before = len(host.reads)
    _healthy(app.run())
    assert "private_previous_account_canary" not in app.session_state
    assert app.session_state["_radt_authenticated_session"] != old_session
    assert app.radio(key="section_access_section").options == ["C"]
    assert host.reads[reads_before:] == ["C"]
    assert "Section B" not in [item.value for item in app.subheader]


def test_admin_button_and_shared_freeze_are_real_interactions(monkeypatch):
    host = _host(frozen=True)
    app = _app(host, monkeypatch)
    assert app.button(key="section_access_admin_action").disabled
    _healthy(app.toggle(key="_radt_shared_frozen").set_value(False).run())
    assert host.store.read_freeze().frozen is False
    assert not app.button(key="section_access_admin_action").disabled
    assert "section_access_admin_runs" not in app.session_state
    before = 0
    _healthy(app.button(key="section_access_admin_action").click().run())
    assert app.session_state["section_access_admin_runs"] == before + 1
    _healthy(app.toggle(key="_radt_shared_frozen").set_value(True).run())
    assert host.store.read_freeze().frozen is True
    assert app.button(key="section_access_admin_action").disabled
    assert app.session_state["section_access_admin_runs"] == before + 1
    # Freeze blocks writes, while authorized section navigation still works.
    _healthy(app.radio(key="section_access_section").set_value("C").run())
    assert "Section C" in [item.value for item in app.subheader]


def test_forged_non_admin_freeze_callback_cannot_change_server_state(monkeypatch):
    import streamlit as st

    callbacks = []
    original = st.toggle

    def capture_toggle(*args, **kwargs):
        if kwargs.get("key") == "_radt_shared_frozen":
            callbacks.append(kwargs["on_change"])
        return original(*args, **kwargs)

    monkeypatch.setattr(st, "toggle", capture_toggle)
    host = _host(("AOnly",), frozen=True)
    app = _app(host, monkeypatch)
    assert app.toggle(key="_radt_shared_frozen").disabled
    before = host.store.read_freeze()
    forged_state = {"_radt_shared_frozen": False, "_radt_freeze_revision": before.revision}
    with monkeypatch.context() as patch:
        patch.setattr(st, "session_state", forged_state)
        callbacks[-1]()
    assert host.store.read_freeze() == before
    assert forged_state["_radt_freeze_denied"] is True


def test_forced_disabled_admin_button_still_cannot_run_while_frozen(monkeypatch):
    import streamlit as st

    host = _host(frozen=True)
    app = _app(host, monkeypatch)
    original = st.button

    def forge_click(*args, **kwargs):
        clicked = original(*args, **kwargs)
        return True if kwargs.get("key") == "section_access_admin_action" else clicked

    monkeypatch.setattr(st, "button", forge_click)
    _healthy(app.run())
    assert any("Admin action denied" in item.value for item in app.error)
    assert "section_access_admin_runs" not in app.session_state


def test_demo_account_switches_cover_matrix_denial_and_recovery():
    from examples.section_access.demo import demo_store

    demo_store.clear()
    demo_path = Path(example.__file__).with_name("demo.py")
    app = _healthy(AppTest.from_file(str(demo_path), default_timeout=15).run())
    assert any("LOCAL SIMULATION" in item.value for item in app.warning)
    for role, sections in EXPECTED_SECTIONS.items():
        _healthy(app.selectbox(key="section_access_demo_account").select(role).run())
        assert not app.error
        assert app.radio(key="section_access_section").options == list(sections)
        assert app.session_state["_radt_role"] == role
    _healthy(app.selectbox(key="section_access_demo_account").select("Unassigned").run())
    assert app.error
    assert not app.radio and not app.metric
    _healthy(app.selectbox(key="section_access_demo_account").select("AB").run())
    assert not app.error
    assert app.radio(key="section_access_section").options == ["A", "B"]
    demo_store.clear()


def test_unknown_demo_account_query_is_denied_instead_of_defaulting_to_admin():
    demo_path = Path(example.__file__).with_name("demo.py")
    app = AppTest.from_file(str(demo_path), default_timeout=15)
    app.query_params["demo_account"] = "SuperAdmin"
    _healthy(app.run())
    assert app.error
    assert not app.radio and not app.metric
    assert app.selectbox(key="section_access_demo_account").value == "Unassigned"


def test_production_entrypoint_ignores_simulation_query_and_uses_trusted_policy(monkeypatch):
    host = _host(("COnly",))
    monkeypatch.setattr(example, "build_access_policy", lambda: host.policy)
    loader = Mock(wraps=example.load_synthetic_section)
    monkeypatch.setattr(example, "load_synthetic_section", loader)
    app = AppTest.from_function(_production_consumer, default_timeout=15)
    app.query_params["demo_account"] = "Admin"
    _healthy(app.run())
    assert not app.error
    assert app.radio(key="section_access_section").options == ["C"]
    assert app.session_state["_radt_role"] == "COnly"
    assert not [widget for widget in app.selectbox if widget.key == "section_access_demo_account"]
    loader.assert_called_once_with("C")


def test_production_missing_configuration_is_safe_denial_before_data_load(monkeypatch):
    monkeypatch.setattr(
        example, "build_access_policy", Mock(side_effect=ValueError("private-configuration-canary")),
    )
    loader = Mock()
    monkeypatch.setattr(example, "load_synthetic_section", loader)
    app = _healthy(AppTest.from_function(_production_consumer, default_timeout=15).run())
    assert app.error
    assert "private-configuration-canary" not in app.error[0].value
    assert not app.radio and not app.metric
    assert not app.selectbox
    loader.assert_not_called()
