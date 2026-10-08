"""Authentication adapter checks use synthetic claims, never a live account."""

from __future__ import annotations

import subprocess
import sys
import traceback
from collections.abc import Mapping
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit.access import AccessDenied, Identity
from role_aware_dashboard_toolkit.streamlit_auth import (
    StreamlitIdentityResolver,
    render_sign_in,
)


@pytest.fixture
def runtime(monkeypatch):
    st = SimpleNamespace(
        user={
            "is_logged_in": True,
            "iss": "https://issuer.example.test",
            "sub": "synthetic-subject",
            "aud": "synthetic-client",
            "iat": 900,
            "exp": 2000,
        },
        session_state={"_radt_role": "Admin"},
        query_params={"role": "Admin"},
    )
    monkeypatch.setitem(sys.modules, "streamlit", st)
    return st


def resolver(**overrides):
    options = {
        "trusted_issuer": "https://issuer.example.test",
        "expected_audience": "synthetic-client",
        "max_session_age": 600,
        "clock": lambda: 1000,
    }
    options.update(overrides)
    return StreamlitIdentityResolver(**options)


def test_minimal_identity_ignores_extra_personal_claims_and_role_input(runtime):
    runtime.user.update(
        email="synthetic@example.test",
        name="Synthetic Person",
        role="Admin",
        access_token="synthetic-private-token",
    )
    identity = resolver()()
    assert identity == Identity(
        issuer="https://issuer.example.test",
        subject="synthetic-subject",
        expires_at=1500,
    )
    assert not hasattr(identity, "email")
    assert not hasattr(identity, "role")
    assert not hasattr(identity, "access_token")


@pytest.mark.parametrize("claim", ["is_logged_in", "iss", "sub", "aud", "iat", "exp"])
def test_missing_required_claim_denies(runtime, claim):
    runtime.user.pop(claim)
    with pytest.raises(AccessDenied, match=r"^Access denied\.$"):
        resolver()()


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("is_logged_in", False),
        ("is_logged_in", "true"),
        ("is_logged_in", 1),
        ("iss", "https://other-issuer.example.test"),
        ("iss", "https://issuer.example.test/"),
        ("sub", None),
        ("sub", ""),
        ("sub", " "),
        ("sub", " leading-space"),
        ("sub", "line\nbreak"),
        ("sub", "é"),
        ("sub", "a" * 256),
        ("sub", 12),
        ("aud", "other-client"),
        ("aud", ["other-client"]),
        ("aud", []),
        ("aud", ["synthetic-client", None]),
        ("aud", {"synthetic-client": True}),
        ("aud", ("synthetic-client",)),
        ("azp", "other-client"),
        ("azp", None),
        ("iat", True),
        ("iat", "900"),
        ("iat", 1001),
        ("iat", 400),
        ("iat", float("nan")),
        ("iat", float("inf")),
        ("exp", 1000),
        ("exp", 999),
        ("exp", 800),
        ("exp", "2000"),
        ("exp", True),
        ("exp", float("nan")),
        ("exp", float("inf")),
        ("exp", -(10**1000)),
        ("nbf", 1001),
        ("nbf", "900"),
        ("nbf", None),
        ("auth_time", 901),
        ("auth_time", 400),
        ("auth_time", None),
        ("auth_time", "900"),
    ],
)
def test_malformed_wrong_or_stale_claim_denies(runtime, claim, value):
    runtime.user[claim] = value
    with pytest.raises(AccessDenied, match=r"^Access denied\.$"):
        resolver()()


def test_multiple_audiences_require_matching_authorized_party(runtime):
    runtime.user["aud"] = ["synthetic-client", "another-resource"]
    with pytest.raises(AccessDenied):
        resolver()()
    runtime.user["azp"] = "synthetic-client"
    assert resolver()().subject == "synthetic-subject"


def test_single_audience_array_is_allowed(runtime):
    runtime.user["aud"] = ["synthetic-client"]
    assert resolver()().subject == "synthetic-subject"


def test_identity_expiry_uses_earliest_token_or_session_deadline(runtime):
    runtime.user["exp"] = 1100
    assert resolver()().expires_at == 1100
    runtime.user["exp"] = 2000
    assert resolver()().expires_at == 1500
    runtime.user["auth_time"] = 500
    assert resolver()().expires_at == 1100


def test_authentication_freshness_can_be_required(runtime):
    require_fresh = resolver(require_auth_time=True)
    with pytest.raises(AccessDenied):
        require_fresh()
    runtime.user["auth_time"] = 900
    assert require_fresh().expires_at == 1500


def test_eligible_not_before_claim_is_allowed(runtime):
    runtime.user["nbf"] = 1000
    assert resolver()().subject == "synthetic-subject"


def test_resolver_rereads_current_identity_and_current_time(runtime):
    clock = [1000]
    current = resolver(clock=lambda: clock[0])
    assert current().subject == "synthetic-subject"
    runtime.user["sub"] = "other-subject"
    assert current().subject == "other-subject"
    clock[0] = 1500
    with pytest.raises(AccessDenied):
        current()
    runtime.user = {}
    with pytest.raises(AccessDenied):
        current()


@pytest.mark.parametrize("user", [None, "synthetic-subject", SimpleNamespace(is_logged_in=True)])
def test_non_mapping_user_cannot_supply_identity(runtime, user):
    runtime.user = user
    with pytest.raises(AccessDenied):
        resolver()()


class UnavailableUser(Mapping):
    def __getitem__(self, key):
        raise RuntimeError("synthetic-private-provider-detail")

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0


def test_provider_failure_does_not_expose_exception_details(runtime):
    runtime.user = UnavailableUser()
    with pytest.raises(AccessDenied) as denied:
        resolver()()
    displayed = "".join(traceback.format_exception(denied.value))
    assert "synthetic-private-provider-detail" not in displayed


@pytest.mark.parametrize(
    "options",
    [
        {"trusted_issuer": ""},
        {"trusted_issuer": " issuer"},
        {"trusted_issuer": None},
        {"expected_audience": ""},
        {"expected_audience": "client\n"},
        {"max_session_age": 0},
        {"max_session_age": -1},
        {"max_session_age": "600"},
        {"max_session_age": True},
        {"max_session_age": float("nan")},
        {"max_session_age": float("inf")},
        {"max_session_age": 10**1000},
        {"require_auth_time": "true"},
        {"clock": 1000},
    ],
)
def test_invalid_server_configuration_is_rejected(options):
    with pytest.raises(ValueError):
        resolver(**options)


@pytest.mark.parametrize("value", [None, True, float("nan"), float("inf"), -1])
def test_broken_clock_denies(runtime, value):
    with pytest.raises(AccessDenied):
        resolver(clock=lambda: value)()


def test_import_does_not_require_streamlit_or_authlib():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import role_aware_dashboard_toolkit.streamlit_auth; "
            "assert 'streamlit' not in sys.modules; assert 'authlib' not in sys.modules",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_installed_streamlit_user_proxy_contract(monkeypatch):
    st = pytest.importorskip("streamlit")
    from streamlit import user_info

    synthetic_claims = {
        "is_logged_in": True,
        "iss": "https://issuer.example.test",
        "sub": "synthetic-subject",
        "aud": "synthetic-client",
        "iat": 900,
        "exp": 2000,
    }
    monkeypatch.setattr(user_info, "_get_user_info", lambda: synthetic_claims)
    assert isinstance(st.user, Mapping)
    assert resolver()().subject == "synthetic-subject"
    synthetic_claims["is_logged_in"] = False
    with pytest.raises(AccessDenied):
        resolver()()


class StopRendering(BaseException):
    pass


class LoginPage:
    def __init__(self, user, *, clicked=False, fail=False):
        self.user = user
        self.clicked = clicked
        self.fail = fail
        self.calls = []

    def warning(self, message):
        self.calls.append(("warning", message))

    def info(self, message):
        self.calls.append(("info", message))

    def error(self, message):
        self.calls.append(("error", message))

    def button(self, label, *, key, on_click=None):
        self.calls.append(("button", label, key))
        if self.clicked and on_click is not None:
            on_click()
        return self.clicked

    def login(self, provider):
        self.calls.append(("login", provider))
        if self.fail:
            raise RuntimeError("synthetic-private-provider-detail")

    def logout(self):
        self.calls.append(("logout",))
        if self.fail:
            raise RuntimeError("synthetic-private-provider-detail")

    def stop(self):
        self.calls.append(("stop",))
        raise StopRendering()


@pytest.mark.parametrize("logged_in", [False, True])
@pytest.mark.parametrize("clicked", [False, True])
def test_sign_in_page_stops_before_protected_content(logged_in, clicked):
    st = LoginPage({"is_logged_in": logged_in}, clicked=clicked)
    with pytest.raises(StopRendering):
        render_sign_in(st, provider="synthetic-provider")
    assert st.calls[-1] == ("stop",)
    if clicked:
        assert st.calls[-2] == (
            ("logout",) if logged_in else ("login", "synthetic-provider")
        )
    else:
        assert not any(call[0] in {"login", "logout"} for call in st.calls)


@pytest.mark.parametrize("logged_in", [False, True])
def test_sign_in_failure_stops_with_generic_message(logged_in):
    st = LoginPage({"is_logged_in": logged_in}, clicked=True, fail=True)
    with pytest.raises(StopRendering):
        render_sign_in(st)
    assert any(call[0] == "error" for call in st.calls)
    assert "synthetic-private-provider-detail" not in repr(st.calls)
    assert st.calls[-1] == ("stop",)


def test_missing_auth_configuration_still_renders_sign_in():
    st = LoginPage(UnavailableUser())
    with pytest.raises(StopRendering):
        render_sign_in(st)
    assert ("button", "Sign in", "_radt_sign_in") in st.calls


def test_sign_in_does_not_continue_if_host_stop_wrapper_returns():
    st = LoginPage({})
    st.stop = lambda: None
    with pytest.raises(AccessDenied):
        render_sign_in(st)
