"""Scaffolding and host-boundary proof for the authenticated starter."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import cli
from role_aware_dashboard_toolkit.access import AccessDenied, AccessPolicy, Identity, InMemoryAccessStore
from role_aware_dashboard_toolkit.guidance import inspect_capabilities, read_guide, read_starter

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def test_authenticated_scaffold_matches_readonly_example_and_contains_no_secrets(tmp_path, capsys):
    destination = tmp_path / "shared"
    assert cli.main(["init", str(destination), "--auth", "--dry-run", "--format", "json"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert ".gitignore" in preview["result"]["files"]
    assert not destination.exists()
    assert cli.main(["init", str(destination), "--auth", "--format", "json"]) == 0
    capsys.readouterr()
    files = read_starter(authenticated=True)
    for name, source in files.items():
        assert (destination / name).read_text(encoding="utf-8") == source
    assert not list(destination.rglob("*secret*"))
    assert not list(destination.rglob("*.key"))
    assert not list(destination.rglob("*.sqlite3"))
    assert cli.main(["example", "authenticated", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["result"]["files"] == files
    assert 'auth_mode="authenticated"' in files["app.py"]
    assert 'auth_mode="demo"' in read_starter()["app.py"]
    generated_config = tomllib.loads(
        (destination / ".streamlit/config.toml").read_text(encoding="utf-8")
    )
    assert generated_config["client"]["disableDataExport"] is True
    assert generated_config["client"]["showErrorDetails"] == "none"
    assert generated_config["server"]["address"] == "127.0.0.1"
    demo_config = tomllib.loads(read_starter()[".streamlit/config.toml"])
    assert demo_config.get("client", {}).get("disableDataExport", False) is False


def test_authentication_guide_is_discoverable_offline(capsys):
    assert cli.main(["guide", "authentication", "--format", "json"]) == 0
    content = json.loads(capsys.readouterr().out)["result"]["content"]
    assert content == read_guide("authentication")["content"]
    assert "access_cli grant" in content
    assert "application never enrolls the first" in content
    assert "Provider-side account/session revocation is not" in content


def test_installed_auth_guidance_requires_current_host_and_session_acceptance():
    guide = read_guide("authentication")["content"]
    starter_readme = read_starter(authenticated=True)["README.md"]
    requirements = inspect_capabilities()

    assert "Streamlit >=1.66.1" in requirements["authentication_requirements"]["streamlit"]
    assert "Authlib >=1.9.1" in requirements["authentication_requirements"]["streamlit"]
    assert requirements["appearance_requirements"]["core_workbench"] == "Streamlit >=1.66.1"
    assert requirements["appearance_requirements"]["pillow"] == "Pillow >=13.0.0"
    assert requirements["python_requirements"] == {
        "core": ">=3.10", "api": ">=3.10", "pandas": ">=3.10",
        "workbench": ">=3.11", "auth": ">=3.11", "full": ">=3.11", "dev": ">=3.11",
    }
    for content in (guide, starter_readme):
        assert "streamlit[auth]>=1.66.1" in content
        assert "Python 3.11" in content
        assert "without system site packages" in content
        assert "pip check" in content
        assert "1.52.2" not in content
    assert "pip-audit" in guide
    assert "| Authlib | 1.9.1 |" in guide
    assert "| certifi | 2026.10.19 |" in guide
    assert "without the initiating browser session" in guide
    assert "consumed authorization code" in guide
    assert "durable protected history of grants" in guide
    assert "post_logout_redirect_uri" in guide
    assert "signed browser token cookie" in guide
    assert "do not set Secure" in " ".join(guide.split())


@pytest.fixture
def starter():
    path = Path(__file__).resolve().parents[1] / "role_aware_dashboard_toolkit/resources/authenticated_starter/app.py"
    spec = importlib.util.spec_from_file_location("synthetic_authenticated_starter", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class StopPage(BaseException):
    pass


@pytest.mark.parametrize("sign_out_pending", [False, True])
def test_missing_configuration_stops_before_identity_or_host_data(starter, monkeypatch, sign_out_pending):
    from role_aware_dashboard_toolkit.streamlit_auth import _SIGN_OUT_PENDING

    events = []
    state = {"private-cache": "synthetic-private-data", "_radt_pending_replay": {"weekly_target": 99}}
    state[_SIGN_OUT_PENDING] = sign_out_pending

    def broken_configuration():
        raise RuntimeError("synthetic-private-secret")

    def stop():
        raise StopPage()

    monkeypatch.setattr(starter, "build_access_policy", broken_configuration)
    monkeypatch.setattr(starter, "prepare_access", lambda config: events.append("identity"))
    monkeypatch.setattr(starter, "session_resources", lambda: events.append("host data"))
    monkeypatch.setattr(starter, "st", SimpleNamespace(
        set_page_config=lambda **kwargs: None,
        error=lambda message: events.append(message), stop=stop, session_state=state,
    ))
    with pytest.raises(StopPage):
        starter.main()
    assert events == ["Access configuration is unavailable. Contact the dashboard administrator."]
    assert state == ({_SIGN_OUT_PENDING: True} if sign_out_pending else {})


def test_denial_does_not_build_controls_or_load_host_data(starter, monkeypatch):
    events = []

    def denied(config):
        events.append("identity gate")
        raise AccessDenied()

    def login(st, *, provider):
        events.append("login")
        raise StopPage()

    monkeypatch.setattr(starter, "build_access_policy", lambda: object())
    monkeypatch.setattr(starter, "prepare_access", denied)
    monkeypatch.setattr(starter, "render_sign_in", login)
    monkeypatch.setattr(starter, "build_controls", lambda: events.append("controls"))
    monkeypatch.setattr(starter, "session_resources", lambda: events.append("host data"))
    monkeypatch.setattr(starter, "st", SimpleNamespace(set_page_config=lambda **kwargs: None))
    with pytest.raises(StopPage):
        starter.main()
    assert events == ["identity gate", "login"]


def test_signout_stops_before_reloading_account_resources(starter, monkeypatch):
    from role_aware_dashboard_toolkit.streamlit_auth import _SIGN_OUT_PENDING

    events = []

    def stop():
        raise StopPage()

    def sign_out_button(*args, **kwargs):
        kwargs["on_click"]()

    monkeypatch.setattr(starter, "build_access_policy", lambda: object())
    monkeypatch.setattr(starter, "prepare_access", lambda config: events.append("identity gate"))
    monkeypatch.setattr(starter, "session_resources", lambda: events.append("host data"))
    monkeypatch.setattr(starter, "st", SimpleNamespace(
        set_page_config=lambda **kwargs: None,
        button=sign_out_button,
        session_state={"synthetic-account-data": True},
        logout=lambda: events.append("logout"), stop=stop,
    ))
    with pytest.raises(StopPage):
        starter.main()
    assert events == ["identity gate", "logout"]
    assert starter.st.session_state == {_SIGN_OUT_PENDING: True}


def test_authorized_render_loads_host_resources_after_gate(starter, monkeypatch):
    events = []
    resources = {"audit": object(), "profiles": object()}
    monkeypatch.setattr(starter, "build_access_policy", lambda: object())
    monkeypatch.setattr(starter, "prepare_access", lambda config: events.append("identity gate"))

    def host_resources(initial_audit):
        assert initial_audit is not None
        events.append("host data")
        return resources

    def render(config):
        assert config.audit is resources["audit"]
        assert config.profile_store is resources["profiles"]
        events.append("render")
        return object()

    monkeypatch.setattr(starter, "session_resources", host_resources)
    monkeypatch.setattr(starter.radt, "render", render)
    monkeypatch.setattr(starter.radt, "has_perm", lambda context, permission: False)
    monkeypatch.setattr(starter, "st", SimpleNamespace(
        set_page_config=lambda **kwargs: None, button=lambda *args, **kwargs: False,
    ))
    starter.main()
    assert events == ["identity gate", "host data", "render"]


def _live_starter(host):
    import importlib.util
    from pathlib import Path

    import role_aware_dashboard_toolkit as radt

    path = Path(radt.__file__).parent / "resources/authenticated_starter/app.py"
    spec = importlib.util.spec_from_file_location("synthetic_live_starter", path)
    starter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(starter)

    def access_policy():
        if getattr(host, "configuration_error", None):
            raise RuntimeError(host.configuration_error)
        return host.policy

    starter.build_access_policy = access_policy
    if hasattr(host, "calls"):
        original_resources = starter.session_resources
        original_controls = starter.build_controls

        def resources(initial_audit):
            host.calls.append("resources")
            return original_resources(initial_audit)

        def controls():
            host.calls.append("controls")
            return original_controls()

        starter.session_resources = resources
        starter.build_controls = controls
    starter.main()


def test_configuration_failure_on_rerun_discards_private_state_without_reloading_resources():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    identity = Identity("synthetic-starter", "configured-account", time.time() + 3600)
    store = InMemoryAccessStore()
    host = SimpleNamespace(calls=[], configuration_error=None)
    host.policy = AccessPolicy(lambda: identity, store, b"synthetic-configuration-test-key-material")
    store.replace_grants(host.policy.identify(), ("Viewer",))
    app = AppTest.from_function(_live_starter, args=(host,), default_timeout=15).run()
    assert not app.exception, [item.message for item in app.exception]
    assert app.metric
    previous_resources = app.session_state["_authenticated_pulse_resources"]
    app.session_state["private-cache"] = "synthetic-private-data"
    app.session_state["_radt_pending_replay"] = {"weekly_target": 99}
    previous_calls = list(host.calls)

    host.configuration_error = "synthetic-secret-that-must-not-reach-the-browser"
    app.run()
    assert not app.exception, [item.message for item in app.exception]
    assert [item.value for item in app.error] == [
        "Access configuration is unavailable. Contact the dashboard administrator.",
    ]
    assert host.calls == previous_calls
    assert not app.metric and not app.number_input and not app.slider
    for key in ("_authenticated_pulse_resources", "private-cache", "_radt_pending_replay"):
        assert key not in app.session_state

    host.configuration_error = None
    app.run()
    assert not app.exception, [item.message for item in app.exception]
    assert app.metric
    assert app.session_state["_authenticated_pulse_resources"] is not previous_resources
    assert host.calls == previous_calls + ["resources", "controls"]


def test_authorized_signout_failure_stays_denied_through_configuration_outage(monkeypatch):
    import streamlit as st
    from role_aware_dashboard_toolkit import _access_ui, streamlit_auth

    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    identity = Identity("synthetic-starter", "logout-account", time.time() + 3600)
    store = InMemoryAccessStore()
    host = SimpleNamespace(calls=[], configuration_error=None)
    host.policy = AccessPolicy(lambda: identity, store, b"synthetic-logout-test-key-material")
    store.replace_grants(host.policy.identify(), ("Viewer",))
    logout_calls = []

    def failed_logout():
        logout_calls.append(True)
        raise RuntimeError("synthetic-provider-secret")

    monkeypatch.setattr(st, "logout", failed_logout)
    monkeypatch.setattr(streamlit_auth, "_streamlit_login_state", lambda st: True)
    monkeypatch.setattr(_access_ui, "_streamlit_login_state", lambda st: True)
    app = AppTest.from_function(_live_starter, args=(host,), default_timeout=15).run()
    assert not app.exception, [item.message for item in app.exception]
    assert app.metric
    previous_calls = list(host.calls)

    app.button(key="_authenticated_pulse_sign_out").click().run()
    assert not app.exception, [item.message for item in app.exception]
    assert logout_calls == [True]
    assert host.calls == previous_calls
    assert "_authenticated_pulse_resources" not in app.session_state
    assert app.session_state[streamlit_auth._SIGN_OUT_PENDING] is True
    assert not app.metric

    host.configuration_error = "synthetic-configuration-secret"
    app.run()
    assert not app.exception, [item.message for item in app.exception]
    assert app.session_state[streamlit_auth._SIGN_OUT_PENDING] is True
    assert host.calls == previous_calls

    host.configuration_error = None
    app.run()
    assert not app.exception, [item.message for item in app.exception]
    assert app.session_state[streamlit_auth._SIGN_OUT_PENDING] is True
    assert host.calls == previous_calls
    assert "_authenticated_pulse_resources" not in app.session_state
    assert not app.metric
    assert app.button(key="_radt_sign_out")
    assert [item.value for item in app.error] == ["Dashboard access could not be confirmed."]


def test_starter_retains_session_audit_across_reruns_and_replaces_it_on_account_change():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    host = SimpleNamespace(identity=Identity("synthetic-starter", "first-account", time.time() + 3600))
    store = InMemoryAccessStore()
    host.policy = AccessPolicy(lambda: host.identity, store, b"synthetic-starter-audit-test-key-material")
    first_principal = host.policy.identify()
    store.replace_grants(first_principal, ("Viewer",))
    app = AppTest.from_function(_live_starter, args=(host,), default_timeout=15).run()
    assert not app.exception, [item.message for item in app.exception]

    resource_key = "_authenticated_pulse_resources"
    first_audit = app.session_state[resource_key]["audit"]
    first_events = first_audit.all_events()
    assert len(first_events) == 1
    assert first_events[0]["type"] == "access_session_started"
    assert first_events[0]["user_id"] == first_principal
    first_session = first_events[0]["session_id"]
    assert len(first_principal) == 64 and len(first_session) == 32
    assert "first-account" not in first_audit.export_jsonl()

    app.run()
    assert not app.exception, [item.message for item in app.exception]
    assert app.session_state[resource_key]["audit"] is first_audit
    assert first_audit.all_events() == first_events

    host.identity = Identity("synthetic-starter", "second-account", time.time() + 3600)
    second_principal = host.policy.identify()
    store.replace_grants(second_principal, ("Viewer",))
    app.run()
    assert not app.exception, [item.message for item in app.exception]
    second_audit = app.session_state[resource_key]["audit"]
    second_events = second_audit.all_events()
    assert second_audit is not first_audit
    assert len(second_events) == 1
    assert second_events[0]["type"] == "access_session_started"
    assert second_events[0]["user_id"] == second_principal
    assert second_events[0]["session_id"] != first_session
    assert first_principal not in second_audit.export_jsonl()
    assert "second-account" not in second_audit.export_jsonl()

    store.replace_grants(second_principal, ())
    app.run()
    assert not app.exception, [item.message for item in app.exception]
    assert resource_key not in app.session_state
    assert first_audit.all_events() == first_events
    assert second_audit.all_events() == second_events
