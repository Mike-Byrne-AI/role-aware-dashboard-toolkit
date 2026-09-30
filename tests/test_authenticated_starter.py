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
from role_aware_dashboard_toolkit.guidance import read_guide, read_starter


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


def test_authentication_guide_is_discoverable_offline(capsys):
    assert cli.main(["guide", "authentication", "--format", "json"]) == 0
    content = json.loads(capsys.readouterr().out)["result"]["content"]
    assert content == read_guide("authentication")["content"]
    assert "access_cli grant" in content
    assert "application never enrolls the first" in content
    assert "Provider-side account/session revocation is not" in content


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


def test_missing_configuration_stops_before_identity_or_host_data(starter, monkeypatch):
    events = []

    def broken_configuration():
        raise RuntimeError("synthetic-private-secret")

    def stop():
        raise StopPage()

    monkeypatch.setattr(starter, "build_access_policy", broken_configuration)
    monkeypatch.setattr(starter, "prepare_access", lambda config: events.append("identity"))
    monkeypatch.setattr(starter, "session_resources", lambda: events.append("host data"))
    monkeypatch.setattr(starter, "st", SimpleNamespace(
        set_page_config=lambda **kwargs: None,
        error=lambda message: events.append(message), stop=stop,
    ))
    with pytest.raises(StopPage):
        starter.main()
    assert events == ["Access configuration is unavailable. Contact the dashboard administrator."]


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
    events = []

    def stop():
        raise StopPage()

    monkeypatch.setattr(starter, "build_access_policy", lambda: object())
    monkeypatch.setattr(starter, "prepare_access", lambda config: events.append("identity gate"))
    monkeypatch.setattr(starter, "session_resources", lambda: events.append("host data"))
    monkeypatch.setattr(starter, "st", SimpleNamespace(
        set_page_config=lambda **kwargs: None,
        button=lambda *args, **kwargs: True,
        session_state={"synthetic-account-data": True},
        logout=lambda: events.append("logout"), stop=stop,
    ))
    with pytest.raises(StopPage):
        starter.main()
    assert events == ["identity gate", "logout"]


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
    starter.build_access_policy = lambda: host.policy
    starter.main()


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
