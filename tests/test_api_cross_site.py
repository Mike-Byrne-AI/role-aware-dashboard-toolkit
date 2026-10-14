"""State-changing API routes refuse requests a browser can send cross-site without a preflight."""
from __future__ import annotations

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.profiles import save_profile

pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
EVIL = {"Origin": "https://evil.example"}
# The three content types an HTML form or a no-cors fetch can send, plus none.
SIMPLE_CONTENT_TYPES = [
    None, "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain",
    "text/plain; charset=utf-8",
]


def _demo_app(monkeypatch, role="Operator"):
    """The local demo the docs describe: anonymous opt-in with an elevated role."""
    from fastapi.testclient import TestClient

    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", raising=False)
    registry = ControlRegistry()
    registry.register("Maintenance mode", kind="toggle", key="maintenance", default=False)
    store = InMemoryProfileStore()
    save_profile("maintenance-on", registry, {"maintenance": True}, store=store)
    audit = AuditLog()
    app = create_app(registry, audit=audit, profile_store=store,
                     allow_anonymous=True, anonymous_role=role)
    # A local demo is addressed as localhost (anonymous writes need a loopback Host).
    return TestClient(app, base_url="http://localhost"), audit, store


def _headers(content_type):
    return {**EVIL, **({"Content-Type": content_type} if content_type else {})}


@pytest.mark.parametrize("content_type", SIMPLE_CONTENT_TYPES)
def test_a_cross_site_form_post_cannot_activate_a_profile(monkeypatch, content_type):
    client, audit, _store = _demo_app(monkeypatch)

    response = client.post("/profiles/maintenance-on/activate", headers=_headers(content_type),
                           content=b"" if content_type else None)

    assert response.status_code == 415
    assert "Content-Type: application/json" in response.json()["detail"]
    assert client.get("/controls/maintenance").json()["value"] is False
    assert audit.all_events() == []


@pytest.mark.parametrize("content_type", SIMPLE_CONTENT_TYPES)
def test_every_state_changing_route_refuses_a_simple_request(monkeypatch, content_type):
    client, audit, store = _demo_app(monkeypatch, role="Admin")
    body = b'{"profile_id":"forged"}'

    responses = [
        client.post("/profiles", headers=_headers(content_type), content=body),
        client.patch("/controls", headers=_headers(content_type),
                     content=b'{"values":{"maintenance":true}}'),
        client.request("DELETE", "/profiles/maintenance-on", headers=_headers(content_type)),
    ]

    assert [response.status_code for response in responses] == [415, 415, 415]
    assert sorted(store.list_ids()) == ["maintenance-on"]
    assert client.get("/controls/maintenance").json()["value"] is False
    assert audit.all_events() == []


@pytest.mark.parametrize("content_type", ["application/json", "application/json; charset=utf-8",
                                          "application/merge-patch+json"])
def test_json_requests_still_work_in_anonymous_mode(monkeypatch, content_type):
    client, audit, store = _demo_app(monkeypatch, role="Admin")
    headers = {"Content-Type": content_type}

    activated = client.post("/profiles/maintenance-on/activate", headers=headers)
    deleted = client.request("DELETE", "/profiles/maintenance-on", headers=headers)

    assert activated.status_code == 200
    assert deleted.status_code == 200
    assert client.get("/controls/maintenance").json()["value"] is True
    assert store.list_ids() == []
    assert [event["type"] for event in audit.all_events()] == ["profile_load", "profile_delete"]


def test_api_key_clients_need_no_content_type(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-cross-site-key")
    registry = ControlRegistry()
    registry.register("Maintenance mode", kind="toggle", key="maintenance", default=False)
    store = InMemoryProfileStore()
    save_profile("maintenance-on", registry, {"maintenance": True}, store=store)
    headers = {"X-API-Key": "synthetic-cross-site-key"}
    with TestClient(create_app(registry, profile_store=store, api_role="Admin")) as client:
        activated = client.post("/profiles/maintenance-on/activate", headers=headers)
        deleted = client.request("DELETE", "/profiles/maintenance-on", headers=headers)
        # Without the key, the request is unauthorized before any other check.
        assert client.post("/profiles/x/activate", headers=EVIL).status_code == 401

    assert activated.status_code == 200
    assert deleted.status_code == 200


def test_read_routes_need_no_content_type(monkeypatch):
    client, _audit, _store = _demo_app(monkeypatch)

    assert client.get("/controls", headers=EVIL).status_code == 200
    assert client.get("/health", headers=EVIL).status_code == 200


# DNS rebinding: a page at rebind.attacker.example re-points its own name at
# 127.0.0.1, so its JSON requests are same-origin to the browser (no
# preflight) and reach the demo API with the attacker's name as Host.
REMOTE_HOSTS = [
    "rebind.attacker.example", "rebind.attacker.example:8000", "192.168.1.20:8000",
    "localhost.attacker.example", "127.0.0.1.attacker.example", "[::2]:8000",
    "localhost:notaport", "testserver",
]
LOOPBACK_HOSTS = [
    "localhost", "localhost:8000", "LOCALHOST", "localhost.", "127.0.0.1", "127.0.0.1:8501",
    "127.8.9.10", "[::1]", "[::1]:8000", "[::ffff:127.0.0.1]:8000",
]


def _state_changing_requests(client, host):
    headers = {"Content-Type": "application/json", "Host": host}
    return [
        client.post("/profiles", headers=headers, content=b'{"profile_id":"forged"}'),
        client.patch("/controls", headers=headers, content=b'{"values":{"maintenance":true}}'),
        client.post("/profiles/maintenance-on/activate", headers=headers),
        client.request("DELETE", "/profiles/maintenance-on", headers=headers),
    ]


@pytest.mark.parametrize("host", REMOTE_HOSTS)
def test_anonymous_state_changes_need_a_loopback_host(monkeypatch, host):
    client, audit, store = _demo_app(monkeypatch, role="Admin")

    responses = _state_changing_requests(client, host)

    assert [response.status_code for response in responses] == [403] * 4
    assert "loopback" in responses[0].json()["detail"]
    assert sorted(store.list_ids()) == ["maintenance-on"]
    assert client.get("/controls/maintenance", headers={"Host": "localhost"}).json()["value"] is False
    assert audit.all_events() == []


@pytest.mark.parametrize("host", LOOPBACK_HOSTS)
def test_anonymous_state_changes_work_at_a_loopback_host(monkeypatch, host):
    client, audit, store = _demo_app(monkeypatch, role="Admin")

    responses = _state_changing_requests(client, host)

    assert [response.status_code for response in responses] == [200] * 4
    assert store.list_ids() == ["forged"]
    assert [event["type"] for event in audit.all_events()] == [
        "profile_save", "control_change", "profile_load", "profile_delete",
    ]


def test_key_clients_and_reads_are_not_host_checked(monkeypatch):
    from fastapi.testclient import TestClient

    client, _audit, _store = _demo_app(monkeypatch)
    assert client.get("/controls", headers={"Host": "rebind.attacker.example"}).status_code == 200

    # A deployment behind a proxy keeps its own Host; the key authenticates it.
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-cross-site-key")
    registry = ControlRegistry()
    registry.register("Maintenance mode", kind="toggle", key="maintenance", default=False)
    app = create_app(registry, api_role="Admin", allow_anonymous=True)
    with TestClient(app) as keyed:
        response = keyed.patch(
            "/controls", json={"values": {"maintenance": True}},
            headers={"X-API-Key": "synthetic-cross-site-key", "Host": "dashboard.example.com"},
        )
    assert response.status_code == 200


@pytest.mark.parametrize("host", ["127.0.0.1:８０", "localhost:٨٠", "[::1]:８"])
def test_a_port_must_be_ascii_digits(host):
    # str.isdigit accepts fullwidth and Arabic-Indic digits; a Host port does not.
    from role_aware_dashboard_toolkit.api import _is_loopback_host

    assert _is_loopback_host(host) is False
