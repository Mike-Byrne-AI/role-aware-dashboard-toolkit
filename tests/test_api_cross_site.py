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
    return TestClient(app), audit, store


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
