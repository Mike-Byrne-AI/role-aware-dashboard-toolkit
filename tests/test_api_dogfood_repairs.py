"""HTTP regression proofs for addressable identifiers and API provenance."""

from urllib.parse import quote

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.profile_store import FileProfileStore, InMemoryProfileStore

pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
HEADERS = {"X-API-Key": "synthetic-api-repair-key"}


@pytest.fixture(params=["memory", "file"])
def api_state(request, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", HEADERS["X-API-Key"])
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=8,
                      min_value=1, max_value=40)
    registry.register("API token", kind="text", key="api_token", sensitive=True,
                      default="SYNTHETIC-PRIVATE-TOKEN")
    store = InMemoryProfileStore() if request.param == "memory" else FileProfileStore(str(tmp_path))
    audit = AuditLog()
    client = TestClient(create_app(registry, profile_store=store, audit=audit,
                                  api_role="Admin"), raise_server_exceptions=False)
    return client, store, audit


@pytest.mark.parametrize("requested,canonical", [
    (" Night shift ", "Night shift"),
    ("service.v2", "service.v2"),
    (".preview", ".preview"),
    ("release..candidate", "release..candidate"),
    ("Nuit caf\u00e9", "Nuit caf\u00e9"),
    ("\u591c\u73ed", "\u591c\u73ed"),
    ("shift \U0001f680", "shift \U0001f680"),
])
def test_created_profile_identifiers_roundtrip_all_routes(api_state, requested, canonical):
    client, store, audit = api_state
    saved = client.post("/profiles", headers=HEADERS, json={"profile_id": requested})
    assert saved.status_code == 200, saved.text
    assert saved.json()["profile_id"] == canonical
    assert client.get("/profiles", headers=HEADERS).json() == [canonical]
    assert store.load(canonical)["profile_id"] == canonical
    route = "/profiles/" + quote(canonical, safe="")
    loaded = client.get(route, headers=HEADERS)
    assert loaded.status_code == 200, loaded.text
    assert loaded.json()["profile_id"] == canonical
    assert client.post(route + "/activate", headers=HEADERS).status_code == 200
    deleted = client.delete(route, headers=HEADERS)
    assert deleted.status_code == 200, deleted.text
    assert deleted.json() == {"deleted": canonical}
    assert client.get("/profiles", headers=HEADERS).json() == []
    assert [event["detail"] for event in audit.all_events()] == [canonical] * 3


@pytest.mark.parametrize("profile_id", [
    "", "   ", ".", "..", " ./ ", "Ops/Night", "Ops\\Night",
    "percent%name", "encoded%2Fslash", "double%252Fslash", "Ops?night", "Ops#night",
    "line\nbreak", "tab\tname", "nul\x00name", "delete\x7fname", "zero\u200bwidth",
])
def test_route_breaking_profile_ids_rejected_without_state_or_audit(api_state, profile_id):
    client, store, audit = api_state
    assert client.post("/profiles", headers=HEADERS, json={"profile_id": "keep"}).status_code == 200
    before = store.load("keep")
    events_before = audit.all_events()
    response = client.post("/profiles", headers=HEADERS, json={"profile_id": profile_id})
    assert response.status_code == 422, response.text
    assert "profile_id" in response.json()["detail"]
    assert store.list_ids() == ["keep"]
    assert store.load("keep") == before
    assert audit.all_events() == events_before


def test_api_changes_and_stored_profile_have_api_source(api_state):
    client, store, audit = api_state
    updated = client.patch("/controls", headers=HEADERS,
                           json={"values": {"workers": 20, "api_token": "SYNTHETIC-NEW-TOKEN"}})
    assert updated.status_code == 200
    assert client.post("/profiles", headers=HEADERS, json={"profile_id": "shift"}).status_code == 200
    assert store.load("shift")["source"] == "api"
    assert "api_token" not in store.load("shift")["values"]
    assert client.post("/profiles/shift/activate", headers=HEADERS).status_code == 200
    assert client.delete("/profiles/shift", headers=HEADERS).status_code == 200
    events = audit.all_events()
    assert [event["type"] for event in events] == [
        "control_change", "control_change", "profile_save", "profile_load", "profile_delete",
    ]
    assert {event["source"] for event in events} == {"api"}
    assert {event["role"] for event in events} == {"Admin"}
    assert "SYNTHETIC-NEW-TOKEN" not in client.get("/audit", headers=HEADERS).text


@pytest.mark.parametrize("operation", ["save", "delete"])
def test_failed_persistence_does_not_emit_success_audit(api_state, monkeypatch, operation):
    client, store, audit = api_state
    assert client.post("/profiles", headers=HEADERS, json={"profile_id": "keep"}).status_code == 200
    before = store.load("keep")
    events_before = audit.all_events()

    def fail(*args, **kwargs):
        raise PermissionError("synthetic read-only profile store")

    monkeypatch.setattr(store, operation, fail)
    if operation == "save":
        response = client.post("/profiles", headers=HEADERS, json={"profile_id": "keep"})
    else:
        response = client.delete("/profiles/keep", headers=HEADERS)
    assert response.status_code == 500
    assert store.load("keep") == before
    assert audit.all_events() == events_before


def test_missing_or_denied_deletion_has_no_success_audit(api_state):
    client, store, audit = api_state
    assert client.delete("/profiles/missing", headers=HEADERS).status_code == 404
    assert client.post("/profiles", headers=HEADERS, json={"profile_id": "keep"}).status_code == 200
    events_before = audit.all_events()
    assert client.delete("/profiles/keep").status_code == 401
    assert store.load("keep") is not None
    assert audit.all_events() == events_before
