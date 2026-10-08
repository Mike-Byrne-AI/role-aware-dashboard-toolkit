"""Profile HTTP responses preserve stored evidence without exposing old secrets."""
from copy import deepcopy
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import ControlRegistry
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.profile_store import FileProfileStore, InMemoryProfileStore


pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")


@pytest.mark.parametrize("file_backed", [False, True])
@pytest.mark.parametrize("api_role", ["Operator", "Admin"])
@pytest.mark.parametrize("nested", [
    {"password": "NESTED-CANARY"},
    {"settings": [{"api_key": "NESTED-CANARY"}]},
    [{"Authorization": "NESTED-CANARY"}],
])
def test_legacy_profile_projection_protects_read_activate_and_later_reads(
    tmp_path, monkeypatch, file_backed, nested, api_role,
):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-review-key")
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=1, step=1)
    registry.register("Connection", kind="text", key="connection", default="public-live")
    registry.register("Notes", kind="text", key="notes", default="retained-live")
    registry.register("Protected", kind="text", key="protected", sensitive=True, default="CURRENT-CANARY")
    public_settings = {"region": "west", "labels": ["public", "settings"]}
    registry.register("Settings", kind="select", key="settings", options=[{}, public_settings], default={})
    store = FileProfileStore(str(tmp_path)) if file_backed else InMemoryProfileStore()
    original = {
        "profile_id": "legacy",
        "values": {
            "workers": 2, "connection": "HISTORICAL-CANARY", "protected": "SAVED-CANARY",
            "retired": "REMOVED-CANARY", "unknown": {"password": "UNKNOWN-CANARY"},
            "notes": nested, "settings": public_settings,
        },
        "control_meta": [
            {"key": "connection", "sensitive": True},
            {"key": "retired", "sensitive": True},
        ],
    }
    store.save(deepcopy(original))
    saved_bytes = Path(store.resolve_path("legacy")).read_bytes() if file_backed else None
    client = TestClient(create_app(registry, profile_store=store, api_role=api_role))
    headers = {"X-API-Key": "synthetic-review-key"}

    response = client.get("/profiles/legacy", headers=headers)
    assert response.status_code == 200
    assert response.json()["values"] == {"workers": 2, "settings": public_settings}
    assert "CANARY" not in response.text
    assert client.get("/controls/workers", headers=headers).json()["value"] == 1

    activated = client.post("/profiles/legacy/activate", headers=headers)
    assert activated.status_code == 200
    assert activated.json()["values"] == {
        "workers": 2, "connection": "public-live", "notes": "retained-live", "settings": public_settings,
    }
    assert "CANARY" not in activated.text
    assert "CANARY" not in client.get("/controls", headers=headers).text
    copied = client.post("/profiles", headers=headers, json={"profile_id": "safe-copy"})
    assert copied.status_code == (200 if api_role == "Admin" else 403)
    if api_role == "Admin":
        assert "CANARY" not in copied.text
        assert "CANARY" not in client.get("/profiles/safe-copy", headers=headers).text
    else:
        assert store.load("safe-copy") is None
    assert store.load("legacy") == original
    if file_backed:
        assert Path(store.resolve_path("legacy")).read_bytes() == saved_bytes


@pytest.mark.parametrize("metadata", [None, [], [{"key": "note", "sensitive": False}]])
def test_profile_projection_keeps_known_public_legacy_values(monkeypatch, metadata):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-review-key")
    registry = ControlRegistry()
    registry.register("Note", kind="text", key="note", default="initial")
    store = InMemoryProfileStore()
    store.save({"profile_id": "old", "values": {"note": "public value"}, "control_meta": metadata})
    client = TestClient(create_app(registry, profile_store=store, api_role="Operator"))
    headers = {"X-API-Key": "synthetic-review-key"}
    for method, path in ((client.get, "/profiles/old"), (client.post, "/profiles/old/activate")):
        response = method(path, headers=headers)
        assert response.status_code == 200
        assert response.json()["values"] == {"note": "public value"}


def test_profile_save_response_omits_nested_secret_control(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-review-key")
    registry = ControlRegistry()
    value = {"public": "retained in store", "password": "SYNTHETIC-CANARY"}
    registry.register("Settings", kind="select", key="settings", options=[value], default=value)
    store = InMemoryProfileStore()
    client = TestClient(create_app(registry, profile_store=store, api_role="Admin"))
    headers = {"X-API-Key": "synthetic-review-key"}
    response = client.post("/profiles", headers=headers, json={"profile_id": "nested"})
    assert response.status_code == 200
    assert response.json()["values"] == {}
    assert "CANARY" not in response.text
    assert store.load("nested")["values"]["settings"] == value
