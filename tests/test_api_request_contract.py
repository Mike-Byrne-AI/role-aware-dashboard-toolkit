"""HTTP API requests are applied exactly as sent or refused before any change."""
from __future__ import annotations

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app

pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
HEADERS = {"X-API-Key": "synthetic-request-contract-key"}


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", HEADERS["X-API-Key"])


def _registry() -> ControlRegistry:
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=8,
                      min_value=1, max_value=40, step=1)
    return registry


@pytest.fixture()
def api():
    from fastapi.testclient import TestClient

    audit = AuditLog()
    profiles = InMemoryProfileStore()
    with TestClient(create_app(_registry(), audit=audit, profile_store=profiles,
                               api_role="Admin")) as client:
        yield client, audit, profiles


@pytest.mark.parametrize("body", [
    {"workers": 20},
    {},
    {"values": {"workers": 20}, "dry_run": True},
])
def test_control_update_requires_exactly_the_values_object(api, body):
    client, audit, _profiles = api

    response = client.patch("/controls", headers=HEADERS, json=body)

    assert response.status_code == 422
    assert client.get("/controls/workers", headers=HEADERS).json()["value"] == 8
    assert audit.all_events() == []


def test_profile_save_rejects_fields_it_would_ignore(api):
    client, audit, profiles = api

    response = client.post("/profiles", headers=HEADERS,
                           json={"profile_id": "night", "values": {"workers": 2}})

    assert response.status_code == 422
    assert profiles.list_ids() == []
    assert audit.all_events() == []


def test_wrapped_control_update_and_profile_save_still_succeed(api):
    client, audit, profiles = api

    updated = client.patch("/controls", headers=HEADERS, json={"values": {"workers": 20}})
    saved = client.post("/profiles", headers=HEADERS,
                        json={"profile_id": "night", "role": "Ops", "extra": {"ticket": "OPS-1"}})

    assert updated.status_code == 200
    assert updated.json()[0]["value"] == 20
    assert saved.status_code == 200
    assert profiles.load("night")["values"] == {"workers": 20}
    assert [event["type"] for event in audit.all_events()] == ["control_change", "profile_save"]
