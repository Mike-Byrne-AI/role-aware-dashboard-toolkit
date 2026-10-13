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


def _typed_registry() -> ControlRegistry:
    registry = _registry()
    registry.register("Mode", kind="select", key="mode",
                      options=["Fast", "Balanced", "Thorough"], default="Balanced")
    registry.register("Maintenance", kind="toggle", key="maint", default=False)
    registry.register("Ratio", kind="slider", key="ratio", default=0.5, min_value=0.0, max_value=1.0)
    registry.register("Banner", kind="text", key="banner", default="ready")
    registry.register("Accent", kind="color", key="accent", default="#112233")
    return registry


@pytest.fixture()
def typed_api():
    from fastapi.testclient import TestClient

    audit = AuditLog()
    profiles = InMemoryProfileStore()
    with TestClient(create_app(_typed_registry(), audit=audit, profile_store=profiles,
                               api_role="Admin")) as client:
        yield client, audit, profiles


REFUSED_WRITES = [
    ("workers", "abc"), ("workers", None), ("workers", 999), ("workers", 0),
    ("workers", True), ("workers", "NaN"), ("workers", 20.5), ("workers", []),
    ("ratio", 1.5), ("ratio", -0.1), ("ratio", "Infinity"),
    ("mode", "thorough"), ("mode", None), ("mode", ["Fast"]),
    ("maint", "yes please"), ("maint", None), ("maint", 2), ("maint", ""), ("maint", {}),
    ("banner", None), ("banner", True), ("banner", ["SECRET-CANARY"]),
    ("banner", {"note": "SECRET-CANARY"}),
    ("accent", "red"), ("accent", None), ("accent", "#12345"), ("accent", ""), ("accent", 123456),
]


@pytest.mark.parametrize("key,value", REFUSED_WRITES)
def test_api_refuses_a_value_it_would_have_to_replace_or_clamp(typed_api, key, value):
    client, audit, _profiles = typed_api
    before = client.get("/controls", headers=HEADERS).json()

    response = client.patch("/controls", headers=HEADERS, json={"values": {key: value}})

    assert response.status_code == 422
    assert f"Control '{key}'" in response.json()["detail"]
    assert "CANARY" not in response.text
    assert client.get("/controls", headers=HEADERS).json() == before
    assert audit.all_events() == []


@pytest.mark.parametrize("request_body", [
    '{"values":{"workers":1e9999}}', '{"values":{"workers":"-Infinity"}}',
])
def test_api_refuses_non_finite_numbers_with_standard_json(typed_api, request_body):
    import json

    client, audit, _profiles = typed_api

    response = client.patch("/controls", headers={**HEADERS, "Content-Type": "application/json"},
                            content=request_body)

    assert response.status_code == 422
    json.loads(response.text, parse_constant=lambda token: pytest.fail(f"non-standard {token}"))
    assert client.get("/controls/workers", headers=HEADERS).json()["value"] == 8
    assert audit.all_events() == []


@pytest.mark.parametrize("key,value,stored", [
    ("workers", 20, 20), ("workers", "20", 20), ("workers", 20.0, 20), ("workers", 40, 40),
    ("ratio", 0.25, 0.25), ("ratio", 1, 1.0),
    ("mode", "Fast", "Fast"),
    ("maint", True, True), ("maint", "on", True), ("maint", "FALSE", False), ("maint", 1, True),
    ("banner", "maintenance window", "maintenance window"), ("banner", 5, "5"),
    ("accent", " #ABCDEF ", "#ABCDEF"),
])
def test_api_stores_an_accepted_value_exactly(typed_api, key, value, stored):
    client, audit, _profiles = typed_api

    response = client.patch("/controls", headers=HEADERS, json={"values": {key: value}})

    assert response.status_code == 200
    assert response.json()[0]["value"] == stored
    assert client.get(f"/controls/{key}", headers=HEADERS).json()["value"] == stored
    assert audit.all_events()[-1]["new"] == stored


def test_one_refused_value_refuses_the_whole_batch(typed_api):
    client, audit, _profiles = typed_api
    before = client.get("/controls", headers=HEADERS).json()

    response = client.patch("/controls", headers=HEADERS,
                            json={"values": {"workers": 20, "mode": "thorough"}})

    assert response.status_code == 422
    assert "Control 'mode'" in response.json()["detail"]
    assert client.get("/controls", headers=HEADERS).json() == before
    assert audit.all_events() == []


def test_profile_activation_still_repairs_a_stale_profile(typed_api):
    client, audit, profiles = typed_api
    profiles.save({"profile_id": "stale", "values": {
        "workers": 999, "mode": "Retired", "maint": "unknown", "accent": "blue",
    }})

    response = client.post("/profiles/stale/activate", headers=HEADERS)

    assert response.status_code == 200
    values = {row["key"]: row["value"] for row in client.get("/controls", headers=HEADERS).json()}
    assert values["workers"] == 40
    assert values["mode"] == "Balanced"
    assert values["maint"] is False
    assert values["accent"] == "#112233"
    assert [event["type"] for event in audit.all_events()] == ["profile_load"]


@pytest.mark.parametrize("value", [9007199254740993, "9007199254740993", "1_000", "0x10", " 1e3 x"])
def test_api_refuses_integers_it_cannot_store_exactly_and_non_json_numbers(value):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register("Sequence", kind="number", key="sequence", default=0,
                      min_value=0, max_value=2**62, step=1)
    audit = AuditLog()
    with TestClient(create_app(registry, audit=audit, api_role="Admin")) as client:
        response = client.patch("/controls", headers=HEADERS, json={"values": {"sequence": value}})
        current = client.get("/controls/sequence", headers=HEADERS).json()["value"]

    assert response.status_code == 422
    assert "Control 'sequence'" in response.json()["detail"]
    assert current == 0
    assert audit.all_events() == []


@pytest.mark.parametrize("value,stored", [(9007199254740992, 9007199254740992), ("-12", None), ("1000", 1000)])
def test_api_keeps_large_and_string_integers_exactly(value, stored):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register("Sequence", kind="number", key="sequence", default=0,
                      min_value=-100, max_value=2**62, step=1)
    with TestClient(create_app(registry, api_role="Admin")) as client:
        response = client.patch("/controls", headers=HEADERS, json={"values": {"sequence": value}})

    assert response.status_code == 200
    assert response.json()[0]["value"] == (int(value) if stored is None else stored)
