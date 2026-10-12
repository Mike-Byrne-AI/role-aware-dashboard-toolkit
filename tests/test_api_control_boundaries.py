"""HTTP control writes preserve read authority and structured secret labels."""
from __future__ import annotations

from copy import deepcopy
from urllib.parse import quote

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.security import RoleDef
from role_aware_dashboard_toolkit.sensitive_values import REDACTED_SECRET


pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
HEADERS = {"X-API-Key": "synthetic-control-boundary-key"}
NESTED = {"region": "west", "settings": [{"password": "SERVER-PASSWORD-CANARY"}]}


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", HEADERS["X-API-Key"])


@pytest.mark.parametrize("kind,source", [
    ("text", "request"), ("text", "default"),
    ("color", "default"), ("color", "invalid_color_fallback"),
])
def test_secret_string_coercion_rejects_entire_batch_before_state_or_audit(kind, source):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    ordinary = "unchanged" if kind == "text" else "#112233"
    default = ordinary if source == "request" else deepcopy(NESTED)
    registry.register("Settings", kind=kind, key="settings", default=default)
    registry.register("Count", kind="number", key="count", default=3)
    requested = deepcopy(NESTED) if source == "request" else None
    if source == "invalid_color_fallback":
        requested = "not-a-color"
    profiles = InMemoryProfileStore()
    audit = AuditLog()
    with TestClient(create_app(registry, profile_store=profiles, audit=audit, api_role="Admin")) as client:
        before = client.get("/controls", headers=HEADERS).json()
        rejected = client.patch("/controls", headers=HEADERS,
                                json={"values": {"count": 9, "settings": requested}})
        assert rejected.status_code == 422
        assert "CANARY" not in rejected.text
        assert client.get("/controls", headers=HEADERS).json() == before
        assert audit.all_events() == []
        saved = client.post("/profiles", headers=HEADERS, json={"profile_id": "unchanged"})
        assert saved.status_code == 200
        assert "CANARY" not in saved.text
    assert profiles.load("unchanged")["values"]["settings"] == default
    assert registry.get("settings").default == default
    assert registry.get("settings").sensitive is False


def test_color_sanitation_can_discard_structured_input_without_exposing_it():
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register("Color", kind="color", key="color", default="#112233")
    with TestClient(create_app(registry, api_role="Admin")) as client:
        response = client.patch("/controls", headers=HEADERS, json={"values": {"color": NESTED}})
        assert response.status_code == 200
        assert response.json()[0]["value"] == "#112233"
        assert "CANARY" not in client.get("/audit", headers=HEADERS).text


@pytest.mark.parametrize("kind,safe", [("text", "public replacement"), ("color", "#abcdef")])
def test_safe_replacement_can_clear_a_nested_secret_default(kind, safe):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register("Settings", kind=kind, key="settings", default=deepcopy(NESTED))
    audit = AuditLog()
    with TestClient(create_app(registry, profile_store=InMemoryProfileStore(), audit=audit,
                               api_role="Operator")) as client:
        response = client.patch("/controls", headers=HEADERS, json={"values": {"settings": safe}})
        assert response.status_code == 200
        assert response.json()[0]["value"] == safe
        assert client.get("/controls/settings", headers=HEADERS).json()["value"] == safe
        assert "CANARY" not in client.get("/audit", headers=HEADERS).text
    assert registry.get("settings").default == NESTED
    assert not registry.get("settings").sensitive


@pytest.mark.parametrize("kind,safe", [("text", "public replacement"), ("color", "#abcdef")])
def test_profile_activation_cannot_stringify_current_or_default_nested_secrets(kind, safe):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register("Settings", kind=kind, key="settings", default=deepcopy(NESTED))
    registry.register("Count", kind="number", key="count", default=3)
    profiles = InMemoryProfileStore()
    profiles.save({"profile_id": "partial", "values": {"count": 9}})
    profiles.save({"profile_id": "replacement", "values": {"count": 9, "settings": safe}})
    audit = AuditLog()
    with TestClient(create_app(registry, profile_store=profiles, audit=audit, api_role="Operator")) as client:
        before = client.get("/controls", headers=HEADERS).json()
        # Reading a profile does not sanitize unrelated live/default values.
        assert client.get("/profiles/partial", headers=HEADERS).json()["values"] == {"count": 9}
        rejected = client.post("/profiles/partial/activate", headers=HEADERS)
        assert rejected.status_code == 422
        assert "CANARY" not in rejected.text
        assert client.get("/controls", headers=HEADERS).json() == before
        assert audit.all_events() == []
        replaced = client.post("/profiles/replacement/activate", headers=HEADERS)
        assert replaced.status_code == 200
        assert replaced.json()["values"] == {"settings": safe, "count": 9}
        assert "CANARY" not in client.get("/audit", headers=HEADERS).text


@pytest.mark.parametrize("valid_default", [False, True])
def test_structured_select_defaults_and_options_keep_safe_siblings(valid_default):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    default = deepcopy(NESTED) if valid_default else "obsolete-option"
    registry.register("Settings", kind="select", key="settings", default=default,
                      options=[deepcopy(NESTED)])
    with TestClient(create_app(registry, profile_store=InMemoryProfileStore(), api_role="Admin")) as client:
        updated = client.patch("/controls", headers=HEADERS, json={"values": {"settings": None}})
        after = client.get("/controls/settings", headers=HEADERS)
        history = client.get("/audit", headers=HEADERS)
        saved = client.post("/profiles", headers=HEADERS, json={"profile_id": "structured"})
        for response in (updated, after, history, saved):
            assert response.status_code == 200
            assert "CANARY" not in response.text
        assert after.json()["value"] == {
            "region": "west", "settings": [{"password": REDACTED_SECRET}],
        }
        assert saved.json()["values"] == {}
    assert registry.get("settings").default == default
    assert registry.get("settings").options == [NESTED]


def test_explicitly_sensitive_structured_text_updates_remain_write_only():
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register("Settings", kind="text", key="settings", default=deepcopy(NESTED), sensitive=True)
    with TestClient(create_app(registry, profile_store=InMemoryProfileStore(), api_role="Admin")) as client:
        response = client.patch("/controls", headers=HEADERS, json={"values": {"settings": None}})
        assert response.status_code == 200
        assert response.json()[0]["value"] == REDACTED_SECRET
        assert response.json()[0]["sensitive"] is True
        assert "CANARY" not in client.get("/controls", headers=HEADERS).text
        assert "CANARY" not in client.get("/audit", headers=HEADERS).text
        saved = client.post("/profiles", headers=HEADERS, json={"profile_id": "sensitive"})
        assert saved.json()["values"] == {}


def test_blind_writes_hide_server_fallbacks_and_preserve_authorized_updates():
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    definitions = [
        ("text", "PRIVATE-DEFAULT-CANARY", {}, None),
        ("number", 17, {"min_value": 1, "max_value": 40}, "invalid"),
        ("slider", 0.75, {}, []),
        ("select", "PRIVATE-OPTION-CANARY", {"options": ["PRIVATE-OPTION-CANARY"]}, None),
        ("color", "#ab19ef", {}, "invalid"),
        ("toggle", True, {}, "invalid"),
    ]
    for kind, default, options, _requested in definitions:
        registry.register(kind, kind=kind, key=kind, default=default, **options)
    role = RoleDef("BlindWriter", {"can_edit_controls": True, "can_view_metrics": False})
    with TestClient(create_app(registry, profile_store=InMemoryProfileStore(),
                               custom_roles={role.name: role}, api_role=role.name)) as client:
        assert client.get("/controls", headers=HEADERS).status_code == 403
        response = client.patch("/controls", headers=HEADERS,
                                json={"values": {kind: requested for kind, _, _, requested in definitions}})
        assert response.status_code == 200
        assert all(row["value"] == REDACTED_SECRET for row in response.json())
        assert all(row["sensitive"] is False for row in response.json())
        assert "CANARY" not in response.text
        # Gaining read permission exposes the successfully applied real values.
        role.perms["can_view_metrics"] = True
        values = {row["key"]: row["value"] for row in client.get("/controls", headers=HEADERS).json()}
        assert values == {kind: default for kind, default, _, _ in definitions}
        response = client.patch("/controls", headers=HEADERS, json={"values": {"text": "public replacement"}})
        assert response.json()[0]["value"] == "public replacement"


@pytest.mark.parametrize("key", [None, "plant/rate", "/plant/rate", "plant//rate", "plant/rate/"])
def test_single_control_reads_address_slash_keys_without_weakening_permissions(key):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    control = registry.register("Requests/second", kind="number", key=key, default=5)
    with TestClient(create_app(registry, api_role="Viewer")) as client:
        path = "/controls/" + quote(control.key, safe="")
        assert client.get(path).status_code == 401
        response = client.get(path, headers=HEADERS)
        assert response.status_code == 200
        assert response.json()["key"] == control.key
        assert response.json()["value"] == 5
        assert client.get("/controls/unknown/field", headers=HEADERS).status_code == 404
        denied = client.patch("/controls", headers=HEADERS, json={"values": {control.key: 7}})
        assert denied.status_code == 403
        assert client.get(path, headers=HEADERS).json()["value"] == 5
