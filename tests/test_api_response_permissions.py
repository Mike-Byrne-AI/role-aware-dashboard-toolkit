"""Operation grants must not disclose independently protected response data."""
from __future__ import annotations

from copy import deepcopy
from itertools import product

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.security import RoleDef


pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")

_PERMISSIONS = (
    "can_view_metrics", "can_load_profiles", "can_save_profiles",
    "can_edit_controls", "can_view_audit", "can_apply_tuning",
)
_LIVE = "UNRELATED-LIVE-CANARY"
_STORED = "STORED-CONTROL-CANARY"
_SENSITIVE = "CURRENT-SENSITIVE-CANARY"
_HEADERS = {"X-API-Key": "synthetic-response-permission-key"}


def _fixtures():
    registry = ControlRegistry()
    registry.register("Tuning", kind="text", key="tuning", default="live-tuning",
                      permission="can_apply_tuning")
    registry.register("Operations note", kind="text", key="operations_note", default=_LIVE)
    registry.register("Credential", kind="text", key="credential", default=_SENSITIVE,
                      sensitive=True)
    profiles = InMemoryProfileStore()
    profiles.save({"profile_id": "partial", "values": {"tuning": "saved-tuning"}})
    profiles.save({
        "profile_id": "full",
        "values": {"operations_note": _STORED, "credential": _SENSITIVE},
        "extra": {"note": "PROFILE-EXTRA-CANARY"},
        "control_meta": [{"key": "credential", "sensitive": True,
                          "default": "PROFILE-METADATA-CANARY"}],
    })
    audit = AuditLog()
    audit.log("synthetic", detail="AUDIT-CANARY")
    return registry, profiles, audit


@pytest.mark.parametrize("bits", list(product((False, True), repeat=len(_PERMISSIONS))))
def test_api_permission_combinations_do_not_borrow_response_read_authority(monkeypatch, bits):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", _HEADERS["X-API-Key"])
    perms = dict(zip(_PERMISSIONS, bits))
    registry, profiles, audit = _fixtures()
    app = create_app(
        registry, profile_store=profiles, audit=audit,
        custom_roles={"Matrix": RoleDef("Matrix", perms)}, api_role="Matrix",
    )
    with TestClient(app) as client:
        responses = {
            "controls": client.get("/controls", headers=_HEADERS),
            "control": client.get("/controls/operations_note", headers=_HEADERS),
            "profiles": client.get("/profiles", headers=_HEADERS),
            "profile": client.get("/profiles/full", headers=_HEADERS),
            "roles": client.get("/roles", headers=_HEADERS),
            "audit": client.get("/audit", headers=_HEADERS),
            "patch": client.patch("/controls", headers=_HEADERS,
                                  json={"values": {"tuning": "USER-SUBMITTED-CANARY"}}),
            "save": client.post("/profiles", headers=_HEADERS, json={"profile_id": "saved"}),
            "activate": client.post("/profiles/partial/activate", headers=_HEADERS),
            "delete": client.delete("/profiles/full", headers=_HEADERS),
            "wrong_key": client.get("/controls", headers={"X-API-Key": "wrong-synthetic-key"}),
        }
    expected = {
        "controls": perms["can_view_metrics"], "control": perms["can_view_metrics"],
        "profiles": perms["can_load_profiles"],
        "profile": perms["can_load_profiles"] and perms["can_view_metrics"],
        "roles": perms["can_view_metrics"], "audit": perms["can_view_audit"],
        "patch": perms["can_edit_controls"] and perms["can_apply_tuning"],
        "save": perms["can_save_profiles"],
        "activate": perms["can_load_profiles"] and perms["can_apply_tuning"],
        "delete": perms["can_save_profiles"],
    }
    for operation, allowed in expected.items():
        assert responses[operation].status_code == (200 if allowed else 403), operation
    assert responses["wrong_key"].status_code == 401
    for operation, response in responses.items():
        for marker in (_SENSITIVE, "PROFILE-EXTRA-CANARY", "PROFILE-METADATA-CANARY"):
            assert marker not in response.text, (operation, marker)
        if response.status_code >= 400 or not perms["can_view_metrics"]:
            assert _LIVE not in response.text and _STORED not in response.text, operation
    for operation in ("save", "activate"):
        if expected[operation]:
            values = responses[operation].json()["values"]
            if perms["can_view_metrics"]:
                assert values["operations_note"] == _LIVE
            else:
                assert values == {}
    if expected["patch"]:
        assert responses["patch"].json()[0]["value"] == "USER-SUBMITTED-CANARY"
    if expected["save"]:
        assert profiles.load("saved")["values"]["operations_note"] == _LIVE


def test_save_and_load_grants_cannot_roundtrip_live_values_without_metrics(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", _HEADERS["X-API-Key"])
    registry, profiles, audit = _fixtures()
    role = RoleDef("ProfileManager", {
        "can_save_profiles": True, "can_load_profiles": True,
        "can_apply_tuning": True, "can_view_metrics": False,
    })
    app = create_app(registry, profile_store=profiles, audit=audit,
                     custom_roles={role.name: role}, api_role=role.name)
    with TestClient(app) as client:
        assert client.get("/controls", headers=_HEADERS).status_code == 403
        saved = client.post("/profiles", headers=_HEADERS, json={"profile_id": "roundtrip"})
        assert saved.status_code == 200 and saved.json()["values"] == {}
        assert profiles.load("roundtrip")["values"]["operations_note"] == _LIVE
        assert "roundtrip" in client.get("/profiles", headers=_HEADERS).json()
        denied = client.get("/profiles/roundtrip", headers=_HEADERS)
        assert denied.status_code == 403 and _LIVE not in denied.text
        activated = client.post("/profiles/partial/activate", headers=_HEADERS)
        assert activated.status_code == 200 and activated.json()["values"] == {}
        # Suppressing response data must not suppress the authorized operation.
        role.perms["can_view_metrics"] = True
        assert client.get("/controls/tuning", headers=_HEADERS).json()["value"] == "saved-tuning"
        assert client.get("/profiles/roundtrip", headers=_HEADERS).json()["values"]["operations_note"] == _LIVE


def test_profile_value_read_denial_does_not_read_the_store(monkeypatch):
    from fastapi.testclient import TestClient

    class UnreadableProfiles(InMemoryProfileStore):
        def load(self, _profile_id):
            raise AssertionError("Denied profile read reached the store")

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", _HEADERS["X-API-Key"])
    registry, _, _ = _fixtures()
    app = create_app(
        registry, profile_store=UnreadableProfiles(),
        custom_roles={"Loader": RoleDef("Loader", {"can_load_profiles": True})},
        api_role="Loader",
    )
    with TestClient(app) as client:
        assert client.get("/profiles/private", headers=_HEADERS).status_code == 403


def test_api_audit_reprojects_history_using_current_sensitive_controls(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", _HEADERS["X-API-Key"])
    registry = ControlRegistry()
    control = registry.register("Connection", kind="text", key="connection", default="CURRENT-CANARY")
    audit = AuditLog()
    audit.log_control_change("connection", "OLD-HISTORY-CANARY", "NEW-HISTORY-CANARY")
    raw_before = deepcopy(audit.all_events())
    app = create_app(registry, audit=audit, profile_store=InMemoryProfileStore(), api_role="Viewer")
    with TestClient(app) as client:
        assert "OLD-HISTORY-CANARY" in client.get("/audit", headers=_HEADERS).text
        control.sensitive = True
        history = client.get("/audit", headers=_HEADERS)
        controls = client.get("/controls", headers=_HEADERS)
    assert history.status_code == controls.status_code == 200
    assert "CANARY" not in history.text and "CANARY" not in controls.text
    assert history.json()[0]["key"] == "connection"
    assert audit.all_events() == raw_before


def test_control_responses_project_nested_secrets_without_changing_values_or_metadata(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", _HEADERS["X-API-Key"])
    options = [
        {"region": "west", "password": "DEFAULT-PASSWORD-CANARY",
         "nested": [{"api_key": "DEFAULT-KEY-CANARY", "enabled": True}]},
        {"region": "east", "password": "UPDATED-PASSWORD-CANARY",
         "nested": [{"api_key": "UPDATED-KEY-CANARY", "enabled": False}]},
    ]
    originals = deepcopy(options)
    registry = ControlRegistry()
    registry.register("Settings", kind="select", key="settings", default=options[0],
                      options=options, sensitive=False)
    registry.register("Token count", kind="number", key="token_count", default=22,
                      sensitive=False)
    profiles = InMemoryProfileStore()
    app = create_app(registry, profile_store=profiles, api_role="Admin")
    with TestClient(app) as client:
        all_controls = client.get("/controls", headers=_HEADERS)
        single = client.get("/controls/settings", headers=_HEADERS)
        updated = client.patch("/controls", headers=_HEADERS,
                               json={"values": {"settings": options[1]}})
        after = client.get("/controls/settings", headers=_HEADERS)
        saved = client.post("/profiles", headers=_HEADERS, json={"profile_id": "nested"})
    for response in (all_controls, single, updated, after, saved):
        assert response.status_code == 200
        assert "CANARY" not in response.text
    assert single.json()["value"]["region"] == "west"
    assert updated.json()[0]["value"]["region"] == "east"
    assert after.json()["value"]["nested"][0]["enabled"] is False
    assert next(row for row in all_controls.json() if row["key"] == "token_count")["value"] == 22
    for row in all_controls.json():
        assert "default" not in row and "options" not in row
    assert registry.get("settings").default == originals[0]
    assert registry.get("settings").options == originals
    assert profiles.load("nested")["values"]["settings"] == originals[1]
