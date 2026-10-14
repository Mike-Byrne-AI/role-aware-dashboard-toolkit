"""Permission names and values deny unless they are explicit."""
from __future__ import annotations

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.security import RoleDef, can_write, has_perm, make_security_context

requires_fastapi = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
HEADERS = {"X-API-Key": "synthetic-permission-value-key"}


@pytest.mark.parametrize("permission", ["", "   ", None, 7])
def test_register_rejects_a_missing_permission_name(permission):
    registry = ControlRegistry()

    with pytest.raises(ValueError, match="permission") as raised:
        registry.register("Maintenance", kind="toggle", key="maintenance", permission=permission)

    assert raised.value.diagnostic["code"] == "RADT-CONTROL-DEFINITION"
    assert "maintenance" not in registry


@requires_fastapi
def test_api_denies_a_control_whose_permission_name_is_empty(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", HEADERS["X-API-Key"])
    registry = ControlRegistry()
    control = registry.register("Maintenance", kind="toggle", key="maintenance", default=False)
    # A definition changed after registration must not become an open control.
    control.permission = ""
    profiles = InMemoryProfileStore()
    profiles.save({"profile_id": "on", "values": {"maintenance": True}})
    loader = RoleDef("Loader", {"can_edit_controls": True, "can_load_profiles": True,
                                "can_view_metrics": True})
    audit = AuditLog()
    with TestClient(create_app(registry, audit=audit, profile_store=profiles,
                               custom_roles={loader.name: loader}, api_role=loader.name)) as client:
        patched = client.patch("/controls", headers=HEADERS, json={"values": {"maintenance": True}})
        activated = client.post("/profiles/on/activate", headers=HEADERS)
        current = client.get("/controls/maintenance", headers=HEADERS).json()["value"]

    assert patched.status_code == 403
    assert activated.status_code == 403
    assert current is False
    assert audit.all_events() == []
    # The native UI already denies the same definition.
    assert can_write(make_security_context("Loader", loader.perms), "") is False


@pytest.mark.parametrize("value", ["false", "true", 1, 0, None, [True]])
def test_role_definition_rejects_non_boolean_permission_values(value):
    with pytest.raises(TypeError, match="can_edit_controls.*True or False"):
        RoleDef("Misconfigured", {"can_edit_controls": value})


@pytest.mark.parametrize("perms", [None, ["can_edit_controls"], {"": True}, {1: True}])
def test_role_definition_rejects_malformed_permission_maps(perms):
    with pytest.raises(TypeError, match="Misconfigured"):
        RoleDef("Misconfigured", perms)


def test_boolean_role_definitions_are_unchanged():
    perms = {"can_edit_controls": True, "can_view_audit": False}
    role = RoleDef("Editor", perms)

    assert role.perms is perms
    assert RoleDef("Empty").perms == {}


@pytest.mark.parametrize("value", ["false", "no", 1, [False]])
def test_has_perm_grants_only_an_explicit_true(value):
    ctx = make_security_context("Misconfigured", {"can_edit_controls": value})

    assert has_perm(ctx, "can_edit_controls") is False
    assert can_write(ctx, "can_edit_controls") is False
    assert has_perm(make_security_context("Editor", {"can_edit_controls": True}),
                    "can_edit_controls") is True
    # An absent permission still falls back to the caller's explicit default.
    assert has_perm(ctx, "unlisted_permission", default=True) is True


@requires_fastapi
def test_api_denies_a_permission_value_changed_to_a_string(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", HEADERS["X-API-Key"])
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=8, min_value=1, max_value=40)
    role = RoleDef("Editor", {"can_edit_controls": True, "can_view_metrics": True})
    with TestClient(create_app(registry, custom_roles={role.name: role}, api_role=role.name)) as client:
        role.perms["can_edit_controls"] = "false"
        response = client.patch("/controls", headers=HEADERS, json={"values": {"workers": 20}})
        current = client.get("/controls/workers", headers=HEADERS).json()["value"]

    assert response.status_code == 403
    assert current == 8
