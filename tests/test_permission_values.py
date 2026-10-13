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
