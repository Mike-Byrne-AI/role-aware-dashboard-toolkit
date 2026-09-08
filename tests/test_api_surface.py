import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 CI
    import tomli as tomllib

import pytest

from role_aware_dashboard_toolkit import ControlRegistry
from role_aware_dashboard_toolkit.audit import AuditLog
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.profile_store import InMemoryProfileStore
from role_aware_dashboard_toolkit.security import RoleDef


requires_fastapi = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")


@pytest.fixture()
def api_registry():
    reg = ControlRegistry()
    reg.register("Temperature", kind="slider", key="temp", min_value=0.0, max_value=2.0, step=0.1, default=0.5)
    reg.register("Mode", kind="select", key="mode", options=["fast", "safe"], default="safe")
    return reg


def test_pyproject_declares_api_and_direct_pydantic_extras():
    data = tomllib.loads(Path(__file__).resolve().parents[1].joinpath("pyproject.toml").read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    assert "api" in extras
    assert any(dep.startswith("fastapi>=") for dep in extras["api"])
    assert any(dep.startswith("pydantic>=") for dep in extras["api"])
    assert any(dep.startswith("pydantic>=") for dep in extras["full"])
    assert any(dep.startswith("pydantic>=") for dep in extras["dev"])


def test_api_module_imports_without_fastapi_or_pydantic():
    script = """
import importlib.abc
import sys

class BlockApiDeps(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "fastapi" or fullname.startswith("fastapi.") or fullname == "pydantic" or fullname.startswith("pydantic."):
            raise ModuleNotFoundError("blocked optional API dependency", name=fullname)
        return None

sys.meta_path.insert(0, BlockApiDeps())
import role_aware_dashboard_toolkit.api as api

assert api.FASTAPI_AVAILABLE is False
try:
    api.create_app(None)
except ImportError as exc:
    assert "role-aware-dashboard-toolkit[api]" in str(exc)
else:
    raise AssertionError("create_app should require role-aware-dashboard-toolkit[api] when FastAPI is missing")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_api_create_app_surfaces_broken_fastapi_imports_directly():
    script = """
import importlib.abc
import sys

class BreakFastapiImport(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "fastapi" or fullname.startswith("fastapi."):
            raise ImportError("broken fastapi import")
        return None

sys.meta_path.insert(0, BreakFastapiImport())
import role_aware_dashboard_toolkit.api as api

assert api.FASTAPI_AVAILABLE is False
try:
    api.create_app(None)
except ImportError as exc:
    assert "broken fastapi import" in str(exc)
    assert "role-aware-dashboard-toolkit[api]" not in str(exc)
else:
    raise AssertionError("create_app should surface non-missing FastAPI import failures")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_api_server_public_contract_is_root_exported():
    import role_aware_dashboard_toolkit as radt
    import role_aware_dashboard_toolkit.api as api

    assert radt.create_app is create_app
    assert radt.FASTAPI_AVAILABLE is FASTAPI_AVAILABLE
    assert "create_app" in radt.__all__
    assert "FASTAPI_AVAILABLE" in radt.__all__
    assert api.__all__ == ["FASTAPI_AVAILABLE", "create_app"]


def test_api_security_docs_call_out_public_bind_network_boundary():
    docs = Path(__file__).resolve().parents[1].joinpath("docs", "api_security.md").read_text(encoding="utf-8")
    assert "0.0.0.0" in docs
    assert "trusted network controls" in docs


@requires_fastapi
def test_api_health_and_controls(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", raising=False)
    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", raising=False)
    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS", raising=False)

    app = create_app(api_registry)
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    controls = client.get("/controls")
    assert controls.status_code == 401

    anonymous_app = create_app(api_registry, allow_anonymous=True)
    anonymous_client = TestClient(anonymous_app)
    controls = anonymous_client.get("/controls")
    assert controls.status_code == 200
    payload = controls.json()
    assert [item["key"] for item in payload] == ["temp", "mode"]
    assert payload[0]["value"] == 0.5


@requires_fastapi
def test_api_initial_numeric_state_normalizes_nonfinite_default():
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    control = registry.register(
        "Threshold",
        kind="number",
        key="threshold",
        default=float("nan"),
        min_value=1.0,
        max_value=10.0,
        step=0.5,
    )
    app = create_app(
        registry,
        allow_anonymous=True,
        anonymous_role="Admin",
    )
    client = TestClient(app)

    response = client.get("/controls")

    assert response.status_code == 200
    payload = json.loads(
        response.text,
        parse_constant=lambda token: pytest.fail(f"non-standard JSON constant: {token}"),
    )
    assert payload[0]["value"] == 1.0
    assert math.isfinite(payload[0]["value"])
    assert control.default == 1.0


@requires_fastapi
def test_api_preserves_caller_provided_empty_audit(api_registry):
    from fastapi.testclient import TestClient

    audit = AuditLog()
    app = create_app(
        api_registry,
        audit=audit,
        allow_anonymous=True,
        anonymous_role="Admin",
    )
    client = TestClient(app)

    response = client.patch("/controls", json={"values": {"temp": 1.2}})

    assert response.status_code == 200
    assert len(audit) == 1
    assert audit.recent(1)[0]["type"] == "control_change"


@requires_fastapi
def test_api_audit_limit_is_bounded(api_registry):
    from fastapi.testclient import TestClient

    audit = AuditLog()
    audit.log("first", key="1")
    audit.log("second", key="2")
    app = create_app(api_registry, audit=audit, allow_anonymous=True, anonymous_role="Admin")
    client = TestClient(app)

    assert client.get("/audit?n=0").json() == []
    assert client.get("/audit?n=-1").json() == []
    assert [event["key"] for event in client.get("/audit?n=1").json()] == ["2"]


@requires_fastapi
def test_api_auth_uses_compare_digest_for_key_check(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    calls = []

    def _spy_compare_digest(left, right):
        calls.append((left, right))
        return left == right

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "secret-key")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Viewer")
    monkeypatch.setattr("role_aware_dashboard_toolkit.api.hmac.compare_digest", _spy_compare_digest)
    app = create_app(api_registry)
    client = TestClient(app)

    assert client.get("/controls", headers={"X-API-Key": "wrong-key"}).status_code == 401
    assert client.get("/controls", headers={"X-API-Key": "secret-key"}).status_code == 200
    assert ("wrong-key", "secret-key") in calls
    assert ("secret-key", "secret-key") in calls


@requires_fastapi
def test_api_auth_and_profile_flow(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "secret-key")
        monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Admin")
        audit = AuditLog()
        app = create_app(api_registry, audit=audit, profile_dir=tmpdir)
        client = TestClient(app)

        unauthorized = client.get("/controls")
        assert unauthorized.status_code == 401

        headers = {"X-API-Key": "secret-key"}
        updated = client.patch("/controls", json={"values": {"temp": 1.7}}, headers=headers)
        assert updated.status_code == 200
        assert updated.json()[0]["value"] == 1.7

        saved = client.post(
            "/profiles",
            json={"profile_id": "prod", "role": "Operator", "extra": {"source": "test"}},
            headers=headers,
        )
        assert saved.status_code == 200
        assert saved.json()["profile_id"] == "prod"
        assert saved.json()["values"]["temp"] == 1.7

        profiles = client.get("/profiles", headers=headers)
        assert profiles.status_code == 200
        assert profiles.json() == ["prod"]

        activated = client.post("/profiles/prod/activate", headers=headers)
        assert activated.status_code == 200
        assert activated.json()["role"] == "Operator"

        deleted = client.delete("/profiles/prod", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json() == {"deleted": "prod"}

        audit_events = client.get("/audit", headers=headers)
        assert audit_events.status_code == 200
        kinds = [event["type"] for event in audit_events.json()]
        assert "control_change" in kinds
        assert "profile_save" in kinds
        assert "profile_load" in kinds


@requires_fastapi
def test_api_profile_activation_returns_applied_sanitized_state(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    store = InMemoryProfileStore()
    store.save(
        {
            "profile_id": "unsafe",
            "saved_at": "2026-01-01T00:00:00+00:00",
            "role": "Operator",
            "values": {"temp": 99.0, "mode": "fast"},
        }
    )

    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", raising=False)
    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS", raising=False)
    app = create_app(api_registry, profile_store=store, allow_anonymous=True, anonymous_role="Admin")
    client = TestClient(app)

    activated = client.post("/profiles/unsafe/activate")
    assert activated.status_code == 200
    payload = activated.json()
    assert payload["profile_id"] == "unsafe"
    assert payload["values"]["temp"] == 2.0
    assert payload["values"]["mode"] == "fast"

    controls = client.get("/controls")
    assert controls.status_code == 200
    control_values = {item["key"]: item["value"] for item in controls.json()}
    assert control_values["temp"] == 2.0
    assert payload["values"]["temp"] == control_values["temp"]


@requires_fastapi
@pytest.mark.parametrize("locked_value", [False, True])
def test_api_profile_activation_enforces_each_control_permission_atomically(monkeypatch, locked_value):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register(
        "Temperature", kind="number", key="temp", default=0.5,
        min_value=0.0, max_value=2.0, permission="can_apply_tuning",
    )
    registry.register(
        "Governance lock", kind="toggle", key="governance_lock", default=False,
        permission="can_manage_governance",
    )
    registry.register(
        "API Token", kind="text", key="api_token", default="existing-token",
        permission="can_manage_governance", sensitive=True,
    )
    custom_roles = {
        "ProfileLoader": RoleDef(
            name="ProfileLoader",
            perms={
                "can_load_profiles": True,
                "can_apply_tuning": True,
                "can_view_metrics": True,
                "can_edit_controls": False,
                "can_manage_governance": False,
            },
        )
    }
    store = InMemoryProfileStore()
    store.save({
        "profile_id": "blocked",
        "values": {"temp": 99.0, "governance_lock": locked_value},
    })
    store.save({
        "profile_id": "permitted",
        "values": {"temp": 99.0, "unknown": "ignored", "api_token": "ignored-token"},
    })
    audit = AuditLog()
    audit.log("existing", detail="Preserve earlier evidence")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "loader-key")
    client = TestClient(create_app(
        registry, profile_store=store, audit=audit,
        custom_roles=custom_roles, api_role="ProfileLoader",
    ))
    headers = {"X-API-Key": "loader-key"}
    controls_before = client.get("/controls", headers=headers).json()
    audit_before = audit.recent(10)

    denied = client.post("/profiles/blocked/activate", headers=headers)

    assert denied.status_code == 403
    assert denied.json() == {"detail": "Forbidden: requires can_manage_governance"}
    assert client.get("/controls", headers=headers).json() == controls_before
    assert audit.recent(10) == audit_before

    permitted = client.post("/profiles/permitted/activate", headers=headers)

    assert permitted.status_code == 200
    assert permitted.json()["values"] == {"temp": 2.0, "governance_lock": False}
    assert client.get("/controls/temp", headers=headers).json()["value"] == 2.0
    assert client.get("/controls/unknown", headers=headers).status_code == 404
    assert audit.recent(10)[:-1] == audit_before
    assert audit.recent(1)[0]["type"] == "profile_load"
    assert audit.recent(1)[0]["role"] == "ProfileLoader"


@requires_fastapi
def test_api_profile_activation_checks_controls_changed_only_by_sanitization(monkeypatch):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register("Temperature", kind="number", key="temp", default=0.5)
    protected = registry.register(
        "Governance limit", kind="number", key="governance_limit", default=5.0,
        min_value=0.0, max_value=10.0, permission="can_manage_governance",
    )
    store = InMemoryProfileStore()
    store.save({"profile_id": "tuning", "values": {"temp": 1.5}})
    audit = AuditLog()
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "operator-key")
    client = TestClient(create_app(
        registry, profile_store=store, audit=audit, api_role="Operator",
    ))
    headers = {"X-API-Key": "operator-key"}
    protected.max_value = 2.0
    controls_before = client.get("/controls", headers=headers).json()

    denied = client.post("/profiles/tuning/activate", headers=headers)

    assert denied.status_code == 403
    assert denied.json() == {"detail": "Forbidden: requires can_manage_governance"}
    assert client.get("/controls", headers=headers).json() == controls_before
    assert len(audit) == 0


@requires_fastapi
def test_api_control_update_reports_sanitized_stored_value(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "secret-key")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Admin")
    app = create_app(api_registry)
    client = TestClient(app)
    headers = {"X-API-Key": "secret-key"}

    updated = client.patch("/controls", json={"values": {"temp": 99.0}}, headers=headers)

    assert updated.status_code == 200
    assert updated.json()[0]["value"] == 2.0
    current = client.get("/controls/temp", headers=headers)
    assert current.status_code == 200
    assert current.json()["value"] == 2.0
    audit_response = client.get("/audit", headers=headers)
    assert audit_response.status_code == 200
    control_events = [event for event in audit_response.json() if event["type"] == "control_change"]
    assert control_events[-1]["old"] == 0.5
    assert control_events[-1]["new"] == 2.0


@requires_fastapi
@pytest.mark.parametrize(
    "request_body",
    [
        '{"values":{"temp":"NaN"}}',
        '{"values":{"temp":"Infinity"}}',
        '{"values":{"temp":"-Infinity"}}',
        '{"values":{"temp":"1e9999"}}',
        '{"values":{"temp":1e9999}}',
    ],
)
def test_api_numeric_update_cannot_store_or_emit_nonfinite_values(api_registry, request_body):
    from fastapi.testclient import TestClient

    audit = AuditLog()
    app = create_app(
        api_registry,
        audit=audit,
        allow_anonymous=True,
        anonymous_role="Admin",
    )
    client = TestClient(app)

    updated = client.patch(
        "/controls",
        content=request_body,
        headers={"Content-Type": "application/json"},
    )
    current = client.get("/controls/temp")
    audit_response = client.get("/audit")

    assert updated.status_code == 200
    assert current.status_code == 200
    assert audit_response.status_code == 200

    responses = (updated, current, audit_response)
    decoded = [
        json.loads(
            response.text,
            parse_constant=lambda token: pytest.fail(
                f"non-standard JSON constant: {token}"
            ),
        )
        for response in responses
    ]
    assert decoded[0][0]["value"] == 0.5
    assert decoded[1]["value"] == 0.5
    event = decoded[2][-1]
    assert event["old"] == 0.5
    assert event["new"] == 0.5
    assert all(
        math.isfinite(value)
        for value in (
            decoded[0][0]["value"],
            decoded[1]["value"],
            event["old"],
            event["new"],
        )
    )


@requires_fastapi
def test_api_control_batch_update_is_atomic_on_unknown_key(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "secret-key")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Admin")
    app = create_app(api_registry)
    client = TestClient(app)
    headers = {"X-API-Key": "secret-key"}

    audit_before = client.get("/audit", headers=headers)
    assert audit_before.status_code == 200

    failed = client.patch("/controls", json={"values": {"temp": 99.0, "unknown": "boom"}}, headers=headers)

    assert failed.status_code == 404
    assert failed.json() == {"detail": "Control 'unknown' not found"}

    current = client.get("/controls/temp", headers=headers)
    assert current.status_code == 200
    assert current.json()["value"] == 0.5

    audit_after = client.get("/audit", headers=headers)
    assert audit_after.status_code == 200
    assert audit_after.json() == audit_before.json()


@requires_fastapi
def test_api_control_batch_update_enforces_each_control_permission_atomically(monkeypatch):
    from fastapi.testclient import TestClient

    registry = ControlRegistry()
    registry.register("Temperature", kind="number", key="temp", default=0.5)
    registry.register(
        "Governance lock",
        kind="toggle",
        key="governance_lock",
        permission="can_manage_governance",
        default=False,
    )
    custom_roles = {
        "ControlEditor": RoleDef(
            name="ControlEditor",
            perms={
                "can_edit_controls": True,
                "can_manage_governance": False,
                "can_view_metrics": True,
            },
        )
    }
    audit = AuditLog()

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "editor-key")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "ControlEditor")
    app = create_app(registry, audit=audit, custom_roles=custom_roles)
    client = TestClient(app)
    headers = {"X-API-Key": "editor-key"}

    denied = client.patch(
        "/controls",
        json={"values": {"temp": 1.5, "governance_lock": True}},
        headers=headers,
    )

    assert denied.status_code == 403
    assert denied.json() == {"detail": "Forbidden: requires can_manage_governance"}
    assert client.get("/controls/temp", headers=headers).json()["value"] == 0.5
    assert client.get("/controls/governance_lock", headers=headers).json()["value"] is False
    assert len(audit) == 0

    permitted = client.patch(
        "/controls",
        json={"values": {"temp": 1.5}},
        headers=headers,
    )

    assert permitted.status_code == 200
    assert permitted.json()[0]["value"] == 1.5
    assert len(audit) == 1


@requires_fastapi
def test_api_role_scope_blocks_forbidden_operations(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    custom_roles = {
        "NoAudit": RoleDef(
            name="NoAudit",
            perms={"can_view_metrics": True, "can_view_audit": False},
            description="Can read controls but cannot inspect audit events.",
        )
    }

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "viewer-key")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Viewer")
    app = create_app(api_registry, custom_roles=custom_roles)
    client = TestClient(app)
    headers = {"X-API-Key": "viewer-key"}

    controls = client.get("/controls", headers=headers)
    assert controls.status_code == 200
    assert client.patch("/controls", json={"values": {"temp": 1.2}}, headers=headers).status_code == 403
    assert client.post("/profiles", json={"profile_id": "blocked"}, headers=headers).status_code == 403
    assert client.get("/profiles", headers=headers).status_code == 403

    no_audit_app = create_app(api_registry, custom_roles=custom_roles, api_role="NoAudit")
    no_audit_client = TestClient(no_audit_app)
    assert no_audit_client.get("/audit", headers=headers).status_code == 403


@requires_fastapi
def test_api_key_without_role_defaults_to_viewer_read_only(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "viewer-key")
    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", raising=False)
    app = create_app(api_registry)
    client = TestClient(app)
    headers = {"X-API-Key": "viewer-key"}

    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/controls", headers=headers).status_code == 200
    assert client.patch("/controls", json={"values": {"temp": 1.2}}, headers=headers).status_code == 403
    assert client.post("/profiles", json={"profile_id": "blocked"}, headers=headers).status_code == 403
    assert client.get("/profiles", headers=headers).status_code == 403


@requires_fastapi
def test_api_authenticated_role_is_frozen_at_app_creation(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "viewer-key")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Viewer")
    app = create_app(api_registry)
    client = TestClient(app)
    headers = {"X-API-Key": "viewer-key"}

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Admin")

    assert client.get("/controls", headers=headers).status_code == 200
    assert client.patch("/controls", json={"values": {"temp": 1.2}}, headers=headers).status_code == 403


@requires_fastapi
def test_api_create_app_rejects_unknown_configured_roles(api_registry):
    with pytest.raises(ValueError, match="Unknown api_role"):
        create_app(api_registry, api_role="NotARole")
    with pytest.raises(ValueError, match="Unknown anonymous_role"):
        create_app(api_registry, allow_anonymous=True, anonymous_role="NotARole")


@requires_fastapi
def test_api_profile_store_takes_precedence_over_profile_dir(api_registry, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", raising=False)
    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS", raising=False)

    with tempfile.TemporaryDirectory() as tmpdir:
        store = InMemoryProfileStore()
        app = create_app(
            api_registry,
            profile_dir=tmpdir,
            profile_store=store,
            allow_anonymous=True,
            anonymous_role="Admin",
        )
        client = TestClient(app)

        saved = client.post(
            "/profiles",
            json={"profile_id": "mem", "role": "Operator", "extra": {"source": "store"}},
        )
        assert saved.status_code == 200
        assert store.load("mem") is not None
        assert not any(Path(tmpdir).glob("*.json"))

        profiles = client.get("/profiles")
        assert profiles.status_code == 200
        assert profiles.json() == ["mem"]


@requires_fastapi
def test_api_protects_sensitive_control_values(monkeypatch):
    from fastapi.testclient import TestClient

    reg = ControlRegistry()
    reg.register("API Token", kind="text", key="api_token", default="")
    store = InMemoryProfileStore()

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "secret-key")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Admin")
    app = create_app(reg, profile_store=store)
    client = TestClient(app)
    headers = {"X-API-Key": "secret-key"}

    updated = client.patch("/controls", json={"values": {"api_token": "top-secret-token"}}, headers=headers)
    assert updated.status_code == 200
    assert updated.json()[0]["value"] == "<redacted-secret>"
    assert updated.json()[0]["sensitive"] is True
    control_response = client.get("/controls/api_token", headers=headers)
    assert control_response.status_code == 200
    assert control_response.json()["value"] == "<redacted-secret>"
    assert control_response.json()["sensitive"] is True

    profile_response = client.post(
        "/profiles",
        json={"profile_id": "secure"},
        headers=headers,
    )
    assert profile_response.status_code == 200
    assert profile_response.json()["values"] == {}
    assert store.load("secure")["values"] == {}
    loaded_profile = client.get("/profiles/secure", headers=headers)
    assert loaded_profile.status_code == 200
    assert loaded_profile.json()["values"] == {}

    audit_response = client.get("/audit", headers=headers)
    assert audit_response.status_code == 200

    control_events = [event for event in audit_response.json() if event["type"] == "control_change" and event["key"] == "api_token"]
    assert control_events
    assert control_events[-1]["old"] == "<redacted-secret>"
    assert control_events[-1]["new"] == "<redacted-secret>"
