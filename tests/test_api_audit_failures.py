"""Post-commit audit failures report the committed result without replaying it."""
from __future__ import annotations

import logging
import time

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.access import AccessPolicy, Identity, InMemoryAccessStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.api_access import APIAuthentication
from role_aware_dashboard_toolkit.state_store import InMemoryStateStore, StateStoreError


pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
PRIVATE_ERROR = "synthetic-private-adapter-path-and-credential"
KEY = "synthetic-audit-failure-api-key"


class FailingAudit(AuditLog):
    def __init__(self, event_type, error_type):
        super().__init__()
        self.failed_event = event_type
        self.error_type = error_type
        self.attempts = []

    def log(self, event_type, **kwargs):
        self.attempts.append(event_type)
        if event_type == self.failed_event:
            error = self.error_type()
            error.args = (PRIVATE_ERROR,)
            raise error
        return super().log(event_type, **kwargs)


@pytest.mark.parametrize("identity_mode", ["shared-key", "per-user"])
@pytest.mark.parametrize("error_type", [RuntimeError, StateStoreError])
@pytest.mark.parametrize("operation,event_type", [
    ("controls", "control_change"), ("activate", "profile_load"),
    ("save", "profile_save"), ("delete", "profile_delete"),
])
def test_audit_failure_reports_committed_operation_and_does_not_retry(
    monkeypatch, caplog, identity_mode, error_type, operation, event_type,
):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", KEY)
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=3, step=1)
    state = InMemoryStateStore({"workers": 3})
    profiles = InMemoryProfileStore()
    if operation in {"activate", "delete"}:
        profiles.save({"profile_id": "night", "values": {"workers": 9}})
    audit = FailingAudit(event_type, error_type)
    options = {"api_role": "Admin"}
    if identity_mode == "per-user":
        # Trusted synthetic resolver only; production hosts must verify credentials.
        identity = Identity("synthetic-issuer", "synthetic-admin", time.time() + 60)
        grants = InMemoryAccessStore()
        identity_key = b"synthetic-audit-identity-key" * 2
        principal = AccessPolicy(lambda: identity, grants, identity_key).identify()
        grants.replace_grants(principal, ("Admin",))
        grants.compare_and_set_freeze(False, 0, principal)
        options = {"authentication": APIAuthentication(lambda request: identity, grants, identity_key)}
    app = create_app(registry, audit=audit, profile_store=profiles, state_store=state, **options)
    headers = {"X-API-Key": KEY, "If-Match": '"0"'}
    with TestClient(app) as client, caplog.at_level(logging.ERROR, logger="role_aware_dashboard_toolkit.api"):
        if operation == "controls":
            response = client.patch("/controls", headers=headers, json={"values": {"workers": 9}})
        elif operation == "activate":
            response = client.post("/profiles/night/activate", headers=headers)
        elif operation == "save":
            response = client.post("/profiles", headers=headers, json={"profile_id": "night"})
        else:
            response = client.delete("/profiles/night", headers=headers)

        assert response.status_code == 500  # An audit StateStoreError is not a pre-commit 503.
        committed = "Control state" if operation in {"controls", "activate"} else "Profile operation"
        assert response.json() == {
            "detail": f"{committed} committed, but audit recording failed. Refresh before retrying.",
        }
        assert audit.attempts == [event_type]
        assert audit.all_events() == []
        assert PRIVATE_ERROR not in response.text
        assert PRIVATE_ERROR not in caplog.text
        assert "Audit recording failed after an API operation committed" in caplog.text

        snapshot = state.read()
        current = client.get("/controls/workers", headers=headers)
        if operation in {"controls", "activate"}:
            assert snapshot.values == {"workers": 9}
            assert snapshot.revision == 1
            assert response.headers["ETag"] == '"1"'
            assert current.headers["ETag"] == response.headers["ETag"]
            assert current.json()["value"] == 9
            # The original revision cannot blindly replay the committed write.
            retry = client.patch("/controls", headers=headers, json={"values": {"workers": 10}})
            assert retry.status_code == 409
            assert state.read() == snapshot
            assert audit.attempts == [event_type]
        else:
            assert snapshot.values == {"workers": 3}
            assert snapshot.revision == 0
            assert "ETag" not in response.headers
            assert current.json()["value"] == 3
            if operation == "save":
                assert profiles.load("night")["values"] == {"workers": 3}
            else:
                assert profiles.load("night") is None
