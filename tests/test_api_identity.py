"""Verified request identities stay bound to live grants and isolated apps."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import ControlRegistry
from role_aware_dashboard_toolkit import api
from role_aware_dashboard_toolkit.access import Identity, InMemoryAccessStore, principal_id
from role_aware_dashboard_toolkit.api_access import APIAuthentication
from role_aware_dashboard_toolkit.audit import AuditLog
from role_aware_dashboard_toolkit.profile_store import InMemoryProfileStore
from role_aware_dashboard_toolkit.state_store import InMemoryStateStore


pytestmark = pytest.mark.skipif(not api.FASTAPI_AVAILABLE, reason="FastAPI not installed")
ISSUER = "https://verified-provider.example"


@pytest.fixture(autouse=True)
def clear_legacy_environment(monkeypatch):
    for name in (
        "ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY",
        "ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE",
        "ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def make_host():
    from fastapi.testclient import TestClient

    clients = []

    def make(organization="alpha", *, resolver=None):
        key = (organization.encode("ascii") + b"-synthetic-identity-key-") * 3
        identities = {
            name: Identity(ISSUER, f"{organization}:{name}", time.time() + 3600)
            for name in ("admin", "viewer", "editor", "unassigned")
        }
        tokens = {f"Bearer {organization}:{name}": identity for name, identity in identities.items()}
        grants = InMemoryAccessStore()
        for name, role in (("admin", "Admin"), ("viewer", "Viewer"), ("editor", "Operator")):
            grants.replace_grants(principal_id(identities[name], key), (role,))
        grants.compare_and_set_freeze(False, 0, principal_id(identities["admin"], key))
        registry = ControlRegistry()
        registry.register("Workspace", key="workspace", kind="text", default=organization)
        profiles = InMemoryProfileStore()
        audit = AuditLog()
        state = InMemoryStateStore()
        authentication = APIAuthentication(
            resolver or (lambda request: tokens.get(request.headers.get("authorization", ""))),
            grants, key,
        )
        app = api.create_app(
            registry, authentication=authentication, profile_store=profiles,
            audit=audit, state_store=state,
        )
        client = TestClient(app)
        clients.append(client)
        return SimpleNamespace(
            client=client, authentication=authentication, grants=grants, key=key,
            identities=identities, tokens=tokens, registry=registry, profiles=profiles,
            audit=audit, state=state,
            headers=lambda name="admin", **extra: {
                "Authorization": f"Bearer {organization}:{name}",
                "Content-Type": "application/json", **extra,
            },
        )

    yield make
    for client in clients:
        client.close()


def _patch(host, value, user="admin", **headers):
    return host.client.patch(
        "/controls", json={"values": {"workspace": value}},
        headers=host.headers(user, **{"If-Match": f'"{host.state.read().revision}"', **headers}),
    )


def _freeze(host):
    current = host.grants.read_freeze()
    host.grants.compare_and_set_freeze(
        True, current.revision, principal_id(host.identities["admin"], host.key),
    )


def test_distinct_users_receive_their_current_grants(make_host):
    host = make_host()
    assert host.client.get("/controls", headers=host.headers("viewer")).status_code == 200
    assert _patch(host, "viewer edit", "viewer").status_code == 403
    assert host.state.read().values == {}
    assert host.audit.recent() == []
    assert _patch(host, "administrator edit").status_code == 200
    assert _patch(host, "operator edit", "editor").status_code == 200
    assert host.state.read().values == {"workspace": "operator edit"}


@pytest.mark.parametrize("selected", ["Admin", "Operator", "Unauthenticated", "unknown"])
def test_request_role_selection_cannot_create_a_grant(make_host, selected):
    host = make_host()
    response = _patch(host, "forged role", "viewer", **{"X-Dashboard-Role": selected})
    assert response.status_code == 401
    assert host.state.read().values == {}
    assert host.audit.recent() == []


def test_role_selection_can_only_choose_among_current_assignments(make_host):
    host = make_host()
    principal = principal_id(host.identities["admin"], host.key)
    host.grants.replace_grants(principal, ("Viewer", "Admin"))
    assert _patch(host, "default viewer").status_code == 403
    assert _patch(host, "selected admin", **{"X-Dashboard-Role": "Admin"}).status_code == 200
    host.grants.replace_grants(principal, ("Viewer",))
    assert _patch(host, "stale selected admin", **{"X-Dashboard-Role": "Admin"}).status_code == 401
    assert host.state.read().values == {"workspace": "selected admin"}


def test_revocation_is_effective_on_next_protected_request(make_host):
    host = make_host()
    assert host.client.get("/controls", headers=host.headers()).status_code == 200
    host.grants.replace_grants(principal_id(host.identities["admin"], host.key), ())
    assert host.client.get("/controls", headers=host.headers()).status_code == 401
    assert _patch(host, "revoked write").status_code == 401
    assert host.state.read().values == {}
    assert host.audit.recent() == []


@pytest.mark.parametrize("identity", [
    None,
    {"issuer": ISSUER, "subject": "alpha:admin", "expires_at": 253402300799},
    Identity(ISSUER, "alpha:admin", 1),
    Identity("https://different-provider.example", "alpha:admin", 253402300799),
])
def test_missing_malformed_expired_and_ungranted_issuer_identities_fail_closed(make_host, identity):
    host = make_host(resolver=lambda request: identity)
    response = host.client.get("/controls", headers=host.headers())
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication could not be confirmed."}
    assert host.state.read().values == {}


def test_provider_failure_is_safe_and_shared_key_cannot_bypass_it(make_host, monkeypatch):
    def failed_provider(request):
        raise RuntimeError("private-provider-subject-and-token")

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-shared-key")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE", "Admin")
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS", "true")
    host = make_host(resolver=failed_provider)
    response = host.client.get("/controls", headers={"X-API-Key": "synthetic-shared-key"})
    assert response.status_code == 401
    assert "private-provider" not in response.text
    assert host.state.read().values == {}


def test_unknown_credential_and_unassigned_user_are_denied(make_host, monkeypatch):
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-shared-key")
    host = make_host()
    for headers in ({}, {"X-API-Key": "synthetic-shared-key"}, host.headers("unknown"), host.headers("unassigned")):
        assert host.client.get("/controls", headers=headers).status_code == 401


def test_identity_is_rechecked_within_the_same_request(make_host):
    calls = []
    admin = Identity(ISSUER, "alpha:admin", 253402300799)
    viewer = Identity(ISSUER, "alpha:viewer", 253402300799)

    def changed_identity(request):
        calls.append(request)
        return admin if len(calls) <= 2 else viewer

    host = make_host(resolver=changed_identity)
    assert _patch(host, "changed user").status_code == 403
    assert len(calls) >= 3
    assert host.state.read().values == {}
    assert host.audit.recent() == []


def test_revocation_during_value_validation_prevents_commit(make_host, monkeypatch):
    host = make_host()
    exact = api._exact_control_value

    def revoke_then_validate(control, value):
        host.grants.replace_grants(principal_id(host.identities["admin"], host.key), ())
        return exact(control, value)

    monkeypatch.setattr(api, "_exact_control_value", revoke_then_validate)
    assert _patch(host, "revoked mid-request").status_code == 403
    assert host.state.read().values == {}
    assert host.audit.recent() == []


@pytest.mark.parametrize("operation", ["controls", "create", "activate", "delete"])
def test_shared_freeze_blocks_every_mutation_even_for_admin(make_host, operation):
    host = make_host()
    assert host.client.post("/profiles", headers=host.headers(), json={"profile_id": "existing"}).status_code == 200
    before_profile = host.profiles.load("existing")
    before_audit = host.audit.recent()
    _freeze(host)
    if operation == "controls":
        response = _patch(host, "frozen change")
    elif operation == "create":
        response = host.client.post("/profiles", headers=host.headers(), json={"profile_id": "new"})
    elif operation == "activate":
        response = host.client.post("/profiles/existing/activate", headers=host.headers(**{"If-Match": '"0"'}))
    else:
        response = host.client.delete("/profiles/existing", headers=host.headers())
    assert response.status_code == 403
    assert host.state.read().values == {}
    assert host.profiles.list_ids() == ["existing"]
    assert host.profiles.load("existing") == before_profile
    assert host.audit.recent() == before_audit
    assert host.client.get("/controls", headers=host.headers()).status_code == 200


def test_audit_records_bind_distinct_verified_actors(make_host):
    host = make_host()
    assert _patch(host, "admin value").status_code == 200
    assert _patch(host, "editor value", "editor").status_code == 200
    events = host.client.get("/audit", headers=host.headers()).json()
    expected = {
        "admin value": principal_id(host.identities["admin"], host.key),
        "editor value": principal_id(host.identities["editor"], host.key),
    }
    assert len(events) == 2
    for event in events:
        assert event["user_id"] == expected[event["new"]]
        assert event["source"] == "api"
        assert event["session_id"]
    assert len({event["user_id"] for event in events}) == 2


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/controls", None),
    ("GET", "/controls/workspace", None),
    ("PATCH", "/controls", {"values": {"workspace": "cross-organization"}}),
    ("GET", "/profiles", None),
    ("GET", "/profiles/shared-name", None),
    ("POST", "/profiles", {"profile_id": "cross-organization"}),
    ("POST", "/profiles/shared-name/activate", None),
    ("DELETE", "/profiles/shared-name", None),
    ("GET", "/audit", None),
])
def test_other_organization_credentials_cannot_read_or_mutate_any_resource(make_host, method, path, body):
    alpha, beta = make_host("alpha"), make_host("beta")
    for host in (alpha, beta):
        assert host.client.post("/profiles", headers=host.headers(), json={"profile_id": "shared-name"}).status_code == 200
    before_profile = beta.profiles.load("shared-name")
    before_audit = beta.audit.recent()
    response = beta.client.request(
        method, path, json=body,
        headers=alpha.headers(**{"X-Tenant-ID": "beta", "X-Dashboard-Role": "Admin", "If-Match": '"0"'}),
    )
    assert response.status_code == 401
    assert beta.state.read().values == {}
    assert beta.profiles.load("shared-name") == before_profile
    assert beta.profiles.list_ids() == ["shared-name"]
    assert beta.audit.recent() == before_audit


def test_identically_named_resources_and_valid_grants_stay_in_the_selected_app(make_host):
    alpha, beta = make_host("alpha"), make_host("beta")
    for host in (alpha, beta):
        assert host.client.post("/profiles", headers=host.headers(), json={"profile_id": "shared-name"}).status_code == 200
    assert alpha.client.post("/profiles", headers=alpha.headers(), json={"profile_id": "alpha-only"}).status_code == 200
    assert beta.client.get("/profiles/alpha-only", headers=beta.headers()).status_code == 404
    assert _patch(alpha, "alpha changed", **{"X-Tenant-ID": "beta"}).status_code == 200
    assert alpha.client.get("/profiles/shared-name", headers=alpha.headers()).json()["values"] == {"workspace": "alpha"}
    assert beta.client.get("/profiles/shared-name", headers=beta.headers()).json()["values"] == {"workspace": "beta"}
    assert beta.client.get("/controls/workspace", headers=beta.headers()).json()["value"] == "beta"
    assert beta.state.read().values == {}
    beta_events = beta.client.get("/audit", headers=beta.headers()).json()
    assert {event["user_id"] for event in beta_events} == {principal_id(beta.identities["admin"], beta.key)}
    assert all(event["type"] != "control_change" for event in beta_events)


def test_same_verified_person_has_independent_grants_in_each_organization(make_host):
    person = Identity(ISSUER, "shared-person", 253402300799)
    alpha = make_host("alpha", resolver=lambda request: person)
    beta = make_host("beta", resolver=lambda request: person)
    alpha.grants.replace_grants(principal_id(person, alpha.key), ("Admin",))
    beta.grants.replace_grants(principal_id(person, beta.key), ("Viewer",))
    assert principal_id(person, alpha.key) != principal_id(person, beta.key)
    assert _patch(alpha, "authorized in alpha").status_code == 200
    assert _patch(beta, "not authorized in beta").status_code == 403
    assert _patch(beta, "forged beta admin", **{"X-Dashboard-Role": "Admin"}).status_code == 401
    assert beta.state.read().values == {}


@pytest.mark.parametrize("method,path", [("POST", "/profiles/existing/activate"), ("DELETE", "/profiles/existing")])
def test_cookie_capable_identity_mode_still_requires_json_for_bodyless_mutations(make_host, method, path):
    host = make_host()
    assert host.client.post("/profiles", headers=host.headers(), json={"profile_id": "existing"}).status_code == 200
    headers = {"Authorization": "Bearer alpha:admin", "If-Match": '"0"'}
    response = host.client.request(method, path, headers=headers)
    assert response.status_code == 415
    assert host.profiles.list_ids() == ["existing"]
    assert host.state.read().values == {}


def test_per_user_api_requires_explicit_profile_storage(make_host):
    host = make_host()
    with pytest.raises(ValueError, match="profile"):
        api.create_app(host.registry, authentication=host.authentication)


@pytest.mark.parametrize("options", [{"allow_anonymous": True}, {"api_role": "Admin"}])
def test_per_user_api_refuses_explicit_legacy_authority_options(make_host, options):
    host = make_host()
    with pytest.raises(ValueError, match="authentication"):
        api.create_app(
            host.registry, authentication=host.authentication,
            profile_store=InMemoryProfileStore(), **options,
        )


def test_profile_audit_actions_keep_verified_actor_and_ignore_profile_role_metadata(make_host):
    host = make_host()
    response = host.client.post(
        "/profiles", headers=host.headers(), json={"profile_id": "existing", "role": "Viewer"},
    )
    assert response.status_code == 200
    assert host.client.post(
        "/profiles/existing/activate", headers=host.headers(**{"If-Match": '"0"'}),
    ).status_code == 200
    assert host.client.delete("/profiles/existing", headers=host.headers()).status_code == 200
    events = host.client.get("/audit", headers=host.headers()).json()
    assert {event["type"] for event in events} == {"profile_save", "profile_load", "profile_delete"}
    assert {event["role"] for event in events} == {"Admin"}
    assert {event["user_id"] for event in events} == {principal_id(host.identities["admin"], host.key)}
