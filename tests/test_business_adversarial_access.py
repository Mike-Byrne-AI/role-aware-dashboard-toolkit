"""Adversarial HTTP boundaries and failure atomicity on disposable accounts only."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
from threading import Barrier, Event

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    NEW_PASSWORD, ORIGIN, business as business, business_admin as business_admin,
    business_seed as business_seed, contact_body, event_body, post_body,
)
from business import auth_routes  # noqa: E402
from business.security import COOKIE_NAME, verify_password  # noqa: E402


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    attempts = []

    def forbid(self, request):
        attempts.append(True)
        raise AssertionError("The adversarial test attempted external HTTP")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbid)
    yield
    assert not attempts, "The adversarial test attempted external HTTP"


def _state_digest(trial):
    """Compare private state without exposing even synthetic secrets on failure."""
    with trial.db() as connection:
        rows = [
            [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")]
            for table in (
                "users", "settings", "events", "assignments", "messages", "contacts",
                "posts", "submissions", "submission_limits", "revenue", "activity",
                "admin_mfa", "session_mfa",
            )
        ]
        # Authorized reads may touch last_seen. Attempt reservations deliberately
        # survive failures, so neither last_seen nor login_limits is an invariant.
        rows.append([tuple(row) for row in connection.execute(
            "SELECT token_hash,user_id,created_at,expires_at FROM sessions ORDER BY token_hash"
        )])
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def _admin_operations():
    return [
        ("GET", "/api/admin/overview", None),
        ("GET", "/api/admin/contacts", None),
        ("GET", "/api/admin/posts", None),
        ("GET", "/api/admin/submissions", None),
        ("GET", "/api/admin/users", None),
        ("GET", "/api/admin/security-metrics", None),
        ("POST", "/api/schedule", event_body()),
        ("PUT", "/api/schedule/{identifier}", {**event_body(), "revision": 0}),
        ("POST", "/api/schedule/{identifier}/archive", {"revision": 0}),
        ("POST", "/api/admin/contacts", contact_body()),
        ("PUT", "/api/admin/contacts/{identifier}", {**contact_body(), "revision": 0}),
        ("POST", "/api/admin/posts", post_body()),
        ("PUT", "/api/admin/posts/{identifier}", {**post_body(), "revision": 0}),
        ("POST", "/api/admin/posts/{identifier}/unpublish", {"revision": 0}),
        ("POST", "/api/admin/submissions/{identifier}/review", {"decision": "approve", "revision": 0}),
        ("POST", "/api/admin/freeze", {"frozen": True, "revision": 0}),
        ("PUT", "/api/admin/users/{identifier}", {"active": False, "revision": 0}),
    ]


def _object_path(template, *, exists=True):
    identifiers = {
        "/api/schedule/": "event-1", "/api/admin/contacts/": "contact-1",
        "/api/admin/posts/": "post-1", "/api/admin/users/": "blair",
        "/api/admin/submissions/": "adversarial-pending",
    }
    identifier = next((value for prefix, value in identifiers.items() if template.startswith(prefix)), "unused")
    return template.replace("{identifier}", identifier if exists else "absent-object-'OR-1=1--")


def test_route_inventory_keeps_admin_adversarial_matrix_complete(business):
    actual = {
        (method, route.path) for route in business.app.routes
        if getattr(route, "path", "").startswith("/api/")
        for method in route.methods
    }
    other = {
        ("POST", "/api/login"), ("POST", "/api/password"), ("POST", "/api/logout"),
        ("GET", "/api/session"), ("GET", "/api/schedule"), ("GET", "/api/messages"),
        ("POST", "/api/messages"), ("GET", "/api/public/posts"), ("POST", "/api/public/submissions"),
        ("GET", "/api/security/sessions"), ("POST", "/api/security/reauthenticate"),
        ("POST", "/api/security/sessions/{identifier}/revoke"),
        ("GET", "/api/security/passkeys"),
        ("POST", "/api/security/passkeys/{identifier}/remove"),
        ("POST", "/api/security/passkeys/register/options"), ("POST", "/api/security/passkeys/register/verify"),
        ("POST", "/api/security/passkeys/reauth/options"), ("POST", "/api/security/passkeys/reauth/verify"),
        ("POST", "/api/passkeys/login/options"), ("POST", "/api/passkeys/login/verify"),
    }
    assert actual == other | {(method, path) for method, path, _ in _admin_operations()}


@pytest.mark.parametrize("actor_kind", ["guest", "employee", "demoted-admin"])
def test_every_admin_route_denies_untrusted_roles_before_object_lookup(business, actor_kind):
    actor = None if actor_kind == "guest" else business.login("admin" if actor_kind == "demoted-admin" else "alex")
    client = actor.client if actor else business.client()
    with business.db() as connection:
        connection.execute(
            "INSERT INTO submissions VALUES('adversarial-pending','Private pending title',"
            "'Private pending body','pending','2026-01-01T00:00:00+00:00',0,NULL)"
        )
        if actor_kind == "demoted-admin":
            connection.execute("UPDATE users SET role='employee' WHERE id='admin'")
    before = _state_digest(business)
    headers = {
        "Origin": ORIGIN, "X-CSRF-Token": actor.csrf if actor else "forged",
        "X-Role": "admin", "X-User-ID": "admin", "Authorization": "Bearer admin",
        "X-Forwarded-User": "admin", "X-Forwarded-Role": "admin",
    }
    expected = 401 if actor_kind == "guest" else 403
    for method, template, body in _admin_operations():
        for exists in ((True, False) if "{identifier}" in template else (True,)):
            path = _object_path(template, exists=exists)
            response = client.request(method, path, json=body, headers=headers)
            assert response.status_code == expected, (method, template, exists)
            assert "Private pending" not in response.text
            assert _state_digest(business) == before, (method, template, exists)
    # Positive controls prevent a blanket failure from masquerading as protection.
    assert client.get("/api/public/posts").status_code == 200
    assert client.get("/api/messages").status_code == (401 if actor is None else 200)


@pytest.mark.parametrize("extra", [{"role": "admin"}, {"user_id": "admin"}, {"author_id": "admin"}, {"approved": True}])
def test_extra_authority_fields_cannot_be_smuggled_into_any_staff_write(business, business_admin, extra):
    before = _state_digest(business)
    operations = [item for item in _admin_operations() if item[0] != "GET"] + [
        ("POST", "/api/messages", {"body": "No forged ownership"}),
        ("POST", "/api/password", {"current_password": business.credentials["admin"], "new_password": NEW_PASSWORD}),
        ("POST", "/api/logout", {}),
    ]
    for method, path, body in operations:
        response = business_admin.request(method, _object_path(path), json={**body, **extra})
        assert response.status_code == 422, (method, path)
        assert response.json() == {"detail": "Check the submitted fields and try again."}
        assert _state_digest(business) == before, (method, path)


def test_object_mutations_require_admin_session_bound_csrf_and_same_origin(business, business_admin):
    employee = business.login("alex")
    before = _state_digest(business)
    attacks = [
        {"Origin": ORIGIN},
        {"Origin": ORIGIN, "X-CSRF-Token": employee.csrf},
        {"Origin": "https://foreign.invalid", "X-CSRF-Token": business_admin.csrf},
        {"Origin": ORIGIN, "X-CSRF-Token": business_admin.csrf, "Sec-Fetch-Site": "cross-site"},
    ]
    for method, template, body in _admin_operations():
        if "{identifier}" not in template:
            continue
        for headers in attacks:
            response = business_admin.client.request(method, _object_path(template), json=body, headers=headers)
            assert response.status_code == 403, (method, template)
            assert _state_digest(business) == before, (method, template)


def test_unknown_object_identifiers_are_data_and_cannot_change_other_records(business, business_admin):
    before = _state_digest(business)
    for method, template, body in _admin_operations():
        if "{identifier}" not in template:
            continue
        response = business_admin.request(method, _object_path(template, exists=False), json=body)
        assert response.status_code == 404, (method, template)
        assert _state_digest(business) == before, (method, template)


@pytest.mark.parametrize("actor_kind", ["guest", "employee"])
def test_encoded_paths_and_method_overrides_do_not_bypass_route_authorization(business, actor_kind):
    actor = business.login("alex") if actor_kind == "employee" else None
    client = actor.client if actor else business.client()
    before = _state_digest(business)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": actor.csrf if actor else "forged"}
    for path in (
        "/api/admin/%75sers", "/api/admin/users/", "/api/schedule/../admin/users",
        "/api//admin/users", "/api/admin/users;.json", "/api/admin/users.json",
        "/api/admin/users?role=admin&user_id=admin", "/api/admin/users%00",
        "/api/admin/users%2falex",
    ):
        response = client.get(path, headers=headers, follow_redirects=True)
        assert response.status_code in {401, 403, 404, 405}, path
    for method in ("GET", "HEAD", "OPTIONS", "TRACE", "PUT", "PATCH", "DELETE"):
        response = client.request(method, "/api/admin/freeze", json={"frozen": True, "revision": 0}, headers={
            **headers, "X-HTTP-Method-Override": "POST", "X-Method-Override": "POST",
        })
        assert response.status_code == 405, method
    assert _state_digest(business) == before


@pytest.mark.parametrize("damage", ["missing", "invalid-freeze", "invalid-revision"])
def test_missing_or_corrupt_freeze_state_denies_authenticated_work(business, business_admin, damage):
    employee = business.login("alex")
    with business.db() as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute({
            "missing": "DELETE FROM settings",
            "invalid-freeze": "UPDATE settings SET frozen=2",
            "invalid-revision": "UPDATE settings SET freeze_revision=1.5",
        }[damage])
    before = _state_digest(business)
    for actor in (business_admin, employee):
        assert actor.request("GET", "/api/session").status_code == 403
        assert actor.request("GET", "/api/messages").status_code == 403
        assert actor.request("POST", "/api/messages", json={"body": "Blocked on damaged storage"}).status_code == 403
    assert business_admin.request("POST", "/api/admin/posts", json=post_body()).status_code == 403
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": 0}).status_code == 403
    assert business.client().get("/api/public/posts").status_code == 503
    assert business.client().get("/healthz").status_code == 503
    assert _state_digest(business) == before


@pytest.mark.parametrize("change", ["freeze", "downgrade", "disable", "mfa-generation"])
def test_request_waiting_for_transaction_sees_completed_access_change(business, business_admin, monkeypatch, change):
    database = business.app.state.database
    transaction = database.transaction
    attempted = Event()

    @contextmanager
    def announced_transaction():
        attempted.set()
        with transaction() as connection:
            yield connection

    monkeypatch.setattr(database, "transaction", announced_transaction)
    with ThreadPoolExecutor(max_workers=1) as pool:
        # This transaction is the operation that wins the race. The HTTP request
        # is launched while it holds SQLite's write reservation, before commit.
        with transaction() as connection:
            connection.execute({
                "freeze": "UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1",
                "downgrade": "UPDATE users SET role='employee' WHERE id='admin'",
                "disable": "UPDATE users SET active=0 WHERE id='admin'",
                "mfa-generation": "UPDATE admin_mfa SET generation='replacement' WHERE user_id='admin'",
            }[change])
            pending = pool.submit(business_admin.request, "POST", "/api/admin/posts", json=post_body())
            assert attempted.wait(timeout=5)
        response = pending.result(timeout=10)
    assert response.status_code == (401 if change in {"disable", "mfa-generation"} else 403)
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM posts WHERE title='Quarterly update'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM activity WHERE action='Created public-board post'").fetchone()[0] == 0


@pytest.mark.parametrize("change", ["downgrade", "mfa-generation"])
def test_admin_password_change_rechecks_role_and_mfa_after_hash_work(business, business_admin, monkeypatch, change):
    entered, release = Event(), Event()
    original = auth_routes.hash_password

    def held_hash(password):
        result = original(password)
        entered.set()
        assert release.wait(timeout=10)
        return result

    monkeypatch.setattr(auth_routes, "hash_password", held_hash)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(business_admin.request, "POST", "/api/password", json={
            "current_password": business.credentials["admin"], "new_password": NEW_PASSWORD,
        })
        try:
            assert entered.wait(timeout=5)
            with business.db() as connection:
                connection.execute({
                    "downgrade": "UPDATE users SET role='employee' WHERE id='admin'",
                    "mfa-generation": "UPDATE admin_mfa SET generation='replacement' WHERE user_id='admin'",
                }[change])
            before = _state_digest(business)
        finally:
            release.set()
        response = pending.result(timeout=5)
    assert response.status_code == (409 if change == "downgrade" else 401)
    assert _state_digest(business) == before


def test_password_storage_failure_rolls_back_credentials_sessions_and_activity(business):
    first, second = business.login("alex"), business.login("alex")
    with business.db() as connection:
        connection.execute(
            "CREATE TRIGGER reject_password_audit BEFORE INSERT ON activity "
            "WHEN NEW.action='Changed password' BEGIN SELECT RAISE(ABORT,'synthetic fault'); END"
        )
    before = _state_digest(business)
    response = first.request("POST", "/api/password", json={
        "current_password": business.credentials["alex"], "new_password": NEW_PASSWORD,
    })
    assert response.status_code == 503
    assert "set-cookie" not in response.headers
    assert _state_digest(business) == before
    assert first.request("GET", "/api/messages").status_code == 200
    assert second.request("GET", "/api/messages").status_code == 200
    with business.db() as connection:
        stored = connection.execute("SELECT password_hash FROM users WHERE id='alex'").fetchone()[0]
    assert verify_password(stored, business.credentials["alex"])
    assert not verify_password(stored, NEW_PASSWORD)


def test_simultaneous_password_changes_commit_exactly_one_and_revoke_both_sessions(business, monkeypatch):
    actors = business.login("alex"), business.login("alex")
    cookies = [actor.client.cookies.get(COOKIE_NAME) for actor in actors]
    replacements = [NEW_PASSWORD, "Different disposable replacement 937!"]
    hashed = Barrier(2)
    original = auth_routes.hash_password

    def held_hash(password):
        result = original(password)
        hashed.wait(timeout=10)
        return result

    monkeypatch.setattr(auth_routes, "hash_password", held_hash)

    def change(index):
        return actors[index].request("POST", "/api/password", json={
            "current_password": business.credentials["alex"], "new_password": replacements[index],
        }).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(change, (0, 1)))
    assert sorted(statuses) == [200, 401]
    winner = statuses.index(200)
    with business.db() as connection:
        stored = connection.execute("SELECT password_hash FROM users WHERE id='alex'").fetchone()[0]
        assert connection.execute("SELECT COUNT(*) FROM sessions WHERE user_id='alex'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM activity WHERE action='Changed password'").fetchone()[0] == 1
    assert verify_password(stored, replacements[winner])
    assert not verify_password(stored, replacements[1 - winner])
    for cookie in cookies:
        replay = business.client().get("/api/messages", headers={"Cookie": f"{COOKIE_NAME}={cookie}"})
        assert replay.status_code == 401
