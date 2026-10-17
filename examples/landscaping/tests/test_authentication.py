"""Session lifecycle, credentials and replay resistance with disposable accounts."""

import hashlib
import json
import time

from argon2 import PasswordHasher
from fastapi.testclient import TestClient
import pytest

from .conftest import COOKIE, NEW_PASSWORD


def replay(trial, token):
    client = trial.client()
    client.cookies.set(COOKIE, token)
    return client


def test_password_hashes_and_session_storage_are_not_plaintext(trial):
    actor = trial.login("alex")
    token = actor.client.cookies.get(COOKIE)
    assert len(token) >= 40
    with trial.db() as connection:
        users = connection.execute("SELECT username,password_hash FROM users").fetchall()
        sessions = connection.execute("SELECT * FROM sessions").fetchall()
    for row in users:
        encoded = row["password_hash"]
        assert encoded.startswith("$argon2id$")
        assert PasswordHasher().verify(encoded, trial.credentials[row["username"]])
        params = dict(pair.split("=") for pair in encoded.split("$")[3].split(","))
        assert int(params["m"]) >= 19456 and int(params["t"]) >= 2
    dumped = json.dumps([dict(row) for row in sessions])
    assert token not in dumped and actor.csrf not in dumped
    assert hashlib.sha256(token.encode()).hexdigest() in dumped
    assert all(password not in dumped for password in trial.credentials.values())


def test_session_cookie_properties_and_login_rotation(trial):
    client = trial.client()
    fixed = "attacker-controlled-session-token-" * 2
    client.cookies.set(COOKIE, fixed, domain="testserver.local", path="/")
    response = client.post("/api/login", json={"username": "alex", "password": trial.credentials["alex"]}, headers={"Origin": "http://testserver"})
    assert response.status_code == 200
    header = response.headers["set-cookie"].lower()
    assert "httponly" in header and "samesite=strict" in header and "path=/" in header
    assert "domain=" not in header
    first = client.cookies.get(COOKIE)
    assert first != fixed
    assert replay(trial, fixed).get("/api/session").status_code == 401
    actor = trial.login("alex", client=client)
    second = client.cookies.get(COOKIE)
    assert second != first
    assert replay(trial, first).get("/api/session").status_code == 401
    assert actor.request("GET", "/api/session").status_code == 200


def test_https_configuration_marks_cookie_secure(trial):
    from landscape.app import create_app

    app = create_app(trial.db_path.parent, testing=True, secure_cookies=True, allowed_hosts=["testserver"])
    with TestClient(app, base_url="https://testserver") as client:
        response = client.post("/api/login", json={"username": "alex", "password": trial.credentials["alex"]}, headers={"Origin": "https://testserver"})
        assert response.status_code == 200
        assert "secure" in response.headers["set-cookie"].lower()
        assert client.get("/api/session").status_code == 200


@pytest.mark.parametrize("token", [
    "", "admin", "0" * 64,
    "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
    "../../../TRIAL_ACCOUNTS.md", "' OR 1=1 --",
])
def test_forged_tokens_cannot_authenticate(trial, token):
    client = replay(trial, token)
    assert client.get("/api/session").status_code == 401
    assert client.get("/api/admin/health").status_code == 401


def test_single_byte_token_tamper_is_rejected(trial):
    actor = trial.login("alex")
    token = actor.client.cookies.get(COOKIE)
    forged = ("a" if token[0] != "a" else "b") + token[1:]
    assert replay(trial, forged).get("/api/jobs").status_code == 401
    assert actor.request("GET", "/api/jobs").status_code == 200


def test_logout_revokes_cookie_and_csrf_replay(trial):
    actor = trial.login("alex")
    token = actor.client.cookies.get(COOKIE)
    assert actor.request("POST", "/api/logout", json={}).status_code == 200
    stolen = replay(trial, token)
    assert stolen.get("/api/session").status_code == 401
    assert stolen.post("/api/messages", json={"body": "Replay after logout"}, headers={"Origin": "http://testserver", "X-CSRF-Token": actor.csrf}).status_code == 401


@pytest.mark.parametrize("field", ["last_seen", "expires_at", "created_at"])
def test_idle_absolute_and_creation_age_expiry(trial, field):
    actor = trial.login("alex")
    with trial.db() as connection:
        if field == "last_seen":
            value = time.time() - 1801
        elif field == "created_at":
            value = time.time() - 28801
        else:
            value = time.time() - 1
        connection.execute(f"UPDATE sessions SET {field}=? WHERE user_id=?", (value, trial.ids["alex"]))
    assert actor.request("GET", "/api/session").status_code == 401
    assert actor.request("POST", "/api/messages", json={"body": "Expired"}).status_code == 401


def test_admin_password_reset_invalidates_every_old_session(trial, admin):
    first, second = trial.login("alex"), trial.login("alex")
    old_tokens = [actor.client.cookies.get(COOKIE) for actor in (first, second)]
    assert admin.request("POST", f"/api/admin/users/{trial.ids['alex']}/password", json={"password": NEW_PASSWORD}).status_code == 200
    for actor, token in zip((first, second), old_tokens):
        assert actor.request("GET", "/api/jobs").status_code == 401
        assert replay(trial, token).get("/api/session").status_code == 401
    client = trial.client()
    assert client.post("/api/login", json={"username": "alex", "password": trial.credentials["alex"]}).status_code == 401
    assert trial.login("alex", NEW_PASSWORD).request("GET", "/api/jobs").status_code == 200


def test_self_password_change_checks_current_and_revokes_all_sessions(trial):
    first, second = trial.login("alex"), trial.login("alex")
    wrong = first.request("POST", "/api/password", json={"current_password": "Incorrect test password", "new_password": NEW_PASSWORD})
    assert wrong.status_code in (400, 401, 403)
    assert second.request("GET", "/api/session").status_code == 200
    assert first.request("POST", "/api/password", json={"current_password": trial.credentials["alex"], "new_password": NEW_PASSWORD}).status_code == 200
    for actor in (first, second):
        assert actor.request("GET", "/api/session").status_code == 401
    assert trial.login("alex", NEW_PASSWORD).request("GET", "/api/jobs").status_code == 200


def test_disable_and_reenable_never_resurrects_old_sessions(trial, admin):
    first, second = trial.login("alex"), trial.login("alex")
    token = first.client.cookies.get(COOKIE)
    endpoint = f"/api/admin/users/{trial.ids['alex']}"
    assert admin.request("PATCH", endpoint, json={"active": False}).status_code == 200
    for actor in (first, second):
        assert actor.request("GET", "/api/jobs").status_code == 401
    unknown = trial.client().post("/api/login", json={"username": "unknown", "password": NEW_PASSWORD})
    disabled = trial.client().post("/api/login", json={"username": "alex", "password": trial.credentials["alex"]})
    wrong = trial.client().post("/api/login", json={"username": "blair", "password": NEW_PASSWORD})
    assert unknown.status_code == disabled.status_code == wrong.status_code == 401
    assert unknown.json() == disabled.json() == wrong.json()
    assert admin.request("PATCH", endpoint, json={"active": True}).status_code == 200
    assert replay(trial, token).get("/api/session").status_code == 401
    assert trial.login("alex").request("GET", "/api/jobs").status_code == 200


def test_account_rate_limit_survives_source_address_changes(trial):
    statuses = []
    for number in range(32):
        client = trial.client(client=(f"192.0.2.{number + 1}", 60000))
        response = client.post("/api/login", json={"username": "alex", "password": "Wrong synthetic password"})
        statuses.append(response.status_code)
        if response.status_code == 429:
            break
    assert 429 in statuses
    response = trial.client(client=("198.51.100.99", 60000)).post("/api/login", json={"username": "alex", "password": trial.credentials["alex"]})
    assert response.status_code == 429


def test_source_rate_limit_ignores_forged_forwarded_addresses(trial):
    client = trial.client()
    statuses = []
    for number in range(64):
        response = client.post(
            "/api/login", json={"username": f"unknown{number}", "password": "Wrong synthetic password"},
            headers={"X-Forwarded-For": f"192.0.2.{number + 1}"},
        )
        statuses.append(response.status_code)
        if response.status_code == 429:
            break
    assert 429 in statuses


def test_authenticated_password_guessing_is_rate_limited(trial):
    actor = trial.login("alex")
    statuses = []
    for number in range(12):
        response = actor.request("POST", "/api/password", json={
            "current_password": f"Wrong synthetic password {number}",
            "new_password": NEW_PASSWORD,
        }, headers={"X-Forwarded-For": f"192.0.2.{number + 1}"})
        statuses.append(response.status_code)
        if response.status_code == 429:
            break
    assert 429 in statuses
    assert actor.request("GET", "/api/session").status_code == 200
    assert trial.login("alex").request("GET", "/api/jobs").status_code == 200
    with trial.db() as connection:
        encoded = connection.execute("SELECT password_hash FROM users WHERE id=?", (trial.ids["alex"],)).fetchone()[0]
    assert PasswordHasher().verify(encoded, trial.credentials["alex"])


def test_credentials_session_and_csrf_do_not_leak_into_audit_or_health(trial, admin):
    actor = trial.login("alex")
    assert actor.request("POST", "/api/messages", json={"body": "Safe audit event"}).status_code in (200, 201)
    assert actor.request("GET", "/api/admin/health").status_code == 403
    health = admin.request("GET", "/api/admin/health")
    assert health.status_code == 200
    with trial.db() as connection:
        audit = [dict(row) for row in connection.execute("SELECT * FROM audit")]
        password_hashes = [row[0] for row in connection.execute("SELECT password_hash FROM users")]
    combined = health.text + json.dumps(audit)
    secrets = [*trial.credentials.values(), *password_hashes, actor.csrf, admin.csrf, actor.client.cookies.get(COOKIE), admin.client.cookies.get(COOKIE)]
    assert all(secret not in combined for secret in secrets)
