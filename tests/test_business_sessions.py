"""Fresh authentication and own-session management with disposable accounts."""

from tools.business_login_client import login_post

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from tests.test_business_dashboard import (
    business as business, business_admin as business_admin, business_seed as business_seed,
    post_body,
)
from business import session_routes, session_state
from business.security import COOKIE_NAME, token_hash


def inventory(actor):
    response = actor.request("GET", "/api/security/sessions")
    assert response.status_code == 200
    return response.json()


def expire_verification(business, actor):
    hashed = token_hash(actor.client.cookies[COOKIE_NAME])
    with business.db() as connection:
        connection.execute("UPDATE session_security SET verified_at=0 WHERE token_hash=?", (hashed,))


def verify(business, actor, username="admin", **patch):
    login = business.login_payload(username)
    payload = {"current_password": login["password"]}
    if "otp" in login:
        payload["otp"] = login["otp"]
    payload.update(patch)
    response = actor.request("POST", "/api/security/reauthenticate", json=payload)
    if response.status_code == 200:
        actor.csrf = response.json()["csrf"]
    return response


def test_inventory_is_own_active_sessions_without_bearer_material(business, business_admin):
    other = business.login("admin")
    employee = business.login("alex")
    data = inventory(business_admin)
    assert len(data["sessions"]) == 2
    assert sum(row["current"] for row in data["sessions"]) == 1
    assert {row["method"] for row in data["sessions"]} == {"totp"}
    assert data["verification_expires_at"] > session_state.current_time()
    serialized = str(data)
    for actor in (business_admin, other, employee):
        token = actor.client.cookies[COOKIE_NAME]
        assert token not in serialized
        assert token_hash(token) not in serialized
        assert actor.csrf not in serialized
    assert len(inventory(employee)["sessions"]) == 1


def test_stale_admin_cannot_mutate_and_reads_do_not_renew_verification(business, business_admin):
    expire_verification(business, business_admin)
    before = inventory(business_admin)
    for path in ("/api/session", "/api/admin/overview", "/api/security/sessions"):
        assert business_admin.request("GET", path).status_code == 200
    denied = business_admin.request("POST", "/api/admin/posts", json=post_body())
    assert denied.status_code == 403
    assert denied.headers["x-reauthentication-required"] == "true"
    assert before["verification_expires_at"] == inventory(business_admin)["verification_expires_at"] == 0
    assert verify(business, business_admin).status_code == 200
    assert business_admin.request("POST", "/api/admin/posts", json=post_body()).status_code == 201


def test_stale_admin_can_pause_but_must_reverify_to_resume(business, business_admin):
    expire_verification(business, business_admin)
    paused = business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0})
    assert paused.status_code == 200
    denied = business_admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": 1})
    assert denied.status_code == 403
    assert denied.headers["x-reauthentication-required"] == "true"
    assert verify(business, business_admin).status_code == 200
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": 1}).status_code == 200


def test_stale_admin_can_contain_but_cannot_restore_authority(business, business_admin):
    response = business_admin.request("POST", "/api/admin/posts", json=post_body())
    assert response.status_code == 201
    post = response.json()["post"]
    expire_verification(business, business_admin)
    assert business_admin.request("POST", f"/api/admin/posts/{post['id']}/unpublish", json={"revision": post["revision"]}).status_code == 200
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": False, "revision": business.user_revision("alex")}).status_code == 200
    denied = business_admin.request("PUT", "/api/admin/users/alex", json={"active": True, "revision": business.user_revision("alex")})
    assert denied.status_code == 403
    assert denied.headers["x-reauthentication-required"] == "true"


def test_reverification_requires_admin_password_and_new_mfa_code(business, business_admin):
    expire_verification(business, business_admin)
    assert verify(business, business_admin, current_password="incorrect password").status_code == 403
    assert verify(business, business_admin, otp=None).status_code == 403
    payload = business.login_payload("admin")
    body = {"current_password": payload["password"], "otp": payload["otp"]}
    response = business_admin.request("POST", "/api/security/reauthenticate", json=body)
    assert response.status_code == 200
    business_admin.csrf = response.json()["csrf"]
    assert business_admin.request("POST", "/api/security/reauthenticate", json=body).status_code == 403
    assert inventory(business_admin)["verification_expires_at"] > 0


def test_reverification_budget_is_shared_and_survives_session_activity(business, business_admin):
    other = business.login("admin")
    for index in range(8):
        actor = business_admin if index % 2 else other
        assert verify(business, actor, current_password="incorrect password").status_code == 403
    assert verify(business, business_admin).status_code == 429
    assert verify(business, other).status_code == 429
    employee = business.login("alex")
    assert verify(business, employee, "alex").status_code == 200


def test_foreign_session_id_and_wrong_csrf_cannot_revoke(business, business_admin):
    employee = business.login("alex")
    foreign_id = inventory(employee)["sessions"][0]["id"]
    assert business_admin.request("POST", f"/api/security/sessions/{foreign_id}/revoke", json={}).status_code == 404
    own = inventory(business_admin)["sessions"][0]["id"]
    assert business_admin.request("POST", f"/api/security/sessions/{own}/revoke", json={}, headers={"X-CSRF-Token": employee.csrf}).status_code == 403
    assert business_admin.request("GET", "/api/admin/overview").status_code == 200
    assert employee.request("GET", "/api/messages").status_code == 200


def test_revoke_other_requires_fresh_auth_and_immediately_denies_old_cookie(business, business_admin):
    other = business.login("admin")
    target = next(row for row in inventory(business_admin)["sessions"] if not row["current"])
    path = f"/api/security/sessions/{target['id']}/revoke"
    expire_verification(business, business_admin)
    assert business_admin.request("POST", path, json={}).status_code == 403
    assert other.request("GET", "/api/admin/overview").status_code == 200
    assert verify(business, business_admin).status_code == 200
    response = business_admin.request("POST", path, json={})
    assert response.status_code == 200
    assert response.json()["current_session_revoked"] is False
    assert "set-cookie" not in response.headers
    assert other.request("GET", "/api/admin/overview").status_code == 401
    assert business_admin.request("GET", "/api/admin/overview").status_code == 200


def test_current_session_revocation_needs_no_fresh_password_and_preserves_other_login(business, business_admin):
    newer = business.login("admin")
    identifier = next(row["id"] for row in inventory(business_admin)["sessions"] if row["current"])
    expire_verification(business, business_admin)
    response = business_admin.request("POST", f"/api/security/sessions/{identifier}/revoke", json={})
    assert response.status_code == 200 and response.json()["current_session_revoked"]
    assert "set-cookie" not in response.headers
    assert business_admin.request("GET", "/api/admin/overview").status_code == 401
    assert newer.request("GET", "/api/admin/overview").status_code == 200


@pytest.mark.parametrize("offset,allowed", [(299, True), (300, False), (-1, False)])
def test_verification_window_boundary_and_future_timestamp_fail_closed(business, business_admin, monkeypatch, offset, allowed):
    now = session_state.current_time()
    monkeypatch.setattr(session_state, "current_time", lambda: now)
    with business.db() as connection:
        connection.execute("UPDATE session_security SET verified_at=?", (now - offset,))
    response = business_admin.request("POST", "/api/admin/posts", json=post_body())
    assert response.status_code == (201 if allowed else 403)


def test_revoked_session_during_password_work_cannot_regain_verification(business, business_admin, monkeypatch):
    started, release = Event(), Event()
    original = session_routes.verify_password

    def delayed(*args):
        started.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(session_routes, "verify_password", delayed)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(verify, business, business_admin)
        try:
            assert started.wait(5)
            hashed = token_hash(business_admin.client.cookies[COOKIE_NAME])
            with business.db() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (hashed,))
        finally:
            release.set()
        assert pending.result(timeout=5).status_code == 401
    with business.db() as connection:
        assert connection.execute("SELECT 1 FROM session_security WHERE token_hash=?", (hashed,)).fetchone() is None


def test_csrf_and_payload_fields_cannot_manufacture_fresh_auth(business, business_admin):
    expire_verification(business, business_admin)
    payload = {"current_password": business.credentials["admin"], "verified_at": session_state.current_time()}
    assert business_admin.request("POST", "/api/security/reauthenticate", json=payload).status_code == 422
    assert business_admin.request("POST", "/api/security/reauthenticate", json={"current_password": "incorrect"}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert inventory(business_admin)["verification_expires_at"] == 0
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM login_limits").fetchone()[0] == 0


@pytest.mark.parametrize("username", ["admin", "alex"])
def test_reverification_replaces_bearer_and_csrf_without_extending_session(business, username):
    owner = business.login(username)
    copied = business.client()
    old_token, old_csrf = owner.client.cookies[COOKIE_NAME], owner.csrf
    copied.cookies.set(COOKIE_NAME, old_token)
    before = inventory(owner)["sessions"][0]
    with business.app.state.database.readonly_snapshot() as connection:
        absolute_expiry = connection.execute("SELECT expires_at FROM sessions WHERE token_hash=?", (token_hash(old_token),)).fetchone()[0]
    expire_verification(business, owner)
    response = verify(business, owner, username)
    assert response.status_code == 200
    new_token = owner.client.cookies[COOKIE_NAME]
    assert bool(new_token != old_token), "Reverification must replace the bearer"
    assert response.json()["csrf"] != old_csrf
    owner.csrf = response.json()["csrf"]
    assert copied.get("/api/messages").status_code == 401
    assert copied.post("/api/security/reauthenticate", json={
        "current_password": business.credentials[username],
    }, headers={"Origin": "http://127.0.0.1:8091", "X-CSRF-Token": old_csrf}).status_code == 401
    assert owner.request("GET", "/api/messages").status_code == 200
    after = inventory(owner)["sessions"][0]
    assert after["id"] == before["id"]
    assert after["created_at"] == before["created_at"]
    with business.db() as connection:
        session = connection.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash(new_token),)).fetchone()
        assert session["expires_at"] == absolute_expiry
        assert connection.execute("SELECT 1 FROM sessions WHERE token_hash=?", (token_hash(old_token),)).fetchone() is None
    assert owner.request("POST", "/api/messages", json={"body": "After verification"},
                         headers={"X-CSRF-Token": old_csrf}).status_code == 403
    assert owner.request("POST", "/api/messages", json={"body": "After verification"}).status_code == 201


def test_login_with_shared_flow_revokes_delayed_rotation_descendant(business):
    from business.browser_flow import COOKIE_NAME as FLOW_COOKIE_NAME
    owner = business.login("alex")
    old = owner.client.cookies[COOKIE_NAME]
    # The browser has not received the first rotation response when another
    # account signs in. This also covers a later descendant of that rotation.
    for _ in range(2):
        response = verify(business, owner, "alex")
        assert response.status_code == 200
        owner.csrf = response.json()["csrf"]
    delayed_token = owner.client.cookies[COOKIE_NAME]
    newer = business.client()
    signed = login_post(newer, "/api/login", json=business.login_payload("blair"), headers={
        "Origin": "http://127.0.0.1:8091",
        "Cookie": f"{COOKIE_NAME}={old}; {FLOW_COOKIE_NAME}={owner.client.cookies[FLOW_COOKIE_NAME]}",
    })
    assert signed.status_code == 200
    assert newer.get("/api/messages").status_code == 200
    # Applying a late Set-Cookie can lose the new browser session, but must
    # never restore the previous account's authority. Sign in again if needed.
    assert newer.get("/api/messages", headers={"Cookie": f"{COOKIE_NAME}={delayed_token}"}).status_code == 401
    assert owner.request("GET", "/api/messages").status_code == 401


def test_reverification_response_loss_never_accepts_old_bearer(business):
    owner = business.login("alex")
    old_token, old_csrf = owner.client.cookies[COOKIE_NAME], owner.csrf
    response = verify(business, owner, "alex")
    assert response.status_code == 200
    # Retry the request as a caller that never received the replacement cookie.
    retry = owner.client.post("/api/security/reauthenticate", json={
        "current_password": business.credentials["alex"],
    }, headers={"Origin": "http://127.0.0.1:8091", "Cookie": f"{COOKIE_NAME}={old_token}",
                "X-CSRF-Token": old_csrf})
    assert retry.status_code == 401 and "set-cookie" not in retry.headers


def test_rotation_audit_failure_rolls_back_token_bindings_and_freshness(business, business_admin, monkeypatch):
    old_token = business_admin.client.cookies[COOKIE_NAME]
    expire_verification(business, business_admin)

    def fail_event(*args, **kwargs):
        import sqlite3
        raise sqlite3.OperationalError("Disposable event failure")

    monkeypatch.setattr(session_routes, "record_event", fail_event)
    response = verify(business, business_admin)
    assert response.status_code == 503 and "set-cookie" not in response.headers
    assert bool(business_admin.client.cookies[COOKIE_NAME] == old_token)
    assert inventory(business_admin)["verification_expires_at"] == 0
    assert business_admin.request("GET", "/api/messages").status_code == 200
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM session_predecessors").fetchone()[0] == 0
        assert connection.execute("SELECT token_hash FROM session_mfa").fetchone()[0] == token_hash(old_token)


def test_rotation_lineage_capacity_refuses_without_forgetting_live_predecessors(business, monkeypatch):
    owner = business.login("alex")
    first = owner.client.cookies[COOKIE_NAME]
    monkeypatch.setattr(session_state, "MAX_SESSION_PREDECESSORS", 1)
    response = verify(business, owner, "alex")
    assert response.status_code == 200
    owner.csrf = response.json()["csrf"]
    current = owner.client.cookies[COOKIE_NAME]
    response = verify(business, owner, "alex")
    assert response.status_code == 409 and "set-cookie" not in response.headers
    assert bool(owner.client.cookies[COOKIE_NAME] == current)
    assert owner.request("GET", "/api/messages").status_code == 200
    with business.db() as connection:
        assert connection.execute("SELECT predecessor_hash FROM session_predecessors").fetchone()[0] == token_hash(first)
