"""Fresh authentication and own-session management with disposable accounts."""

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
    return actor.request("POST", "/api/security/reauthenticate", json=payload)


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
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": False, "revision": 0}).status_code == 200
    denied = business_admin.request("PUT", "/api/admin/users/alex", json={"active": True, "revision": 1})
    assert denied.status_code == 403
    assert denied.headers["x-reauthentication-required"] == "true"


def test_reverification_requires_admin_password_and_new_mfa_code(business, business_admin):
    expire_verification(business, business_admin)
    assert verify(business, business_admin, current_password="incorrect password").status_code == 403
    assert verify(business, business_admin, otp=None).status_code == 403
    payload = business.login_payload("admin")
    body = {"current_password": payload["password"], "otp": payload["otp"]}
    assert business_admin.request("POST", "/api/security/reauthenticate", json=body).status_code == 200
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
