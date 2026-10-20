"""Durable auth attempt limits, without collateral shared-proxy lockouts."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
from threading import Barrier, Event

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    Actor, NEW_PASSWORD, ORIGIN, business as business, business_seed as business_seed,
)
from business import auth_routes  # noqa: E402
from business.app import create_app  # noqa: E402
from business.security import COOKIE_NAME  # noqa: E402


def _password(actor, current="Incorrect disposable password", **kwargs):
    return actor.request("POST", "/api/password", json={
        "current_password": current, "new_password": NEW_PASSWORD,
    }, **kwargs)


def _login(business, username, password="Incorrect disposable password", **headers):
    return business.client().post("/api/login", json={
        "username": username, "password": password,
    }, headers={"Origin": ORIGIN, **headers})


def _protected_auth_rows(business):
    with business.db() as connection:
        return {
            "users": [tuple(row) for row in connection.execute("SELECT * FROM users ORDER BY id")],
            "sessions": [tuple(row) for row in connection.execute(
                "SELECT token_hash,user_id,created_at,expires_at FROM sessions ORDER BY token_hash"
            )],
            "mfa": [tuple(row) for row in connection.execute("SELECT * FROM admin_mfa ORDER BY user_id")],
            "activity": [tuple(row) for row in connection.execute("SELECT * FROM activity ORDER BY id")],
        }


def _limit_rows(business):
    with business.db() as connection:
        return [tuple(row) for row in connection.execute(
            "SELECT key_hash,window_start,attempts FROM login_limits ORDER BY key_hash"
        )]


def test_password_guess_budget_survives_other_sessions_login_and_restart(business):
    first, second = business.login("alex"), business.login("alex")
    before = _protected_auth_rows(business)
    for index in range(auth_routes.ATTEMPT_LIMIT):
        assert _password((first, second)[index % 2]).status_code == 403
    assert _protected_auth_rows(business) == before
    rows = _limit_rows(business)
    assert len(rows) == 1 and rows[0][2] == auth_routes.ATTEMPT_LIMIT

    # A fresh process and a fresh session do not provide another guessing budget.
    application = create_app(business.directory, public_origin=ORIGIN)
    client = business.client(app=application)
    response = client.post("/api/login", json={
        "username": "alex", "password": business.credentials["alex"],
    }, headers={"Origin": ORIGIN})
    assert response.status_code == 200
    third = Actor(client, response.json()["user"], response.json()["csrf"])
    before = _protected_auth_rows(business)
    for actor in (first, second, third):
        response = _password(actor, business.credentials["alex"])
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "300"
        assert "set-cookie" not in response.headers
        assert actor.request("GET", "/api/messages").status_code == 200
    assert _protected_auth_rows(business) == before
    assert _limit_rows(business) == rows


def test_password_limit_is_per_account_and_expires_at_window_boundary(business, monkeypatch):
    alex, blair = business.login("alex"), business.login("blair")
    started = auth_routes.current_time()
    monkeypatch.setattr(auth_routes, "current_time", lambda: started)
    for _ in range(auth_routes.ATTEMPT_LIMIT):
        assert _password(alex).status_code == 403
    assert _password(blair, business.credentials["blair"]).status_code == 200

    monkeypatch.setattr(auth_routes, "current_time", lambda: started + 299.999)
    assert _password(alex, business.credentials["alex"]).status_code == 429
    monkeypatch.setattr(auth_routes, "current_time", lambda: started + 300)
    assert _password(alex, business.credentials["alex"]).status_code == 200
    assert _limit_rows(business) == []


def test_correct_password_change_after_failures_revokes_all_sessions(business):
    first, second = business.login("alex"), business.login("alex")
    for _ in range(auth_routes.ATTEMPT_LIMIT - 1):
        assert _password(first).status_code == 403
    old_cookie = second.client.cookies.get(COOKIE_NAME)
    response = _password(first, business.credentials["alex"])
    assert response.status_code == 200
    assert "Max-Age=0" in response.headers["set-cookie"]
    # Successful changes release their own reservation, not prior failures.
    assert _limit_rows(business)[0][2] == auth_routes.ATTEMPT_LIMIT - 1
    assert first.request("GET", "/api/messages").status_code == 401
    assert second.request("GET", "/api/messages").status_code == 401
    assert business.client().get(
        "/api/messages", headers={"Cookie": f"{COOKIE_NAME}={old_cookie}"},
    ).status_code == 401
    assert _login(business, "alex", business.credentials["alex"]).status_code == 401
    assert business.login("alex", NEW_PASSWORD).request("GET", "/api/messages").status_code == 200


def test_password_failure_increment_is_atomic_across_simultaneous_sessions(business):
    actors = business.login("alex"), business.login("alex")
    for _ in range(auth_routes.ATTEMPT_LIMIT - 1):
        assert _password(actors[0]).status_code == 403
    barrier = Barrier(2)

    def attempt(actor):
        barrier.wait(timeout=5)
        return _password(actor).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, actors)) == [403, 429]
    assert _limit_rows(business)[0][2] == auth_routes.ATTEMPT_LIMIT


def test_invalid_csrf_does_not_spend_the_password_budget(business):
    actor = business.login("alex")
    for _ in range(auth_routes.ATTEMPT_LIMIT + 1):
        assert _password(actor, headers={"X-CSRF-Token": "invalid"}).status_code == 403
    assert _limit_rows(business) == []
    assert _password(actor, business.credentials["alex"]).status_code == 200


def test_unknown_users_and_legacy_peer_history_do_not_lock_out_real_accounts(business):
    # Preserve an old-version saturated transport-peer bucket across an upgrade.
    key = hmac.new(
        business.app.state.database.identity_key, b"address:testclient", hashlib.sha256,
    ).hexdigest()
    with business.db() as connection:
        connection.execute("INSERT INTO login_limits VALUES(?,?,30)", (key, auth_routes.current_time()))
    before = _limit_rows(business)
    for index in range(35):
        assert _login(business, f"missing-account-{index}").status_code == 401
    assert _limit_rows(business) == before
    assert business.login("alex").profile["role"] == "employee"
    assert business.login("admin").profile["role"] == "admin"


def test_account_password_limit_survives_case_headers_and_restart(business):
    for index in range(auth_routes.ATTEMPT_LIMIT):
        assert _login(
            business, "ALEX" if index % 2 else "alex",
            **{"X-Forwarded-For": f"192.0.2.{index}", "CF-Connecting-IP": f"198.51.100.{index}"},
        ).status_code == 401
    application = create_app(business.directory, public_origin=ORIGIN)
    response = business.client(app=application).post("/api/login", json={
        "username": "alex", "password": business.credentials["alex"],
    }, headers={"Origin": ORIGIN, "X-Forwarded-For": "203.0.113.99"})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "300"
    assert business.login("blair").profile["role"] == "employee"
    assert business.login("admin").profile["role"] == "admin"


def test_login_window_expiry_restores_signin_and_clears_only_own_bucket(business):
    for _ in range(auth_routes.ATTEMPT_LIMIT):
        assert _login(business, "alex").status_code == 401
    with business.db() as connection:
        connection.execute(
            "UPDATE login_limits SET window_start=?",
            (auth_routes.current_time() - auth_routes.ATTEMPT_WINDOW_SECONDS,),
        )
        connection.execute(
            "INSERT INTO login_limits VALUES(?,?,1)", ("other-route-reservation", 0),
        )
    assert business.login("alex").profile["role"] == "employee"
    assert _limit_rows(business) == [("other-route-reservation", 0, 1)]


def test_successful_login_preserves_failed_and_inflight_reservations(business, monkeypatch):
    assert _login(business, "alex").status_code == 401
    entered, release = Event(), Event()
    original = auth_routes.verify_password

    def held_verification(stored, password):
        result = original(stored, password)
        if result:
            entered.set()
            assert release.wait(timeout=10)
        return result

    monkeypatch.setattr(auth_routes, "verify_password", held_verification)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(_login, business, "alex", business.credentials["alex"])
        try:
            assert entered.wait(timeout=5)
            assert _login(business, "alex").status_code == 401
            assert _limit_rows(business)[0][2] == 3
        finally:
            release.set()
        assert pending.result(timeout=5).status_code == 200
    assert _limit_rows(business)[0][2] == 2


@pytest.mark.parametrize("change", ["disabled", "password", "role", "revision", "mfa"])
def test_login_rechecks_credentials_and_mfa_after_password_work(business, monkeypatch, change):
    username = "admin" if change == "mfa" else "alex"
    payload = business.login_payload(username)
    entered, release = Event(), Event()
    original = auth_routes.verify_password

    def held_verification(stored, password):
        result = original(stored, password)
        entered.set()
        assert release.wait(timeout=10)
        return result

    monkeypatch.setattr(auth_routes, "verify_password", held_verification)
    client = business.client()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.post, "/api/login", json=payload, headers={"Origin": ORIGIN})
        try:
            assert entered.wait(timeout=5)
            # Health uses the real storage transaction, which remains available
            # while the deliberately stalled password KDF has no SQLite lock.
            assert business.client().get("/healthz").status_code == 200
            with business.db() as connection:
                sql = {
                    "disabled": "UPDATE users SET active=0 WHERE id='alex'",
                    "password": "UPDATE users SET password_hash='replaced' WHERE id='alex'",
                    "role": "UPDATE users SET role='admin' WHERE id='alex'",
                    "revision": "UPDATE users SET revision=revision+1 WHERE id='alex'",
                    "mfa": "UPDATE admin_mfa SET generation='replacement-enrollment' WHERE user_id='admin'",
                }[change]
                connection.execute(sql)
            before = _protected_auth_rows(business)
        finally:
            release.set()
        response = pending.result(timeout=5)
    assert response.status_code == 401
    assert "set-cookie" not in response.headers
    assert _protected_auth_rows(business) == before


@pytest.mark.parametrize("change", ["logout", "disabled", "password", "revision"])
def test_password_change_rechecks_session_and_identity_after_password_work(business, monkeypatch, change):
    actor = business.login("alex")
    entered, release = Event(), Event()
    original = auth_routes.verify_password

    def held_verification(stored, password):
        result = original(stored, password)
        entered.set()
        assert release.wait(timeout=10)
        return result

    monkeypatch.setattr(auth_routes, "verify_password", held_verification)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(_password, actor, business.credentials["alex"])
        try:
            assert entered.wait(timeout=5)
            assert business.client().get("/healthz").status_code == 200
            with business.db() as connection:
                sql = {
                    "logout": "DELETE FROM sessions WHERE user_id='alex'",
                    "disabled": "UPDATE users SET active=0 WHERE id='alex'",
                    "password": "UPDATE users SET password_hash='replaced' WHERE id='alex'",
                    "revision": "UPDATE users SET revision=revision+1 WHERE id='alex'",
                }[change]
                connection.execute(sql)
            before = _protected_auth_rows(business)
        finally:
            release.set()
        response = pending.result(timeout=5)
    assert response.status_code == (401 if change in {"logout", "disabled"} else 409)
    assert _protected_auth_rows(business) == before


def test_auth_work_saturation_rejects_without_blocking_health_or_private_reads(business, monkeypatch):
    actor = business.login("casey")
    arrived, release = Barrier(3), Event()
    original = auth_routes.verify_password

    def held_verification(stored, password):
        result = original(stored, password)
        arrived.wait(timeout=5)
        assert release.wait(timeout=10)
        return result

    monkeypatch.setattr(auth_routes, "verify_password", held_verification)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [
            pool.submit(_login, business, username, business.credentials[username])
            for username in ("alex", "blair")
        ]
        try:
            arrived.wait(timeout=5)
            assert business.client().get("/healthz").status_code == 200
            assert actor.request("GET", "/api/messages").status_code == 200
            response = _login(business, "missing")
            assert response.status_code == 429
            assert response.headers["Retry-After"] == "1"
            assert _password(actor, business.credentials["casey"]).status_code == 429
        finally:
            release.set()
        assert [future.result(timeout=5).status_code for future in pending] == [200, 200]
    assert actor.request("GET", "/api/messages").status_code == 200


def test_expired_inflight_login_cannot_issue_session_or_reduce_new_window(business, monkeypatch):
    entered, release = Event(), Event()
    clock = [auth_routes.current_time()]
    monkeypatch.setattr(auth_routes, "current_time", lambda: clock[0])
    original = auth_routes.verify_password

    def held_verification(stored, password):
        result = original(stored, password)
        if result:
            entered.set()
            assert release.wait(timeout=10)
        return result

    monkeypatch.setattr(auth_routes, "verify_password", held_verification)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(_login, business, "alex", business.credentials["alex"])
        try:
            assert entered.wait(timeout=5)
            clock[0] += auth_routes.ATTEMPT_WINDOW_SECONDS
            assert _login(business, "alex").status_code == 401
            newer = _limit_rows(business)
            assert len(newer) == 1 and newer[0][1:] == (clock[0], 1)
        finally:
            release.set()
        response = pending.result(timeout=5)
    assert response.status_code == 429
    assert "set-cookie" not in response.headers
    assert _limit_rows(business) == newer
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    monkeypatch.setattr(auth_routes, "verify_password", original)
    assert business.login("alex").profile["role"] == "employee"
    assert _limit_rows(business) == newer
