"""Exercise actual enrollment HTTP capabilities and both roles' auth boundary."""

from tools.business_login_client import login_post

from contextlib import ExitStack
from pathlib import Path
import secrets
import sys
import tempfile
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")
from fastapi.testclient import TestClient  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "business_dashboard"))
from business import enrollment, mfa  # noqa: E402
from business.app import create_app  # noqa: E402
from business.seed import provision  # noqa: E402
from business.security import COOKIE_NAME  # noqa: E402
from business.security_delivery import SecurityEventDispatcher  # noqa: E402

ORIGIN = "http://127.0.0.1:8091"
PASSWORD = "Privately chosen unique password 582!"


@pytest.fixture
def flow(monkeypatch):
    monkeypatch.setattr(SecurityEventDispatcher, "start", lambda _: None)
    monkeypatch.setattr(SecurityEventDispatcher, "stop", lambda _: None)
    with tempfile.TemporaryDirectory(prefix="radt-enrollment-http-") as temporary, ExitStack() as stack:
        directory = Path(temporary) / "private"
        grants = provision(directory)
        app = create_app(directory, public_origin=ORIGIN)
        result = SimpleNamespace(app=app, grants=grants, now=time.time(), directory=directory)
        result.client = lambda: stack.enter_context(TestClient(app, base_url=ORIGIN))
        monkeypatch.setattr(enrollment, "current_time", lambda: result.now)
        monkeypatch.setattr(mfa, "current_time", lambda: result.now)
        yield result


def begin(flow, username="admin", *, client=None, grant=None):
    client = client or flow.client()
    response = client.post("/api/enrollment/start", headers={"Origin": ORIGIN}, json={
        "username": username, "enrollment_secret": grant or flow.grants[username],
    })
    assert response.status_code == 200
    return client, response.json(), response


def finish(flow, client, setup, *, password=PASSWORD, csrf=None, otp=None):
    return client.post("/api/enrollment/complete", headers={
        "Origin": ORIGIN, "X-Enrollment-CSRF": setup["csrf"] if csrf is None else csrf,
    }, json={"new_password": password, "otp": otp or pyotp.TOTP(setup["secret"]).at(flow.now)})


def login(flow, client, setup, username="admin", *, password=PASSWORD, code=True):
    flow.now = (int(flow.now // 30) + 1) * 30
    body = {"username": username, "password": password}
    if code:
        body["otp"] = pyotp.TOTP(setup["secret"]).at(flow.now)
    return login_post(client, "/api/login", headers={"Origin": ORIGIN}, json=body)


@pytest.mark.parametrize("username", ["admin", "alex"])
def test_initial_capability_never_authenticates_and_chosen_password_requires_mfa(flow, username):
    client = flow.client()
    response = login_post(client, "/api/login", headers={"Origin": ORIGIN}, json={
        "username": username, "password": flow.grants[username],
    })
    assert response.status_code == 401
    client, setup, response = begin(flow, username, client=client)
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    assert "Domain=" not in cookie and COOKIE_NAME not in client.cookies
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/api/messages").status_code == 401
    assert client.get("/api/session").json()["user"] is None
    assert finish(flow, client, setup).status_code == 200
    assert COOKIE_NAME not in client.cookies
    assert client.get("/api/messages").status_code == 401
    assert finish(flow, client, setup).status_code == 403
    assert login(flow, client, setup, username, code=False).status_code == 401
    response = login(flow, client, setup, username)
    assert response.status_code == 200 and response.json()["user"]["mfa_required"] is True
    assert client.get("/api/messages").status_code == 200


def test_origin_and_purpose_specific_csrf_are_required_without_consuming_setup(flow):
    client = flow.client()
    payload = {"username": "admin", "enrollment_secret": flow.grants["admin"]}
    assert client.post("/api/enrollment/start", json=payload).status_code == 403
    assert client.post("/api/enrollment/start", headers={"Origin": "https://foreign.invalid"}, json=payload).status_code == 403
    client, setup, _ = begin(flow, client=client)
    payload = {"new_password": PASSWORD, "otp": pyotp.TOTP(setup["secret"]).at(flow.now)}
    assert client.post("/api/enrollment/complete", headers={"Origin": ORIGIN, "X-CSRF-Token": setup["csrf"]}, json=payload).status_code == 403
    assert finish(flow, client, setup, csrf="wrong").status_code == 403
    assert finish(flow, client, setup).status_code == 200


def test_grant_claim_is_single_use_and_expired_pending_cookie_cannot_complete(flow):
    client, setup, _ = begin(flow)
    replay = flow.client().post("/api/enrollment/start", headers={"Origin": ORIGIN}, json={
        "username": "admin", "enrollment_secret": flow.grants["admin"],
    })
    assert replay.status_code == 403
    flow.now = setup["expires_at"]
    assert finish(flow, client, setup).status_code == 403
    assert client.get("/api/messages").status_code == 401


def test_duplicate_enrollment_cookies_and_application_cookie_substitution_fail(flow):
    client, setup, _ = begin(flow)
    token = client.cookies["westbridge_enrollment"]
    response = client.post("/api/enrollment/complete", headers={
        "Origin": ORIGIN, "X-Enrollment-CSRF": setup["csrf"],
        "Cookie": f"westbridge_enrollment={token}; westbridge_enrollment={token}",
    }, json={"new_password": PASSWORD, "otp": pyotp.TOTP(setup["secret"]).at(flow.now)})
    assert response.status_code == 400
    outsider = flow.client()
    outsider.cookies.set(COOKIE_NAME, token)
    assert outsider.get("/api/messages").status_code == 401
    assert finish(flow, outsider, setup).status_code == 403
    assert finish(flow, client, setup).status_code == 200


def test_https_enrollment_uses_only_host_prefixed_cookie_and_redacts_invalid_input(flow, monkeypatch):
    origin = "https://dashboard.example.test"
    monkeypatch.setenv("BUSINESS_TURNSTILE_SITE_KEY", "synthetic-site-key")
    monkeypatch.setenv("BUSINESS_TURNSTILE_SECRET_KEY", "synthetic-secret-key")
    application = create_app(flow.directory, public_origin=origin)
    with TestClient(application, base_url=origin) as client:
        begun = client.post("/api/enrollment/start", headers={"Origin": origin}, json={
            "username": "admin", "enrollment_secret": flow.grants["admin"],
        })
        assert begun.status_code == 200
        cookie = begun.headers["set-cookie"]
        assert cookie.startswith("__Host-westbridge_enrollment=")
        assert all(value in cookie for value in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"))
        assert "Domain=" not in cookie and "westbridge_enrollment" not in client.cookies
        setup = begun.json()
        body = {"new_password": PASSWORD, "otp": pyotp.TOTP(setup["secret"]).at(flow.now)}
        headers = {"Origin": origin, "X-Enrollment-CSRF": setup["csrf"]}
        token = client.cookies["__Host-westbridge_enrollment"]
        substituted = {**headers, "Cookie": f"westbridge_enrollment={token}"}
        assert client.post("/api/enrollment/complete", headers=substituted, json=body).status_code == 403
        invalid = client.post("/api/enrollment/complete", headers=headers, json={**body, "otp": "private-code-canary"})
        assert invalid.status_code == 422 and "private-code-canary" not in invalid.text and PASSWORD not in invalid.text
        assert client.post("/api/enrollment/complete", headers=headers, json=body).status_code == 200
        assert "set-cookie" not in client.post("/api/enrollment/complete", headers=headers, json=body).headers


def test_enrollment_code_cannot_become_password_and_setup_code_is_consumed(flow):
    client, setup, _ = begin(flow)
    assert finish(flow, client, setup, password=flow.grants["admin"]).status_code == 422
    otp = pyotp.TOTP(setup["secret"]).at(flow.now)
    assert finish(flow, client, setup, otp=otp).status_code == 200
    assert login_post(client, "/api/login", headers={"Origin": ORIGIN}, json={
        "username": "admin", "password": PASSWORD, "otp": otp,
    }).status_code == 401
    assert login(flow, client, setup).status_code == 200


def test_recovery_revokes_existing_authority_and_requires_external_case_reference(flow):
    client, setup, _ = begin(flow)
    assert finish(flow, client, setup).status_code == 200
    assert login(flow, client, setup).status_code == 200
    database = flow.app.state.database
    with pytest.raises(ValueError, match="case reference"), database.transaction() as connection:
        enrollment.issue_grant(connection, "admin", purpose="recovery")
    assert client.get("/api/messages").status_code == 200
    with database.transaction() as connection:
        grant = enrollment.issue_grant(connection, "admin", purpose="recovery", case_reference="case-http-001")
        assert connection.execute("SELECT 1 FROM account_mfa WHERE user_id='admin'").fetchone() is None
        assert connection.execute("SELECT 1 FROM sessions WHERE user_id='admin'").fetchone() is None
    assert client.get("/api/messages").status_code == 401
    replacement, pending, _ = begin(flow, grant=grant)
    assert finish(flow, replacement, pending, password=PASSWORD).status_code == 422
    password = secrets.token_urlsafe(32)
    assert finish(flow, replacement, pending, password=password).status_code == 200
    assert login(flow, replacement, pending, password=password).status_code == 200
    assert client.get("/api/messages").status_code == 401
    with database.transaction() as connection:
        assert connection.execute("SELECT case_reference FROM enrollment_decisions WHERE purpose='recovery'").fetchone()[0] == "case-http-001"
        assert connection.execute("SELECT retired_password_hash FROM account_security WHERE user_id='admin'").fetchone()[0] is None


def test_recovery_grant_cannot_reactivate_disabled_account(flow):
    database = flow.app.state.database
    with database.transaction() as connection:
        connection.execute("UPDATE users SET active=0,revision=revision+1 WHERE id='admin'")
        grant = enrollment.issue_grant(connection, "admin", purpose="recovery", case_reference="case-disabled")
    response = flow.client().post("/api/enrollment/start", headers={"Origin": ORIGIN}, json={
        "username": "admin", "enrollment_secret": grant,
    })
    assert response.status_code == 403


def test_password_reverification_for_employee_requires_current_mfa_and_rotates_bearer(flow):
    client, setup, _ = begin(flow, "alex")
    assert finish(flow, client, setup).status_code == 200
    signed = login(flow, client, setup, "alex").json()
    previous = client.cookies[COOKIE_NAME]
    headers = {"Origin": ORIGIN, "X-CSRF-Token": signed["csrf"]}
    assert client.post("/api/security/reauthenticate", headers=headers, json={"current_password": PASSWORD}).status_code == 403
    flow.now += 30
    response = client.post("/api/security/reauthenticate", headers=headers, json={
        "current_password": PASSWORD, "otp": pyotp.TOTP(setup["secret"]).at(flow.now),
    })
    assert response.status_code == 200
    assert client.cookies[COOKIE_NAME] != previous and response.json()["csrf"] != signed["csrf"]
    stale = flow.client()
    stale.cookies.set(COOKIE_NAME, previous)
    assert stale.get("/api/messages").status_code == 401


@pytest.mark.parametrize("username", ["admin", "alex"])
@pytest.mark.parametrize("factor", ["missing", "unconfirmed"])
def test_final_passkey_cannot_be_removed_without_another_confirmed_factor(flow, username, factor):
    from tests.test_business_dashboard import Actor
    from tests.test_business_passkeys import enroll, finish_login, login_options

    client, setup, _ = begin(flow, username)
    assert finish(flow, client, setup).status_code == 200
    signed = login(flow, client, setup, username).json()
    key, public = enroll(Actor(client, signed["user"], signed["csrf"]))
    passkey_client = flow.client()
    ceremony = login_options(passkey_client)
    signed = finish_login(passkey_client, ceremony, key.assertion(ceremony["options"])).json()
    with flow.app.state.database.transaction() as connection:
        if factor == "missing":
            connection.execute("DELETE FROM account_mfa WHERE user_id=?", (username,))
        else:
            connection.execute("UPDATE account_mfa SET last_counter=-1 WHERE user_id=?", (username,))
    response = passkey_client.post(f"/api/security/passkeys/{public['id']}/remove", json={}, headers={
        "Origin": ORIGIN, "X-CSRF-Token": signed["csrf"],
    })
    assert response.status_code == 409
    assert passkey_client.get("/api/messages").status_code == 200
    assert len(passkey_client.get("/api/security/passkeys").json()["passkeys"]) == 1
