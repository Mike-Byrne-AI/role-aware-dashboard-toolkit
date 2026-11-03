"""Login replacement uses the browser flow; a retired bearer is not a locator."""

from tools.business_login_client import login_post

import hashlib
import sqlite3
from urllib.parse import urlsplit

import pytest

from tests.test_business_dashboard import (
    ORIGIN, business as business, business_seed as business_seed, pyotp,
)
from tests.test_business_passkeys import enroll, finish_login, login_options
from tests.test_business_sessions import verify
from business import auth_routes, mfa, passkeys
from business.security import COOKIE_NAME
from business.browser_flow import COOKIE_NAME as FLOW_COOKIE_NAME


def _rotated_owner(business):
    owner = business.login("alex")
    predecessor = owner.client.cookies[COOKIE_NAME]
    for _ in range(2):
        assert verify(business, owner, "alex").status_code == 200
    return owner, predecessor


def _authority_fingerprint(business):
    # Exclude charged attempt budgets, consumed challenges and bounded denial
    # observations. Failed attempts must preserve credentials and session state.
    tables = ("users", "account_mfa", "session_mfa", "sessions", "session_security",
              "session_passkey", "passkey_credentials", "session_predecessors", "activity",
              "browser_login_flows", "session_browser_flow")
    with business.db() as connection:
        rows = {table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")]
                for table in tables}
        rows["successful_events"] = [tuple(row) for row in connection.execute(
            "SELECT * FROM security_events WHERE outcome='succeeded' ORDER BY sequence"
        )]
        rows["successful_obligations"] = [tuple(row) for row in connection.execute(
            "SELECT o.* FROM security_delivery_obligations o JOIN security_events e ON e.id=o.event_id "
            "WHERE e.outcome='succeeded' ORDER BY o.event_id"
        )]
    return hashlib.sha256(repr(rows).encode()).hexdigest()


def test_successful_passkey_login_with_flow_revokes_current_rotated_head(business):
    owner, predecessor = _rotated_owner(business)
    enrolled = business.login("blair")
    key, _ = enroll(enrolled)
    successor = business.client()
    successor.cookies.set(COOKIE_NAME, predecessor, domain=urlsplit(ORIGIN).hostname, path="/")
    successor.cookies.set(FLOW_COOKIE_NAME, owner.client.cookies[FLOW_COOKIE_NAME], domain=urlsplit(ORIGIN).hostname, path="/")
    ceremony = login_options(successor)
    response = finish_login(successor, ceremony, key.assertion(ceremony["options"]))
    assert response.status_code == 200
    assert response.json()["user"]["id"] == "blair"
    assert "set-cookie" in response.headers
    assert owner.request("GET", "/api/messages").status_code == 401
    assert successor.get("/api/messages").status_code == 200
    assert enrolled.request("GET", "/api/messages").status_code == 200
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions WHERE user_id='alex'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM session_predecessors").fetchone()[0] == 0


@pytest.mark.parametrize("failure", ["password", "missing_mfa", "invalid_mfa"])
def test_failed_password_or_mfa_login_preserves_rotated_descendant(business, failure):
    owner, predecessor = _rotated_owner(business)
    if failure == "password":
        payload = {"username": "blair", "password": "Incorrect disposable password"}
    else:
        payload = business.login_payload("admin")
        if failure == "missing_mfa":
            payload.pop("otp")
        else:
            with business.db() as connection:
                enrollment = connection.execute("SELECT * FROM account_mfa WHERE user_id='admin'").fetchone()
            secret = business.app.state.database.mfa_secrets.decrypt(
                enrollment["secret_ciphertext"], "admin", enrollment["generation"])
            counter = int(business.mfa_time // mfa.INTERVAL)
            totp = pyotp.TOTP(secret, interval=mfa.INTERVAL)
            accepted = {totp.at(value * mfa.INTERVAL) for value in (counter - 1, counter, counter + 1)}
            payload["otp"] = next(str(value).zfill(6) for value in range(4) if str(value).zfill(6) not in accepted)
    before = _authority_fingerprint(business)
    response = login_post(business.client(), "/api/login", json=payload, headers={
        "Origin": ORIGIN, "Cookie": f"{COOKIE_NAME}={predecessor}",
    })
    assert response.status_code == 401 and "set-cookie" not in response.headers
    assert _authority_fingerprint(business) == before
    assert owner.request("GET", "/api/messages").status_code == 200


def test_failed_passkey_login_preserves_rotated_descendant(business):
    owner, predecessor = _rotated_owner(business)
    key, _ = enroll(business.login("blair"))
    successor = business.client()
    successor.cookies.set(COOKIE_NAME, predecessor, domain=urlsplit(ORIGIN).hostname, path="/")
    ceremony = login_options(successor)
    before = _authority_fingerprint(business)
    response = finish_login(successor, ceremony, key.assertion(ceremony["options"], change="signature"))
    assert response.status_code == 403 and "set-cookie" not in response.headers
    assert _authority_fingerprint(business) == before
    assert owner.request("GET", "/api/messages").status_code == 200


@pytest.mark.parametrize("method", ["password", "passkey"])
def test_required_login_event_failure_rolls_back_descendant_revocation_and_new_login(business, monkeypatch, method):
    owner, predecessor = _rotated_owner(business)
    successor = business.client()
    successor.cookies.set(COOKIE_NAME, predecessor, domain=urlsplit(ORIGIN).hostname, path="/")
    successor.cookies.set(FLOW_COOKIE_NAME, owner.client.cookies[FLOW_COOKIE_NAME], domain=urlsplit(ORIGIN).hostname, path="/")
    if method == "passkey":
        key, _ = enroll(business.login("admin"))
        ceremony = login_options(successor)
        payload = key.assertion(ceremony["options"])
        module = passkeys
    else:
        payload = business.login_payload("admin")
        module = auth_routes
    before = _authority_fingerprint(business)

    def fail_event(*args, **kwargs):
        raise sqlite3.OperationalError("Disposable required login event failure")

    monkeypatch.setattr(module, "record_event", fail_event)
    response = (finish_login(successor, ceremony, payload) if method == "passkey" else
                login_post(successor, "/api/login", json=payload, headers={"Origin": ORIGIN}))
    assert response.status_code == 503 and "set-cookie" not in response.headers
    assert _authority_fingerprint(business) == before
    assert owner.request("GET", "/api/messages").status_code == 200
    assert successor.get("/api/messages").status_code == 401


def test_retired_bearer_without_flow_cannot_select_rotated_head_for_replacement(business):
    owner, predecessor = _rotated_owner(business)
    successor = business.client()
    successor.cookies.set(COOKIE_NAME, predecessor, domain=urlsplit(ORIGIN).hostname, path="/")
    response = login_post(successor, "/api/login", json=business.login_payload("blair"), headers={"Origin": ORIGIN})
    assert response.status_code == 200
    assert owner.request("GET", "/api/messages").status_code == 200
    assert successor.get("/api/session").json()["user"]["id"] == "blair"
