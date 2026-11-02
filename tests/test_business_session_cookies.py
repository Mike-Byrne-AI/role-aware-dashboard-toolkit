"""HTTPS session authority never falls back to a sibling-injectable cookie."""

from tests.test_business_dashboard import business as business, business_seed as business_seed
from tests.test_business_passkeys import Authenticator
from fastapi.testclient import TestClient
from business.app import create_app
from business.security import COOKIE_NAME, HTTPS_COOKIE_NAME, token_hash

ORIGIN = "https://dashboard.example.test"


def https_app(business, monkeypatch):
    # Never contact a provider; only authentication routes use this synthetic app.
    monkeypatch.setenv("BUSINESS_TURNSTILE_SITE_KEY", "synthetic-site-key")
    monkeypatch.setenv("BUSINESS_TURNSTILE_SECRET_KEY", "synthetic-secret-key")
    return create_app(business.directory, public_origin=ORIGIN)


def login(business, client, username):
    response = client.post("/api/login", json=business.login_payload(username), headers={"Origin": ORIGIN})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(HTTPS_COOKIE_NAME + "=")
    assert "Domain=" not in cookie and "Path=/" in cookie
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert COOKIE_NAME not in client.cookies
    return {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf"]}


def test_https_rejects_legacy_and_ambiguous_cookies_without_mutation(business, monkeypatch):
    app = https_app(business, monkeypatch)
    with TestClient(app, base_url=ORIGIN) as owner, TestClient(app, base_url=ORIGIN) as sibling, TestClient(app, base_url=ORIGIN) as probe:
        headers = login(business, owner, "alex")
        login(business, sibling, "blair")
        own, foreign = owner.cookies[HTTPS_COOKIE_NAME], sibling.cookies[HTTPS_COOKIE_NAME]
        # An old cookie name has no HTTPS authority even if its bearer is valid.
        legacy = {"Cookie": f"{COOKIE_NAME}={own}"}
        assert probe.get("/api/session", headers=legacy).json() == {"user": None}
        assert probe.get("/api/messages", headers=legacy).status_code == 401
        for cookie in (f"{COOKIE_NAME}={foreign}; {HTTPS_COOKIE_NAME}={own}",
                       f"{HTTPS_COOKIE_NAME}={own}; {COOKIE_NAME}={foreign}"):
            assert probe.get("/api/session", headers={"Cookie": cookie}).json()["user"]["id"] == "alex"
        before = owner.get("/api/messages").json()
        ambiguous = f"{HTTPS_COOKIE_NAME}={own}; {HTTPS_COOKIE_NAME}={foreign}"
        assert probe.get("/api/session", headers={"Cookie": ambiguous}).status_code == 400
        assert probe.get("/api/session", headers=[("Cookie", f"{HTTPS_COOKIE_NAME}={own}"),
                                                  ("Cookie", f"{HTTPS_COOKIE_NAME}={foreign}")]).status_code == 400
        rejected = probe.post("/api/messages", json={"body": "Must not save with ambiguous authority"},
                              headers={**headers, "Cookie": ambiguous})
        assert rejected.status_code == 400
        assert owner.get("/api/messages").json() == before
        assert owner.post("/api/messages", json={"body": "Legitimate current owner"}, headers=headers).status_code == 201


def test_https_sessions_fresh_verification_and_logout_use_prefixed_cookie(business, monkeypatch):
    app = https_app(business, monkeypatch)
    with TestClient(app, base_url=ORIGIN) as owner, TestClient(app, base_url=ORIGIN) as other:
        headers = login(business, owner, "admin")
        login(business, other, "admin")
        inventory = owner.get("/api/security/sessions").json()
        target = next(row["id"] for row in inventory["sessions"] if not row["current"])
        with app.state.database.transaction() as connection:
            connection.execute("UPDATE session_security SET verified_at=0 WHERE token_hash=?",
                               (token_hash(owner.cookies[HTTPS_COOKIE_NAME]),))
        path = f"/api/security/sessions/{target}/revoke"
        assert owner.post(path, json={}, headers=headers).status_code == 403
        payload = business.login_payload("admin")
        response = owner.post("/api/security/reauthenticate", json={
            "current_password": payload["password"], "otp": payload["otp"],
        }, headers=headers)
        assert response.status_code == 200
        assert owner.post(path, json={}, headers=headers).status_code == 200
        assert other.get("/api/admin/overview").status_code == 401
        assert owner.post("/api/admin/freeze", json={"frozen": True, "revision": 0}, headers=headers).status_code == 200
        assert owner.post("/api/admin/freeze", json={"frozen": False, "revision": 1}, headers=headers).status_code == 200
        assert owner.post("/api/admin/security/events/dispatch", json={}, headers=headers).status_code == 200
        assert owner.post("/api/logout", json={}, headers=headers).status_code == 200
        assert owner.get("/api/messages").status_code == 401


def test_https_passkey_registration_reauthentication_login_and_removal(business, monkeypatch):
    app = https_app(business, monkeypatch)
    with TestClient(app, base_url=ORIGIN) as owner, TestClient(app, base_url=ORIGIN) as signed, TestClient(app, base_url=ORIGIN) as retained:
        headers = login(business, owner, "admin")
        retained_headers = login(business, retained, "admin")
        key = Authenticator(origin=ORIGIN)
        options = owner.post("/api/security/passkeys/register/options", json={}, headers=headers).json()
        registered = owner.post("/api/security/passkeys/register/verify", json={
            "request_id": options["request_id"], "credential": key.register(options["options"]),
            "name": "Disposable HTTPS key",
        }, headers=headers)
        assert registered.status_code == 200
        identifier = registered.json()["passkey"]["id"]
        options = owner.post("/api/security/passkeys/reauth/options", json={}, headers=headers).json()
        assert owner.post("/api/security/passkeys/reauth/verify", json={
            "request_id": options["request_id"], "credential": key.assertion(options["options"], counter=1),
        }, headers=headers).status_code == 200
        options = signed.post("/api/passkeys/login/options", json={}, headers={"Origin": ORIGIN}).json()
        response = signed.post("/api/passkeys/login/verify", json={
            "request_id": options["request_id"], "credential": key.assertion(options["options"], counter=2),
        }, headers={"Origin": ORIGIN, "X-Passkey-CSRF": options["csrf"]})
        assert response.status_code == 200
        assert response.headers["set-cookie"].startswith(HTTPS_COOKIE_NAME + "=")
        assert COOKIE_NAME not in signed.cookies
        assert signed.get("/api/admin/overview").status_code == 200
        assert retained.post(f"/api/security/passkeys/{identifier}/remove", json={}, headers=retained_headers).status_code == 200
        assert signed.get("/api/admin/overview").status_code == 401
        assert owner.get("/api/admin/overview").status_code == 401
        assert retained.get("/api/admin/overview").status_code == 200
