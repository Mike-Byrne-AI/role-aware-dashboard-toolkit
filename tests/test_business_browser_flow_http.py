"""Raw HTTP login-context boundaries and actual signed credential races."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from tests.test_business_dashboard import ORIGIN, business as business, business_seed as business_seed
from tests.test_business_passkeys import enroll
from business import auth_routes, passkeys
from business.security import COOKIE_NAME, token_hash


def context(client, *, csrf=None):
    headers = {"Origin": ORIGIN}
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    response = client.post("/api/login/context", json={}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def password(client, payload, captured):
    return client.post("/api/login", json=payload,
                       headers={"Origin": ORIGIN, "X-Login-CSRF": captured["csrf"]})


def copy_jar(source, target):
    target.cookies.update(source.cookies)


def prepare(business, client, method, username, captured, key=None, counter=1):
    if method == "password":
        payload = business.login_payload(username)
        return lambda: password(client, payload, captured)
    response = client.post("/api/passkeys/login/options", json={},
                           headers={"Origin": ORIGIN, "X-Login-CSRF": captured["csrf"]})
    assert response.status_code == 200
    ceremony = response.json()
    payload = {"request_id": ceremony["request_id"],
               "credential": key.assertion(ceremony["options"], counter=counter)}
    return lambda: client.post("/api/passkeys/login/verify", json=payload,
                               headers={"Origin": ORIGIN, "X-Login-CSRF": captured["csrf"]})


@pytest.mark.parametrize("path,payload", [
    ("/api/login", {"username": "admin", "password": "Valid format wrong password"}),
    ("/api/passkeys/login/options", {}),
    ("/api/passkeys/login/verify", {"request_id": "a" * 32, "credential": {}}),
])
def test_raw_login_paths_require_context_without_authority_or_cookie_mutation(business, path, payload):
    client = business.client()
    for supplied in (None, "wrong", "v1.0.0." + "a" * 43):
        headers = {"Origin": ORIGIN}
        if supplied is not None:
            headers["X-Login-CSRF"] = supplied
        response = client.post(path, json=payload, headers=headers)
        assert response.status_code == 409
        assert response.json() == {"detail": "Sign-in changed or expired. Start sign-in again."}
        assert "set-cookie" not in response.headers
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM passkey_challenges").fetchone()[0] == 0


@pytest.mark.parametrize("methods", [("password", "password"), ("passkey", "passkey"),
                                     ("password", "passkey"), ("passkey", "password")])
@pytest.mark.parametrize("same_user", [False, True])
@pytest.mark.parametrize("winner", [0, 1])
def test_first_commit_wins_shared_generation_after_both_real_proofs(business, monkeypatch, methods, same_user, winner):
    users = ["admin", "admin" if same_user else "alex"]
    keys = {}
    for method, username in zip(methods, users):
        if method == "passkey" and username not in keys:
            keys[username] = enroll(business.login(username))[0]
    clients = [business.client(), business.client()]
    captured = context(clients[0])
    copy_jar(clients[0], clients[1])
    ready, release = [Event(), Event()], [Event(), Event()]
    sequence = iter(range(2))
    original_password, original_assertion = auth_routes.verify_password, passkeys._assertion

    def gate(callable_, *args, **kwargs):
        result = callable_(*args, **kwargs)
        # FastAPI executes the proof in its own worker, not the calling client
        # thread. The second proof is started only after this first rendezvous.
        index = next(sequence)
        ready[index].set()
        assert release[index].wait(15), "Disposable race was not released"
        return result

    monkeypatch.setattr(auth_routes, "verify_password", lambda *args: gate(original_password, *args))
    monkeypatch.setattr(passkeys, "_assertion", lambda *args, **kwargs: gate(original_assertion, *args, **kwargs))

    def run(index, submit):
        return submit()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = prepare(business, clients[0], methods[0], users[0], captured, keys.get(users[0]))
        futures = [pool.submit(run, 0, first)]
        try:
            assert ready[0].wait(15)
            # The first passkey challenge is already durably claimed. Issuing
            # the second cannot accidentally test the one-pending-challenge cap.
            second = prepare(business, clients[1], methods[1], users[1], captured, keys.get(users[1]), counter=2)
            futures.append(pool.submit(run, 1, second))
            assert ready[1].wait(15)
            release[winner].set()
            success = futures[winner].result(timeout=15)
            assert success.status_code == 200, success.text
            release[1 - winner].set()
            rejected = futures[1 - winner].result(timeout=15)
            assert rejected.status_code == 409
            assert "set-cookie" not in rejected.headers
        finally:
            for event in release:
                event.set()
    assert clients[winner].get("/api/session").json()["user"]["id"] == users[winner]
    assert clients[1 - winner].get("/api/session").json() == {"user": None}
    with business.db() as connection:
        head = connection.execute(
            "SELECT s.user_id FROM session_browser_flow f JOIN session_security v USING(public_id) "
            "JOIN sessions s ON s.token_hash=v.token_hash WHERE f.flow_hash="
            "(SELECT flow_hash FROM browser_login_flows WHERE generation=1 AND created_by_user_id=? "
            "ORDER BY issued_at DESC LIMIT 1)", (users[winner],),
        ).fetchone()
        assert head and head[0] == users[winner]


def test_deliberate_next_generation_invalidates_earlier_cookie_and_stale_bootstrap(business):
    client = business.client()
    first = password(client, business.login_payload("admin"), context(client))
    assert first.status_code == 200
    old_cookie = client.cookies[COOKIE_NAME]
    old = business.client()
    copy_jar(client, old)
    captured = context(client, csrf=first.json()["csrf"])
    second = password(client, business.login_payload("alex"), captured)
    assert second.status_code == 200
    assert old.get("/api/session").json() == {"user": None}
    rejected = old.post("/api/login/context", json={}, headers={"Origin": ORIGIN, "X-CSRF-Token": first.json()["csrf"]})
    assert rejected.status_code in (401, 409)
    assert "set-cookie" not in rejected.headers
    rejected = old.post("/api/logout", json={}, headers={"Origin": ORIGIN, "X-CSRF-Token": first.json()["csrf"]})
    assert rejected.status_code == 401
    assert client.get("/api/session").json()["user"]["id"] == "alex"
    # Model the browser applying a delayed earlier Set-Cookie after B committed.
    delayed = business.client()
    delayed.cookies.set(COOKIE_NAME, old_cookie)
    assert delayed.get("/api/messages").status_code == 401
    with business.db() as connection:
        assert connection.execute("SELECT 1 FROM sessions WHERE token_hash=?", (token_hash(old_cookie),)).fetchone() is None


def test_logout_closes_captured_context_and_explicit_restart_uses_new_flow(business):
    client = business.client()
    first = password(client, business.login_payload("admin"), context(client))
    captured = context(client, csrf=first.json()["csrf"])
    assert client.post("/api/logout", json={}, headers={"Origin": ORIGIN, "X-CSRF-Token": first.json()["csrf"]}).status_code == 200
    rejected = password(client, business.login_payload("alex"), captured)
    assert rejected.status_code == 409 and "set-cookie" not in rejected.headers
    fresh = context(client)
    assert fresh["csrf"] != captured["csrf"]
    assert password(client, business.login_payload("alex"), fresh).status_code == 200


def test_live_session_bootstrap_requires_its_current_ordinary_csrf(business):
    owner = business.login("admin")
    before = dict(owner.client.cookies)
    for headers in ({"Origin": ORIGIN}, {"Origin": ORIGIN, "X-CSRF-Token": "wrong"}):
        response = owner.client.post("/api/login/context", json={}, headers=headers)
        assert response.status_code in (403, 409)
        assert "set-cookie" not in response.headers
        assert dict(owner.client.cookies) == before
    assert context(owner.client, csrf=owner.csrf)
    assert owner.request("GET", "/api/messages").status_code == 200


@pytest.mark.parametrize("headers,body,status", [
    ({}, {}, 403),
    ({"Origin": "https://foreign.invalid"}, {}, 403),
    ({"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"}, {}, 403),
    ({"Origin": ORIGIN}, {"extra": "field"}, 422),
])
def test_context_retains_origin_fetch_site_and_exact_empty_body_guards(business, headers, body, status):
    client = business.client()
    response = client.post("/api/login/context", json=body, headers=headers)
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers
