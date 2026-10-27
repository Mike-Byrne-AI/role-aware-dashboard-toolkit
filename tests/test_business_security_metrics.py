"""Bounded authentication admission and identifier-free local decision counters."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Barrier, Event

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    NEW_PASSWORD, ORIGIN, business as business, business_seed as business_seed,
)
from fastapi import HTTPException  # noqa: E402
from business import auth_routes, message_limits, request_security, submission_routes, telemetry  # noqa: E402
from business.abuse import PUBLIC_RULES, SubmissionGuard  # noqa: E402
from business.app import create_app  # noqa: E402
from business.request_security import RequestSecurityMiddleware  # noqa: E402
from business.telemetry import SecurityMetrics  # noqa: E402


def _login(business, username, password="DISPOSABLE_PASSWORD_CANARY"):
    return business.client().post("/api/login", headers={"Origin": ORIGIN}, json={
        "username": username, "password": password,
    })


def test_lookup_admission_is_bounded_and_existing_sessions_keep_independent_capacity(business, monkeypatch):
    actor = business.login("alex")
    entered, release = Barrier(3), Event()
    original = auth_routes._classify_login

    def held_lookup(*args):
        entered.wait(timeout=5)
        assert release.wait(timeout=10)
        return original(*args)

    monkeypatch.setattr(auth_routes, "_classify_login", held_lookup)
    monkeypatch.setattr(auth_routes, "dummy_password_check", lambda password: None)
    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [executor.submit(_login, business, f"missing-{index}") for index in range(2)]
        try:
            entered.wait(timeout=5)
            response = _login(business, "blair", business.credentials["blair"])
            assert response.status_code == 429 and response.headers["retry-after"] == "1"
            assert business.client().get("/healthz").status_code == 200
            assert actor.request("GET", "/api/messages").status_code == 200
            assert actor.request("POST", "/api/password", json={
                "current_password": business.credentials["alex"], "new_password": NEW_PASSWORD,
            }).status_code == 200
        finally:
            release.set()
        # Separate unknown-user admission can reject one released lookup when
        # both complete together; neither is permitted to issue a session.
        assert {future.result(timeout=5).status_code for future in pending} <= {401, 429}
    counters = business.app.state.security_metrics.snapshot()["counters"]
    assert counters["auth_lookup_busy"] == 1
    assert counters["password_changed"] == 1


def test_account_appearing_after_classification_cannot_borrow_unknown_work(business, monkeypatch):
    original = auth_routes._classify_login

    def classify_then_create(database, username):
        result = original(database, username)
        assert result is None
        # Simulate an operator creating this name by renaming a disposable row.
        with database.transaction() as connection:
            connection.execute("UPDATE users SET username=? WHERE id='alex'", (username,))
        return result

    def forbidden_hash(*args):
        pytest.fail("Changed account identity must be refused before password work")

    monkeypatch.setattr(auth_routes, "_classify_login", classify_then_create)
    monkeypatch.setattr(auth_routes, "dummy_password_check", forbidden_hash)
    monkeypatch.setattr(auth_routes, "verify_password", forbidden_hash)
    response = _login(business, "newly-created-name", business.credentials["alex"])
    assert response.status_code == 401
    assert response.json() == {"detail": "The sign-in details are incorrect."}
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM login_limits").fetchone()[0] == 0
    assert business.app.state.security_metrics.snapshot()["counters"]["login_identity_changed"] == 1


def test_login_counters_distinguish_budget_decisions_without_request_labels(business, monkeypatch):
    original = auth_routes.verify_password
    monkeypatch.setattr(auth_routes, "verify_password", lambda *args: False)
    monkeypatch.setattr(auth_routes, "dummy_password_check", lambda password: None)
    for _ in range(auth_routes.ATTEMPT_LIMIT):
        assert _login(business, "alex").status_code == 401
    assert _login(business, "alex").status_code == 429
    for name in ("ABSENT_USERNAME_CANARY_ONE", "ABSENT_USERNAME_CANARY_TWO"):
        assert _login(business, name).status_code == 401
    monkeypatch.setattr(auth_routes, "verify_password", original)
    assert _login(business, "blair", business.credentials["blair"]).status_code == 200
    snapshot = business.app.state.security_metrics.snapshot()
    assert set(snapshot["counters"]) == set(telemetry.EVENTS)
    assert snapshot["counters"]["login_rejected"] == auth_routes.ATTEMPT_LIMIT + 2
    assert snapshot["counters"]["login_budget_denied"] == 1
    assert snapshot["counters"]["login_succeeded"] == 1
    assert "CANARY" not in json.dumps(snapshot)
    assert "alex" not in json.dumps(snapshot) and "blair" not in json.dumps(snapshot)
    fresh = create_app(business.directory, public_origin=ORIGIN).state.security_metrics.snapshot()
    assert fresh["resets_on_restart"] is True
    assert all(value == 0 for value in fresh["counters"].values())


def test_counter_storage_is_fixed_thread_safe_and_saturating(monkeypatch):
    metrics = SecurityMetrics()
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: metrics.record("login_rejected"), range(100)))
    assert metrics.snapshot()["counters"]["login_rejected"] == 100
    before = metrics.snapshot()
    with pytest.raises(ValueError, match="Unsupported security metric"):
        metrics.record("DISPOSABLE_REQUEST_LABEL_CANARY")
    assert metrics.snapshot() == before
    snapshot = metrics.snapshot()
    snapshot["counters"]["login_rejected"] = -1
    assert metrics.snapshot()["counters"]["login_rejected"] == 100
    monkeypatch.setattr(telemetry, "MAX_COUNTER", 3)
    limited = SecurityMetrics()
    for _ in range(10):
        limited.record("login_rejected")
    assert limited.snapshot()["counters"]["login_rejected"] == 3


def test_request_intake_counters_distinguish_capacity_timeout_and_size(monkeypatch):
    monkeypatch.setattr(request_security, "BODY_READ_CAPACITY", 1)
    monkeypatch.setattr(request_security, "BODY_READ_TIMEOUT_SECONDS", 0.1)
    metrics = SecurityMetrics()

    async def scenario():
        entered = asyncio.Event()

        async def forbidden(*args):
            pytest.fail("Rejected intake must not reach the application")

        middleware = RequestSecurityMiddleware(forbidden, ORIGIN, on_event=metrics.record)

        async def request(receive, extra_headers=()):
            responses = []

            async def send(message):
                responses.append(message)

            await middleware({"type": "http", "method": "POST", "path": "/", "headers": [
                (b"origin", ORIGIN.encode()), (b"content-type", b"application/json"), *extra_headers,
            ]}, receive, send)
            return responses[0]["status"]

        async def stalled():
            entered.set()
            await asyncio.Event().wait()

        pending = asyncio.create_task(request(stalled))
        await asyncio.wait_for(entered.wait(), timeout=2)
        assert await request(forbidden) == 429
        assert await asyncio.wait_for(pending, timeout=2) == 408
        assert await request(forbidden, [(b"content-length", b"32769")]) == 413

    asyncio.run(scenario())
    counters = metrics.snapshot()["counters"]
    assert counters["body_capacity_denied"] == counters["body_timeout"] == counters["body_oversized"] == 1


def _submission(business, token="synthetic-token"):
    return business.client().post("/api/public/submissions", headers={"Origin": ORIGIN}, json={
        "title": "Disposable public metric", "body": "Fictional content for local verification.",
        "accept_rules": True, "rules_version": PUBLIC_RULES["version"], "turnstile_token": token,
    })


def test_public_provider_and_accepted_quota_decisions_have_separate_counters(business, monkeypatch):
    def verify(guard, token, remote):
        if token == "rejected":
            raise HTTPException(403, "Synthetic rejection")
        if token == "unavailable":
            raise HTTPException(503, "Synthetic provider failure")

    monkeypatch.setattr(SubmissionGuard, "verify", verify)
    assert _submission(business, "rejected").status_code == 403
    assert _submission(business, "unavailable").status_code == 503
    for _ in range(3):
        assert _submission(business).status_code == 202
    assert _submission(business).status_code == 429
    counters = business.app.state.security_metrics.snapshot()["counters"]
    assert counters["public_verification_rejected"] == 1
    assert counters["public_verification_unavailable"] == 1
    assert counters["public_submission_accepted"] == 3
    assert counters["public_submission_quota_denied"] == 1
    assert counters["public_verification_budget_denied"] == 0


def test_public_attempt_budget_denial_is_distinct_from_provider_rejection(business, monkeypatch):
    def reject(*args):
        raise HTTPException(403, "Synthetic rejection")

    monkeypatch.setattr(SubmissionGuard, "verify", reject)
    for _ in range(submission_routes.PEER_ATTEMPT_LIMIT):
        assert _submission(business).status_code == 403
    assert _submission(business).status_code == 429
    counters = business.app.state.security_metrics.snapshot()["counters"]
    assert counters["public_verification_rejected"] == submission_routes.PEER_ATTEMPT_LIMIT
    assert counters["public_verification_budget_denied"] == 1
    assert counters["public_submission_accepted"] == 0


def test_team_message_quota_and_storage_capacity_have_separate_counters(business, monkeypatch):
    actor = business.login("alex")
    monkeypatch.setattr(message_limits, "MESSAGE_MINUTE_LIMIT", 1)
    assert actor.request("POST", "/api/messages", json={"body": "Fictional metric test"}).status_code == 201
    assert actor.request("POST", "/api/messages", json={"body": "Quota rejection"}).status_code == 429
    monkeypatch.setattr(message_limits, "MESSAGE_CAPACITY", 1)
    assert actor.request("POST", "/api/messages", json={"body": "Capacity rejection"}).status_code == 507
    counters = business.app.state.security_metrics.snapshot()["counters"]
    assert counters["message_quota_denied"] == 1
    assert counters["message_capacity_denied"] == 1
