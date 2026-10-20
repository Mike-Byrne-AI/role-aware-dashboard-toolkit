"""Rejected verifications have durable budgets and cannot occupy all API workers."""

import asyncio
from contextlib import ExitStack
import json
from threading import Event, Lock

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
pytest.importorskip("pyotp")
import anyio  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tests.test_business_dashboard import business as business, business_seed as business_seed  # noqa: E402
from business import abuse, submission_routes  # noqa: E402
from business.abuse import PUBLIC_RULES  # noqa: E402
from business.app import create_app  # noqa: E402

ORIGIN = "https://verification-test.invalid"
SUCCESS = {"success": True, "hostname": "verification-test.invalid", "action": "guest_submission"}


def payload():
    return {
        "title": "Disposable security test", "body": "Keep private pending moderation.",
        "accept_rules": True, "rules_version": PUBLIC_RULES["version"], "turnstile_token": "fixture-token",
    }


@pytest.fixture
def hosted(business, monkeypatch):
    monkeypatch.setenv("BUSINESS_TURNSTILE_SITE_KEY", "fictional-site-key")
    monkeypatch.setenv("BUSINESS_TURNSTILE_SECRET_KEY", "fictional-secret-key")
    return create_app(business.directory, public_origin=ORIGIN)


def mock_provider(monkeypatch, handler):
    real_client = httpx.Client
    monkeypatch.setattr(
        abuse.httpx, "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )


def provider_response(value):
    return httpx.Response(200, stream=httpx.ByteStream(json.dumps(value).encode()))


def post(client, **headers):
    return client.post("/api/public/submissions", json=payload(), headers={"Origin": ORIGIN, **headers})


def counters(business):
    with business.db() as connection:
        return {
            "attempts": connection.execute(
                "SELECT attempts FROM login_limits WHERE key_hash=?",
                (submission_routes.ATTEMPT_PREFIX + "global",),
            ).fetchone()[0],
            "accepted": connection.execute("SELECT COUNT(*) FROM submission_limits").fetchone()[0],
            "pending": connection.execute("SELECT COUNT(*) FROM submissions").fetchone()[0],
        }


def test_rejected_attempts_persist_across_apps_and_forwarded_header_changes(hosted, business, monkeypatch):
    calls = []
    moment = [100000.0]
    monkeypatch.setattr(submission_routes, "current_time", lambda: moment[0])
    mock_provider(monkeypatch, lambda request: (calls.append(request), provider_response({"success": False}))[1])
    with TestClient(hosted, base_url=ORIGIN) as client:
        for _ in range(submission_routes.PEER_ATTEMPT_LIMIT):
            assert post(client).status_code == 403
        assert post(client, **{"X-Forwarded-For": "198.51.100.9", "CF-Connecting-IP": "203.0.113.8"}).status_code == 429
    replacement = create_app(business.directory, public_origin=ORIGIN)
    with TestClient(replacement, base_url=ORIGIN) as client:
        assert post(client).status_code == 429
        assert len(calls) == submission_routes.PEER_ATTEMPT_LIMIT
        assert counters(business) == {"attempts": 10, "accepted": 0, "pending": 0}
        moment[0] += submission_routes.ATTEMPT_WINDOW_SECONDS + 1
        assert post(client).status_code == 403
        assert counters(business) == {"attempts": 1, "accepted": 0, "pending": 0}


def test_global_attempt_budget_bounds_rotating_peers_and_row_growth(hosted, business, monkeypatch):
    calls = []
    moment = [100000.0]
    monkeypatch.setattr(submission_routes, "current_time", lambda: moment[0])
    mock_provider(monkeypatch, lambda request: (calls.append(request), provider_response({"success": False}))[1])
    with ExitStack() as stack:
        for number in range(submission_routes.GLOBAL_ATTEMPT_LIMIT + 5):
            client = stack.enter_context(TestClient(hosted, base_url=ORIGIN, client=(f"198.51.100.{number}", 123)))
            assert post(client).status_code == (403 if number < submission_routes.GLOBAL_ATTEMPT_LIMIT else 429)
        assert len(calls) == submission_routes.GLOBAL_ATTEMPT_LIMIT
        with business.db() as connection:
            assert connection.execute("SELECT COUNT(*) FROM login_limits").fetchone()[0] == 31
            # Expiring public counters must not prune a different security budget.
            connection.execute("INSERT INTO login_limits VALUES('unrelated-budget',0,7)")
        moment[0] += submission_routes.ATTEMPT_WINDOW_SECONDS + 1
        assert post(client).status_code == 403
        with business.db() as connection:
            assert connection.execute("SELECT COUNT(*) FROM login_limits").fetchone()[0] == 3
            assert connection.execute("SELECT attempts FROM login_limits WHERE key_hash='unrelated-budget'").fetchone()[0] == 7


@pytest.mark.parametrize("outcome,status", [("reject", 403), ("timeout", 503), ("malformed", 503), ("success", 202)])
def test_every_provider_outcome_keeps_committed_attempts(hosted, business, monkeypatch, outcome, status):
    calls = []

    def handler(request):
        calls.append(request)
        # A separate write transaction can read the committed reservation while
        # the provider is running: no SQLite write lock crosses this boundary.
        assert counters(business) == {"attempts": 1, "accepted": 0, "pending": 0}
        if outcome == "timeout":
            raise httpx.ReadTimeout("secret-response-canary")
        if outcome == "malformed":
            return httpx.Response(200, stream=httpx.ByteStream(b"not-json"))
        return provider_response(SUCCESS if outcome == "success" else {"success": False})

    mock_provider(monkeypatch, handler)
    with TestClient(hosted, base_url=ORIGIN) as client:
        response = post(client)
        assert response.status_code == status
        assert "secret-response-canary" not in response.text
    assert len(calls) == 1
    accepted = int(outcome == "success")
    assert counters(business) == {"attempts": 1, "accepted": accepted, "pending": accepted}


def test_two_app_instances_share_atomic_verification_attempt_reservations(hosted, business, monkeypatch):
    calls = []
    lock = Lock()

    def handler(request):
        with lock:
            calls.append(request)
        return provider_response({"success": False})

    mock_provider(monkeypatch, handler)
    second = create_app(business.directory, public_origin=ORIGIN)
    with TestClient(hosted, base_url=ORIGIN) as client:
        for _ in range(submission_routes.PEER_ATTEMPT_LIMIT - 1):
            assert post(client).status_code == 403

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=hosted, client=("testclient", 1)), base_url=ORIGIN) as one:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=second, client=("testclient", 2)), base_url=ORIGIN) as two:
                responses = await asyncio.gather(*[
                    client.post("/api/public/submissions", json=payload(), headers={"Origin": ORIGIN})
                    for client in (one, two)
                ])
                assert sorted(response.status_code for response in responses) == [403, 429]

    asyncio.run(scenario())
    assert len(calls) == submission_routes.PEER_ATTEMPT_LIMIT
    assert counters(business) == {"attempts": 10, "accepted": 0, "pending": 0}


def test_slow_provider_and_cancelled_request_preserve_health_and_auth_capacity(hosted, business, monkeypatch):
    entered, release = Event(), Event()
    lock = Lock()
    running = {"active": 0, "maximum": 0, "calls": 0}

    def handler(request):
        with lock:
            running["active"] += 1
            running["calls"] += 1
            running["maximum"] = max(running["maximum"], running["active"])
            if running["active"] == submission_routes.VERIFICATION_CAPACITY:
                entered.set()
        try:
            assert release.wait(10), "Test provider was not released"
            return provider_response({"success": False})
        finally:
            with lock:
                running["active"] -= 1

    mock_provider(monkeypatch, handler)

    async def scenario():
        limiter = anyio.to_thread.current_default_thread_limiter()
        previous = limiter.total_tokens
        limiter.total_tokens = 1
        tasks = []
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=hosted), base_url=ORIGIN) as client:
                tasks = [
                    asyncio.create_task(client.post("/api/public/submissions", json=payload(), headers={"Origin": ORIGIN}))
                    for _ in range(submission_routes.VERIFICATION_CAPACITY)
                ]
                assert await asyncio.to_thread(entered.wait, 5), "Provider work did not enter its independent capacity"
                busy = await asyncio.wait_for(client.post(
                    "/api/public/submissions", json=payload(), headers={"Origin": ORIGIN},
                ), 2)
                assert busy.status_code == 429 and busy.headers["retry-after"] == "1"
                tasks[0].cancel()
                with pytest.raises(asyncio.CancelledError):
                    await tasks[0]
                assert (await asyncio.wait_for(client.post(
                    "/api/public/submissions", json=payload(), headers={"Origin": ORIGIN},
                ), 2)).status_code == 429
                assert (await asyncio.wait_for(client.get("/healthz"), 2)).status_code == 200
                signed_in = await asyncio.wait_for(client.post(
                    "/api/login", json={"username": "alex", "password": business.credentials["alex"]},
                    headers={"Origin": ORIGIN},
                ), 3)
                assert signed_in.status_code == 200
                assert (await asyncio.wait_for(client.get("/api/messages"), 2)).status_code == 200
                assert running["calls"] == submission_routes.VERIFICATION_CAPACITY
                release.set()
                await asyncio.gather(*tasks, return_exceptions=True)
                assert (await client.post(
                    "/api/public/submissions", json=payload(), headers={"Origin": ORIGIN},
                )).status_code == 403
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            limiter.total_tokens = previous

    asyncio.run(scenario())
    assert running["maximum"] == submission_routes.VERIFICATION_CAPACITY
    assert counters(business)["pending"] == 0
