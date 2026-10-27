"""Adversarial request streams and provider failures against disposable local state."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import sys
from threading import Event

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
pytest.importorskip("pyotp")
from fastapi.testclient import TestClient  # noqa: E402

from tests.test_business_dashboard import business as business, business_seed as business_seed  # noqa: E402
from business import abuse, auth_routes, request_security  # noqa: E402
from business.abuse import PUBLIC_RULES  # noqa: E402
from business.app import create_app  # noqa: E402
from business.request_security import MAX_BODY_BYTES, RequestSecurityMiddleware  # noqa: E402

ORIGIN = "https://adversarial-abuse.invalid"


def run_stream(messages, extra_headers=()):
    """Invoke the ASGI boundary directly so HTTP client normalization cannot hide chunks."""
    responses, reached = [], []
    scope = {
        "type": "http", "method": "POST", "path": "/", "headers": [
            (b"origin", ORIGIN.encode()), (b"content-type", b"application/json"), *extra_headers,
        ],
    }
    iterator = iter(messages)

    async def receive():
        return next(iterator)

    async def downstream(scope, receive, send):
        reached.append(await receive())

    async def send(message):
        responses.append(message)

    asyncio.run(RequestSecurityMiddleware(downstream, ORIGIN)(scope, receive, send))
    return responses, reached


@pytest.mark.parametrize("headers", [(), ((b"content-length", b"1"),)])
def test_streamed_oversize_rejected_even_when_declared_length_is_absent_or_small(headers):
    responses, reached = run_stream([
        {"type": "http.request", "body": b"x" * MAX_BODY_BYTES, "more_body": True},
        {"type": "http.request", "body": b"x", "more_body": False},
    ], headers)
    assert reached == []
    assert responses[0]["status"] == 413
    assert (b"cache-control", b"no-store") in responses[0]["headers"]


def test_disconnect_during_body_never_reaches_a_mutation():
    responses, reached = run_stream([
        {"type": "http.request", "body": b'{"body":"unfinished', "more_body": True},
        {"type": "http.disconnect"},
    ])
    assert reached == []
    assert responses == []


def test_fragmented_complete_request_reaches_application_exactly_once():
    body = b'{"body":"A complete harmless message"}'
    responses, reached = run_stream([
        {"type": "http.request", "body": body[:7], "more_body": True},
        {"type": "http.request", "body": b"", "more_body": True},
        {"type": "http.request", "body": body[7:], "more_body": False},
    ])
    assert responses == []
    assert reached == [{"type": "http.request", "body": body, "more_body": False}]


@pytest.mark.parametrize("header,value", [
    (b"origin", ORIGIN.encode()), (b"content-type", b"application/json"),
])
def test_duplicate_security_headers_rejected_before_consuming_body(header, value):
    responses, reached = run_stream([], ((header, value),))
    assert reached == []
    assert responses[0]["status"] == 400


def test_duplicate_content_lengths_rejected_before_consuming_body():
    responses, reached = run_stream([], ((b"content-length", b"2"), (b"content-length", b"2")))
    assert reached == []
    assert responses[0]["status"] == 400


def test_provider_excessive_nesting_returns_recoverable_failure_without_queue_mutation(business, monkeypatch):
    monkeypatch.setenv("BUSINESS_TURNSTILE_SITE_KEY", "synthetic-site-key")
    monkeypatch.setenv("BUSINESS_TURNSTILE_SECRET_KEY", "synthetic-secret-key")
    application = create_app(business.directory, public_origin=ORIGIN)
    nesting = sys.getrecursionlimit() + 100
    body = b"[" * nesting + b"0" + b"]" * nesting
    assert len(body) < abuse.MAX_PROVIDER_BYTES
    # This is a malformed synthetic provider response, not an attacker-controlled
    # Siteverify endpoint or a claim of real-provider compromise.
    real_client = httpx.Client
    calls = []

    def provider(request):
        calls.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(body))

    monkeypatch.setattr(abuse.httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(provider), **kwargs,
    ))
    with TestClient(application, base_url=ORIGIN, raise_server_exceptions=False) as client:
        response = client.post("/api/public/submissions", headers={"Origin": ORIGIN}, json={
            "title": "Synthetic nesting probe", "body": "Keep private until moderated.",
            "accept_rules": True, "rules_version": PUBLIC_RULES["version"],
            "turnstile_token": "synthetic-token",
        })
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM submissions").fetchone()[0] == 0
    assert len(calls) == 1
    assert response.status_code == 503
    assert response.json() == {"detail": "Verification is unavailable. Please try again later."}
    assert "synthetic-token" not in response.text


def test_streamed_json_with_escaped_secret_is_not_echoed_in_schema_errors(business):
    canary = "DISPOSABLE_INVALID_PASSWORD_CANARY"
    body = json.dumps({"username": "alex", "password": canary, "role": "admin"}).encode()
    response = business.client().post("/api/login", content=iter([body[:3], body[3:]]), headers={
        "Origin": "http://127.0.0.1:8091", "Content-Type": "application/json",
    })
    assert response.status_code == 422
    assert canary not in response.text


def test_unknown_identity_work_has_bounded_capacity_independent_of_real_signin(business, monkeypatch):
    actor = business.login("casey")
    entered, release = Event(), Event()

    def held_dummy_check(password):
        entered.set()
        assert release.wait(timeout=10)

    monkeypatch.setattr(auth_routes, "dummy_password_check", held_dummy_check)

    def attempt(username, password):
        return business.client().post("/api/login", headers={"Origin": "http://127.0.0.1:8091"}, json={
            "username": username, "password": password,
        })

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(attempt, "absent-one", "synthetic-password")
        try:
            assert entered.wait(timeout=5)
            assert business.client().get("/healthz").status_code == 200
            assert actor.request("GET", "/api/messages").status_code == 200
            assert attempt("alex", business.credentials["alex"]).status_code == 200
            response = attempt("absent-two", "synthetic-password")
            assert response.status_code == 429
            assert response.headers["Retry-After"] == "1"
            with business.db() as connection:
                assert connection.execute("SELECT COUNT(*) FROM login_limits").fetchone()[0] == 0
        finally:
            release.set()
        assert pending.result(timeout=5).status_code == 401
    assert attempt("alex", business.credentials["alex"]).status_code == 200


class IntakeProbe:
    """Exercise one middleware instance with independent asynchronous request streams."""

    def __init__(self, downstream=None):
        self.reached = []

        async def application(scope, receive, send):
            self.reached.append(scope["method"])
            if downstream is not None:
                await downstream(scope, receive)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        self.middleware = RequestSecurityMiddleware(application, ORIGIN)

    async def request(self, receive=None, method="POST"):
        responses = []

        async def complete():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(message):
            responses.append(message)

        scope = {"type": "http", "method": method, "path": "/", "headers": [
            (b"origin", ORIGIN.encode()), (b"content-type", b"application/json"),
        ]}
        await self.middleware(scope, receive or complete, send)
        return responses


@pytest.mark.parametrize("mode", ["no_data", "trickle", "ready_empty_chunks"])
def test_body_completion_deadline_covers_stalled_and_trickling_streams(monkeypatch, mode):
    monkeypatch.setattr(request_security, "BODY_READ_TIMEOUT_SECONDS", 0.04)
    monkeypatch.setattr(request_security, "BODY_READ_CAPACITY", 1)

    async def scenario():
        probe = IntakeProbe()

        async def slow_receive():
            if mode == "no_data":
                await asyncio.Event().wait()
            if mode == "ready_empty_chunks":
                return {"type": "http.request", "body": b"", "more_body": True}
            await asyncio.sleep(0.005)
            return {"type": "http.request", "body": b"x", "more_body": True}

        response = await asyncio.wait_for(probe.request(slow_receive), timeout=2)
        assert response[0]["status"] == 408
        assert (b"cache-control", b"no-store") in response[0]["headers"]
        assert probe.reached == []
        assert (await probe.request())[0]["status"] == 200

    asyncio.run(scenario())


def test_body_reader_saturation_rejects_without_reading_or_blocking_gets(monkeypatch):
    monkeypatch.setattr(request_security, "BODY_READ_CAPACITY", 2)

    async def scenario():
        probe = IntakeProbe()
        entered = asyncio.Queue()
        release = asyncio.Event()

        async def held_receive():
            await entered.put(True)
            await release.wait()
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def forbidden_receive():
            pytest.fail("Rejected or read-only requests must not consume a body")

        pending = [asyncio.create_task(probe.request(held_receive)) for _ in range(2)]
        try:
            for _ in pending:
                await asyncio.wait_for(entered.get(), timeout=2)
            rejected = await probe.request(forbidden_receive)
            assert rejected[0]["status"] == 429
            assert (b"retry-after", b"1") in rejected[0]["headers"]
            assert probe.reached == []
            assert (await probe.request(forbidden_receive, method="GET"))[0]["status"] == 200
        finally:
            release.set()
            completed = await asyncio.gather(*pending)
        assert [item[0]["status"] for item in completed] == [200, 200]
        assert (await probe.request())[0]["status"] == 200

    asyncio.run(scenario())


@pytest.mark.parametrize("outcome", ["disconnect", "overflow", "exception", "cancel"])
def test_body_reader_slot_is_reusable_after_every_exit(monkeypatch, outcome):
    monkeypatch.setattr(request_security, "BODY_READ_CAPACITY", 1)

    async def scenario():
        probe = IntakeProbe()
        entered = asyncio.Event()

        async def interrupted_receive():
            entered.set()
            if outcome == "disconnect":
                return {"type": "http.disconnect"}
            if outcome == "overflow":
                return {"type": "http.request", "body": b"x" * (MAX_BODY_BYTES + 1), "more_body": False}
            if outcome == "exception":
                raise RuntimeError("Synthetic transport failure")
            await asyncio.Event().wait()

        task = asyncio.create_task(probe.request(interrupted_receive))
        await asyncio.wait_for(entered.wait(), timeout=2)
        if outcome == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif outcome == "exception":
            with pytest.raises(RuntimeError, match="Synthetic transport failure"):
                await task
        else:
            response = await task
            if outcome == "disconnect":
                assert response == []
            else:
                assert response[0]["status"] == 413
        assert probe.reached == []
        assert (await probe.request())[0]["status"] == 200

    asyncio.run(scenario())


def test_completed_bodies_release_intake_before_downstream_work(monkeypatch):
    monkeypatch.setattr(request_security, "BODY_READ_CAPACITY", 1)

    async def scenario():
        entered = asyncio.Queue()
        release = asyncio.Event()

        async def held_downstream(scope, receive):
            assert (await receive())["body"] == b"{}"
            await entered.put(True)
            await release.wait()

        probe = IntakeProbe(held_downstream)
        pending = []
        try:
            for _ in range(2):
                pending.append(asyncio.create_task(probe.request()))
                await asyncio.wait_for(entered.get(), timeout=2)
        finally:
            release.set()
            completed = await asyncio.gather(*pending)
        assert [item[0]["status"] for item in completed] == [200, 200]

    asyncio.run(scenario())
