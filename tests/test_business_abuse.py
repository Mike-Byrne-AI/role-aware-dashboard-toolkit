"""Public challenge failures cannot bypass the business example's queue gate."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
from fastapi import FastAPI, HTTPException, Request  # noqa: E402 -- optional API dependencies
from fastapi.testclient import TestClient  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "business_dashboard"))
from business import abuse  # noqa: E402
from business.abuse import PUBLIC_RULES, SubmissionGuard  # noqa: E402
from business.request_security import RequestSecurityMiddleware  # noqa: E402

ORIGIN = "https://example-dashboard.mikebyrne.ai"
PUBLIC_HOST = "example-dashboard.mikebyrne.ai"
SUCCESS = {"success": True, "hostname": PUBLIC_HOST, "action": "guest_submission"}


@pytest.fixture
def guard(monkeypatch):
    monkeypatch.setenv("BUSINESS_TURNSTILE_SITE_KEY", "site-key-fixture")
    monkeypatch.setenv("BUSINESS_TURNSTILE_SECRET_KEY", "secret-key-fixture")
    return SubmissionGuard.from_origin(ORIGIN)


def provider(monkeypatch, *, value=None, body=None, status=200, headers=None, exception=None):
    calls = []
    configurations = []
    real_client = httpx.Client

    def handler(request):
        calls.append(request)
        if exception:
            raise exception
        encoded = body if body is not None else json.dumps(value if value is not None else SUCCESS).encode()
        return httpx.Response(status, stream=httpx.ByteStream(encoded), headers=headers)

    def client(**kwargs):
        configurations.append(kwargs)
        return real_client(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(abuse.httpx, "Client", client)
    return calls, configurations


@pytest.mark.parametrize("origin", ["http://localhost:8091", "http://127.0.0.1:8091", "http://[::1]:8091"])
def test_loopback_requires_rules_without_contacting_external_challenge(monkeypatch, origin):
    monkeypatch.delenv("BUSINESS_TURNSTILE_SITE_KEY", raising=False)
    monkeypatch.delenv("BUSINESS_TURNSTILE_SECRET_KEY", raising=False)
    local = SubmissionGuard.from_origin(origin)
    calls, _ = provider(monkeypatch)
    assert local.public_config() == {"provider": "none", "site_key": None, "required": False}
    local.verify(None)
    assert calls == []
    with pytest.raises(HTTPException) as error:
        local.validate_policy(PUBLIC_RULES["version"], False)
    assert error.value.status_code == 422


@pytest.mark.parametrize("accepted", [False, None, 1, "true"])
def test_policy_requires_explicit_true(guard, accepted):
    with pytest.raises(HTTPException) as error:
        guard.validate_policy(PUBLIC_RULES["version"], accepted)
    assert error.value.status_code == 422


def test_policy_rejects_stale_version_and_accepts_current(guard):
    with pytest.raises(HTTPException):
        guard.validate_policy("old-rules", True)
    guard.validate_policy(PUBLIC_RULES["version"], True)


@pytest.mark.parametrize("missing", ["BUSINESS_TURNSTILE_SITE_KEY", "BUSINESS_TURNSTILE_SECRET_KEY"])
def test_https_fails_startup_without_configured_challenge(guard, monkeypatch, missing):
    monkeypatch.delenv(missing)
    with pytest.raises(ValueError, match="HTTPS requires"):
        SubmissionGuard.from_origin(ORIGIN)


@pytest.mark.parametrize("key", sorted(abuse._TEST_KEYS))
def test_public_host_rejects_official_dummy_keys(guard, monkeypatch, key):
    variable = "BUSINESS_TURNSTILE_SECRET_KEY" if len(key) > 30 else "BUSINESS_TURNSTILE_SITE_KEY"
    monkeypatch.setenv(variable, key)
    with pytest.raises(ValueError, match="real Turnstile"):
        SubmissionGuard.from_origin(ORIGIN)


def test_public_config_never_contains_secret(guard):
    assert guard.public_config() == {"provider": "turnstile", "site_key": "site-key-fixture", "required": True}
    assert guard.secret_key not in repr(guard)
    assert guard.secret_key not in json.dumps(guard.public_config())


@pytest.mark.parametrize("origin", ["http://example-dashboard.mikebyrne.ai", "https://example.com/path", "https://user:password@example.com"])
def test_invalid_origin_cannot_choose_local_bypass(origin):
    with pytest.raises(ValueError):
        SubmissionGuard.from_origin(origin)


def test_verified_response_uses_fixed_endpoint_and_bounded_nonredirecting_client(guard, monkeypatch):
    calls, configs = provider(monkeypatch)
    guard.verify("a-valid-token", "192.0.2.18")
    assert str(calls[0].url) == abuse.SITEVERIFY_URL
    assert calls[0].method == "POST"
    assert parse_qs(calls[0].content.decode()) == {
        "secret": [guard.secret_key], "response": ["a-valid-token"],
    }
    assert configs[0]["follow_redirects"] is False
    assert configs[0]["trust_env"] is False
    assert configs[0]["timeout"].read == 5.0
    assert configs[0]["timeout"].connect == 3.0


@pytest.mark.parametrize("peer", [
    None, "testclient", "1.1.1.1", "10.0.0.1", "127.0.0.1", "::1",
    "2606:4700:4700::1111", "192.0.2.1, 203.0.113.4", "CF-Connecting-IP: 192.0.2.1",
])
def test_transport_peer_is_never_asserted_as_visitor_ip(guard, monkeypatch, peer):
    calls, _ = provider(monkeypatch)
    guard.verify("a-valid-token", peer)
    assert "remoteip" not in parse_qs(calls[0].content.decode())


@pytest.mark.parametrize("token", [None, "", "x" * 2049, "a token", "\u2603", 1])
def test_missing_or_malformed_token_never_contacts_provider(guard, monkeypatch, token):
    calls, _ = provider(monkeypatch)
    with pytest.raises(HTTPException) as error:
        guard.verify(token)
    assert error.value.status_code == 422
    assert calls == []


@pytest.mark.parametrize("value", [
    {}, [], True,
    {**SUCCESS, "success": False}, {**SUCCESS, "success": "true"}, {**SUCCESS, "success": 1},
    {**SUCCESS, "hostname": "localhost"}, {**SUCCESS, "hostname": "attacker.example"},
    {**SUCCESS, "action": "login"},
    {"success": False, "error-codes": ["timeout-or-duplicate"]},
])
def test_failed_expired_replayed_or_misbound_tokens_are_denied(guard, monkeypatch, value):
    provider(monkeypatch, value=value)
    with pytest.raises(HTTPException) as error:
        guard.verify("a-valid-token")
    assert error.value.status_code == 403


@pytest.mark.parametrize("parameters", [
    {"body": b"not-json"}, {"body": b"\xff"},
    {"body": b"x" * (abuse.MAX_PROVIDER_BYTES + 1)},
    {"status": 302, "headers": {"location": "https://attacker.example"}},
    {"status": 429}, {"status": 500},
    {"headers": {"content-encoding": "gzip"}},
    {"exception": httpx.ReadTimeout("private token must not appear")},
    {"exception": httpx.ConnectError("private secret must not appear")},
])
def test_provider_failures_fail_closed_without_sensitive_error_text(guard, monkeypatch, parameters, caplog):
    calls, _ = provider(monkeypatch, **parameters)
    with pytest.raises(HTTPException) as error:
        guard.verify("private-token-fixture")
    assert error.value.status_code == 503
    assert error.value.detail == "Verification is unavailable. Please try again later."
    assert len(calls) == 1
    assert "private" not in caplog.text
    assert guard.secret_key not in caplog.text


def test_provider_response_must_finish_within_deadline(guard, monkeypatch):
    provider(monkeypatch)
    times = iter([0.0, abuse.PROVIDER_DEADLINE_SECONDS + 0.1])
    monkeypatch.setattr(abuse, "time", SimpleNamespace(monotonic=lambda: next(times)))
    with pytest.raises(HTTPException) as error:
        guard.verify("a-valid-token")
    assert error.value.status_code == 503


def test_spoofed_forwarding_headers_cannot_downgrade_challenge_or_change_hostname(guard, monkeypatch):
    app = FastAPI()
    app.add_middleware(RequestSecurityMiddleware, public_origin=ORIGIN, challenge_required=guard.required)

    @app.post("/")
    def submit(request: Request):
        guard.verify("a-valid-token", request.client.host)
        return {"accepted": True}

    with TestClient(app, base_url=ORIGIN) as client:
        calls, _ = provider(monkeypatch, value={**SUCCESS, "hostname": "localhost"})
        response = client.post("/", json={}, headers={
            "Origin": ORIGIN, "X-Forwarded-Host": "localhost", "X-Forwarded-Proto": "http",
            "X-Forwarded-For": "127.0.0.1", "CF-Connecting-IP": "127.0.0.1",
        })
    assert response.status_code == 403
    assert len(calls) == 1
    assert "remoteip" not in parse_qs(calls[0].content.decode())


@pytest.mark.parametrize("required", [False, True])
def test_challenge_csp_grants_only_its_exact_service_origin(required):
    app = FastAPI()
    app.add_middleware(RequestSecurityMiddleware, public_origin=ORIGIN, challenge_required=required)

    @app.get("/")
    def index():
        return {"ok": True}

    with TestClient(app, base_url=ORIGIN) as client:
        response = client.get("/")
    policy = response.headers["content-security-policy"]
    assert ("https://challenges.cloudflare.com" in policy) is required
    assert "unsafe-inline" not in policy
    assert "*" not in policy
    if required:
        assert "script-src 'self' https://challenges.cloudflare.com" in policy
        assert "frame-src https://challenges.cloudflare.com" in policy
