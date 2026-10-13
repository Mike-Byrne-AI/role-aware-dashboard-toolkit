"""API startup warnings and request size limits."""
from __future__ import annotations

import logging

import pytest

from role_aware_dashboard_toolkit import ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app

pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
KEY_ENV = "ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY"


def _registry() -> ControlRegistry:
    registry = ControlRegistry()
    registry.register("Banner", kind="text", key="banner", default="ready")
    return registry


def _key_warnings(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records
            if record.name == "role_aware_dashboard_toolkit.api" and KEY_ENV in record.getMessage()]


def test_create_app_warns_when_every_protected_route_would_return_401(monkeypatch, caplog):
    monkeypatch.delenv(KEY_ENV, raising=False)
    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS", raising=False)

    with caplog.at_level(logging.WARNING, logger="role_aware_dashboard_toolkit.api"):
        create_app(_registry())

    warnings = _key_warnings(caplog)
    assert len(warnings) == 1
    assert "401" in warnings[0]
    assert all(record.levelno == logging.WARNING for record in caplog.records
               if KEY_ENV in record.getMessage())


@pytest.mark.parametrize("configured", ["key", "anonymous"])
def test_create_app_is_quiet_when_requests_can_succeed(monkeypatch, caplog, configured):
    if configured == "key":
        monkeypatch.setenv(KEY_ENV, "synthetic-startup-key")
        kwargs = {}
    else:
        monkeypatch.delenv(KEY_ENV, raising=False)
        kwargs = {"allow_anonymous": True}

    with caplog.at_level(logging.WARNING, logger="role_aware_dashboard_toolkit.api"):
        create_app(_registry(), **kwargs)

    assert _key_warnings(caplog) == []


HEADERS = {"X-API-Key": "synthetic-limit-key", "Content-Type": "application/json"}


def _client(monkeypatch, store, **kwargs):
    from fastapi.testclient import TestClient

    monkeypatch.setenv(KEY_ENV, HEADERS["X-API-Key"])
    return TestClient(create_app(_registry(), profile_store=store, api_role="Admin", **kwargs))


def _nested(depth: int) -> str:
    return "[" * depth + "]" * depth


def test_default_body_limit_refuses_an_oversized_request(monkeypatch):
    store = InMemoryProfileStore()
    body = '{"profile_id":"big","extra":{"x":"' + "A" * (2 * 1024 * 1024) + '"}}'

    response = _client(monkeypatch, store).post("/profiles", headers=HEADERS, content=body)

    assert response.status_code == 413
    assert "1048576 bytes" in response.json()["detail"]
    assert store.list_ids() == []


def test_body_limit_counts_a_streamed_body_without_content_length(monkeypatch):
    store = InMemoryProfileStore()
    client = _client(monkeypatch, store, max_body_bytes=1024)

    def chunks():
        yield b'{"profile_id":"streamed","extra":{"x":"'
        for _ in range(8):
            yield b"A" * 512
        yield b'"}}'

    response = client.post("/profiles", headers=HEADERS, content=chunks())

    assert response.status_code == 413
    assert store.list_ids() == []


def test_body_limit_is_configurable_and_allows_requests_within_it(monkeypatch):
    store = InMemoryProfileStore()
    client = _client(monkeypatch, store, max_body_bytes=4096)
    small = '{"profile_id":"small","extra":{"x":"' + "A" * 1024 + '"}}'
    large = '{"profile_id":"large","extra":{"x":"' + "A" * 8192 + '"}}'

    assert client.post("/profiles", headers=HEADERS, content=small).status_code == 200
    assert client.post("/profiles", headers=HEADERS, content=large).status_code == 413
    assert store.list_ids() == ["small"]


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "1024"])
def test_body_limit_must_be_a_positive_integer(monkeypatch, limit):
    monkeypatch.setenv(KEY_ENV, "synthetic-limit-key")

    with pytest.raises(ValueError, match="max_body_bytes"):
        create_app(_registry(), max_body_bytes=limit)


@pytest.mark.parametrize("depth,status", [(32, 200), (33, 422), (500, 422), (5000, 422)])
def test_profile_extra_nesting_is_limited(monkeypatch, depth, status):
    store = InMemoryProfileStore()
    body = '{"profile_id":"deep","extra":{"x":' + _nested(depth - 1) + "}}"

    response = _client(monkeypatch, store).post("/profiles", headers=HEADERS, content=body)

    assert response.status_code == status
    assert store.list_ids() == (["deep"] if status == 200 else [])
    if status == 422:
        assert "extra" in response.json()["detail"]


def test_control_value_nesting_is_limited_before_validation(monkeypatch):
    store = InMemoryProfileStore()
    body = '{"values":{"banner":' + _nested(500) + "}}"

    response = _client(monkeypatch, store).patch("/controls", headers=HEADERS, content=body)

    assert response.status_code == 422
    assert "banner" in response.json()["detail"]


def test_deep_json_in_a_rejected_field_is_a_validation_error(monkeypatch):
    store = InMemoryProfileStore()
    client = _client(monkeypatch, store)

    patched = client.patch("/controls", headers=HEADERS,
                           content='{"values":{},"unexpected":' + _nested(5000) + "}")
    saved = client.post("/profiles", headers=HEADERS,
                        content='{"profile_id":' + _nested(5000) + "}")

    assert patched.status_code == 422
    assert saved.status_code == 422
    assert store.list_ids() == []


def test_validation_errors_do_not_echo_submitted_values(monkeypatch):
    client = _client(monkeypatch, InMemoryProfileStore())

    response = client.post("/profiles", headers=HEADERS,
                           json={"profile_id": "x", "token": "SUBMITTED-CANARY"})

    assert response.status_code == 422
    assert "SUBMITTED-CANARY" not in response.text
    assert [error["loc"] for error in response.json()["detail"]] == [["body", "token"]]


def test_an_absurd_content_length_is_refused_not_crashed():
    import asyncio

    from role_aware_dashboard_toolkit.api import _RequestBodyLimit

    sent = []

    async def app(scope, receive, send):
        raise AssertionError("the route must not run")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/profiles",
             "headers": [(b"content-length", b"9" * 5000)]}
    asyncio.run(_RequestBodyLimit(app, 1024)(scope, receive, send))

    assert sent[0]["status"] == 413
