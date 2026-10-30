"""Durable, transactional team-board budgets using disposable local accounts."""

from concurrent.futures import ThreadPoolExecutor
import sqlite3
from threading import Barrier

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    Actor, ORIGIN, business as business, business_admin as business_admin,
    business_seed as business_seed,
)
from business import app as app_module, message_limits  # noqa: E402
from business.app import create_app  # noqa: E402
from business.security import COOKIE_NAME  # noqa: E402


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    def forbid(self, request):
        raise AssertionError("Team-message regressions must not make external requests")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbid)


def _post(actor, body="A disposable team message", **kwargs):
    return actor.request("POST", "/api/messages", json={"body": body}, **kwargs)


def _limits(business):
    with business.db() as connection:
        return [tuple(row) for row in connection.execute(
            "SELECT key_hash,window_start,attempts FROM login_limits ORDER BY key_hash",
        )]


def _messages_and_activity(business):
    with business.db() as connection:
        return tuple(tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1"))
                     for table in ("messages", "activity"))


def _same_session(business, actor, *, app=None):
    client = business.client(app=app)
    client.cookies.set(COOKIE_NAME, actor.client.cookies.get(COOKIE_NAME))
    return Actor(client, actor.profile, actor.csrf)


@pytest.mark.parametrize("username", ["alex", "admin"])
def test_minute_quota_accepts_ten_then_rejects_without_mutation(business, monkeypatch, username):
    actor = business.login(username)
    monkeypatch.setattr(message_limits, "current_time", lambda: 10_000.0)
    for index in range(message_limits.MESSAGE_MINUTE_LIMIT):
        assert _post(actor, f"Accepted message {index}").status_code == 201
    before, limits = _messages_and_activity(business), _limits(business)
    blocked = _post(actor)
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "60"
    assert _messages_and_activity(business) == before
    assert _limits(business) == limits
    assert actor.request("GET", "/api/messages").status_code == 200
    assert business.client().get("/healthz").status_code == 200


def test_quota_is_shared_across_sessions_instances_restart_and_new_login(business, monkeypatch):
    first, second = business.login("alex"), business.login("alex")
    monkeypatch.setattr(message_limits, "current_time", lambda: 10_000.0)
    for index in range(message_limits.MESSAGE_MINUTE_LIMIT):
        assert _post((first, second)[index % 2]).status_code == 201
    restarted_app = create_app(business.directory, public_origin=ORIGIN)
    restarted = _same_session(business, first, app=restarted_app)
    fresh = business.login("alex")
    for actor in (first, second, restarted, fresh):
        assert _post(actor).status_code == 429
    # A different account has its own budget; changing the browser cannot reset it.
    assert _post(business.login("blair")).status_code == 201
    assert len(_limits(business)) == 4


def test_clock_boundary_and_retry_after_are_exact_and_backwards_clock_does_not_reset(business, monkeypatch):
    actor = business.login("alex")
    monkeypatch.setattr(message_limits, "current_time", lambda: 10_000.0)
    for _ in range(message_limits.MESSAGE_MINUTE_LIMIT):
        assert _post(actor).status_code == 201
    monkeypatch.setattr(message_limits, "current_time", lambda: 10_059.001)
    blocked = _post(actor)
    assert blocked.status_code == 429 and blocked.headers["Retry-After"] == "1"
    monkeypatch.setattr(message_limits, "current_time", lambda: 9_999.0)
    blocked = _post(actor)
    assert blocked.status_code == 429 and blocked.headers["Retry-After"] == "61"
    monkeypatch.setattr(message_limits, "current_time", lambda: 10_060.0)
    assert _post(actor).status_code == 201
    assert sorted(row[2] for row in _limits(business)) == [1, 11]


def test_hour_quota_survives_minute_resets_and_denials_do_not_extend_it(business, monkeypatch):
    actor = business.login("alex")
    now = 10_000.0
    monkeypatch.setattr(message_limits, "current_time", lambda: now)
    for minute in range(10):
        now = 10_000.0 + minute * 60
        for _ in range(message_limits.MESSAGE_MINUTE_LIMIT):
            assert _post(actor).status_code == 201
    now = 10_600.0
    limits = _limits(business)
    blocked = _post(actor)
    assert blocked.status_code == 429 and blocked.headers["Retry-After"] == "3000"
    assert _limits(business) == limits
    now = 13_599.5
    assert _post(actor).headers["Retry-After"] == "1"
    now = 13_600.0
    assert _post(actor).status_code == 201
    assert [row[2] for row in _limits(business)] == [1, 1]


def test_concurrent_last_budget_slot_is_accepted_once_across_app_instances(business, monkeypatch):
    actor = business.login("alex")
    monkeypatch.setattr(message_limits, "current_time", lambda: 10_000.0)
    for _ in range(message_limits.MESSAGE_MINUTE_LIMIT - 1):
        assert _post(actor).status_code == 201
    actors = [_same_session(business, actor, app=create_app(business.directory, public_origin=ORIGIN))
              for _ in range(4)]
    gate = Barrier(len(actors))

    def post(candidate):
        gate.wait(timeout=10)
        return _post(candidate).status_code

    before = len(_messages_and_activity(business)[0])
    with ThreadPoolExecutor(max_workers=len(actors)) as executor:
        statuses = list(executor.map(post, actors))
    assert sorted(statuses) == [201, 429, 429, 429]
    assert len(_messages_and_activity(business)[0]) == before + 1
    assert [row[2] for row in _limits(business)] == [10, 10]


def test_global_capacity_preserves_history_and_refuses_new_messages_for_all_accounts(business, monkeypatch):
    alex, admin = business.login("alex"), business.login("admin")
    initial = len(_messages_and_activity(business)[0])
    monkeypatch.setattr(message_limits, "MESSAGE_CAPACITY", initial + 1)
    assert _post(alex).status_code == 201
    before, limits = _messages_and_activity(business), _limits(business)
    for actor in (alex, admin):
        response = _post(actor)
        assert response.status_code == 507
        assert "operator" in response.json()["detail"]
        assert "back up" in response.json()["detail"]
    assert _messages_and_activity(business) == before
    assert _limits(business) == limits
    assert alex.request("GET", "/api/messages").status_code == 200


def test_concurrent_final_capacity_slot_is_accepted_once(business, monkeypatch):
    actors = [business.login(username) for username in ("alex", "blair", "admin")]
    before = len(_messages_and_activity(business)[0])
    monkeypatch.setattr(message_limits, "MESSAGE_CAPACITY", before + 1)
    gate = Barrier(len(actors))

    def post(actor):
        gate.wait(timeout=10)
        return _post(actor).status_code

    with ThreadPoolExecutor(max_workers=len(actors)) as executor:
        statuses = list(executor.map(post, actors))
    assert sorted(statuses) == [201, 507, 507]
    assert len(_messages_and_activity(business)[0]) == before + 1
    assert len(_limits(business)) == 2


def test_existing_over_capacity_board_is_preserved_on_restart(business, monkeypatch):
    actor = business.login("alex")
    before = _messages_and_activity(business)
    monkeypatch.setattr(message_limits, "MESSAGE_CAPACITY", len(before[0]) - 1)
    restarted = _same_session(business, actor, app=create_app(business.directory, public_origin=ORIGIN))
    assert _post(restarted).status_code == 507
    assert _messages_and_activity(business) == before
    assert not _limits(business)


def test_audit_failure_rolls_back_message_and_both_quota_charges(business, monkeypatch):
    actor = business.login("alex")
    before, limits = _messages_and_activity(business), _limits(business)
    record_activity = app_module.record_activity

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("Disposable audit write failure")

    monkeypatch.setattr(app_module, "record_activity", fail)
    assert _post(actor).status_code == 503
    assert _messages_and_activity(business) == before
    assert _limits(business) == limits
    monkeypatch.setattr(app_module, "record_activity", record_activity)
    assert _post(actor).status_code == 201
    assert [row[2] for row in _limits(business)] == [1, 1]


def test_denied_or_malformed_writes_do_not_spend_budget(business, business_admin):
    actor = business.login("alex")
    assert business.client().post("/api/messages", json={"body": "Guest attempt"},
                                  headers={"Origin": ORIGIN}).status_code == 401
    assert _post(actor, headers={"X-CSRF-Token": "invalid"}).status_code == 403
    assert _post(actor, headers={"Origin": "https://attacker.invalid"}).status_code == 403
    assert _post(actor, body="").status_code == 422
    assert _post(actor, body="x" * 4001).status_code == 422
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    assert _post(actor).status_code == 403
    assert _post(business_admin).status_code == 403
    assert not _limits(business)
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": 1}).status_code == 200
    assert _post(actor).status_code == 201


def test_other_limit_namespaces_are_preserved(business, monkeypatch):
    actor = business.login("alex")
    with business.db() as connection:
        connection.execute("INSERT INTO login_limits VALUES(?,?,?)", ("other-route", 1.0, 87))
    monkeypatch.setattr(message_limits, "current_time", lambda: 10_000.0)
    assert _post(actor).status_code == 201
    monkeypatch.setattr(message_limits, "current_time", lambda: 20_000.0)
    assert _post(actor).status_code == 201
    assert ("other-route", 1.0, 87) in _limits(business)
    assert len(_limits(business)) == 3


@pytest.mark.parametrize("constraint,status", [("quota", 429), ("capacity", 507)])
def test_saved_receipt_replays_after_quota_or_capacity_is_full(business, monkeypatch, constraint, status):
    actor = business.login("alex")
    monkeypatch.setattr(message_limits, "current_time", lambda: 10_000.0)
    headers = {"Idempotency-Key": "disposable-message-key"}
    accepted = _post(actor, body="Saved once", headers=headers)
    assert accepted.status_code == 201
    if constraint == "quota":
        for _ in range(message_limits.MESSAGE_MINUTE_LIMIT - 1):
            assert _post(actor).status_code == 201
    else:
        monkeypatch.setattr(message_limits, "MESSAGE_CAPACITY", len(_messages_and_activity(business)[0]))
    before, limits = _messages_and_activity(business), _limits(business)
    replay = _post(actor, body="Saved once", headers=headers)
    assert replay.status_code == 201 and replay.json() == accepted.json()
    assert _post(actor, body="Changed payload", headers=headers).status_code == 409
    assert _post(actor, headers={"Idempotency-Key": "disposable-new-message-key"}).status_code == status
    assert _messages_and_activity(business) == before
    assert _limits(business) == limits
