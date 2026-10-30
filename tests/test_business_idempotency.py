"""Authenticated create retries on disposable storage and real route checks."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
from threading import Barrier

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    ORIGIN, business as business, business_admin as business_admin,
    business_seed as business_seed, contact_body, event_body, post_body,
)
from business import app as app_module, idempotency, message_limits, models  # noqa: E402
from business.app import create_app  # noqa: E402
from business.security import COOKIE_NAME, token_hash  # noqa: E402

KEY = "synthetic-retry-key-000000000001"


def _counts(trial):
    with trial.db() as connection:
        return tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                     for table in ("events", "assignments", "messages", "contacts", "posts", "activity", "create_receipts"))


def _create(actor, path, payload, key=KEY, **kwargs):
    headers = {"Idempotency-Key": key}
    headers.update(kwargs.pop("headers", {}))
    return actor.request("POST", path, json=payload, headers=headers, **kwargs)


@pytest.mark.parametrize("path,body,result", [
    ("/api/schedule", event_body, "event"),
    ("/api/messages", lambda: {"body": "One synthetic team message"}, "message"),
    ("/api/admin/contacts", contact_body, "contact"),
    ("/api/admin/posts", post_body, "post"),
])
def test_exact_create_retry_replays_once_without_mutation_or_extra_activity(business, business_admin, path, body, result):
    payload = body()
    first = _create(business_admin, path, payload)
    assert first.status_code == 201
    before = _counts(business)
    replay = _create(business_admin, path, payload)
    assert replay.status_code == 201
    assert replay.json() == first.json()
    assert result in replay.json()
    assert _counts(business) == before
    with business.db() as connection:
        row = connection.execute("SELECT key_hash,response_json FROM create_receipts").fetchone()
        assert row["key_hash"] == hashlib.sha256(KEY.encode()).hexdigest()
        assert KEY not in row["response_json"]


def test_completed_event_replays_after_authorization_without_allowing_new_past_writes(
    business, business_admin, monkeypatch,
):
    # Isolate this short event from fictional seed assignments at any clock time.
    with business.db() as connection:
        connection.execute("UPDATE events SET archived=1")
    started = datetime.now(timezone.utc).replace(microsecond=0)
    payload = event_body(
        title="Short completed event retry",
        starts_at=(started + timedelta(minutes=1)).isoformat(),
        ends_at=(started + timedelta(minutes=2)).isoformat(),
        employee_ids=["alex"],
    )
    first = _create(business_admin, "/api/schedule", payload)
    assert first.status_code == 201
    before = _counts(business)

    class FinishedEventTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return (started + timedelta(minutes=3)).astimezone(tz)

    # Move the schedule clock three minutes, within receipt/session lifetimes.
    # Patching both sites catches a future-time check moved back into the model.
    monkeypatch.setattr(app_module, "datetime", FinishedEventTime)
    monkeypatch.setattr(models, "datetime", FinishedEventTime)
    assert _create(business_admin, "/api/schedule", payload,
                   headers={"X-CSRF-Token": "invalid"}).status_code == 403
    assert business.client().post("/api/schedule", json=payload, headers={
        "Origin": ORIGIN, "Idempotency-Key": KEY,
    }).status_code == 401
    replay = _create(business_admin, "/api/schedule", payload)
    assert replay.status_code == 201
    assert replay.json() == first.json()

    assert _create(business_admin, "/api/schedule", payload, "new-past-event-key-00002").status_code == 422
    assert business_admin.request("POST", "/api/schedule", json=payload).status_code == 422
    event = first.json()["event"]
    assert business_admin.request("PUT", f"/api/schedule/{event['id']}", json={
        **payload, "revision": event["revision"],
    }).status_code == 422
    assert _counts(business) == before
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM events WHERE title=?", (payload["title"],)).fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM activity WHERE action='Scheduled work' AND target=?",
                                  (payload["title"],)).fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM create_receipts").fetchone()[0] == 1


def test_receipt_survives_restart_and_normalized_payload_order(business, business_admin):
    payload = contact_body()
    first = _create(business_admin, "/api/admin/contacts", payload)
    assert first.status_code == 201
    replacement = business.client(create_app(business.directory, public_origin=ORIGIN))
    replacement.cookies.update(business_admin.client.cookies)
    retry = replacement.post("/api/admin/contacts", json=dict(reversed(list(payload.items()))), headers={
        "Origin": ORIGIN, "X-CSRF-Token": business_admin.csrf, "Idempotency-Key": KEY,
    })
    assert retry.status_code == 201
    assert retry.json() == first.json()


@pytest.mark.parametrize("path,body,count_index", [
    ("/api/admin/contacts", contact_body, 3), ("/api/messages", lambda: {"body": "Concurrent retry"}, 2),
])
def test_concurrent_same_key_creates_one_record_and_one_activity(business, business_admin, path, body, count_index):
    clients = [business.client(), business.client()]
    for client in clients:
        client.cookies.update(business_admin.client.cookies)
    barrier = Barrier(2)
    before = _counts(business)

    def save(client):
        barrier.wait(timeout=10)
        return client.post(path, json=body(), headers={
            "Origin": ORIGIN, "X-CSRF-Token": business_admin.csrf, "Idempotency-Key": KEY,
        })

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(save, clients))
    assert [response.status_code for response in responses] == [201, 201]
    assert responses[0].json() == responses[1].json()
    after = _counts(business)
    assert after[count_index] == before[count_index] + 1
    assert after[-2:] == (before[-2] + 1, before[-1] + 1)
    if path == "/api/messages":
        with business.db() as connection:
            for window in (60, 3600):
                key = message_limits._key(business.app.state.database, "admin", window)
                assert connection.execute("SELECT attempts FROM login_limits WHERE key_hash=?", (key,)).fetchone()[0] == 1


def test_same_key_changed_content_is_conflict_without_another_write(business, business_admin):
    first = _create(business_admin, "/api/admin/contacts", contact_body())
    assert first.status_code == 201
    before = _counts(business)
    changed = _create(business_admin, "/api/admin/contacts", contact_body(notes="Different intent"))
    assert changed.status_code == 409
    assert _counts(business) == before
    assert _create(business_admin, "/api/admin/contacts", contact_body()).json() == first.json()


def test_same_key_is_independent_for_different_accounts_and_endpoints(business, business_admin):
    alex, blair = business.login("alex"), business.login("blair")
    one = _create(alex, "/api/messages", {"body": "Shared words do not mean shared identity"})
    two = _create(blair, "/api/messages", {"body": "Shared words do not mean shared identity"})
    contact = _create(business_admin, "/api/admin/contacts", contact_body())
    post = _create(business_admin, "/api/admin/posts", post_body())
    assert [response.status_code for response in (one, two, contact, post)] == [201] * 4
    assert one.json()["message"]["id"] != two.json()["message"]["id"]
    assert one.json()["message"]["author"] != two.json()["message"]["author"]
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM create_receipts").fetchone()[0] == 4


def test_message_replay_does_not_consume_quota_or_fail_when_budget_is_exhausted(business, monkeypatch):
    actor = business.login("alex")
    monkeypatch.setattr(message_limits, "MESSAGE_MINUTE_LIMIT", 1)
    first = _create(actor, "/api/messages", {"body": "One accepted posting"})
    assert first.status_code == 201
    before = _counts(business)
    for _ in range(3):
        replay = _create(actor, "/api/messages", {"body": "One accepted posting"})
        assert replay.status_code == 201
        assert replay.json() == first.json()
    assert _create(actor, "/api/messages", {"body": "Another posting"}, "another-synthetic-key-0002").status_code == 429
    assert _counts(business) == before
    with business.db() as connection:
        for window in (60, 3600):
            key = message_limits._key(business.app.state.database, "alex", window)
            assert connection.execute("SELECT attempts FROM login_limits WHERE key_hash=?", (key,)).fetchone()[0] == 1


def test_missing_key_preserves_optional_api_contract(business, business_admin):
    first = business_admin.request("POST", "/api/admin/contacts", json=contact_body())
    second = business_admin.request("POST", "/api/admin/contacts", json=contact_body())
    assert first.status_code == second.status_code == 201
    assert first.json()["contact"]["id"] != second.json()["contact"]["id"]
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM create_receipts").fetchone()[0] == 0


@pytest.mark.parametrize("key", ["", "too-short", "x" * 129, "invalid key with spaces", "invalid/key/with/slashes"])
def test_malformed_key_rejected_without_save(business, business_admin, key):
    before = _counts(business)
    assert _create(business_admin, "/api/admin/contacts", contact_body(), key).status_code == 422
    assert _counts(business) == before


def test_duplicate_key_headers_rejected_without_save(business, business_admin):
    before = _counts(business)
    response = business_admin.client.post("/api/admin/contacts", json=contact_body(), headers=[
        ("Origin", ORIGIN), ("X-CSRF-Token", business_admin.csrf),
        ("Idempotency-Key", KEY), ("Idempotency-Key", KEY),
    ])
    assert response.status_code == 422
    assert _counts(business) == before


@pytest.mark.parametrize("change,status", [
    ("revoked", 401), ("inactive", 401), ("demoted", 403), ("frozen", 403),
    ("csrf", 403), ("origin", 403), ("mfa", 401),
])
def test_current_authorization_is_checked_before_receipt_replay(business, business_admin, change, status):
    payload = contact_body()
    assert _create(business_admin, "/api/admin/contacts", payload).status_code == 201
    with business.db() as connection:
        if change == "revoked":
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(business_admin.client.cookies[COOKIE_NAME]),))
        elif change == "inactive":
            connection.execute("UPDATE users SET active=0 WHERE id='admin'")
        elif change == "demoted":
            connection.execute("UPDATE users SET role='employee' WHERE id='admin'")
        elif change == "frozen":
            connection.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1 WHERE id=1")
        elif change == "mfa":
            connection.execute("UPDATE admin_mfa SET generation='replacement-generation' WHERE user_id='admin'")
    headers = {"X-CSRF-Token": "invalid"} if change == "csrf" else {"Origin": "https://foreign.invalid"} if change == "origin" else {}
    before = _counts(business)
    response = _create(business_admin, "/api/admin/contacts", payload, headers=headers)
    assert response.status_code == status
    assert "Private outreach canary" not in response.text
    assert _counts(business) == before


@pytest.mark.parametrize("username,status", [(None, 401), ("alex", 403)])
def test_other_roles_cannot_disclose_an_admin_receipt(business, business_admin, username, status):
    assert _create(business_admin, "/api/admin/contacts", contact_body()).status_code == 201
    actor = business.login(username) if username else None
    client = actor.client if actor else business.client()
    before = _counts(business)
    response = client.post("/api/admin/contacts", json=contact_body(), headers={
        "Origin": ORIGIN, "Idempotency-Key": KEY, "X-CSRF-Token": actor.csrf if actor else "invalid",
    })
    assert response.status_code == status
    assert "Private outreach canary" not in response.text
    assert _counts(business) == before


def test_rejected_creation_does_not_consume_key(business, business_admin):
    bad = event_body(employee_ids=["missing-employee"])
    assert _create(business_admin, "/api/schedule", bad).status_code == 422
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM create_receipts").fetchone()[0] == 0
    good = {**bad, "employee_ids": ["alex"]}
    assert _create(business_admin, "/api/schedule", good).status_code == 201


def test_audit_failure_rolls_back_mutation_and_receipt_then_retry_succeeds(business, business_admin, monkeypatch):
    before = _counts(business)

    def fail(*args):
        raise sqlite3.OperationalError("Synthetic audit failure")

    with monkeypatch.context() as patch:
        patch.setattr(app_module, "record_activity", fail)
        assert _create(business_admin, "/api/admin/contacts", contact_body()).status_code == 503
    assert _counts(business) == before
    assert _create(business_admin, "/api/admin/contacts", contact_body()).status_code == 201


@pytest.mark.parametrize("path,body", [
    ("/api/admin/contacts", contact_body), ("/api/messages", lambda: {"body": "Atomic posting quota"}),
])
def test_receipt_insert_failure_rolls_back_business_write_and_activity(business, business_admin, path, body):
    with business.db() as connection:
        connection.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON create_receipts BEGIN SELECT RAISE(ABORT,'synthetic receipt failure'); END")
    before = _counts(business)
    with business.db() as connection:
        quota_before = [tuple(row) for row in connection.execute("SELECT * FROM login_limits ORDER BY key_hash")]
    assert _create(business_admin, path, body()).status_code == 503
    assert _counts(business) == before
    with business.db() as connection:
        assert [tuple(row) for row in connection.execute("SELECT * FROM login_limits ORDER BY key_hash")] == quota_before
        connection.execute("DROP TRIGGER fail_receipt")
    assert _create(business_admin, path, body()).status_code == 201


@pytest.mark.parametrize("limit", ["MAX_RECEIPTS_PER_USER", "MAX_RECEIPTS"])
def test_capacity_preserves_existing_replay_and_rejects_new_key(business, business_admin, monkeypatch, limit):
    first = _create(business_admin, "/api/admin/contacts", contact_body())
    assert first.status_code == 201
    monkeypatch.setattr(idempotency, limit, 1)
    before = _counts(business)
    full = _create(business_admin, "/api/admin/contacts", contact_body(), "different-synthetic-key-00002")
    assert full.status_code == 503
    assert full.headers["retry-after"] == "60"
    assert _counts(business) == before
    assert _create(business_admin, "/api/admin/contacts", contact_body()).json() == first.json()


def test_expired_receipt_frees_capacity_and_key_has_no_permanent_deduplication(business, business_admin, monkeypatch):
    first = _create(business_admin, "/api/admin/contacts", contact_body())
    assert first.status_code == 201
    monkeypatch.setattr(idempotency, "MAX_RECEIPTS", 1)
    with business.db() as connection:
        connection.execute("UPDATE create_receipts SET created_at=created_at-?", (idempotency.RECEIPT_SECONDS + 1,))
    later = _create(business_admin, "/api/admin/contacts", contact_body())
    assert later.status_code == 201
    assert later.json()["contact"]["id"] != first.json()["contact"]["id"]
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM create_receipts").fetchone()[0] == 1


def test_clock_moving_backwards_does_not_discard_a_saved_receipt(business, business_admin):
    first = _create(business_admin, "/api/admin/contacts", contact_body())
    assert first.status_code == 201
    with business.db() as connection:
        connection.execute("UPDATE create_receipts SET created_at=created_at+?", (idempotency.RECEIPT_SECONDS,))
    before = _counts(business)
    assert _create(business_admin, "/api/admin/contacts", contact_body()).json() == first.json()
    assert _counts(business) == before


def test_corrupt_receipt_cannot_be_reinterpreted_as_a_new_write(business, business_admin):
    assert _create(business_admin, "/api/admin/contacts", contact_body()).status_code == 201
    with business.db() as connection:
        connection.execute("UPDATE create_receipts SET response_json='not-json'")
    before = _counts(business)
    assert _create(business_admin, "/api/admin/contacts", contact_body()).status_code == 503
    assert _counts(business) == before


def test_valid_unicode_response_fits_receipt_and_replays(business, business_admin):
    # HTTPX's JSON encoding preserves Unicode, as the browser's JSON.stringify does.
    payload = contact_body(name="\U0001f331" * 120, company="\U0001f331" * 120, notes="\U0001f331" * 4000)
    first = _create(business_admin, "/api/admin/contacts", payload)
    assert first.status_code == 201
    assert len(first.content) > 16 * 1024
    replay = _create(business_admin, "/api/admin/contacts", payload)
    assert replay.status_code == 201
    assert replay.json() == first.json()


def test_receipt_size_failure_rolls_back_entire_write(business, business_admin, monkeypatch):
    monkeypatch.setattr(idempotency, "MAX_RESPONSE_BYTES", 8)
    before = _counts(business)
    assert _create(business_admin, "/api/admin/contacts", contact_body()).status_code == 503
    assert _counts(business) == before
