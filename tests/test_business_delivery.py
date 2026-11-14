"""Delivery workflow: real transactions and authority, using disposable accounts."""
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from tests.test_business_dashboard import business as business, business_seed as business_seed


def schedule(actor, *, contact="contact-4", revision=0, key="delivery_test_key_0001"):
    start = datetime.now(timezone.utc) + timedelta(days=20)
    return actor.request("POST", f"/api/admin/contacts/{contact}/schedule", json={
        "title": "Client delivery", "starts_at": start.isoformat(),
        "ends_at": (start + timedelta(hours=2)).isoformat(), "employee_ids": ["alex"],
        "contact_revision": revision,
    }, headers={"Idempotency-Key": key})


def test_workflow_and_private_read_scope(business):
    admin, alex, blair = (business.login(name) for name in ("admin", "alex", "blair"))
    created = schedule(admin)
    assert created.status_code == 201
    identifier = created.json()["work"]["id"]
    work = alex.request("GET", "/api/work").json()["work"][0]
    assert "company" not in work and "contact_id" not in work
    assert blair.request("GET", "/api/work").json()["work"] == []
    assert business.client().get("/api/work").status_code == 401
    path = f"/api/work/{identifier}"
    payload = {"revision": 0, "event_revision": 0, "note": "Starting the agreed scope."}
    assert blair.request("POST", path + "/start", json=payload).status_code == 404
    assert alex.request("POST", path + "/complete", json=payload).status_code == 409
    assert alex.request("POST", path + "/start", json=payload).status_code == 200
    assert alex.request("POST", path + "/start", json=payload).status_code == 409
    payload.update(revision=1, note="Delivered and handed over.")
    assert alex.request("POST", path + "/complete", json=payload).status_code == 200
    assert alex.request("POST", path + "/complete", json=payload).status_code == 409
    overview = admin.request("GET", "/api/admin/overview").json()
    assert overview["delivery"]["completed"] == 1
    assert overview["delivery"]["in_progress"] == 0
    completed = admin.request("GET", "/api/work").json()["work"][0]
    assert completed["company"] == "Form & Function"
    assert len(completed["history"]) == 3
    assert completed["history"][-1]["actor"] == "Alex Morgan"
    event = next(item for item in admin.request("GET", "/api/schedule").json()["events"]
                 if item["id"] == completed["event_id"])
    assert event["work_status"] == "completed"
    assert admin.request("POST", f"/api/schedule/{event['id']}/archive", json={"revision": 0}).status_code == 409
    update = {key: event[key] for key in ("title", "starts_at", "ends_at", "location", "notes", "employee_ids", "revision")}
    assert admin.request("PUT", f"/api/schedule/{event['id']}", json=update).status_code == 409
    assert admin.request("POST", "/api/schedule", json={key: value for key, value in update.items() if key != "revision"}).status_code == 201


def test_conversion_requires_won_and_current_revision(business):
    admin, employee = business.login("admin"), business.login("alex")
    assert schedule(employee).status_code == 403
    assert schedule(admin, contact="contact-1").status_code == 409
    assert schedule(admin, revision=99).status_code == 409
    assert schedule(admin).status_code == 201
    assert schedule(admin, key="another_delivery_key_01").status_code == 409
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 1


def test_work_requires_current_assignment_csrf_and_unfrozen_access(business):
    admin, alex = business.login("admin"), business.login("alex")
    identifier = schedule(admin).json()["work"]["id"]
    path = f"/api/work/{identifier}/start"
    payload = {"revision": 0, "event_revision": 0, "note": "Ready."}
    assert alex.request("POST", path, json=payload, headers={"X-CSRF-Token": "bad"}).status_code == 403
    assert admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    assert alex.request("POST", path, json=payload).status_code == 403
    assert admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": 1}).status_code == 200
    with business.db() as connection:
        connection.execute("DELETE FROM assignments WHERE event_id=(SELECT event_id FROM work_items WHERE id=?)", (identifier,))
    assert alex.request("POST", path, json=payload).status_code == 404


def test_history_failure_rolls_back_work_and_schedule(business):
    admin = business.login("admin")
    with business.db() as connection:
        before = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        connection.execute("CREATE TRIGGER reject_work_history BEFORE INSERT ON work_history BEGIN SELECT RAISE(ABORT,'test'); END")
    assert schedule(admin).status_code == 503
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before
        assert connection.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0


def test_transition_rejects_changed_schedule_and_empty_note(business):
    admin = business.login("admin")
    work = schedule(admin).json()["work"]
    with business.db() as connection:
        connection.execute("UPDATE events SET revision=revision+1 WHERE id=?", (work["event_id"],))
    path = f"/api/work/{work['id']}/start"
    assert admin.request("POST", path, json={"revision": 0, "event_revision": 0, "note": "Ready"}).status_code == 409
    assert admin.request("POST", path, json={"revision": 0, "event_revision": 1, "note": " "}).status_code == 422
    assert admin.request("POST", path, json={"revision": 0, "event_revision": 1, "note": "Ready"}).status_code == 200


def test_conversion_replay_and_transition_history_are_exactly_once(business):
    admin = business.login("admin")
    created = schedule(admin)
    replay = admin.request("POST", "/api/admin/contacts/contact-4/schedule",
                           json=json.loads(created.request.content),
                           headers={"Idempotency-Key": "delivery_test_key_0001"})
    assert replay.status_code == 201 and replay.json() == created.json()
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM work_history").fetchone()[0] == 1
    identifier = created.json()["work"]["id"]
    path = f"/api/work/{identifier}/start"
    with business.db() as connection:
        connection.execute("CREATE TRIGGER reject_transition_history BEFORE INSERT ON work_history BEGIN SELECT RAISE(ABORT,'test'); END")
    assert admin.request("POST", path, json={"revision": 0, "event_revision": 0, "note": "Ready"}).status_code == 503
    with business.db() as connection:
        assert connection.execute("SELECT status,revision FROM work_items").fetchone()[:] == ("scheduled", 0)


def test_schema_ten_upgrade_is_explicit_preserves_rows_and_rolls_back(business, monkeypatch):
    from business import db
    with business.raw_db() as connection:
        connection.execute("DROP TABLE work_history")
        connection.execute("DROP TABLE work_items")
        connection.execute("PRAGMA user_version=10")
        db._require_schema(connection, 10)
        before = "\n".join(connection.iterdump())
    with pytest.raises(ValueError, match="explicit reviewed migration"):
        db.Database(business.directory)
    migrate = db._apply_delivery_work_migration

    def failed(connection):
        migrate(connection)
        raise sqlite3.OperationalError("Injected DDL failure")

    with monkeypatch.context() as patch:
        patch.setattr(db, "_apply_delivery_work_migration", failed)
        with pytest.raises(ValueError):
            db.Database(business.directory, migrate=True)
    with business.raw_db() as connection:
        assert "\n".join(connection.iterdump()) == before
    migrated = db.Database(business.directory, migrate=True)
    with migrated.transaction() as connection:
        db._require_schema(connection, 11)
        assert connection.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM contacts").fetchone()[0] == 4


def test_work_history_survives_quarantined_restore(business):
    from tests.test_business_backup import backup, _make_backup, _rows
    from business.secret_store import default_key_path

    admin = business.login("admin")
    identifier = schedule(admin).json()["work"]["id"]
    assert admin.request("POST", f"/api/work/{identifier}/start",
                         json={"revision": 0, "event_revision": 0, "note": "Beginning client delivery."}).status_code == 200
    bundle = _make_backup(business)
    restored = business.directory.parent / "delivery-restore"
    result = backup.restore_backup(bundle, restored, mfa_key_file=default_key_path(business.directory))
    assert result["quarantined"] is True and result["sessions_revoked"] is True
    for table in ("work_items", "work_history", "events", "assignments", "contacts"):
        assert _rows(restored, table) == _rows(bundle, table)


def test_admin_work_transitions_require_fresh_verification(business):
    admin = business.login("admin")
    identifier = schedule(admin).json()["work"]["id"]
    with business.db() as connection:
        connection.execute("UPDATE session_security SET verified_at=0")
    denied = admin.request("POST", f"/api/work/{identifier}/start",
                           json={"revision": 0, "event_revision": 0, "note": "Ready."})
    assert denied.status_code == 403 and denied.headers["X-Reauthentication-Required"] == "true"
    assert admin.request("GET", "/api/work").json()["work"][0]["status"] == "scheduled"
