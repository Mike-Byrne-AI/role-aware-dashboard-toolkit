"""Adversarial lifecycle checks against disposable accounts and SQLite storage.

These tests use the HTTP boundary and deliberately fail actual database writes.
The application is imported only through conftest's isolated-data fixture.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import sys
from threading import Barrier
from zoneinfo import ZoneInfo

import pytest

from .conftest import COOKIE, WORKERS


def future_start(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()


def read_job(admin, job_id):
    response = admin.request("GET", f"/api/admin/jobs/{job_id}")
    assert response.status_code == 200, response.text
    return response.json()["job"]


def schedule_body(job, **patch):
    return {
        "starts_at": future_start(), "expected_revision": job["revision"],
        "reason": "Customer requested a later visit.", "acknowledge_conflicts": False,
        **patch,
    }


def status_body(job, **patch):
    return {
        "status": "cancelled", "expected_revision": job["revision"],
        "reason": "Customer cancelled the visit.", "acknowledge_conflicts": False,
        **patch,
    }


def lifecycle_operations(job):
    base = f"/api/admin/jobs/{job['id']}"
    return (
        ("PUT", f"{base}/schedule", schedule_body(job)),
        ("POST", f"{base}/status", status_body(job)),
        ("GET", f"{base}/history", None),
    )


def business_state(trial):
    with trial.db() as connection:
        return tuple(
            tuple(tuple(row) for row in connection.execute(sql))
            for sql in (
                "SELECT * FROM jobs ORDER BY id",
                "SELECT * FROM job_signups ORDER BY job_id,user_id",
                "SELECT * FROM job_history ORDER BY id",
                "SELECT * FROM audit WHERE action LIKE 'job.%' ORDER BY id",
            )
        )


def history(admin, job_id):
    response = admin.request("GET", f"/api/admin/jobs/{job_id}/history")
    assert response.status_code == 200, response.text
    return response.json()["history"]


def assign(admin, job, user_ids):
    response = admin.request("PUT", f"/api/admin/jobs/{job['id']}/crew", json={
        "worker_ids": user_ids, "capacity": job["capacity"],
        "expected_revision": job["revision"],
    })
    assert response.status_code == 200, response.text
    return response.json()["job"]


@pytest.mark.parametrize("name", WORKERS)
def test_every_worker_denied_lifecycle_and_history_despite_forged_identity(trial, admin, name):
    worker = trial.login(name)
    job = read_job(admin, trial.empty_job)
    before = business_state(trial)
    headers = {
        "X-Role": "admin", "X-User-ID": trial.ids["admin"],
        "X-Forwarded-User": "admin", "Authorization": "Bearer forged-admin",
    }
    for target in (job, {**job, "id": "missing-job"}):
        for method, path, body in lifecycle_operations(target):
            response = worker.request(method, path, headers=headers,
                                      **({"json": body} if body is not None else {}))
            assert response.status_code == 403, (name, path, response.text)
            assert not any(key in response.text for key in ("before_json", "principal", "password"))
    assert business_state(trial) == before


@pytest.mark.parametrize("token", [None, "admin", "A" * 43])
def test_lifecycle_and_history_require_real_server_session(trial, admin, token):
    client = trial.client()
    if token is not None:
        client.cookies.set(COOKIE, token)
    job = read_job(admin, trial.empty_job)
    before = business_state(trial)
    for method, path, body in lifecycle_operations(job):
        response = client.request(method, path, **({"json": body} if body is not None else {}))
        assert response.status_code == 401, (path, response.text)
    assert business_state(trial) == before


@pytest.mark.parametrize("attack", ["missing", "forged", "other-session", "cross-origin"])
def test_lifecycle_writes_bind_csrf_to_session_and_origin(trial, admin, attack):
    worker = trial.login("alex")
    job = read_job(admin, trial.empty_job)
    headers = {"Origin": "http://testserver", "X-CSRF-Token": admin.csrf}
    if attack == "missing":
        del headers["X-CSRF-Token"]
    elif attack == "forged":
        headers["X-CSRF-Token"] = "forged"
    elif attack == "other-session":
        headers["X-CSRF-Token"] = worker.csrf
    else:
        headers["Origin"] = "https://testserver.evil.invalid"
    before = business_state(trial)
    for method, path, body in lifecycle_operations(job)[:2]:
        response = admin.client.request(method, path, json=body, headers=headers)
        assert response.status_code == 403, (path, response.text)
    assert business_state(trial) == before


@pytest.mark.parametrize("change", ["revoke-session", "disable", "demote"])
def test_open_lifecycle_form_cannot_outlive_live_authority(trial, admin, change):
    job = read_job(admin, trial.empty_job)
    with trial.db() as connection:
        if change == "revoke-session":
            connection.execute("DELETE FROM sessions WHERE user_id=?", (trial.ids["admin"],))
        elif change == "disable":
            connection.execute("UPDATE users SET active=0 WHERE id=?", (trial.ids["admin"],))
        else:
            connection.execute("UPDATE users SET role='worker' WHERE id=?", (trial.ids["admin"],))
    before = business_state(trial)
    for method, path, body in lifecycle_operations(job):
        response = admin.request(method, path, **({"json": body} if body is not None else {}))
        assert response.status_code == (403 if change == "demote" else 401), response.text
    assert business_state(trial) == before


def test_freeze_after_form_blocks_schedule_and_status_but_allows_history(trial, admin):
    job = read_job(admin, trial.empty_job)
    session = admin.request("GET", "/api/session").json()
    assert admin.request("POST", "/api/admin/freeze", json={
        "frozen": True, "expected_revision": session["freeze_revision"],
    }).status_code == 200
    before = business_state(trial)
    for method, path, body in lifecycle_operations(job)[:2]:
        response = admin.request(method, path, json=body)
        assert response.status_code in (403, 423), response.text
    history(admin, job["id"])
    assert business_state(trial) == before


@pytest.mark.parametrize("change", ["revoke", "freeze", "demote", "switch-account"])
def test_authority_rechecked_after_business_validation_before_actual_save(trial, admin, monkeypatch, change):
    """Inject a change at the trusted callback boundary, after initial auth.

    The nested savepoint also rolls back this injected fixture change. Real
    cross-request revocation is covered separately above.
    """
    module = sys.modules["landscape.app"]
    original = module.execute_change

    def inject_after_validation(**kwargs):
        propose = kwargs["propose"]
        connection = kwargs["connection"]

        def change_authority(record):
            result = propose(record)
            if change == "revoke":
                connection.execute("DELETE FROM sessions WHERE user_id=?", (trial.ids["admin"],))
            elif change == "freeze":
                connection.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1")
            elif change == "demote":
                connection.execute("UPDATE users SET role='worker' WHERE id=?", (trial.ids["admin"],))
            else:
                connection.execute("UPDATE sessions SET user_id=? WHERE user_id=?",
                                   (trial.ids["alex"], trial.ids["admin"]))
            return result

        kwargs["propose"] = change_authority
        return original(**kwargs)

    monkeypatch.setattr(module, "execute_change", inject_after_validation)
    job = read_job(admin, trial.empty_job)
    before = business_state(trial)
    response = admin.request("PUT", f"/api/admin/jobs/{job['id']}/schedule", json=schedule_body(job))
    assert response.status_code in (401, 403), response.text
    assert business_state(trial) == before


@pytest.mark.parametrize("patch", [
    {"expected_revision": True}, {"expected_revision": "0"}, {"expected_revision": -1},
    {"expected_revision": 10**30}, {"reason": " \t\n"}, {"reason": "x" * 501},
    {"reason": {"$ne": None}}, {"acknowledge_conflicts": "true"},
    {"acknowledge_conflicts": 1}, {"actor_id": "admin"}, {"role": "admin"},
    {"user_id": "alex"}, {"revision": 1000}, {"reason": "hidden\x00reason"},
])
def test_lifecycle_commands_reject_type_confusion_and_identity_overrides(trial, admin, patch):
    job = read_job(admin, trial.empty_job)
    before = business_state(trial)
    for method, path, body in lifecycle_operations(job)[:2]:
        response = admin.request(method, path, json={**body, **patch})
        assert response.status_code == 422, (path, response.text)
    assert business_state(trial) == before


@pytest.mark.parametrize("starts_at", [
    "2099-01-02T09:00:00", "2099-01-02", "2020-01-02T09:00:00+00:00",
    "2099-01-02T09:00:00+24:00", "9999-12-31T23:00:00+00:00",
    "not-a-date", 1234567890, None,
])
def test_reschedule_rejects_ambiguous_past_or_unrepresentable_dates(trial, admin, starts_at):
    job = read_job(admin, trial.empty_job)
    before = business_state(trial)
    response = admin.request("PUT", f"/api/admin/jobs/{job['id']}/schedule",
                             json=schedule_body(job, starts_at=starts_at))
    assert response.status_code == 422, response.text
    assert business_state(trial) == before


@pytest.mark.parametrize("status", ["archived", "Complete", "admin", True, None])
def test_status_transition_rejects_unknown_states(trial, admin, status):
    job = read_job(admin, trial.empty_job)
    before = business_state(trial)
    response = admin.request("POST", f"/api/admin/jobs/{job['id']}/status",
                             json=status_body(job, status=status))
    assert response.status_code == 422, response.text
    assert business_state(trial) == before


@pytest.mark.parametrize("change", ["signup", "capacity", "archive"])
def test_stale_lifecycle_form_cannot_overwrite_newer_job_changes(trial, admin, change):
    old = read_job(admin, trial.empty_job)
    if change == "signup":
        worker = trial.login("alex")
        assert worker.request("POST", f"/api/jobs/{old['id']}/signup", json={}).status_code == 200
    elif change == "capacity":
        assert admin.request("PUT", f"/api/admin/jobs/{old['id']}/crew", json={
            "worker_ids": [], "capacity": 1 if old["capacity"] != 1 else 2,
            "expected_revision": old["revision"],
        }).status_code == 200
    else:
        assert admin.request("POST", f"/api/admin/jobs/{old['id']}/archive", json={
            "expected_revision": old["revision"],
        }).status_code == 200
    before = business_state(trial)
    for method, path, body in lifecycle_operations(old)[:2]:
        response = admin.request(method, path, json=body)
        assert response.status_code == 409, response.text
    assert business_state(trial) == before


def test_successful_command_cannot_replay_or_transfer_to_worker(trial, admin):
    job = read_job(admin, trial.empty_job)
    path = f"/api/admin/jobs/{job['id']}/status"
    body = status_body(job)
    assert admin.request("POST", path, json=body).status_code == 200
    worker = trial.login("alex")
    before = business_state(trial)
    assert admin.request("POST", path, json=body).status_code == 409
    assert worker.request("POST", path, json=body).status_code == 403
    assert business_state(trial) == before


def parallel_actions(*actions):
    barrier = Barrier(len(actions))

    def perform(action):
        barrier.wait(timeout=10)
        return action()

    with ThreadPoolExecutor(max_workers=len(actions)) as pool:
        return list(pool.map(perform, actions))


def test_simultaneous_reschedules_have_one_winner_and_one_history_record(trial, admin):
    second = trial.login("admin")
    job = read_job(admin, trial.empty_job)
    previous = history(admin, job["id"])
    choices = (future_start(30), future_start(31))
    responses = parallel_actions(*[
        lambda actor=actor, choice=choice: actor.request(
            "PUT", f"/api/admin/jobs/{job['id']}/schedule",
            json=schedule_body(job, starts_at=choice),
        ) for actor, choice in zip((admin, second), choices)
    ])
    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = choices[next(i for i, response in enumerate(responses) if response.status_code == 200)]
    current = read_job(admin, job["id"])
    assert datetime.fromisoformat(current["starts_at"]) == datetime.fromisoformat(winner)
    assert current["revision"] == job["revision"] + 1
    assert len(history(admin, job["id"])) == len(previous) + 1


def test_cancellation_racing_signup_never_silently_changes_the_reviewed_crew(trial, admin):
    worker = trial.login("alex")
    job = read_job(admin, trial.empty_job)
    cancel, signup = parallel_actions(
        lambda: admin.request("POST", f"/api/admin/jobs/{job['id']}/status", json=status_body(job)),
        lambda: worker.request("POST", f"/api/jobs/{job['id']}/signup", json={}),
    )
    assert sorted((cancel.status_code, signup.status_code)) == [200, 409]
    current = read_job(admin, job["id"])
    assert current["revision"] == job["revision"] + 1
    if cancel.status_code == 200:
        assert current["lifecycle"] == "cancelled" and current["crew"] == []
    else:
        assert current["lifecycle"] == "scheduled"
        assert [member["id"] for member in current["crew"]] == [trial.ids["alex"]]


@pytest.mark.parametrize("failing_table", ["audit", "job_history"])
@pytest.mark.parametrize("operation", ["schedule", "status"])
def test_failed_history_or_audit_write_rolls_back_effect_and_revision(trial, failing_table, operation):
    admin = trial.login("admin", client=trial.client(raise_server_exceptions=False))
    job = read_job(admin, trial.empty_job)
    with trial.db() as connection:
        condition = "WHEN NEW.action LIKE 'job.%' " if failing_table == "audit" else ""
        connection.execute(
            f"CREATE TRIGGER test_fail_lifecycle BEFORE INSERT ON {failing_table} "
            f"{condition}BEGIN SELECT RAISE(ABORT, 'private-storage-failure'); END"
        )
    before = business_state(trial)
    method, body = ("PUT", schedule_body(job)) if operation == "schedule" else ("POST", status_body(job))
    response = admin.request(method, f"/api/admin/jobs/{job['id']}/{operation}", json=body)
    assert response.status_code == 500, response.text
    assert "private-storage-failure" not in response.text
    assert "sqlite" not in response.text.lower()
    assert business_state(trial) == before


def test_closed_jobs_preserve_crew_without_exposing_private_history_or_accepting_signups(trial, admin):
    alex, blair = trial.login("alex"), trial.login("blair")
    job = assign(admin, read_job(admin, trial.empty_job), [trial.ids["alex"]])
    reason = "Private customer cancellation detail: do not show on the crew board."
    closed = admin.request("POST", f"/api/admin/jobs/{job['id']}/status",
                           json=status_body(job, reason=reason))
    assert closed.status_code == 200, closed.text
    assert [member["id"] for member in closed.json()["job"]["crew"]] == [trial.ids["alex"]]
    before = business_state(trial)
    for worker in (alex, blair):
        current = worker.request("GET", "/api/jobs")
        assert job["id"] not in {row["id"] for row in current.json()["jobs"]}
        shared = worker.request("GET", "/api/jobs", params={"view": "history"})
        assert shared.status_code == 200
        item = next(row for row in shared.json()["jobs"] if row["id"] == job["id"])
        assert item["lifecycle"] == "cancelled"
        assert reason not in shared.text and "before_json" not in shared.text
        assert item["crew"] == [{"display_name": alex.profile["display_name"]}]
        for method in ("POST", "DELETE"):
            response = worker.request(method, f"/api/jobs/{job['id']}/signup",
                                      **({"json": {}} if method == "POST" else {}))
            assert response.status_code == 409, response.text
    assert business_state(trial) == before
    assert history(admin, job["id"])[0]["reason"] == reason


def test_future_job_cannot_be_completed_even_with_conflict_override(trial, admin):
    job = read_job(admin, trial.empty_job)
    before = business_state(trial)
    response = admin.request("POST", f"/api/admin/jobs/{job['id']}/status", json=status_body(
        job, status="completed", acknowledge_conflicts=True,
    ))
    assert response.status_code == 409, response.text
    assert business_state(trial) == before


def test_reopen_cannot_reactivate_disabled_employee_and_admin_can_correct_crew(trial, admin):
    job = assign(admin, read_job(admin, trial.empty_job), [trial.ids["alex"]])
    closed = admin.request("POST", f"/api/admin/jobs/{job['id']}/status", json=status_body(job))
    assert closed.status_code == 200
    assert admin.request("PATCH", f"/api/admin/users/{trial.ids['alex']}",
                         json={"active": False}).status_code == 200
    current = read_job(admin, job["id"])
    assert [member["id"] for member in current["crew"]] == [trial.ids["alex"]]
    before = business_state(trial)
    response = admin.request("POST", f"/api/admin/jobs/{job['id']}/status", json=status_body(
        current, status="scheduled", acknowledge_conflicts=True,
    ))
    assert response.status_code in (409, 422), response.text
    assert business_state(trial) == before
    corrected = assign(admin, current, [])
    assert admin.request("POST", f"/api/admin/jobs/{job['id']}/status",
                         json=status_body(corrected, status="scheduled")).status_code == 200
    assert read_job(admin, job["id"])["crew"] == []


def overlapping_jobs(trial, admin):
    first_id, second_id = trial.job_ids[:2]
    first_start = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=30)
    with trial.db() as connection:
        connection.execute("DELETE FROM job_signups WHERE job_id IN (?,?)", (first_id, second_id))
        connection.execute("UPDATE jobs SET starts_at=?,hours=2 WHERE id=?", (first_start.isoformat(), first_id))
        connection.execute("UPDATE jobs SET starts_at=?,hours=2 WHERE id=?", ((first_start + timedelta(days=1)).isoformat(), second_id))
    first = assign(admin, read_job(admin, first_id), [trial.ids["alex"]])
    second = assign(admin, read_job(admin, second_id), [trial.ids["alex"]])
    return first, second


def test_reschedule_overlap_requires_explicit_acknowledgment_and_records_override(trial, admin):
    first, second = overlapping_jobs(trial, admin)
    offset_start = datetime.fromisoformat(first["starts_at"]).astimezone(timezone(timedelta(hours=-4)))
    body = schedule_body(second, starts_at=offset_start.isoformat())
    before = business_state(trial)
    path = f"/api/admin/jobs/{second['id']}/schedule"
    blocked = admin.request("PUT", path, json=body)
    assert blocked.status_code == 409 and blocked.json().get("code") == "schedule_conflict"
    assert business_state(trial) == before
    allowed = admin.request("PUT", path, json={**body, "acknowledge_conflicts": True})
    assert allowed.status_code == 200, allowed.text
    assert datetime.fromisoformat(allowed.json()["job"]["starts_at"]) == offset_start
    with trial.db() as connection:
        assert any("conflict" in row["action"] or "overlap" in row["action"] for row in connection.execute(
            "SELECT action FROM audit WHERE target=?", (second["id"],),
        ))


def test_reopen_rechecks_current_overlapping_assignments(trial, admin):
    first, second = overlapping_jobs(trial, admin)
    closed = admin.request("POST", f"/api/admin/jobs/{second['id']}/status", json=status_body(second))
    assert closed.status_code == 200
    with trial.db() as connection:
        connection.execute("UPDATE jobs SET starts_at=? WHERE id=?", (first["starts_at"], second["id"]))
    current = read_job(admin, second["id"])
    before = business_state(trial)
    body = status_body(current, status="scheduled")
    path = f"/api/admin/jobs/{second['id']}/status"
    blocked = admin.request("POST", path, json=body)
    assert blocked.status_code == 409 and blocked.json().get("code") == "schedule_conflict"
    assert business_state(trial) == before
    assert admin.request("POST", path, json={**body, "acknowledge_conflicts": True}).status_code == 200


def test_adjacent_jobs_do_not_create_false_overlap(trial, admin):
    first, second = overlapping_jobs(trial, admin)
    boundary = datetime.fromisoformat(first["starts_at"]) + timedelta(hours=first["hours"])
    response = admin.request("PUT", f"/api/admin/jobs/{second['id']}/schedule",
                             json=schedule_body(second, starts_at=boundary.isoformat()))
    assert response.status_code == 200, response.text


def test_explicit_dst_fall_back_offsets_remain_distinct_instants_and_audited(trial, admin):
    year = datetime.now(timezone.utc).year + 1
    first_november = datetime(year, 11, 1)
    first_sunday = first_november + timedelta(days=(6 - first_november.weekday()) % 7)
    local = first_sunday.replace(hour=1, minute=30, tzinfo=ZoneInfo("America/New_York"))
    first, second = local.replace(fold=0), local.replace(fold=1)
    assert first.utcoffset() != second.utcoffset()
    job = read_job(admin, trial.empty_job)
    for instant in (first, second):
        response = admin.request("PUT", f"/api/admin/jobs/{job['id']}/schedule",
                                 json=schedule_body(job, starts_at=instant.isoformat()))
        assert response.status_code == 200, response.text
        job = response.json()["job"]
        assert datetime.fromisoformat(job["starts_at"]).astimezone(timezone.utc) == instant.astimezone(timezone.utc)
    changes = history(admin, job["id"])
    assert changes[0]["after"]["starts_at"] != changes[1]["after"]["starts_at"]
