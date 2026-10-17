"""Job lifecycle changes preserve crew/history and share the live write boundary."""

from datetime import datetime, timedelta, timezone

import pytest

from .test_admin_job_management import read_job, replace_crew


def reschedule(admin, job, starts_at, **overrides):
    body = {"starts_at": starts_at, "expected_revision": job["revision"], "reason": "Customer requested another time."}
    body.update(overrides)
    return admin.request("PUT", f"/api/admin/jobs/{job['id']}/schedule", json=body)


def change_status(admin, job, status, **overrides):
    body = {"status": status, "expected_revision": job["revision"], "reason": "Administrator reviewed the job."}
    body.update(overrides)
    return admin.request("POST", f"/api/admin/jobs/{job['id']}/status", json=body)


def history(admin, job_id):
    response = admin.request("GET", f"/api/admin/jobs/{job_id}/history")
    assert response.status_code == 200
    return response.json()["history"]


def future(days=90):
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()


def test_reschedule_keeps_crew_records_reason_and_is_visible_to_workers(trial, admin):
    worker = trial.login("alex")
    job = replace_crew(admin, read_job(admin, trial.empty_job), [trial.ids["alex"]]).json()["job"]
    new_start = future()
    response = reschedule(admin, job, new_start, reason="  Rain delay.  ")
    assert response.status_code == 200
    updated = response.json()["job"]
    assert updated["starts_at"] == new_start
    assert updated["crew"] == job["crew"] and updated["revision"] == job["revision"] + 1
    shared = next(row for row in worker.request("GET", "/api/jobs?view=mine").json()["jobs"] if row["id"] == job["id"])
    assert shared["starts_at"] == new_start and shared["lifecycle"] == "scheduled"
    entry = history(admin, job["id"])[0]
    assert entry["actor"] == "admin" and entry["reason"] == "Rain delay."
    assert entry["before"]["starts_at"] == job["starts_at"]
    assert entry["after"]["starts_at"] == new_start and entry["action"] == "job.rescheduled"
    assert reschedule(admin, job, future(91)).status_code == 409
    unchanged_history = history(admin, job["id"])
    assert reschedule(admin, updated, new_start).json()["job"]["revision"] == updated["revision"]
    assert history(admin, job["id"]) == unchanged_history


def test_cancel_reopen_complete_preserves_crew_and_metrics_are_scheduled_only(trial, admin):
    worker = trial.login("alex")
    job = replace_crew(admin, read_job(admin, trial.empty_job), [trial.ids["alex"]]).json()["job"]
    before = admin.request("GET", "/api/admin/metrics").json()["metrics"]
    cancelled = change_status(admin, job, "cancelled").json()["job"]
    assert cancelled["status"] == "cancelled" and cancelled["crew"] == job["crew"]
    assert job["id"] not in {row["id"] for row in worker.request("GET", "/api/jobs").json()["jobs"]}
    closed = worker.request("GET", "/api/jobs?view=history").json()["jobs"]
    assert next(row for row in closed if row["id"] == job["id"])["status"] == "cancelled"
    metrics = admin.request("GET", "/api/admin/metrics").json()["metrics"]
    assert metrics["cancelled_jobs"] == before["cancelled_jobs"] + 1
    assert metrics["scheduled_jobs"] == before["scheduled_jobs"] - 1
    assert metrics["scheduled_hours"] == pytest.approx(before["scheduled_hours"] - job["hours"])
    assert metrics["booked_revenue"] == before["booked_revenue"]
    for method, kwargs in (("POST", {"json": {}}), ("DELETE", {})):
        assert worker.request(method, f"/api/jobs/{job['id']}/signup", **kwargs).status_code == 409
    assert reschedule(admin, cancelled, future()).status_code == 409
    assert change_status(admin, cancelled, "completed").status_code == 409
    reopened = change_status(admin, cancelled, "scheduled").json()["job"]
    assert reopened["crew"] == job["crew"] and reopened["lifecycle"] == "scheduled"
    assert change_status(admin, reopened, "completed").status_code == 409
    with trial.db() as conn:
        conn.execute("UPDATE jobs SET starts_at=? WHERE id=?", ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), job["id"]))
    completed = change_status(admin, read_job(admin, job["id"]), "completed").json()["job"]
    assert completed["status"] == "completed"
    corrected = change_status(admin, completed, "scheduled").json()["job"]
    assert corrected["status"] == "started" and corrected["crew"] == job["crew"]


def test_reschedule_overlap_requires_explicit_acknowledgment_and_adjacent_is_allowed(trial, admin):
    job = replace_crew(admin, read_job(admin, trial.empty_job), [trial.ids["alex"]]).json()["job"]
    other_id = next(item for item in trial.job_ids if item != job["id"])
    replace_crew(admin, read_job(admin, other_id), [trial.ids["alex"]])
    with trial.db() as conn:
        conn.execute("UPDATE jobs SET starts_at=?,hours=2 WHERE id=?", (future(), other_id))
    other = read_job(admin, other_id)
    overlap = reschedule(admin, job, other["starts_at"])
    assert overlap.status_code == 409 and overlap.json()["code"] == "schedule_conflict"
    assert read_job(admin, job["id"])["revision"] == job["revision"]
    confirmed = reschedule(admin, job, other["starts_at"], acknowledge_conflicts=True)
    assert confirmed.status_code == 200
    assert history(admin, job["id"])[0]["action"] == "job.rescheduled.overlap_acknowledged"
    adjacent = (datetime.fromisoformat(other["starts_at"]) + timedelta(hours=2)).isoformat()
    assert reschedule(admin, confirmed.json()["job"], adjacent).status_code == 200


def test_closed_crew_survives_account_disable_and_must_be_corrected_before_reopening(trial, admin):
    job = replace_crew(admin, read_job(admin, trial.empty_job), [trial.ids["alex"]]).json()["job"]
    cancelled = change_status(admin, job, "cancelled").json()["job"]
    assert admin.request("PATCH", f"/api/admin/users/{trial.ids['alex']}", json={"active": False}).status_code == 200
    assert read_job(admin, job["id"])["crew"] == cancelled["crew"]
    rejected = change_status(admin, cancelled, "scheduled")
    assert rejected.status_code == 409 and "disabled" in rejected.json()["detail"]
    corrected = replace_crew(admin, cancelled, []).json()["job"]
    assert change_status(admin, corrected, "scheduled").status_code == 200


@pytest.mark.parametrize("value", ["2020-01-01T10:00:00+00:00", "2090-01-01T10:00:00", "9999-12-31T23:00:00+00:00", "not-a-date"])
def test_reschedule_rejects_unusable_dates(trial, admin, value):
    job = read_job(admin, trial.empty_job)
    assert reschedule(admin, job, value).status_code == 422
    assert read_job(admin, job["id"])["revision"] == job["revision"]


def test_history_endpoint_never_exposes_private_account_material(trial, admin):
    job = read_job(admin, trial.empty_job)
    assert change_status(admin, job, "cancelled").status_code == 200
    entries = history(admin, job["id"])
    assert entries and set(entries[0]) == {"id", "job_id", "actor", "action", "reason", "before", "after", "created_at"}
    assert set(entries[0]["after"]) == {"id", "customer", "site", "service", "starts_at", "hours", "pay", "capacity", "archived", "revision", "lifecycle", "crew"}
    assert trial.login("alex").request("GET", f"/api/admin/jobs/{job['id']}/history").status_code == 403
