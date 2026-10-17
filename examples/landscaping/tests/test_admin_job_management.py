"""Administrative job management preserves history and authoritative revisions."""

from datetime import datetime, timedelta, timezone

import pytest

from .test_authorization import members


def read_job(admin, job_id):
    response = admin.request("GET", f"/api/admin/jobs/{job_id}")
    assert response.status_code == 200
    return response.json()["job"]


def replace_crew(admin, job, worker_ids, capacity=None):
    return admin.request("PUT", f"/api/admin/jobs/{job['id']}/crew", json={
        "worker_ids": worker_ids,
        "capacity": job["capacity"] if capacity is None else capacity,
        "expected_revision": job["revision"],
    })


def test_admin_assigns_and_removes_workers_with_shared_visibility_and_audit(trial, admin):
    job = read_job(admin, trial.empty_job)
    alex, blair = trial.login("alex"), trial.login("blair")
    assigned = replace_crew(admin, job, [trial.ids["alex"], trial.ids["blair"]], 3)
    assert assigned.status_code == 200
    updated = assigned.json()["job"]
    assert updated["revision"] == job["revision"] + 1
    assert updated["capacity"] == 3 and updated["signup_count"] == 2
    assert {member["id"] for member in updated["crew"]} == {trial.ids["alex"], trial.ids["blair"]}
    for worker in (alex, blair):
        shared = next(row for row in worker.request("GET", "/api/jobs").json()["jobs"] if row["id"] == job["id"])
        assert shared["joined"] is True and shared["signup_count"] == 2
        assert all(set(member) == {"display_name"} for member in shared["crew"])
    removed = replace_crew(admin, updated, [trial.ids["blair"]], 1)
    assert removed.status_code == 200 and removed.json()["job"]["revision"] == updated["revision"] + 1
    assert members(trial, job["id"]) == {trial.ids["blair"]}
    audit = admin.request("GET", "/api/admin/health").json()["audit"]
    assert any(row["action"] == "job.crew_assigned" and row["target"] == f"{job['id']}:{trial.ids['alex']}" for row in audit)
    assert any(row["action"] == "job.crew_removed" and row["target"] == f"{job['id']}:{trial.ids['alex']}" for row in audit)
    assert any(row["action"] == "job.capacity_changed" for row in audit)


def test_admin_can_correct_started_job_and_empty_crew_without_touching_other_jobs(trial, admin):
    job_id = trial.empty_job
    with trial.db() as connection:
        connection.execute("UPDATE jobs SET starts_at=? WHERE id=?", ((datetime.now(timezone.utc)-timedelta(days=1)).isoformat(), job_id))
        other_memberships = [tuple(row) for row in connection.execute("SELECT * FROM job_signups WHERE job_id<>? ORDER BY job_id,user_id", (job_id,))]
    job = read_job(admin, job_id)
    assert job["status"] == "started"
    assigned = replace_crew(admin, job, [trial.ids["alex"]])
    assert assigned.status_code == 200
    emptied = replace_crew(admin, assigned.json()["job"], [])
    assert emptied.status_code == 200 and emptied.json()["job"]["signup_count"] == 0
    unchanged = replace_crew(admin, emptied.json()["job"], [])
    assert unchanged.json()["job"]["revision"] == emptied.json()["job"]["revision"]
    with trial.db() as connection:
        assert [tuple(row) for row in connection.execute("SELECT * FROM job_signups WHERE job_id<>? ORDER BY job_id,user_id", (job_id,))] == other_memberships


def test_archive_removes_job_from_shared_views_and_metrics_restore_clears_old_assignments(trial, admin):
    worker = trial.login("alex")
    job = read_job(admin, trial.empty_job)
    job = replace_crew(admin, job, [trial.ids["alex"]]).json()["job"]
    before = admin.request("GET", "/api/admin/metrics").json()
    shared_before = worker.request("GET", "/api/jobs").json()
    removed = admin.request("POST", f"/api/admin/jobs/{job['id']}/archive", json={"expected_revision": job["revision"]})
    assert removed.status_code == 200
    archived = removed.json()["job"]
    assert archived["archived"] is True and archived["status"] == "archived"
    assert archived["revision"] == job["revision"] + 1
    assert members(trial, job["id"]) == {trial.ids["alex"]}
    assert job["id"] not in {row["id"] for row in admin.request("GET", "/api/admin/jobs").json()["jobs"]}
    assert job["id"] in {row["id"] for row in admin.request("GET", "/api/admin/jobs?view=archived").json()["jobs"]}
    shared_after = worker.request("GET", "/api/jobs").json()
    assert job["id"] not in {row["id"] for row in shared_after["jobs"]}
    assert shared_after["summary"]["total_jobs"] == shared_before["summary"]["total_jobs"] - 1
    assert shared_after["summary"]["my_jobs"] == shared_before["summary"]["my_jobs"] - 1
    after = admin.request("GET", "/api/admin/metrics").json()
    for field, deduction in (("total_jobs", 1), ("scheduled_hours", job["hours"]), ("total_spots", job["capacity"]), ("filled_spots", 1)):
        assert after["metrics"][field] == pytest.approx(before["metrics"][field] - deduction)
    assert after["metrics"]["booked_revenue"] == before["metrics"]["booked_revenue"]
    assert sum(row["jobs"] for row in after["by_service"]) == after["metrics"]["total_jobs"]
    restored = admin.request("POST", f"/api/admin/jobs/{job['id']}/restore", json={"expected_revision": archived["revision"]})
    assert restored.status_code == 200
    active = restored.json()["job"]
    assert active["archived"] is False and active["crew"] == [] and active["revision"] == archived["revision"] + 1
    assert members(trial, job["id"]) == set()
    assert job["id"] in {row["id"] for row in worker.request("GET", "/api/jobs").json()["jobs"]}
    audit = admin.request("GET", "/api/admin/health").json()["audit"]
    assert any(row["action"] == "job.restore_assignment_cleared" and row["target"] == f"{job['id']}:{trial.ids['alex']}" for row in audit)


def test_self_signup_cancel_and_disable_each_advance_affected_revision(trial, admin):
    worker = trial.login("alex")
    initial = read_job(admin, trial.empty_job)
    endpoint = f"/api/jobs/{trial.empty_job}/signup"
    assert worker.request("POST", endpoint, json={}).status_code == 200
    joined = read_job(admin, trial.empty_job)
    assert joined["revision"] == initial["revision"] + 1
    assert worker.request("POST", endpoint, json={}).status_code == 200
    assert read_job(admin, trial.empty_job)["revision"] == joined["revision"]
    assert worker.request("DELETE", endpoint).status_code == 200
    left = read_job(admin, trial.empty_job)
    assert left["revision"] == joined["revision"] + 1
    assert worker.request("DELETE", endpoint).status_code == 200
    assert read_job(admin, trial.empty_job)["revision"] == left["revision"]
    assert worker.request("POST", endpoint, json={}).status_code == 200
    before = read_job(admin, trial.empty_job)
    archived = admin.request("POST", f"/api/admin/jobs/{trial.empty_job}/archive", json={"expected_revision": before["revision"]}).json()["job"]
    assert admin.request("PATCH", f"/api/admin/users/{trial.ids['alex']}", json={"active": False}).status_code == 200
    disabled = read_job(admin, trial.empty_job)
    assert disabled["revision"] == archived["revision"] + 1 and disabled["crew"] == []
    assert admin.request("PATCH", f"/api/admin/users/{trial.ids['alex']}", json={"active": True}).status_code == 200
    assert read_job(admin, trial.empty_job)["revision"] == disabled["revision"]
