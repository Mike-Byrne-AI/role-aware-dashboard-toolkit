"""Shared crew enrollment invariants, capacity races, dates and revocation."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from zoneinfo import ZoneInfo

import pytest

from .conftest import NEW_PASSWORD
from .test_authorization import job_body, members


def test_capacity_multiple_members_and_duplicate_full_signup_are_atomic(trial):
    actors = [trial.login(name) for name in ("alex", "blair", "casey")]
    job_id = trial.empty_job
    with trial.db() as connection:
        connection.execute("UPDATE jobs SET capacity=2 WHERE id=?", (job_id,))
    endpoint = f"/api/jobs/{job_id}/signup"
    for actor in actors[:2]:
        assert actor.request("POST", endpoint, json={}).status_code == 200
    assert actors[2].request("POST", endpoint, json={}).status_code == 409
    assert actors[0].request("POST", endpoint, json={}).status_code == 200
    row = next(row for row in actors[2].request("GET", "/api/jobs").json()["jobs"] if row["id"] == job_id)
    assert row["status"] == "full" and row["remaining_spots"] == 0 and row["signup_count"] == 2
    assert row["joined"] is False
    assert {entry["display_name"] for entry in row["crew"]} == {actor.profile["display_name"] for actor in actors[:2]}
    assert all(set(entry) == {"display_name"} for entry in row["crew"])
    assert actors[0].request("DELETE", endpoint).status_code == 200
    assert members(trial, job_id) == {trial.ids["blair"]}
    assert actors[2].request("POST", endpoint, json={}).status_code == 200
    assert members(trial, job_id) == {trial.ids["blair"], trial.ids["casey"]}


def test_concurrent_last_spot_has_exactly_one_winner(trial):
    actors = [trial.login("alex"), trial.login("blair")]
    job_id = trial.empty_job
    with trial.db() as connection:
        connection.execute("UPDATE jobs SET capacity=1 WHERE id=?", (job_id,))
    gate = Barrier(3)

    def join(actor):
        gate.wait(timeout=10)
        return actor.profile["id"], actor.request("POST", f"/api/jobs/{job_id}/signup", json={}).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(join, actor) for actor in actors]
        gate.wait(timeout=10)
        results = [future.result(timeout=20) for future in futures]
    assert sorted(status for _, status in results) == [200, 409]
    winner = next(user_id for user_id, status in results if status == 200)
    assert members(trial, job_id) == {winner}


def test_started_jobs_reject_new_and_cancelled_memberships(trial, admin):
    actor, other = trial.login("alex"), trial.login("blair")
    job_id = trial.empty_job
    endpoint = f"/api/jobs/{job_id}/signup"
    assert actor.request("POST", endpoint, json={}).status_code == 200
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with trial.db() as connection:
        connection.execute("UPDATE jobs SET starts_at=? WHERE id=?", (past, job_id))
    assert actor.request("DELETE", endpoint).status_code == 409
    assert actor.request("POST", endpoint, json={}).status_code == 409
    assert other.request("POST", endpoint, json={}).status_code == 409
    assert members(trial, job_id) == {trial.ids["alex"]}
    assert admin.request("POST", "/api/admin/jobs", json={**job_body(), "starts_at": past}).status_code == 422


def test_disable_releases_future_seats_keeps_history_and_reset_preserves_enrollments(trial, admin):
    actor = trial.login("alex")
    future = trial.empty_job
    past = next(job_id for job_id in trial.job_ids if job_id != future)
    assert actor.request("POST", f"/api/jobs/{future}/signup", json={}).status_code == 200
    with trial.db() as connection:
        connection.execute("UPDATE jobs SET starts_at=? WHERE id=?", ((datetime.now(timezone.utc)-timedelta(days=1)).isoformat(), past))
        connection.execute("INSERT OR IGNORE INTO job_signups VALUES(?,?,?)", (past, trial.ids["alex"], datetime.now(timezone.utc).isoformat()))
        before = {row[0] for row in connection.execute("SELECT job_id FROM job_signups WHERE user_id=?", (trial.ids["alex"],))}
    assert admin.request("POST", f"/api/admin/users/{trial.ids['alex']}/password", json={"password": NEW_PASSWORD}).status_code == 200
    assert actor.request("GET", "/api/session").status_code == 401
    with trial.db() as connection:
        assert {row[0] for row in connection.execute("SELECT job_id FROM job_signups WHERE user_id=?", (trial.ids["alex"],))} == before
    replacement = trial.login("alex", NEW_PASSWORD)
    assert admin.request("PATCH", f"/api/admin/users/{trial.ids['alex']}", json={"active": False}).status_code == 200
    assert replacement.request("GET", "/api/session").status_code == 401
    with trial.db() as connection:
        remaining = {row[0] for row in connection.execute("SELECT job_id FROM job_signups WHERE user_id=?", (trial.ids["alex"],))}
    assert remaining == {past}
    assert trial.ids["alex"] not in members(trial, future)
    audit = admin.request("GET", "/api/admin/health").json()["audit"]
    assert any("released" in event["action"] for event in audit)
    assert admin.request("PATCH", f"/api/admin/users/{trial.ids['alex']}", json={"active": True}).status_code == 200
    assert trial.ids["alex"] not in members(trial, future)


def test_shared_filters_and_unfiltered_summary_are_derived_from_authenticated_worker(trial):
    actor = trial.login("alex")
    all_data = actor.request("GET", "/api/jobs").json()
    assert len(all_data["jobs"]) == 12
    assert any(row["signup_count"] == 0 for row in all_data["jobs"])
    assert any(row["status"] == "full" for row in all_data["jobs"])
    assert all("owner_id" not in row for row in all_data["jobs"])
    assert all(set(entry) == {"display_name"} for row in all_data["jobs"] for entry in row["crew"])
    summary = all_data["summary"]
    mine = [row for row in all_data["jobs"] if row["joined"]]
    assert summary["total_jobs"] == 12
    assert summary["open_spots"] == sum(row["remaining_spots"] for row in all_data["jobs"])
    assert summary["my_jobs"] == len(mine)
    assert summary["my_hours"] == pytest.approx(sum(row["hours"] for row in mine))
    for view in ("all", "open", "mine"):
        response = actor.request("GET", "/api/jobs", params={"view": view})
        assert response.status_code == 200
        data = response.json()
        assert data["summary"] == summary
        expected = all_data["jobs"] if view == "all" else [row for row in all_data["jobs"] if row["remaining_spots"] > 0] if view == "open" else mine
        assert {row["id"] for row in data["jobs"]} == {row["id"] for row in expected}
    service = all_data["jobs"][0]["service"]
    filtered = actor.request("GET", "/api/jobs", params={"service": service}).json()
    assert filtered["summary"] == summary
    assert {row["service"] for row in filtered["jobs"]} == {service}


def test_business_date_filter_uses_new_york_date_not_utc_date(trial):
    actor = trial.login("alex")
    boundary = (datetime.now(timezone.utc) + timedelta(days=2)).replace(hour=3, minute=30, second=0, microsecond=0)
    ny_date = boundary.astimezone(ZoneInfo("America/New_York")).date().isoformat()
    utc_date = boundary.date().isoformat()
    assert ny_date != utc_date
    with trial.db() as connection:
        connection.execute("UPDATE jobs SET starts_at=? WHERE id=?", (boundary.isoformat(), trial.empty_job))
    local = actor.request("GET", "/api/jobs", params={"date": ny_date})
    other = actor.request("GET", "/api/jobs", params={"date": utc_date})
    assert local.status_code == other.status_code == 200
    assert trial.empty_job in {row["id"] for row in local.json()["jobs"]}
    assert trial.empty_job not in {row["id"] for row in other.json()["jobs"]}


@pytest.mark.parametrize("query", [{"view": "admin"}, {"date": "2026-02-30"}, {"date": "2026-1-1"}, {"worker_id": "alex"}])
def test_shared_filter_input_is_strict(trial, query):
    assert trial.login("alex").request("GET", "/api/jobs", params=query).status_code == 422


@pytest.mark.parametrize("capacity", [0, 11, True, "2", 1.5])
def test_job_capacity_is_bounded_integer(trial, admin, capacity):
    assert admin.request("POST", "/api/admin/jobs", json={**job_body(), "capacity": capacity}).status_code == 422
