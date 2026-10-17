"""Adversarial checks for job administration, using only disposable fixture data."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from .conftest import COOKIE, NEW_PASSWORD, WORKERS


def detail(admin, job_id):
    response = admin.request("GET", f"/api/admin/jobs/{job_id}")
    assert response.status_code == 200, response.text
    return response.json()["job"]


def crew_body(trial, job, names=("blair",), capacity=2):
    return {
        "worker_ids": [trial.ids[name] for name in names],
        "capacity": capacity,
        "expected_revision": job["revision"],
    }


def admin_operations(trial, job_id, revision=0):
    return [
        ("GET", "/api/admin/jobs", None),
        ("GET", "/api/admin/jobs?view=archived", None),
        ("GET", f"/api/admin/jobs/{job_id}", None),
        ("PUT", f"/api/admin/jobs/{job_id}/crew", {
            "worker_ids": [trial.ids["blair"]], "capacity": 2,
            "expected_revision": revision,
        }),
        ("POST", f"/api/admin/jobs/{job_id}/archive", {"expected_revision": revision}),
        ("POST", f"/api/admin/jobs/{job_id}/restore", {"expected_revision": revision}),
    ]


def state(trial):
    """Security denials may audit; they must not change jobs or memberships."""
    with trial.db() as connection:
        return (
            [tuple(row) for row in connection.execute("SELECT * FROM jobs ORDER BY id")],
            [tuple(row) for row in connection.execute(
                "SELECT * FROM job_signups ORDER BY job_id,user_id"
            )],
        )


def members(trial, job_id):
    with trial.db() as connection:
        return {row[0] for row in connection.execute(
            "SELECT user_id FROM job_signups WHERE job_id=?", (job_id,)
        )}


@pytest.mark.parametrize("name", WORKERS)
def test_all_workers_denied_every_new_admin_endpoint_despite_identity_headers(trial, name):
    worker = trial.login(name)
    before = state(trial)
    forged = {
        "X-Role": "admin", "X-User-ID": trial.ids["admin"],
        "X-Forwarded-User": "admin",
        "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
    }
    for job_id in (trial.empty_job, "unknown-job"):
        for method, path, body in admin_operations(trial, job_id):
            response = worker.request(method, path, headers=forged,
                                      **({"json": body} if body is not None else {}))
            assert response.status_code == 403, (name, method, path, response.text)
            assert not any(key in response.text for key in ("worker_ids", "password_hash"))
    assert state(trial) == before


@pytest.mark.parametrize("token", [None, "admin", "A" * 43])
def test_new_admin_endpoints_reject_missing_and_forged_session_tokens(trial, token):
    client = trial.client()
    if token is not None:
        client.cookies.set(COOKIE, token)
    before = state(trial)
    for method, path, body in admin_operations(trial, trial.empty_job):
        response = client.request(method, path,
                                  **({"json": body} if body is not None else {}))
        assert response.status_code == 401, (method, path, response.text)
    assert state(trial) == before


@pytest.mark.parametrize("attack", ["missing", "forged", "other-session", "cross-origin"])
def test_new_admin_writes_require_session_csrf_and_same_origin(trial, admin, attack):
    job = detail(admin, trial.empty_job)
    worker = trial.login("alex")
    headers = {"Origin": "http://testserver", "X-CSRF-Token": admin.csrf}
    if attack == "missing":
        del headers["X-CSRF-Token"]
    elif attack == "forged":
        headers["X-CSRF-Token"] = "forged-csrf"
    elif attack == "other-session":
        headers["X-CSRF-Token"] = worker.csrf
    else:
        headers["Origin"] = "https://testserver.evil.invalid"
    before = state(trial)
    for method, path, body in admin_operations(trial, trial.empty_job, job["revision"]):
        if method != "GET":
            response = admin.client.request(method, path, json=body, headers=headers)
            assert response.status_code == 403, (path, response.text)
    assert state(trial) == before


@pytest.mark.parametrize("change", ["revoke-session", "disable", "demote"])
def test_open_admin_dialog_cannot_outlive_live_authority(trial, admin, change):
    job = detail(admin, trial.empty_job)
    with trial.db() as connection:
        if change == "revoke-session":
            connection.execute("DELETE FROM sessions WHERE user_id=?", (trial.ids["admin"],))
        elif change == "disable":
            connection.execute("UPDATE users SET active=0 WHERE id=?", (trial.ids["admin"],))
        else:
            connection.execute("UPDATE users SET role='worker' WHERE id=?", (trial.ids["admin"],))
    before = state(trial)
    for method, path, body in admin_operations(trial, trial.empty_job, job["revision"]):
        response = admin.request(method, path,
                                 **({"json": body} if body is not None else {}))
        assert response.status_code == (403 if change == "demote" else 401), response.text
    assert state(trial) == before


def test_freeze_after_dialog_blocks_crew_archive_and_restore(trial, admin):
    active_id = trial.empty_job
    archived_id = next(job_id for job_id in trial.job_ids if job_id != active_id)
    archived = detail(admin, archived_id)
    assert admin.request("POST", f"/api/admin/jobs/{archived_id}/archive",
                         json={"expected_revision": archived["revision"]}).status_code == 200
    active, archived = detail(admin, active_id), detail(admin, archived_id)
    session = admin.request("GET", "/api/session").json()
    assert admin.request("POST", "/api/admin/freeze", json={
        "frozen": True, "expected_revision": session["freeze_revision"],
    }).status_code == 200
    before = state(trial)
    writes = [
        ("PUT", f"/api/admin/jobs/{active_id}/crew", crew_body(trial, active)),
        ("POST", f"/api/admin/jobs/{active_id}/archive", {
            "expected_revision": active["revision"],
        }),
        ("POST", f"/api/admin/jobs/{archived_id}/restore", {
            "expected_revision": archived["revision"],
        }),
    ]
    for method, path, body in writes:
        response = admin.request(method, path, json=body)
        assert response.status_code in (403, 423), (path, response.text)
    assert state(trial) == before
    assert detail(admin, active_id)["revision"] == active["revision"]


@pytest.mark.parametrize("change", ["join", "leave", "disable", "admin-replacement"])
def test_stale_dialog_cannot_overwrite_changed_crew_or_archive_it(trial, admin, change):
    job_id = trial.empty_job
    worker = trial.login("alex")
    signup = f"/api/jobs/{job_id}/signup"
    if change in ("leave", "disable"):
        assert worker.request("POST", signup, json={}).status_code == 200
    old = detail(admin, job_id)
    if change == "join":
        assert worker.request("POST", signup, json={}).status_code == 200
    elif change == "leave":
        assert worker.request("DELETE", signup).status_code == 200
    elif change == "disable":
        assert admin.request("PATCH", f"/api/admin/users/{trial.ids['alex']}",
                             json={"active": False}).status_code == 200
    else:
        second_admin = trial.login("admin")
        assert second_admin.request("PUT", f"/api/admin/jobs/{job_id}/crew",
                                    json=crew_body(trial, old, ("casey",))).status_code == 200
    current = detail(admin, job_id)
    assert current["revision"] > old["revision"]
    before = state(trial)
    replace = admin.request("PUT", f"/api/admin/jobs/{job_id}/crew", json=crew_body(trial, old))
    archive = admin.request("POST", f"/api/admin/jobs/{job_id}/archive",
                            json={"expected_revision": old["revision"]})
    assert replace.status_code == archive.status_code == 409
    assert state(trial) == before


def parallel_actions(*actions):
    barrier = Barrier(len(actions))

    def perform(action):
        barrier.wait(timeout=10)
        return action()

    with ThreadPoolExecutor(max_workers=len(actions)) as pool:
        return list(pool.map(perform, actions))


def test_simultaneous_admin_replacements_have_one_winner_without_lost_update(trial, admin):
    other = trial.login("admin")
    job = detail(admin, trial.empty_job)
    path = f"/api/admin/jobs/{job['id']}/crew"
    names = ("alex", "blair")
    responses = parallel_actions(*[
        lambda actor=actor, name=name: actor.request(
            "PUT", path, json=crew_body(trial, job, (name,), capacity=1)
        ) for actor, name in zip((admin, other), names)
    ])
    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = names[next(i for i, response in enumerate(responses) if response.status_code == 200)]
    assert members(trial, job["id"]) == {trial.ids[winner]}
    assert detail(admin, job["id"])["revision"] == job["revision"] + 1


def test_worker_signup_racing_admin_replacement_cannot_exceed_capacity_or_get_lost(trial, admin):
    worker = trial.login("alex")
    job = detail(admin, trial.empty_job)
    with trial.db() as connection:
        connection.execute("UPDATE jobs SET capacity=1 WHERE id=?", (job["id"],))
    replace, signup = parallel_actions(
        lambda: admin.request("PUT", f"/api/admin/jobs/{job['id']}/crew",
                              json=crew_body(trial, job, ("blair",), capacity=1)),
        lambda: worker.request("POST", f"/api/jobs/{job['id']}/signup", json={}),
    )
    assert sorted((replace.status_code, signup.status_code)) == [200, 409]
    expected = "blair" if replace.status_code == 200 else "alex"
    assert members(trial, job["id"]) == {trial.ids[expected]}
    assert detail(admin, job["id"])["capacity"] == 1


def test_archive_racing_worker_signup_never_silently_removes_new_membership(trial, admin):
    worker = trial.login("alex")
    job = detail(admin, trial.empty_job)
    archive, signup = parallel_actions(
        lambda: admin.request("POST", f"/api/admin/jobs/{job['id']}/archive",
                              json={"expected_revision": job["revision"]}),
        lambda: worker.request("POST", f"/api/jobs/{job['id']}/signup", json={}),
    )
    if archive.status_code == 200:
        assert signup.status_code == 404
        assert members(trial, job["id"]) == set()
    else:
        assert (archive.status_code, signup.status_code) == (409, 200)
        assert members(trial, job["id"]) == {trial.ids["alex"]}


def test_archived_job_is_absent_from_worker_views_and_totals_and_restores_without_crew(trial, admin):
    worker = trial.login("alex")
    job_id = trial.empty_job
    assert worker.request("POST", f"/api/jobs/{job_id}/signup", json={}).status_code == 200
    job = detail(admin, job_id)
    before_schedule = worker.request("GET", "/api/jobs").json()
    before_metrics = admin.request("GET", "/api/admin/metrics").json()["metrics"]
    assert admin.request("POST", f"/api/admin/jobs/{job_id}/archive",
                         json={"expected_revision": job["revision"]}).status_code == 200
    for view in ("all", "open", "mine"):
        response = worker.request("GET", "/api/jobs", params={"view": view})
        assert response.status_code == 200
        assert job_id not in {row["id"] for row in response.json()["jobs"]}
        assert response.json()["summary"]["total_jobs"] == before_schedule["summary"]["total_jobs"] - 1
        assert response.json()["summary"]["my_jobs"] == before_schedule["summary"]["my_jobs"] - 1
        for row in response.json()["jobs"]:
            assert all(set(member) == {"display_name"} for member in row["crew"])
    for method in ("POST", "DELETE"):
        response = worker.request(method, f"/api/jobs/{job_id}/signup",
                                  **({"json": {}} if method == "POST" else {}))
        assert response.status_code == 404
    after_metrics = admin.request("GET", "/api/admin/metrics").json()["metrics"]
    assert after_metrics["total_jobs"] == before_metrics["total_jobs"] - 1
    assert after_metrics["booked_revenue"] == before_metrics["booked_revenue"]
    archived = detail(admin, job_id)
    assert admin.request("POST", f"/api/admin/jobs/{job_id}/restore",
                         json={"expected_revision": archived["revision"]}).status_code == 200
    restored = next(row for row in worker.request("GET", "/api/jobs").json()["jobs"] if row["id"] == job_id)
    assert restored["crew"] == [] and restored["joined"] is False
    assert members(trial, job_id) == set()


@pytest.mark.parametrize("attack", [
    "duplicate", "unknown", "admin", "disabled", "sql", "non-string", "over-capacity",
])
def test_crew_replacement_rejects_invalid_accounts_atomically(trial, admin, attack):
    worker = trial.login("alex")
    assert worker.request("POST", f"/api/jobs/{trial.empty_job}/signup", json={}).status_code == 200
    job = detail(admin, trial.empty_job)
    values = {
        "duplicate": [trial.ids["blair"], trial.ids["blair"]],
        "unknown": ["unknown-worker"],
        "admin": [trial.ids["admin"]],
        "disabled": [trial.ids["blair"]],
        "sql": ["' OR 1=1; DROP TABLE users; --"],
        "non-string": [True],
        "over-capacity": [trial.ids["blair"], trial.ids["casey"]],
    }
    if attack == "disabled":
        assert admin.request("PATCH", f"/api/admin/users/{trial.ids['blair']}",
                             json={"active": False}).status_code == 200
    before = state(trial)
    body = {**crew_body(trial, job), "worker_ids": values[attack]}
    if attack == "over-capacity":
        body["capacity"] = 1
    response = admin.request("PUT", f"/api/admin/jobs/{job['id']}/crew", json=body)
    assert response.status_code == 422, response.text
    assert state(trial) == before
    assert members(trial, job["id"]) == {trial.ids["alex"]}


@pytest.mark.parametrize("patch", [
    {"capacity": True}, {"capacity": "2"}, {"capacity": 0}, {"capacity": 11},
    {"expected_revision": True}, {"expected_revision": "0"}, {"expected_revision": -1},
    {"expected_revision": 10 ** 30}, {"role": "admin"}, {"actor_id": "admin"},
    {"worker_ids": "alex"}, {"worker_ids": None},
])
def test_crew_replacement_rejects_type_confusion_and_actor_overrides(trial, admin, patch):
    job = detail(admin, trial.empty_job)
    before = state(trial)
    response = admin.request("PUT", f"/api/admin/jobs/{job['id']}/crew",
                             json={**crew_body(trial, job), **patch})
    assert response.status_code == 422, response.text
    assert state(trial) == before


def test_archived_job_crew_cannot_change_and_stale_restore_is_rejected(trial, admin):
    job = detail(admin, trial.empty_job)
    assert admin.request("POST", f"/api/admin/jobs/{job['id']}/archive",
                         json={"expected_revision": job["revision"]}).status_code == 200
    archived = detail(admin, job["id"])
    before = state(trial)
    assert admin.request("PUT", f"/api/admin/jobs/{job['id']}/crew",
                         json=crew_body(trial, archived)).status_code == 409
    assert admin.request("POST", f"/api/admin/jobs/{job['id']}/restore",
                         json={"expected_revision": job["revision"]}).status_code == 409
    assert state(trial) == before


def test_hostile_display_names_remain_json_data_without_secret_account_fields(trial, admin):
    display_name = '<img src=x onerror="window.PWNED=1">; DROP TABLE users;--'
    created = admin.request("POST", "/api/admin/users", json={
        "username": "hostile_name", "display_name": display_name, "password": NEW_PASSWORD,
    })
    assert created.status_code in (200, 201)
    worker_id = created.json()["user"]["id"]
    job = detail(admin, trial.empty_job)
    response = admin.request("PUT", f"/api/admin/jobs/{job['id']}/crew", json={
        "worker_ids": [worker_id], "capacity": 1, "expected_revision": job["revision"],
    })
    assert response.status_code == 200
    assert response.json()["job"]["crew"] == [{"id": worker_id, "display_name": display_name}]
    worker = trial.login("alex")
    shared = worker.request("GET", "/api/jobs")
    row = next(row for row in shared.json()["jobs"] if row["id"] == job["id"])
    assert row["crew"] == [{"display_name": display_name}]
    assert shared.headers["content-type"].startswith("application/json")
    assert shared.headers["x-content-type-options"] == "nosniff"
    for forbidden in (worker_id, NEW_PASSWORD, "password_hash", "principal", "csrf_hash"):
        assert forbidden not in shared.text
