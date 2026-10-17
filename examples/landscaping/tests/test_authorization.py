"""Shared visibility, self-only enrollment, and server-side admin boundaries."""
from datetime import datetime, timedelta, timezone
from itertools import permutations
import pytest
from .conftest import NEW_PASSWORD, WORKERS


def job_body():
    return {"customer": "Synthetic authorization test", "site": "100 Example Lane", "service": "mowing",
            "starts_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(), "hours": 2.5, "pay": 90, "capacity": 2}


def customer_body():
    return {"name": "Synthetic customer", "contact": "person@example.invalid", "service": "mowing",
            "stage": "Lead", "value": 120, "notes": "Fake test data"}


def admin_requests(trial):
    worker_id = trial.ids["alex"]
    with trial.db() as connection:
        customer_id = connection.execute("SELECT id FROM customers LIMIT 1").fetchone()[0]
    return [
        ("GET", "/api/workers", None), ("GET", "/api/admin/customers", None),
        ("GET", "/api/admin/health", None), ("GET", "/api/admin/metrics", None),
        ("POST", "/api/admin/users", {"username": "intruder", "display_name": "Intruder", "password": NEW_PASSWORD}),
        ("POST", f"/api/admin/users/{worker_id}/password", {"password": NEW_PASSWORD}),
        ("PATCH", f"/api/admin/users/{worker_id}", {"active": False}),
        ("POST", "/api/admin/freeze", {"frozen": True, "expected_revision": 0}),
        ("POST", "/api/admin/jobs", job_body()), ("POST", "/api/admin/customers", customer_body()),
        ("PATCH", f"/api/admin/customers/{customer_id}", {"stage": "Booked", "notes": "Forged"}),
    ]


def members(trial, job_id):
    with trial.db() as connection:
        return {row[0] for row in connection.execute("SELECT user_id FROM job_signups WHERE job_id=?", (job_id,))}


@pytest.mark.parametrize("actor_name,target_name", list(permutations(WORKERS, 2)))
def test_all_twenty_pairs_share_schedule_but_cannot_impersonate_or_cancel_peer(trial, actor_name, target_name):
    actor, target = trial.login(actor_name), trial.login(target_name)
    own_id, target_id = trial.ids[actor_name], trial.ids[target_name]
    job_id = trial.empty_job
    endpoint = f"/api/jobs/{job_id}/signup"
    own_schedule = actor.request("GET", "/api/jobs").json()
    target_schedule = target.request("GET", "/api/jobs").json()
    assert {row["id"] for row in own_schedule["jobs"]} == {row["id"] for row in target_schedule["jobs"]}
    assert len(own_schedule["jobs"]) == 12
    assert actor.request("GET", "/schedule").status_code == 200
    legacy = actor.request("GET", f"/work/{target_name}", follow_redirects=False)
    assert legacy.status_code in (302, 303, 307, 308) and legacy.headers["location"] == "/schedule"
    assert actor.request("GET", "/api/jobs", params={"worker_id": target_id}).status_code == 422
    assert target.request("POST", endpoint, json={}).status_code == 200
    for override in ("user_id", "worker_id", "actor_id", "signed_by"):
        assert actor.request("POST", endpoint, json={override: target_id}).status_code == 422
        assert actor.request("DELETE", endpoint, json={override: target_id}).status_code == 422
        assert actor.request("DELETE", endpoint, params={override: target_id}).status_code == 422
    for method in ("POST", "DELETE"):
        kwargs = {"json": {}} if method == "POST" else {}
        assert actor.request(method, endpoint, params={"worker_id": target_id}, **kwargs).status_code == 422
        for path in (f"{endpoint}/{target_id}", f"/api/jobs/{job_id}/signups/{target_id}"):
            assert actor.request(method, path, **kwargs).status_code in (404, 405)
    assert members(trial, job_id) == {target_id}
    assert actor.request("DELETE", endpoint).status_code == 200
    assert members(trial, job_id) == {target_id}
    assert actor.request("POST", endpoint, json={}).status_code == 200
    assert members(trial, job_id) == {target_id, own_id}
    assert actor.request("DELETE", endpoint).status_code == 200
    assert members(trial, job_id) == {target_id}
    row = next(row for row in actor.request("GET", "/api/jobs").json()["jobs"] if row["id"] == job_id)
    assert row["joined"] is False and row["signup_count"] == 1
    assert row["crew"] == [{"display_name": target.profile["display_name"]}]


@pytest.mark.parametrize("actor_name", WORKERS)
def test_each_worker_is_denied_every_admin_api_and_html_page(trial, actor_name):
    actor = trial.login(actor_name)
    for method, path, body in admin_requests(trial):
        kwargs = {"json": body} if body is not None else {}
        assert actor.request(method, path, **kwargs).status_code == 403, f"{actor_name}: {method} {path}"
    for page in ("customers", "health", "metrics"):
        assert actor.request("GET", f"/admin/{page}").status_code == 403


def test_unauthenticated_private_api_denies_and_html_redirects(trial):
    client = trial.client()
    requests = admin_requests(trial) + [("GET", "/api/session", None), ("GET", "/api/jobs", None),
        ("GET", "/api/messages", None), ("POST", "/api/messages", {"body": "Anonymous attack"}),
        ("POST", f"/api/jobs/{trial.empty_job}/signup", {})]
    for method, path, body in requests:
        kwargs = {"json": body} if body is not None else {}
        assert client.request(method, path, **kwargs).status_code == 401, f"{method} {path}"
    for path in ("/schedule", "/work/alex", "/admin/customers", "/admin/health", "/admin/metrics"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code in (302, 303, 307) and response.headers["location"] == "/"


def test_forged_browser_identity_never_changes_server_scope(trial):
    actor = trial.login("alex")
    headers = {"X-User-ID": trial.ids["admin"], "X-Role": "admin", "X-Forwarded-User": "admin",
               "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."}
    response = actor.request("GET", "/api/jobs", params={"view": "mine"}, headers=headers)
    assert response.status_code == 200
    with trial.db() as connection:
        own_jobs = {row[0] for row in connection.execute("SELECT job_id FROM job_signups WHERE user_id=?", (trial.ids["alex"],))}
    assert {row["id"] for row in response.json()["jobs"]} == own_jobs
    assert actor.request("GET", "/api/admin/health", headers=headers).status_code == 403
    for body in ({"body": "Forged admin", "author": "admin"}, {"body": "Forged admin", "role": "admin"},
                 {"body": "Forged admin", "user_id": trial.ids["admin"]}):
        assert actor.request("POST", "/api/messages", json=body).status_code == 422
    assert actor.request("POST", f"/api/jobs/{trial.empty_job}/signup", json={"signed_by": trial.ids["admin"]}).status_code == 422


def test_admin_can_create_only_workers_and_cannot_disable_or_reset_admin(trial, admin):
    body = {"username": "newworker", "display_name": "New Worker", "password": NEW_PASSWORD}
    for injection in ({"role": "admin"}, {"id": trial.ids["admin"]}, {"active": True}):
        assert admin.request("POST", "/api/admin/users", json={**body, **injection}).status_code == 422
    assert admin.request("PATCH", f"/api/admin/users/{trial.ids['admin']}", json={"active": False}).status_code in (400, 403, 404)
    assert admin.request("POST", f"/api/admin/users/{trial.ids['admin']}/password", json={"password": NEW_PASSWORD}).status_code in (400, 403, 404)
    endpoint = f"/api/jobs/{trial.empty_job}/signup"
    assert admin.request("POST", endpoint, json={}).status_code == 403
    assert admin.request("DELETE", endpoint).status_code == 403
    assert members(trial, trial.empty_job) == set()
    assert admin.request("GET", "/api/admin/health").status_code == 200


def test_admin_end_to_end_account_shared_schedule_outreach_and_metrics(trial, admin):
    before = admin.request("GET", "/api/admin/metrics").json()["metrics"]
    response = admin.request("POST", "/api/admin/users", json={"username": "newworker", "display_name": "New Worker", "password": NEW_PASSWORD})
    assert response.status_code in (200, 201)
    user = response.json()["user"]
    assert user["role"] == "worker" and user["active"]
    worker = trial.login("newworker", NEW_PASSWORD)
    existing = worker.request("GET", "/api/jobs").json()
    assert len(existing["jobs"]) == 12 and existing["summary"]["my_jobs"] == 0
    assert not any(row["joined"] for row in existing["jobs"])
    assert admin.request("POST", "/api/admin/jobs", json=job_body()).status_code in (200, 201)
    jobs = worker.request("GET", "/api/jobs").json()["jobs"]
    created = next(row for row in jobs if row["customer"] == "Synthetic authorization test")
    assert len(jobs) == 13 and created["capacity"] == 2 and "owner_id" not in created
    assert worker.request("POST", f"/api/jobs/{created['id']}/signup", json={}).status_code == 200
    assert admin.request("POST", "/api/admin/jobs", json={**job_body(), "owner_id": user["id"]}).status_code == 422
    for name in WORKERS:
        assert admin.request("GET", f"/work/{name}", follow_redirects=False).headers["location"] == "/schedule"
    assert admin.request("POST", "/api/admin/customers", json=customer_body()).status_code in (200, 201)
    customer = next(row for row in admin.request("GET", "/api/admin/customers").json()["customers"] if row["name"] == "Synthetic customer")
    assert admin.request("PATCH", f"/api/admin/customers/{customer['id']}", json={"stage": "Booked", "notes": "Contacted in synthetic test"}).status_code == 200
    result = admin.request("GET", "/api/admin/metrics").json()
    after = result["metrics"]
    assert after["total_jobs"] == before["total_jobs"] + 1
    assert after["active_workers"] == before["active_workers"] + 1
    assert after["booked_revenue"] == before["booked_revenue"] + 120
    assert sum(row["revenue"] for row in result["by_service"]) == after["booked_revenue"]
    assert admin.request("GET", "/api/admin/health").json()["audit"]


def test_signing_up_changes_staffing_metrics_without_changing_customer_revenue(trial, admin):
    worker = trial.login("alex")
    before = admin.request("GET", "/api/admin/metrics").json()
    assert worker.request("POST", f"/api/jobs/{trial.empty_job}/signup", json={}).status_code == 200
    after = admin.request("GET", "/api/admin/metrics").json()
    assert after["metrics"]["signup_rate"] > before["metrics"]["signup_rate"]
    assert after["metrics"]["booked_revenue"] == before["metrics"]["booked_revenue"]
    assert {row["service"]: row["revenue"] for row in after["by_service"]} == {row["service"]: row["revenue"] for row in before["by_service"]}
    with trial.db() as connection:
        filled = connection.execute("SELECT COUNT(*) FROM job_signups").fetchone()[0]
        capacity = connection.execute("SELECT SUM(capacity) FROM jobs").fetchone()[0]
    assert after["metrics"]["signup_rate"] == pytest.approx(filled / capacity)


def test_worker_signup_cancel_sort_filter_and_shared_immutable_attribution(trial):
    alex, blair = trial.login("alex"), trial.login("blair")
    jobs = alex.request("GET", "/api/jobs").json()["jobs"]
    job_id = trial.empty_job
    for _ in range(2):
        assert alex.request("POST", f"/api/jobs/{job_id}/signup", json={}).status_code == 200
    signed = next(row for row in alex.request("GET", "/api/jobs").json()["jobs"] if row["id"] == job_id)
    assert signed["joined"] is True and signed["signup_count"] == 1
    assert alex.request("DELETE", f"/api/jobs/{job_id}/signup").status_code == 200
    for key in ("starts_at", "hours", "pay"):
        for direction in ("asc", "desc"):
            rows = alex.request("GET", "/api/jobs", params={"sort": key, "direction": direction}).json()["jobs"]
            assert [row[key] for row in rows] == sorted([row[key] for row in rows], reverse=direction == "desc")
    filtered = alex.request("GET", "/api/jobs", params={"service": jobs[0]["service"]}).json()["jobs"]
    assert filtered and {row["service"] for row in filtered} == {jobs[0]["service"]}
    message = "Shared synthetic message from Alex"
    assert alex.request("POST", "/api/messages", json={"body": message}).status_code in (200, 201)
    row = next(row for row in blair.request("GET", "/api/messages").json()["messages"] if row["body"] == message)
    assert row["author"] in ("alex", alex.profile["display_name"])


def test_freeze_cross_session_blocks_business_writes_but_allows_security_controls(trial, admin):
    worker = trial.login("alex")
    initial = admin.request("GET", "/api/session").json()
    frozen = admin.request("POST", "/api/admin/freeze", json={"frozen": True, "expected_revision": initial["freeze_revision"]})
    assert frozen.status_code == 200
    revision = frozen.json()["freeze_revision"]
    assert revision > initial["freeze_revision"]
    assert worker.request("GET", "/api/jobs").json()["frozen"] is True
    assert worker.request("GET", "/api/messages").status_code == 200
    endpoint = f"/api/jobs/{trial.empty_job}/signup"
    blocked = [(worker, "POST", endpoint, {}), (worker, "DELETE", endpoint, None),
        (worker, "POST", "/api/messages", {"body": "Blocked while frozen"}),
        (admin, "POST", "/api/admin/users", {"username": "frozenworker", "display_name": "Frozen", "password": NEW_PASSWORD}),
        (admin, "POST", "/api/admin/jobs", job_body()), (admin, "POST", "/api/admin/customers", customer_body())]
    for actor, method, path, body in blocked:
        kwargs = {"json": body} if body is not None else {}
        assert actor.request(method, path, **kwargs).status_code in (403, 409, 423), path
    assert admin.request("POST", "/api/admin/freeze", json={"frozen": False, "expected_revision": initial["freeze_revision"]}).status_code == 409
    assert admin.request("POST", f"/api/admin/users/{trial.ids['alex']}/password", json={"password": NEW_PASSWORD}).status_code == 200
    assert worker.request("GET", "/api/session").status_code == 401
    assert admin.request("PATCH", f"/api/admin/users/{trial.ids['blair']}", json={"active": False}).status_code == 200
    assert admin.request("POST", "/api/admin/freeze", json={"frozen": False, "expected_revision": revision}).status_code == 200
