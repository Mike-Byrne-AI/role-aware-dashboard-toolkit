"""HTTP boundary, malformed input, CSRF, stored-content and SQL attacks."""

import json

import pytest

from .conftest import NEW_PASSWORD
from .test_authorization import admin_requests, customer_body, job_body


@pytest.mark.parametrize("origin", [
    "https://evil.invalid", "null", "http://testserver.evil.invalid",
    "https://testserver", "http://testserver:9999", "http://testserver@evil.invalid",
])
def test_login_rejects_cross_origin_and_origin_confusion(trial, origin):
    response = trial.client().post("/api/login", json={"username": "alex", "password": trial.credentials["alex"]}, headers={"Origin": origin})
    assert response.status_code == 403


def test_cross_site_fetch_metadata_and_untrusted_host_are_denied(trial):
    client = trial.client()
    assert client.post("/api/login", json={"username": "alex", "password": trial.credentials["alex"]}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/", headers={"Host": "evil.invalid"}).status_code in (400, 403)
    assert client.post("/api/login", json={"username": "alex", "password": trial.credentials["alex"]}, headers={"Host": "evil.invalid", "Origin": "http://evil.invalid"}).status_code in (400, 403)


@pytest.mark.parametrize("content_type,body", [
    ("application/x-www-form-urlencoded", "username=alex&password=whatever"),
    ("text/plain", '{"username":"alex","password":"whatever"}'),
    ("multipart/form-data; boundary=x", "--x--"),
])
def test_login_requires_json(trial, content_type, body):
    response = trial.client().post("/api/login", content=body, headers={"Content-Type": content_type})
    assert response.status_code in (400, 415, 422)


def test_csrf_required_on_every_authenticated_write(trial, admin):
    worker = trial.login("alex")
    job = trial.empty_job
    writes = [(admin, method, path, body) for method, path, body in admin_requests(trial) if method != "GET"]
    writes += [
        (worker, "POST", f"/api/jobs/{job}/signup", {}),
        (worker, "DELETE", f"/api/jobs/{job}/signup", None),
        (worker, "POST", "/api/messages", {"body": "CSRF attack"}),
        (worker, "POST", "/api/password", {"current_password": trial.credentials["alex"], "new_password": NEW_PASSWORD}),
        (worker, "POST", "/api/logout", {}),
    ]
    for actor, method, path, body in writes:
        for token in (None, "forged-csrf-token"):
            headers = {"Origin": "http://testserver"}
            if token is not None:
                headers["X-CSRF-Token"] = token
            kwargs = {"json": body} if body is not None else {}
            response = actor.client.request(method, path, headers=headers, **kwargs)
            assert response.status_code == 403, f"{method} {path}"
    assert worker.request("GET", "/api/session").status_code == 200


def test_csrf_is_bound_to_session_and_origin_checked_even_with_valid_token(trial):
    alex, blair = trial.login("alex"), trial.login("blair")
    assert alex.request("POST", "/api/messages", json={"body": "Forged"}, headers={"X-CSRF-Token": blair.csrf}).status_code == 403
    assert alex.request("POST", "/api/messages", json={"body": "Forged"}, headers={"Origin": "https://evil.invalid"}).status_code == 403
    assert alex.request("POST", "/api/messages", json={"body": "Forged"}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert alex.request("POST", "/api/messages", json={"body": "Legitimate"}).status_code in (200, 201)


@pytest.mark.parametrize("query", [
    {"sort": "pay DESC; DROP TABLE users;--"},
    {"sort": "(SELECT password_hash FROM users LIMIT 1)"},
    {"direction": "asc;DROP TABLE jobs;--"},
    {"sort": "owner_id"},
])
def test_sort_allowlist_rejects_sql_fragments(trial, query):
    actor = trial.login("alex")
    assert actor.request("GET", "/api/jobs", params=query).status_code in (400, 422)
    assert actor.request("GET", "/api/jobs").status_code == 200


def test_sql_parameter_injection_never_expands_scope(trial):
    actor = trial.login("alex")
    injected = "' OR 1=1 --"
    assert actor.request("GET", "/api/jobs", params={"worker_id": injected}).status_code in (400, 403, 422)
    response = actor.request("GET", "/api/jobs", params={"service": injected})
    assert response.status_code in (200, 400, 422)
    if response.status_code == 200:
        assert response.json()["jobs"] == []
    response = trial.client().post("/api/login", json={"username": injected, "password": NEW_PASSWORD})
    assert response.status_code in (401, 422)
    assert actor.request("GET", "/api/jobs").status_code == 200


def test_secret_inputs_are_not_reflected_by_validation_errors(trial, admin):
    secret = "SECRET_VALIDATION_CANARY_" + "x" * 1100
    responses = [
        trial.client().post("/api/login", json={"username": "alex", "password": secret}),
        admin.request("POST", "/api/admin/users", json={"username": "bad", "display_name": "Bad", "password": secret}),
        admin.request("POST", f"/api/admin/users/{trial.ids['alex']}/password", json={"password": secret}),
        admin.request("POST", "/api/password", json={"current_password": secret, "new_password": secret}),
    ]
    for response in responses:
        assert response.status_code in (400, 413, 422)
        assert "SECRET_VALIDATION_CANARY" not in response.text
        assert isinstance(response.json()["detail"], str)


def test_oversize_and_malformed_bodies_are_bounded_and_safe(trial):
    actor = trial.login("alex")
    body = json.dumps({"body": "x" * 17000})
    response = actor.request("POST", "/api/messages", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    response = actor.request("POST", "/api/messages", content="{ invalid json SECRET_PARSER_CANARY", headers={"Content-Type": "application/json"})
    assert response.status_code in (400, 422)
    assert "SECRET_PARSER_CANARY" not in response.text
    assert actor.request("POST", "/api/messages", json={"body": ""}).status_code == 422
    assert actor.request("POST", "/api/messages", json={"body": "x" * 1001}).status_code == 422


def test_streamed_oversize_body_cannot_bypass_content_length_limit(trial):
    actor = trial.login("alex")
    chunks = iter([b'{"body":"', b"x" * 9000, b"x" * 9000, b'"}'])
    response = actor.request("POST", "/api/messages", content=chunks, headers={"Content-Type": "application/json"})
    assert "content-length" not in response.request.headers
    assert response.status_code == 413


@pytest.mark.parametrize("header,values", [
    ("Host", ("testserver", "evil.invalid")),
    ("Origin", ("http://testserver", "https://evil.invalid")),
    ("X-CSRF-Token", ("first", "second")),
])
def test_ambiguous_duplicate_security_headers_fail_closed(trial, header, values):
    response = trial.client().get("/api/session", headers=[(header, value) for value in values])
    assert response.status_code == 400


@pytest.mark.parametrize("payload", [
    '<img src=x onerror="window.PWNED=1">',
    '</script><script>window.PWNED=1</script>',
    '<a href="javascript:alert(1)">attack</a>',
    "'; DROP TABLE messages; --",
])
def test_hostile_message_strings_remain_plain_json_data(trial, payload):
    actor, other = trial.login("alex"), trial.login("blair")
    assert actor.request("POST", "/api/messages", json={"body": payload}).status_code in (200, 201)
    response = other.request("GET", "/api/messages")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert any(row["body"] == payload for row in response.json()["messages"])
    assert response.headers["x-content-type-options"] == "nosniff"


def test_private_records_and_credentials_are_absent_from_public_files(trial, admin):
    customers = admin.request("GET", "/api/admin/customers").json()["customers"]
    client = trial.client()
    content = ""
    for path in ("/", "/static/app.js", "/static/styles.css"):
        response = client.get(path)
        assert response.status_code == 200
        content += response.text
    assert all(password not in content for password in trial.credentials.values())
    assert all(row["contact"] not in content for row in customers if row["contact"])
    for path in ("/TRIAL_ACCOUNTS.md", "/landscape.sqlite3", "/static/../TRIAL_ACCOUNTS.md", "/static/%2e%2e/landscape.sqlite3"):
        assert client.get(path).status_code in (400, 403, 404)


def test_security_headers_and_no_store_apply_to_success_and_denial(trial, admin):
    worker = trial.login("alex")
    responses = [
        trial.client().get("/api/session"), worker.request("GET", "/api/jobs"),
        worker.request("GET", "/api/admin/health"), admin.request("GET", "/api/admin/health"),
        worker.request("GET", "/schedule"), worker.request("GET", "/admin/health"),
    ]
    for response in responses:
        assert "no-store" in response.headers.get("cache-control", "")
        assert response.headers.get("x-content-type-options") == "nosniff"
    html = worker.request("GET", "/schedule")
    csp = html.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp and "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_strict_boolean_and_finite_numeric_input_types(trial, admin):
    worker_id = trial.ids["alex"]
    assert admin.request("PATCH", f"/api/admin/users/{worker_id}", json={"active": "false"}).status_code == 422
    revision = admin.request("GET", "/api/session").json()["freeze_revision"]
    assert admin.request("POST", "/api/admin/freeze", json={"frozen": 1, "expected_revision": revision}).status_code == 422
    for field, value in (("pay", True), ("pay", -1), ("hours", 0), ("hours", "2")):
        body = {**job_body(), field: value}
        assert admin.request("POST", "/api/admin/jobs", json=body).status_code == 422
    for numeric in ("NaN", "Infinity", "-Infinity"):
        body = json.dumps(customer_body()).replace('"value": 120', f'"value": {numeric}')
        response = admin.request("POST", "/api/admin/customers", content=body, headers={"Content-Type": "application/json"})
        assert response.status_code in (400, 422)
