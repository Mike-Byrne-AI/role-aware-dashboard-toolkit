"""Business example behavior and access boundaries using disposable local data."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time
from threading import Barrier

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")
from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "business_dashboard"
sys.path.insert(0, str(EXAMPLE))

from business.app import create_app  # noqa: E402 -- source example, not an installed package
from business.seed import provision  # noqa: E402
from business.security import COOKIE_NAME  # noqa: E402
from business.secret_store import default_key_path  # noqa: E402
from business import mfa  # noqa: E402
from business.abuse import PUBLIC_RULES  # noqa: E402

ORIGIN = "http://127.0.0.1:8091"
EMPLOYEES = ("alex", "blair", "casey", "drew", "ellis")
NEW_PASSWORD = "Separate disposable password 482!"


@dataclass
class Seed:
    directory: Path
    credentials: dict[str, str] = field(repr=False)
    output: str = field(repr=False)


@dataclass
class Actor:
    client: TestClient
    profile: dict
    csrf: str = field(repr=False)

    def request(self, method, path, **kwargs):
        headers = {"Origin": ORIGIN, "X-CSRF-Token": self.csrf}
        headers.update(kwargs.pop("headers", {}))
        return self.client.request(method, path, headers=headers, **kwargs)


class Trial:
    def __init__(self, directory, credentials, stack):
        self.directory = directory
        self.credentials = credentials
        self.app = create_app(directory, public_origin=ORIGIN)
        self.stack = stack
        self.mfa_time = mfa.current_time()

    def client(self, app=None, **kwargs):
        return self.stack.enter_context(TestClient(app or self.app, base_url=ORIGIN, **kwargs))

    def login_payload(self, username, password=None):
        payload = {
            "username": username, "password": password or self.credentials[username],
        }
        with self.db() as connection:
            enrollment = connection.execute("SELECT * FROM admin_mfa WHERE user_id=?", (username,)).fetchone()
        if enrollment:
            self.mfa_time = max(self.mfa_time, (enrollment["last_counter"] + 1) * mfa.INTERVAL)
            secret = self.app.state.database.mfa_secrets.decrypt(enrollment["secret_ciphertext"], username, enrollment["generation"])
            payload["otp"] = pyotp.TOTP(secret).at(self.mfa_time)
        return payload

    def login(self, username, password=None):
        client = self.client()
        response = client.post("/api/login", json=self.login_payload(username, password), headers={"Origin": ORIGIN})
        assert response.status_code == 200, "Disposable account could not sign in"
        data = response.json()
        return Actor(client, data["user"], data["csrf"])

    def db(self):
        return self.app.state.database.transaction()


@pytest.fixture(scope="session")
def business_seed():
    # Deliberately independent of pytest's default in-repository basetemp.
    with tempfile.TemporaryDirectory(prefix="radt-business-seed-") as temporary:
        directory = Path(temporary).resolve() / "private"
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            credentials = provision(directory)
        yield Seed(directory, credentials, output.getvalue())


@pytest.fixture
def business(business_seed, monkeypatch):
    with tempfile.TemporaryDirectory(prefix="radt-business-test-") as temporary:
        directory = Path(temporary).resolve() / "private"
        shutil.copytree(business_seed.directory, directory)
        shutil.copytree(default_key_path(business_seed.directory).parent, default_key_path(directory).parent)
        with ExitStack() as stack:
            trial = Trial(directory, business_seed.credentials, stack)
            monkeypatch.setattr(mfa, "current_time", lambda: trial.mfa_time)
            yield trial


@pytest.fixture
def business_admin(business):
    return business.login("admin")


def event_body(**patch):
    start = (datetime.now(timezone.utc) + timedelta(days=60)).replace(microsecond=0)
    return {
        "title": "Client planning session", "starts_at": start.isoformat(),
        "ends_at": (start + timedelta(hours=2)).isoformat(), "location": "Meeting room A",
        "notes": "Private scheduling note", "employee_ids": ["alex"], **patch,
    }


def contact_body(**patch):
    return {"name": "Taylor Park", "company": "Fictional Partners", "email": "taylor@example.invalid",
            "stage": "New", "value": 1250, "notes": "Private outreach canary", **patch}


def post_body(**patch):
    return {"title": "Quarterly update", "body": "A public business announcement.",
            "category": "Company", "published": True, **patch}


def saved(response, key):
    assert response.status_code in (200, 201), "Expected record save failed"
    return response.json()[key]


def business_rows(trial):
    with trial.db() as connection:
        return tuple(tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1"))
                     for table in ("events", "assignments", "messages", "contacts", "posts", "activity"))


def test_seed_has_one_admin_five_employees_unique_passwords_and_no_console_secrets(business, business_seed):
    assert set(business_seed.credentials) == {"admin", *EMPLOYEES}
    assert len(set(business_seed.credentials.values())) == 6
    assert all(len(password) >= 12 for password in business_seed.credentials.values())
    with business.db() as connection:
        users = connection.execute("SELECT username,role,password_hash FROM users ORDER BY username").fetchall()
    assert {row["username"]: row["role"] for row in users} == {
        "admin": "admin", **dict.fromkeys(EMPLOYEES, "employee"),
    }
    for row in users:
        assert row["password_hash"].startswith("pbkdf2_sha256$")
        assert business_seed.credentials[row["username"]] not in row["password_hash"]
    assert all(password not in business_seed.output for password in business_seed.credentials.values())
    assert (business.directory / "ACCOUNTS.md").is_file()


def test_public_board_projects_published_posts_without_private_records(business, business_admin):
    public = saved(business_admin.request("POST", "/api/admin/posts", json=post_body()), "post")
    saved(business_admin.request("POST", "/api/admin/posts", json=post_body(
        title="DRAFT_TITLE_CANARY", body="DRAFT_BODY_CANARY", published=False)), "post")
    saved(business_admin.request("POST", "/api/admin/contacts", json=contact_body()), "contact")
    saved(business_admin.request("POST", "/api/messages", json={"body": "PRIVATE_MESSAGE_CANARY"}), "message")
    saved(business_admin.request("POST", "/api/schedule", json=event_body(notes="PRIVATE_SCHEDULE_CANARY")), "event")
    guest = business.client()
    assert guest.get("/api/session").json()["user"] is None
    response = guest.get("/api/public/posts")
    assert response.status_code == 200
    posts = response.json()["posts"]
    assert public["id"] in {row["id"] for row in posts}
    assert all(set(row) == {"id", "title", "body", "category", "published_at"} for row in posts)
    assert not any(marker in response.text for marker in (
        "DRAFT_TITLE_CANARY", "DRAFT_BODY_CANARY", "PRIVATE_MESSAGE_CANARY",
        "PRIVATE_SCHEDULE_CANARY", "Private outreach canary", "taylor@example.invalid",
    ))
    assert COOKIE_NAME not in guest.cookies


def test_public_board_link_serves_shell_without_private_data_or_staff_access(business, business_admin):
    saved(business_admin.request("POST", "/api/admin/posts", json=post_body(
        title="LINK_PRIVATE_DRAFT", body="LINK_PRIVATE_BODY", published=False)), "post")
    saved(business_admin.request("POST", "/api/messages", json={"body": "LINK_PRIVATE_MESSAGE"}), "message")
    guest = business.client()
    response = guest.get("/board")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-store"
    assert 'id="app"' in response.text and 'src="/static/app.js"' in response.text
    assert not any(value in response.text for value in (
        "LINK_PRIVATE_DRAFT", "LINK_PRIVATE_BODY", "LINK_PRIVATE_MESSAGE",
        *business.credentials.values(),
    ))
    assert COOKIE_NAME not in guest.cookies
    assert guest.get("/api/session").json()["user"] is None
    assert guest.get("/api/admin/submissions").status_code == 401
    assert guest.get("/board", headers={
        "Host": "other.example.invalid", "X-Forwarded-Host": "127.0.0.1",
    }).status_code == 400


def test_guest_is_not_a_passwordless_staff_account(business):
    client = business.client()
    for username in ("guest", "admin", "alex"):
        response = client.post("/api/login", json={"username": username, "password": ""}, headers={"Origin": ORIGIN})
        assert response.status_code in (401, 422)
    assert client.get("/api/session").json()["user"] is None
    assert client.get("/api/public/posts").status_code == 200


def test_all_private_data_requires_a_valid_session(business):
    client = business.client()
    for path in ("/api/schedule", "/api/messages", "/api/admin/overview", "/api/admin/contacts",
                 "/api/admin/posts", "/api/admin/users"):
        assert client.get(path).status_code == 401, path
    client.cookies.set(COOKIE_NAME, "A" * 43)
    assert client.get("/api/schedule").status_code == 401


@pytest.mark.parametrize("username", EMPLOYEES)
def test_every_employee_has_shared_work_but_cannot_invoke_admin_routes(business, username):
    employee = business.login(username)
    assert employee.profile["role"] == "employee"
    assert employee.request("GET", "/api/schedule").status_code == 200
    assert employee.request("GET", "/api/messages").status_code == 200
    before = business_rows(business)
    headers = {"X-Role": "admin", "X-User-ID": "admin", "Authorization": "Bearer admin"}
    for path in ("/api/admin/overview", "/api/admin/contacts", "/api/admin/posts", "/api/admin/users"):
        assert employee.request("GET", path, headers=headers).status_code == 403, path
    for path, body in (("/api/schedule", event_body()), ("/api/admin/contacts", contact_body()),
                       ("/api/admin/posts", post_body()), ("/api/admin/freeze", {"frozen": True, "revision": 0})):
        assert employee.request("POST", path, json=body, headers=headers).status_code == 403, path
    assert employee.request("PUT", "/api/admin/users/blair", json={"active": False, "revision": 0}).status_code == 403
    assert business_rows(business) == before


def test_messages_are_shared_and_author_is_server_owned(business):
    alex, blair = business.login("alex"), business.login("blair")
    payload = '<img src=x onerror="window.PWNED=1"> Staff update'
    message = saved(alex.request("POST", "/api/messages", json={"body": payload}), "message")
    response = blair.request("GET", "/api/messages")
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert any(row["id"] == message["id"] and row["body"] == payload
               and row["author"] == alex.profile["name"] for row in response.json()["messages"])
    assert alex.request("POST", "/api/messages", json={"body": "Forged", "author_id": "admin"}).status_code == 422


def test_csrf_missing_forged_other_session_and_origin_attacks_preserve_records(business, business_admin):
    alex = business.login("alex")
    operations = [
        ("POST", "/api/messages", {"body": "Not accepted"}),
        ("POST", "/api/schedule", event_body()),
        ("POST", "/api/admin/contacts", contact_body()),
        ("POST", "/api/admin/posts", post_body()),
        ("POST", "/api/admin/freeze", {"frozen": True, "revision": 0}),
        ("PUT", "/api/admin/users/alex", {"active": False, "revision": 0}),
        ("POST", "/api/password", {"current_password": business.credentials["admin"], "new_password": NEW_PASSWORD}),
        ("POST", "/api/logout", {}),
    ]
    before = business_rows(business)
    attacks = ({"Origin": ORIGIN}, {"Origin": ORIGIN, "X-CSRF-Token": "forged"},
               {"Origin": ORIGIN, "X-CSRF-Token": alex.csrf},
               {"Origin": "https://evil.invalid", "X-CSRF-Token": business_admin.csrf})
    for method, path, body in operations:
        for headers in attacks:
            response = business_admin.client.request(method, path, json=body, headers=headers)
            assert response.status_code == 403, path
    assert business_rows(business) == before
    assert business_admin.request("GET", "/api/admin/overview").status_code == 200


@pytest.mark.parametrize("origin", [None, "null", "http://127.0.0.1:8091.evil.invalid", "https://127.0.0.1:8091"])
def test_login_rejects_missing_or_foreign_origin(business, origin):
    response = business.client().post("/api/login", json={"username": "admin", "password": business.credentials["admin"]},
                                      headers={} if origin is None else {"Origin": origin})
    assert response.status_code == 403


def test_logout_revokes_replayed_cookie(business):
    employee = business.login("alex")
    cookie = employee.client.cookies.get(COOKIE_NAME)
    assert employee.request("POST", "/api/logout", json={}).status_code == 200
    replay = business.client()
    replay.cookies.set(COOKIE_NAME, cookie)
    assert replay.get("/api/messages").status_code == 401


def test_password_change_revokes_all_sessions_and_old_password(business):
    first, second = business.login("alex"), business.login("alex")
    cookie = first.client.cookies.get(COOKIE_NAME)
    assert first.request("POST", "/api/password", json={
        "current_password": business.credentials["alex"], "new_password": NEW_PASSWORD,
    }).status_code == 200
    assert second.request("GET", "/api/schedule").status_code == 401
    replay = business.client()
    replay.cookies.set(COOKIE_NAME, cookie)
    assert replay.get("/api/messages").status_code == 401
    assert business.client().post("/api/login", json={
        "username": "alex", "password": business.credentials["alex"],
    }, headers={"Origin": ORIGIN}).status_code == 401
    assert business.login("alex", NEW_PASSWORD).request("GET", "/api/messages").status_code == 200


def test_disable_reenable_does_not_resurrect_previous_session(business, business_admin):
    employee = business.login("alex")
    cookie = employee.client.cookies.get(COOKIE_NAME)
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": False, "revision": 0}).status_code == 200
    users = business_admin.request("GET", "/api/admin/users").json()["users"]
    user = next(row for row in users if row["id"] == "alex")
    assert employee.request("GET", "/api/messages").status_code == 401
    assert business.client().post("/api/login", json={"username": "alex", "password": business.credentials["alex"]},
                                  headers={"Origin": ORIGIN}).status_code == 401
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": True, "revision": user["revision"]}).status_code == 200
    replay = business.client()
    replay.cookies.set(COOKIE_NAME, cookie)
    assert replay.get("/api/messages").status_code == 401
    assert business.login("alex").request("GET", "/api/messages").status_code == 200


def test_existing_session_uses_current_database_role(business, business_admin):
    with business.db() as connection:
        connection.execute("UPDATE users SET role='employee' WHERE id='admin'")
    assert business_admin.request("GET", "/api/admin/overview").status_code == 403
    assert business_admin.request("POST", "/api/admin/posts", json=post_body()).status_code == 403
    assert business_admin.request("GET", "/api/messages").status_code == 200


def test_toolkit_authorization_denial_blocks_actual_host_mutation(business, business_admin, monkeypatch):
    from role_aware_dashboard_toolkit.access import AccessPolicy

    calls = []
    original = AccessPolicy.authorize

    def deny_business_write(self, principal_id, role, permission, custom_roles=None, *, write=False):
        calls.append((permission, write, self.store.connection.in_transaction))
        if write:
            return False
        return original(self, principal_id, role, permission, custom_roles, write=write)

    monkeypatch.setattr(AccessPolicy, "authorize", deny_business_write)
    before = business_rows(business)
    assert business_admin.request("POST", "/api/schedule", json=event_body()).status_code == 403
    assert any(permission == "can_manage_business" and write and transaction
               for permission, write, transaction in calls)
    assert business_rows(business) == before


def test_freeze_blocks_business_writes_preserves_reads_and_admin_can_resume(business, business_admin):
    employee = business.login("alex")
    frozen = business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0})
    assert frozen.status_code == 200
    revision = frozen.json()["freeze_revision"]
    before = business_rows(business)
    assert employee.request("POST", "/api/messages", json={"body": "Blocked while paused"}).status_code == 403
    for path, body in (("/api/schedule", event_body()), ("/api/admin/contacts", contact_body()), ("/api/admin/posts", post_body())):
        assert business_admin.request("POST", path, json=body).status_code == 403
    assert business_rows(business) == before
    assert employee.request("GET", "/api/schedule").status_code == 200
    assert employee.request("GET", "/api/messages").status_code == 200
    assert business_admin.request("GET", "/api/admin/overview").status_code == 200
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": 0}).status_code == 409
    resumed = business_admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": revision})
    assert resumed.status_code == 200
    saved(employee.request("POST", "/api/messages", json={"body": "Accepted after resume"}), "message")


def test_freeze_keeps_account_security_available_with_stale_and_last_admin_protection(business, business_admin):
    alex, blair, casey = (business.login(username) for username in ("alex", "blair", "casey"))
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": False, "revision": 0}).status_code == 200
    assert alex.request("GET", "/api/messages").status_code == 401
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": False, "revision": 0}).status_code == 409
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": True, "revision": 1}).status_code == 403
    assert business_admin.request("PUT", "/api/admin/users/admin", json={"active": False, "revision": 0}).status_code == 409
    assert blair.request("POST", "/api/password", json={
        "current_password": business.credentials["blair"], "new_password": NEW_PASSWORD,
    }).status_code == 200
    assert blair.request("GET", "/api/messages").status_code == 401
    assert casey.request("POST", "/api/logout", json={}).status_code == 200
    assert casey.request("GET", "/api/messages").status_code == 401
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": 1}).status_code == 200
    assert business_admin.request("PUT", "/api/admin/users/alex", json={"active": True, "revision": 1}).status_code == 200


def test_schedule_revisions_preserve_newer_edits_and_archive(business, business_admin):
    body = event_body()
    event = saved(business_admin.request("POST", "/api/schedule", json=body), "event")
    path = f"/api/schedule/{event['id']}"
    updated = saved(business_admin.request("PUT", path, json={**body, "title": "Updated session", "revision": event["revision"]}), "event")
    assert updated["revision"] == event["revision"] + 1
    assert business_admin.request("PUT", path, json={**body, "title": "Stale overwrite", "revision": event["revision"]}).status_code == 409
    assert business_admin.request("POST", path + "/archive", json={"revision": event["revision"]}).status_code == 409
    assert business_admin.request("POST", path + "/archive", json={"revision": updated["revision"]}).status_code == 200
    employee = business.login("alex")
    assert event["id"] not in {row["id"] for row in employee.request("GET", "/api/schedule").json()["events"]}


def test_schedule_rejects_employee_overlap_but_allows_adjacent_and_other_staff(business, business_admin):
    body = event_body()
    saved(business_admin.request("POST", "/api/schedule", json=body), "event")
    assert business_admin.request("POST", "/api/schedule", json={**body, "title": "Overlapping"}).status_code == 409
    saved(business_admin.request("POST", "/api/schedule", json={**body, "employee_ids": ["blair"]}), "event")
    adjacent_start = datetime.fromisoformat(body["ends_at"])
    saved(business_admin.request("POST", "/api/schedule", json={**body,
        "starts_at": adjacent_start.isoformat(), "ends_at": (adjacent_start + timedelta(hours=1)).isoformat(),
    }), "event")


@pytest.mark.parametrize("patch", [{"employee_ids": ["missing"]}, {"employee_ids": ["alex", "alex"]},
    {"starts_at": "2099-01-01T10:00:00"}, {"ends_at": "2020-01-01T10:00:00+00:00"}, {"title": "   "},
    {"starts_at": "9999-12-31T23:59:00-23:00", "ends_at": "9999-12-31T23:59:59-23:00"}])
def test_schedule_invalid_input_does_not_change_saved_work(business, business_admin, patch):
    before = business_rows(business)
    assert business_admin.request("POST", "/api/schedule", json=event_body(**patch)).status_code == 422
    assert business_rows(business) == before


def test_outreach_updates_are_revision_checked_and_feed_analytics(business, business_admin):
    before = business_admin.request("GET", "/api/admin/overview").json()["metrics"]
    body = contact_body(value=4321)
    contact = saved(business_admin.request("POST", "/api/admin/contacts", json=body), "contact")
    after = business_admin.request("GET", "/api/admin/overview").json()["metrics"]
    assert after["pipeline_value"] == pytest.approx(before["pipeline_value"] + 4321)
    assert after["open_leads"] == before["open_leads"] + 1
    path = f"/api/admin/contacts/{contact['id']}"
    saved(business_admin.request("PUT", path, json={**body, "stage": "Won", "revision": contact["revision"]}), "contact")
    assert business_admin.request("PUT", path, json={**body, "revision": contact["revision"]}).status_code == 409
    final = business_admin.request("GET", "/api/admin/overview").json()["metrics"]
    assert final["open_leads"] == before["open_leads"]


def test_published_notice_can_be_withdrawn_without_stale_republication(business, business_admin):
    body = post_body()
    post = saved(business_admin.request("POST", "/api/admin/posts", json=body), "post")
    path = f"/api/admin/posts/{post['id']}"
    saved(business_admin.request("PUT", path, json={**body, "published": False, "revision": post["revision"]}), "post")
    assert business_admin.request("PUT", path, json={**body, "revision": post["revision"]}).status_code == 409
    public = business.client().get("/api/public/posts")
    assert public.status_code == 200
    assert public.headers["cache-control"] == "no-store"
    posts = public.json()["posts"]
    assert post["id"] not in {row["id"] for row in posts}
    assert all(set(row) == {"id", "title", "body", "category", "published_at"} for row in posts)


def test_restart_preserves_saved_records_credentials_and_identity(business, business_admin):
    message = saved(business_admin.request("POST", "/api/messages", json={"body": "Retained across restart"}), "message")
    before = business_rows(business)
    account_sheet = (business.directory / "ACCOUNTS.md").read_bytes()
    identity = (business.directory / "identity.key").read_bytes()
    restarted = create_app(business.directory, public_origin=ORIGIN)
    client = business.client(restarted)
    response = client.post("/api/login", json=business.login_payload("admin"), headers={"Origin": ORIGIN})
    assert response.status_code == 200
    assert any(row["id"] == message["id"] for row in client.get("/api/messages").json()["messages"])
    # Login may append an audit entry; business records themselves must survive untouched.
    assert business_rows(business)[:-1] == before[:-1]
    assert (business.directory / "ACCOUNTS.md").read_bytes() == account_sheet
    assert (business.directory / "identity.key").read_bytes() == identity
    with pytest.raises(ValueError):
        provision(business.directory)
    assert (business.directory / "identity.key").read_bytes() == identity


def test_startup_requires_provisioning_and_rejects_source_storage():
    with tempfile.TemporaryDirectory(prefix="radt-business-empty-") as temporary:
        missing = Path(temporary).resolve() / "missing"
        with pytest.raises(ValueError):
            create_app(missing, public_origin=ORIGIN)
        assert not missing.exists()
    source_data = EXAMPLE / "forbidden-runtime-data"
    assert not source_data.exists()
    for operation in (provision, create_app):
        with pytest.raises(ValueError, match="source tree"):
            operation(source_data)
    assert not source_data.exists()


def test_missing_identity_key_fails_closed_without_recreating_state(business):
    identity = business.directory / "identity.key"
    identity.rename(business.directory / "identity.saved")
    database_before = business.app.state.database.path.read_bytes()
    with pytest.raises(ValueError):
        create_app(business.directory, public_origin=ORIGIN)
    with pytest.raises(ValueError):
        provision(business.directory)
    assert not identity.exists()
    assert business.app.state.database.path.read_bytes() == database_before


def test_errors_and_public_assets_do_not_expose_credentials_or_database(business, business_admin):
    secret = "SECRET_VALIDATION_CANARY_" + "x" * 500
    responses = [
        business.client().post("/api/login", json={"username": "admin", "password": secret}, headers={"Origin": ORIGIN}),
        business_admin.request("POST", "/api/password", json={"current_password": secret, "new_password": secret}),
        business_admin.request("POST", "/api/messages", content="{invalid SECRET_PARSER_CANARY", headers={"Content-Type": "application/json"}),
    ]
    for response in responses:
        assert response.status_code in (400, 413, 422)
        assert "SECRET_VALIDATION_CANARY" not in response.text
        assert "SECRET_PARSER_CANARY" not in response.text
    client = business.client()
    for path in ("/ACCOUNTS.md", "/business.sqlite3", "/identity.key", "/static/%2e%2e/business.sqlite3"):
        response = client.get(path)
        assert response.status_code in (400, 403, 404), path
    for path in ("/", "/static/app.js", "/static/styles.css", "/api/public/posts"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert all(password not in response.text for password in business.credentials.values())
        assert response.headers["x-content-type-options"] == "nosniff"
    assert "no-store" in business_admin.request("GET", "/api/admin/users").headers["cache-control"]


def test_oversized_and_wrong_type_requests_are_rejected(business):
    employee = business.login("alex")
    for body in ({"body": "x" * 4001}, {"body": "  "}, {"body": {"html": "unexpected"}}):
        assert employee.request("POST", "/api/messages", json=body).status_code == 422
    response = employee.request("POST", "/api/messages", content=json.dumps({"body": "x" * 100_000}),
                                headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def submit_guest(client, **patch):
    return client.post("/api/public/submissions", json={
        "title": "Community project idea", "body": "A public workshop for local businesses.",
        "rules_version": PUBLIC_RULES["version"], "accept_rules": True, **patch,
    }, headers={"Origin": ORIGIN})


def pending_submissions(admin):
    response = admin.request("GET", "/api/admin/submissions")
    assert response.status_code == 200
    return response.json()["submissions"]


def review_submission(admin, submission, decision="approve"):
    return admin.request("POST", f"/api/admin/submissions/{submission['id']}/review", json={
        "decision": decision, "revision": submission["revision"],
    })


def test_guest_submission_stays_private_until_admin_approval(business, business_admin):
    guest = business.client()
    response = submit_guest(guest, title="PENDING_TITLE_CANARY", body="PENDING_BODY_CANARY")
    assert response.status_code == 202
    assert response.json() == {"submitted": True}
    assert COOKIE_NAME not in guest.cookies
    public = guest.get("/api/public/posts")
    assert public.json()["accepting_submissions"] is True
    assert public.headers["cache-control"] == "no-store"
    assert "PENDING_TITLE_CANARY" not in public.text
    assert "PENDING_BODY_CANARY" not in public.text
    pending = pending_submissions(business_admin)
    assert len(pending) == 1
    submission = pending[0]
    assert set(submission) == {"id", "title", "body", "submitted_at", "revision"}
    assert submission["title"] == "PENDING_TITLE_CANARY"
    assert review_submission(business_admin, submission).status_code == 200
    assert pending_submissions(business_admin) == []
    published = [post for post in guest.get("/api/public/posts").json()["posts"]
                 if post["title"] == "PENDING_TITLE_CANARY"]
    assert len(published) == 1
    assert published[0]["body"] == "PENDING_BODY_CANARY"
    assert published[0]["category"] == "Community"
    assert set(published[0]) == {"id", "title", "body", "category", "published_at"}
    for decision in ("approve", "reject"):
        assert review_submission(business_admin, submission, decision).status_code == 409
    assert len([post for post in guest.get("/api/public/posts").json()["posts"]
                if post["title"] == "PENDING_TITLE_CANARY"]) == 1


def test_rejected_guest_submission_never_becomes_public(business, business_admin):
    guest = business.client()
    assert submit_guest(guest, title="REJECTED_TITLE_CANARY").status_code == 202
    submission = pending_submissions(business_admin)[0]
    assert review_submission(business_admin, submission, "reject").status_code == 200
    assert pending_submissions(business_admin) == []
    assert "REJECTED_TITLE_CANARY" not in guest.get("/api/public/posts").text
    assert review_submission(business_admin, submission).status_code == 409
    assert "REJECTED_TITLE_CANARY" not in guest.get("/api/public/posts").text


def test_submission_review_requires_current_admin_and_bound_csrf(business, business_admin):
    guest = business.client()
    assert submit_guest(guest).status_code == 202
    submission = pending_submissions(business_admin)[0]
    path = f"/api/admin/submissions/{submission['id']}/review"
    body = {"decision": "approve", "revision": submission["revision"]}
    assert guest.get("/api/admin/submissions").status_code == 401
    assert guest.post(path, json=body, headers={"Origin": ORIGIN}).status_code == 401
    employee = business.login("alex")
    assert employee.request("GET", "/api/admin/submissions").status_code == 403
    assert employee.request("POST", path, json=body, headers={"X-Role": "admin"}).status_code == 403
    for headers in ({"Origin": ORIGIN}, {"Origin": ORIGIN, "X-CSRF-Token": employee.csrf},
                    {"Origin": "https://evil.invalid", "X-CSRF-Token": business_admin.csrf}):
        assert business_admin.client.post(path, json=body, headers=headers).status_code == 403
    assert review_submission(business_admin, {**submission, "revision": submission["revision"] + 1}).status_code == 409
    with business.db() as connection:
        connection.execute("UPDATE users SET role='employee' WHERE id='admin'")
    assert review_submission(business_admin, submission).status_code == 403
    assert "Community project idea" not in guest.get("/api/public/posts").text


def test_freeze_stops_guest_submission_and_review_until_resume(business, business_admin):
    guest = business.client()
    public_before = guest.get("/api/public/posts").json()["posts"]
    assert submit_guest(guest).status_code == 202
    submission = pending_submissions(business_admin)[0]
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    paused = guest.get("/api/public/posts")
    assert paused.headers["cache-control"] == "no-store"
    assert paused.json()["accepting_submissions"] is False
    assert paused.json()["posts"] == public_before
    assert all(set(row) == {"id", "title", "body", "category", "published_at"}
               for row in paused.json()["posts"])
    assert submit_guest(guest, title="Paused submission").status_code == 503
    for decision in ("approve", "reject"):
        assert review_submission(business_admin, submission, decision).status_code == 403
    assert pending_submissions(business_admin) == [submission]
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": False, "revision": 1}).status_code == 200
    assert guest.get("/api/public/posts").json()["accepting_submissions"] is True
    assert review_submission(business_admin, submission).status_code == 200


def test_submission_json_origin_and_payload_validation(business, business_admin):
    guest = business.client()
    for patch in ({"title": " "}, {"title": "x" * 121}, {"body": " "}, {"body": "x" * 4001},
                  {"body": {"html": "unexpected"}}, {"published": True}, {"author_id": "admin"}):
        assert submit_guest(guest, **patch).status_code == 422
    for origin in (None, "null", "https://evil.invalid"):
        assert guest.post("/api/public/submissions", json={"title": "Title", "body": "Body"},
                          headers={} if origin is None else {"Origin": origin}).status_code == 403
    assert guest.post("/api/public/submissions", content="title=Title&body=Body", headers={
        "Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded",
    }).status_code == 415
    assert pending_submissions(business_admin) == []


def test_submission_limit_uses_actual_peer_not_forwarded_address(business):
    peer = "203.0.113.24"
    guest = business.client(client=(peer, 50001))
    for number in range(3):
        assert submit_guest(guest, title=f"Allowed submission {number}").status_code == 202
    response = guest.post("/api/public/submissions", json={"title": "Blocked", "body": "Too many",
                          "rules_version": PUBLIC_RULES["version"], "accept_rules": True}, headers={
        "Origin": ORIGIN, "X-Forwarded-For": "198.51.100.87", "CF-Connecting-IP": "198.51.100.88",
    })
    assert response.status_code == 429
    assert "retry-after" in response.headers
    different = business.client(client=("203.0.113.25", 50002))
    assert submit_guest(different).status_code == 202
    assert peer.encode() not in business.app.state.database.path.read_bytes()


def test_global_submission_limit_bounds_multiple_addresses(business):
    for number in range(10):
        guest = business.client(client=(f"198.51.100.{number + 1}", 50001))
        for attempt in range(3):
            assert submit_guest(guest, title=f"Submission {number}-{attempt}").status_code == 202
    guest = business.client(client=("198.51.100.99", 50001))
    assert submit_guest(guest).status_code == 429
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM submissions").fetchone()[0] == 30


def test_pending_submission_capacity_never_discards_existing_entries(business):
    guest = business.client()
    assert submit_guest(guest).status_code == 202
    with business.db() as connection:
        template = dict(connection.execute("SELECT * FROM submissions").fetchone())
        columns = ",".join(template)
        parameters = ",".join("?" for _ in template)
        for number in range(99):
            row = {**template, "id": f"pending-capacity-{number}"}
            connection.execute(f"INSERT INTO submissions({columns}) VALUES({parameters})", tuple(row.values()))
    assert submit_guest(guest, title="Capacity overflow").status_code == 429
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM submissions").fetchone()[0] == 100
        assert connection.execute("SELECT COUNT(*) FROM submissions WHERE title='Capacity overflow'").fetchone()[0] == 0


def test_review_rolls_back_pending_state_and_audit_when_publication_fails(business, business_admin):
    assert submit_guest(business.client()).status_code == 202
    submission = pending_submissions(business_admin)[0]
    before = business_rows(business)
    with business.db() as connection:
        connection.execute("CREATE TRIGGER reject_publication BEFORE INSERT ON posts BEGIN SELECT RAISE(ABORT,'test failure'); END")
    assert review_submission(business_admin, submission).status_code == 503
    assert pending_submissions(business_admin) == [submission]
    assert business_rows(business) == before
    with business.db() as connection:
        connection.execute("DROP TRIGGER reject_publication")
    assert review_submission(business_admin, submission).status_code == 200


def test_concurrent_reviews_publish_one_post(business, business_admin):
    other_admin = business.login("admin")
    assert submit_guest(business.client(), title="Single concurrent publication").status_code == 202
    submission = pending_submissions(business_admin)[0]
    barrier = Barrier(2)

    def approve(actor):
        barrier.wait(timeout=5)
        return review_submission(actor, submission).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(approve, (business_admin, other_admin)))
    assert sorted(results) == [200, 409]
    posts = business.client().get("/api/public/posts").json()["posts"]
    assert len([post for post in posts if post["title"] == "Single concurrent publication"]) == 1


def as_legacy_database(business):
    with business.db() as connection:
        connection.execute("DROP TABLE session_passkey")
        connection.execute("DROP TABLE passkey_challenges")
        connection.execute("DROP TABLE passkey_credentials")
        connection.execute("DROP TABLE session_security")
        connection.execute("DROP TABLE mfa_key_binding")
        connection.execute("DROP TABLE create_receipts")
        connection.execute("DROP TABLE session_mfa")
        connection.execute("DROP TABLE admin_mfa")
        connection.execute("DROP TABLE submissions")
        connection.execute("DROP TABLE submission_limits")
        connection.execute("PRAGMA user_version=1")


def test_submission_schema_migration_preserves_accounts_and_employee_sessions_revokes_old_admin(business, business_admin):
    from business.db import Database
    saved(business_admin.request("POST", "/api/messages", json={"body": "Preserved legacy message"}), "message")
    employee = business.login("alex")
    as_legacy_database(business)
    before = business_rows(business)
    identity = (business.directory / "identity.key").read_bytes()
    accounts = (business.directory / "ACCOUNTS.md").read_bytes()
    with business.db() as connection:
        users_before = [tuple(row) for row in connection.execute("SELECT * FROM users ORDER BY id")]
        sessions_before = [tuple(row) for row in connection.execute("SELECT * FROM sessions WHERE user_id<>'admin' ORDER BY token_hash")]
    with pytest.raises(ValueError, match="explicit"):
        create_app(business.directory, public_origin=ORIGIN)
    Database(business.directory, migrate=True)
    migrated = create_app(business.directory, public_origin=ORIGIN)
    assert business_rows(business) == before
    with business.db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert [tuple(row) for row in connection.execute("SELECT * FROM users ORDER BY id")] == users_before
        assert [tuple(row) for row in connection.execute("SELECT * FROM sessions ORDER BY token_hash")] == sessions_before
    assert (business.directory / "identity.key").read_bytes() == identity
    assert (business.directory / "ACCOUNTS.md").read_bytes() == accounts
    client = business.client(migrated)
    client.cookies.set(COOKIE_NAME, business_admin.client.cookies.get(COOKIE_NAME))
    assert client.get("/api/admin/submissions").status_code == 401
    assert employee.request("GET", "/api/messages").status_code == 200
    assert submit_guest(business.client(migrated)).status_code == 202


@pytest.mark.parametrize("damage", ["missing-old-table", "new-table-collision"])
def test_submission_migration_refuses_malformed_legacy_state_without_partial_ddl(business, damage):
    from business.db import Database
    as_legacy_database(business)
    with business.db() as connection:
        if damage == "missing-old-table":
            connection.execute("DROP TABLE contacts")
        else:
            connection.execute("CREATE TABLE submission_limits(preserved TEXT)")
            connection.execute("INSERT INTO submission_limits VALUES('Keep existing data')")
        schema_before = [tuple(row) for row in connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name")]
        users_before = [tuple(row) for row in connection.execute("SELECT * FROM users ORDER BY id")]
    with pytest.raises(ValueError):
        Database(business.directory, migrate=True)
    with business.db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert [tuple(row) for row in connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name")] == schema_before
        assert [tuple(row) for row in connection.execute("SELECT * FROM users ORDER BY id")] == users_before
        if damage == "new-table-collision":
            assert connection.execute("SELECT preserved FROM submission_limits").fetchone()[0] == "Keep existing data"


def test_submission_migration_failure_rolls_back_created_tables_and_version(business, monkeypatch):
    from business import db

    as_legacy_database(business)
    before = business_rows(business)
    with business.db() as connection:
        schema_before = [tuple(row) for row in connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name")]
    apply = db._apply_submission_migration

    def fail_after_ddl(connection):
        apply(connection)
        raise sqlite3.OperationalError("Simulated migration failure")

    monkeypatch.setattr(db, "_apply_submission_migration", fail_after_ddl)
    with pytest.raises(ValueError):
        db.Database(business.directory, migrate=True)
    assert business_rows(business) == before
    with business.db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert [tuple(row) for row in connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name")] == schema_before
    monkeypatch.setattr(db, "_apply_submission_migration", apply)
    db.Database(business.directory, migrate=True)
    with business.db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5


@pytest.mark.parametrize("condition", ["paused", "address-limit", "global-limit", "queue-full"])
def test_submission_preflight_denial_does_not_call_challenge_provider(business, monkeypatch, condition):
    from business.abuse import SubmissionGuard

    guest = business.client()
    if condition == "address-limit":
        for _ in range(3):
            assert submit_guest(guest).status_code == 202
    with business.db() as connection:
        if condition == "paused":
            connection.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1 WHERE id=1")
        elif condition == "global-limit":
            connection.executemany("INSERT INTO submission_limits(key_hash,submitted_at) VALUES(?,?)", [(f"other-{index}", time.time()) for index in range(30)])
        elif condition == "queue-full":
            connection.executemany("INSERT INTO submissions VALUES(?,?,?,'pending',?,0,NULL)", [(f"full-{index}", "Existing title", "Existing body", "2026-10-18T00:00:00+00:00") for index in range(100)])

    def refuse_unnecessary_provider_call(*args):
        pytest.fail("The challenge provider must not be called after a local denial")

    monkeypatch.setattr(SubmissionGuard, "verify", refuse_unnecessary_provider_call)
    assert submit_guest(guest).status_code == (503 if condition == "paused" else 429)


def test_submission_rechecks_pause_after_provider_without_holding_database_lock(business, monkeypatch):
    from business.abuse import SubmissionGuard

    def pause_during_provider_call(*args):
        # This second connection would time out if the request retained the
        # first transaction while waiting for its network verification.
        with business.db() as connection:
            connection.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1 WHERE id=1")

    monkeypatch.setattr(SubmissionGuard, "verify", pause_during_provider_call)
    assert submit_guest(business.client()).status_code == 503
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM submissions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM submission_limits").fetchone()[0] == 0
