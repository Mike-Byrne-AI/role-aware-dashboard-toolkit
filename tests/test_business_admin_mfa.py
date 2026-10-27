"""Administrator sign-in and containment regressions for the source example."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
from pathlib import Path
import sqlite3
from threading import Barrier

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    ORIGIN, business as business, business_admin as business_admin,
    business_seed as business_seed, business_rows, post_body, saved,
)
from business import db, mfa  # noqa: E402
from business.app import create_app  # noqa: E402
from business.security import COOKIE_NAME  # noqa: E402


def raw_login(business, payload, client=None):
    return (client or business.client()).post("/api/login", json=payload, headers={"Origin": ORIGIN})


def synthetic_secret(business):
    with business.db() as connection:
        row = connection.execute("SELECT * FROM admin_mfa WHERE user_id='admin'").fetchone()
    return business.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], "admin", row["generation"])


def invalid_code(business):
    secret = synthetic_secret(business)
    allowed = {pyotp.TOTP(secret).at(business.mfa_time + offset) for offset in (-30, 0, 30)}
    return next(f"{number:06d}" for number in range(10) if f"{number:06d}" not in allowed)


def test_admin_requires_password_and_authenticator_with_generic_failure(business):
    payload = business.login_payload("admin")
    responses = [raw_login(business, {key: value for key, value in payload.items() if key != "otp"}),
                 raw_login(business, {**payload, "otp": invalid_code(business)}),
                 raw_login(business, {**payload, "password": "incorrect password"}),
                 raw_login(business, {**payload, "username": "nonexistent"})]
    assert {response.status_code for response in responses} == {401}
    assert len({response.text for response in responses}) == 1
    assert raw_login(business, payload).status_code == 200
    assert business.login("alex").profile["role"] == "employee"


def test_admin_authenticator_replay_is_rejected_across_sessions(business):
    payload = business.login_payload("admin")
    assert raw_login(business, payload).status_code == 200
    assert raw_login(business, payload).status_code == 401
    assert raw_login(business, business.login_payload("admin")).status_code == 200


def test_simultaneous_admin_logins_consume_code_once(business):
    payload = business.login_payload("admin")
    clients = [business.client(), business.client()]
    barrier = Barrier(2)

    def login(client):
        barrier.wait(timeout=5)
        return raw_login(business, payload, client).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(login, clients)) == [200, 401]


@pytest.mark.parametrize("offset,accepted", [(-60, False), (-30, True), (0, True), (30, True), (60, False)])
def test_authenticator_clock_tolerance_is_bounded(business, offset, accepted):
    payload = business.login_payload("admin")
    secret = synthetic_secret(business)
    payload["otp"] = pyotp.TOTP(secret).at(business.mfa_time + offset)
    assert raw_login(business, payload).status_code == (200 if accepted else 401)


@pytest.mark.parametrize("timestamp,code", [(59, "287082"), (1111111109, "081804"),
    (1111111111, "050471"), (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")])
def test_pyotp_matches_rfc6238_sha1_vectors_at_six_digits(business, timestamp, code):
    # RFC 6238 Appendix B publishes eight-digit SHA-1 values; retain the six
    # least significant digits used by this authenticator configuration.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    business.mfa_time = timestamp
    with business.db() as connection:
        store = business.app.state.database.mfa_secrets
        generation = connection.execute("SELECT generation FROM admin_mfa WHERE user_id='admin'").fetchone()[0]
        connection.execute("UPDATE admin_mfa SET secret_ciphertext=?,last_counter=-1 WHERE user_id='admin'", (store.encrypt(secret, "admin", generation),))
        assert mfa.verify_admin_code(connection, "admin", code, store) is not None
        assert mfa.verify_admin_code(connection, "admin", code, store) is None


def test_invalid_authenticator_attempts_share_password_login_limits(business):
    payload = {**business.login_payload("admin"), "otp": invalid_code(business)}
    for _ in range(8):
        assert raw_login(business, payload).status_code == 401
    response = raw_login(business, business.login_payload("admin"))
    assert response.status_code == 429
    assert response.headers["retry-after"] == "300"


def test_staff_session_cannot_be_promoted_into_admin_without_mfa(business):
    employee = business.login("alex")
    with business.db() as connection:
        connection.execute("UPDATE users SET role='admin' WHERE id='alex'")
    assert employee.request("GET", "/api/admin/posts").status_code == 401
    assert raw_login(business, {"username": "alex", "password": business.credentials["alex"]}).status_code == 401
    assert mfa.setup_admin_mfa(business.directory) is not None
    assert employee.request("GET", "/api/admin/posts").status_code == 401
    assert business.login("alex").request("GET", "/api/admin/posts").status_code == 200


def test_mfa_reset_revokes_sessions_preserves_accounts_and_old_setup_sheet(business, business_admin):
    employee = business.login("alex")
    before = business_rows(business)[:-1]
    sheet = business.directory / "ADMIN_MFA_SETUP.md"
    original = sheet.read_bytes()
    accounts = (business.directory / "ACCOUNTS.md").read_bytes()
    payload = business.login_payload("admin")
    with business.db() as connection:
        previous = dict(connection.execute("SELECT * FROM admin_mfa WHERE user_id='admin'").fetchone())
    assert mfa.setup_admin_mfa(business.directory) is None
    replacement = mfa.setup_admin_mfa(business.directory, reset=True)
    assert replacement != sheet and replacement.is_file()
    assert sheet.read_bytes() == original
    assert (business.directory / "ACCOUNTS.md").read_bytes() == accounts
    assert business_rows(business)[:-1] == before
    assert business_admin.request("GET", "/api/admin/posts").status_code == 401
    assert employee.request("GET", "/api/messages").status_code == 200
    with business.db() as connection:
        current = dict(connection.execute("SELECT * FROM admin_mfa WHERE user_id='admin'").fetchone())
    assert previous["secret_ciphertext"] != current["secret_ciphertext"] and previous["generation"] != current["generation"]
    assert raw_login(business, payload).status_code == 401
    assert business.login("admin").request("GET", "/api/admin/posts").status_code == 200


def test_failed_setup_sheet_write_rolls_back_reset_and_session_revocation(business, business_admin, monkeypatch):
    with business.db() as connection:
        previous = tuple(connection.execute("SELECT * FROM admin_mfa").fetchone())

    def refuse(*args, **kwargs):
        raise OSError("Simulated private-file failure")

    monkeypatch.setattr(mfa, "create_private_file", refuse)
    with pytest.raises(OSError):
        mfa.setup_admin_mfa(business.directory, reset=True)
    with business.db() as connection:
        assert tuple(connection.execute("SELECT * FROM admin_mfa").fetchone()) == previous
    assert business_admin.request("GET", "/api/admin/posts").status_code == 200


def test_mfa_secret_never_appears_in_api_assets_or_provision_console(business, business_seed, business_admin):
    secret = synthetic_secret(business)
    assert secret not in business_seed.output
    assert secret in (business.directory / "ADMIN_MFA_SETUP.md").read_text()
    for path in ("/api/session", "/api/admin/users", "/api/admin/overview", "/api/public/posts", "/", "/static/app.js"):
        response = business_admin.request("GET", path)
        assert response.status_code == 200
        assert secret not in response.text and "otpauth://" not in response.text
    assert business.client().get("/ADMIN_MFA_SETUP.md").status_code == 404


def test_cli_setup_and_reset_report_paths_not_secrets(business):
    import importlib.util
    spec = importlib.util.spec_from_file_location("business_cli_mfa_test", Path(__file__).resolve().parents[1] / "examples/business_dashboard/run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = io.StringIO()
    with redirect_stdout(output):
        assert module.main(["--data-dir", str(business.directory), "--setup-admin-mfa"]) == 0
        assert module.main(["--data-dir", str(business.directory), "--reset-admin-mfa"]) == 0
    secret = synthetic_secret(business)
    assert secret not in output.getvalue() and "otpauth://" not in output.getvalue()
    assert "ADMIN_MFA_SETUP-" in output.getvalue()


def downgrade_v2(business):
    with business.db() as connection:
        connection.execute("DROP TABLE session_passkey")
        connection.execute("DROP TABLE passkey_challenges")
        connection.execute("DROP TABLE passkey_credentials")
        connection.execute("DROP TABLE session_security")
        connection.execute("DROP TABLE mfa_key_binding")
        connection.execute("DROP TABLE create_receipts")
        connection.execute("DROP TABLE session_mfa")
        connection.execute("DROP TABLE admin_mfa")
        connection.execute("PRAGMA user_version=2")


def test_v2_upgrade_preserves_business_and_staff_revokes_admin_requires_local_enrollment(business, business_admin):
    employee = business.login("alex")
    before = business_rows(business)
    downgrade_v2(business)
    db.Database(business.directory, migrate=True)
    migrated = create_app(business.directory, public_origin=ORIGIN)
    assert business_rows(business) == before
    with business.db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("SELECT COUNT(*) FROM admin_mfa").fetchone()[0] == 0
    admin = business.client(migrated)
    admin.cookies.set(COOKIE_NAME, business_admin.client.cookies.get(COOKIE_NAME))
    assert admin.get("/api/admin/posts").status_code == 401
    assert employee.request("GET", "/api/messages").status_code == 200
    assert raw_login(business, {"username": "admin", "password": business.credentials["admin"]}).status_code == 401
    assert mfa.setup_admin_mfa(business.directory).is_file()
    assert business.login("admin").request("GET", "/api/admin/posts").status_code == 200


def test_mfa_migration_failure_rolls_back_ddl_and_admin_session_deletion(business, business_admin, monkeypatch):
    downgrade_v2(business)
    with business.db() as connection:
        before = [tuple(row) for row in connection.execute("SELECT * FROM sessions ORDER BY token_hash")]
    apply = db._apply_mfa_migration
    completed = []

    def fail(connection):
        apply(connection)
        completed.append(True)
        raise sqlite3.OperationalError("Simulated schema failure")

    monkeypatch.setattr(db, "_apply_mfa_migration", fail)
    with pytest.raises(ValueError):
        db.Database(business.directory, migrate=True)
    assert completed == [True]
    with business.db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert [tuple(row) for row in connection.execute("SELECT * FROM sessions ORDER BY token_hash")] == before
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='admin_mfa'").fetchone() is None


def test_emergency_unpublish_removes_only_publication_while_paused(business, business_admin):
    post = saved(business_admin.request("POST", "/api/admin/posts", json=post_body()), "post")
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    endpoint = f"/api/admin/posts/{post['id']}/unpublish"
    removed = saved(business_admin.request("POST", endpoint, json={"revision": post["revision"]}), "post")
    assert removed == {**post, "published": False, "published_at": None, "revision": post["revision"] + 1}
    public = business.client().get("/api/public/posts").json()
    assert public["accepting_submissions"] is False
    assert post["id"] not in {row["id"] for row in public["posts"]}
    assert business_admin.request("POST", endpoint, json={"revision": post["revision"]}).status_code == 409
    assert business_admin.request("POST", endpoint, json={"revision": removed["revision"]}).status_code == 409
    assert business_admin.request("PUT", f"/api/admin/posts/{post['id']}", json={**post_body(), "revision": removed["revision"]}).status_code == 403
    assert business_admin.request("POST", "/api/admin/posts", json=post_body()).status_code == 403
    assert any(row["action"] == "Removed public-board post" and row["target"] == post["id"]
               for row in business_admin.request("GET", "/api/admin/overview").json()["activity"])


def test_unpublish_requires_current_admin_csrf_origin_and_revision(business, business_admin):
    employee = business.login("alex")
    endpoint = "/api/admin/posts/post-1/unpublish"
    body = {"revision": 0}
    before = business_rows(business)
    assert business.client().post(endpoint, json=body, headers={"Origin": ORIGIN}).status_code == 401
    assert employee.request("POST", endpoint, json=body).status_code == 403
    for headers in ({"Origin": ORIGIN}, {"Origin": ORIGIN, "X-CSRF-Token": employee.csrf},
                    {"Origin": "https://evil.invalid", "X-CSRF-Token": business_admin.csrf}):
        assert business_admin.client.post(endpoint, json=body, headers=headers).status_code == 403
    assert business_admin.request("POST", endpoint, json={"revision": 99}).status_code == 409
    assert business_admin.request("POST", endpoint, json={"revision": 0, "body": "Edit during pause"}).status_code == 422
    assert business_admin.request("POST", endpoint, json={"revision": 0, "published": True}).status_code == 422
    with business.db() as connection:
        connection.execute("UPDATE users SET role='employee' WHERE id='admin'")
    assert business_admin.request("POST", endpoint, json=body).status_code == 403
    assert business_rows(business) == before


def test_emergency_unpublish_transaction_rolls_back_if_audit_fails(business, business_admin):
    assert business_admin.request("POST", "/api/admin/freeze", json={"frozen": True, "revision": 0}).status_code == 200
    before = business_rows(business)
    with business.db() as connection:
        connection.execute("CREATE TRIGGER reject_unpublish_audit BEFORE INSERT ON activity BEGIN SELECT RAISE(ABORT,'test'); END")
    assert business_admin.request("POST", "/api/admin/posts/post-1/unpublish", json={"revision": 0}).status_code == 503
    assert business_rows(business) == before
    assert "post-1" in {post["id"] for post in business.client().get("/api/public/posts").json()["posts"]}
