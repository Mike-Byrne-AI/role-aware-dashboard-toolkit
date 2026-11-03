"""Administrator sign-in and containment regressions for the source example."""

from tools.business_login_client import login_post

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
import re
from pathlib import Path
import sqlite3
from threading import Barrier

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    ORIGIN, business as business, business_admin as business_admin,
    business_seed as business_seed, business_rows, downgrade_enrollment_schema, post_body, saved,
)
from business import db, mfa  # noqa: E402
from business.app import create_app  # noqa: E402
from business.security import COOKIE_NAME  # noqa: E402


def raw_login(business, payload, client=None):
    return login_post(client or business.client(), "/api/login", json=payload, headers={"Origin": ORIGIN})


def synthetic_secret(business):
    with business.db() as connection:
        row = connection.execute("SELECT * FROM account_mfa WHERE user_id='admin'").fetchone()
    return business.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], "admin", row["generation"])


def sheet_grant(path):
    """Read only the one-account synthetic grant in an operator test sheet."""
    matches = re.findall(r"Enrollment grant: `([A-Za-z0-9_-]{43})`", path.read_text())
    assert len(matches) == 1, "Expected one disposable operator enrollment"
    return matches[0]


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


@pytest.mark.parametrize("offset,accepted", [(-60, False), (-30, False), (0, True), (30, False), (60, False)])
def test_authenticator_accepts_only_the_current_30_second_step(business, offset, accepted):
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
        generation = connection.execute("SELECT generation FROM account_mfa WHERE user_id='admin'").fetchone()[0]
        connection.execute("UPDATE account_mfa SET secret_ciphertext=?,last_counter=-1 WHERE user_id='admin'", (store.encrypt(secret, "admin", generation),))
        assert mfa.verify_account_code(connection, "admin", code, store) is not None
        assert mfa.verify_account_code(connection, "admin", code, store) is None


def test_invalid_authenticator_attempts_share_password_login_limits(business):
    payload = {**business.login_payload("admin"), "otp": invalid_code(business)}
    for _ in range(8):
        assert raw_login(business, payload).status_code == 401
    response = raw_login(business, business.login_payload("admin"))
    assert response.status_code == 429
    assert response.headers["retry-after"] == "300"


def test_transition_password_only_staff_session_cannot_be_promoted_without_mfa(business):
    # Deliberately model an explicitly migrated legacy account, rather than
    # weakening the normal fully enrolled strict-policy fixture.
    with business.db() as connection:
        connection.execute("UPDATE authentication_policy SET mode='transition'")
        connection.execute("UPDATE account_security SET lifecycle='legacy' WHERE user_id='alex'")
        connection.execute("DELETE FROM account_mfa WHERE user_id='alex'")
    employee = business.login("alex")
    with business.db() as connection:
        connection.execute("UPDATE users SET role='admin' WHERE id='alex'")
    assert employee.request("GET", "/api/admin/posts").status_code == 401
    assert raw_login(business, {"username": "alex", "password": business.credentials["alex"]}).status_code == 401
    sheet = mfa.setup_admin_mfa(business.directory)
    assert sheet is not None
    assert employee.request("GET", "/api/admin/posts").status_code == 401
    business.complete_enrollment("alex", sheet_grant(sheet))
    assert business.login("alex").request("GET", "/api/admin/posts").status_code == 200


def test_mfa_recovery_revokes_authority_until_proven_enrollment_and_preserves_old_sheet(business, business_admin):
    employee = business.login("alex")
    before = business_rows(business)[:-1]
    sheet = business.directory / "ADMIN_ENROLLMENT.md"
    db.create_private_file(sheet, b"Previously retained private enrollment document.\n")
    original = sheet.read_bytes()
    accounts = (business.directory / "ACCOUNTS.md").read_bytes()
    payload = business.login_payload("admin")
    with business.db() as connection:
        previous = dict(connection.execute("SELECT * FROM account_mfa WHERE user_id='admin'").fetchone())
    assert mfa.setup_admin_mfa(business.directory) is None
    replacement = mfa.setup_admin_mfa(business.directory, reset=True, case_reference="CASE-MFA-RECOVERY")
    assert replacement != sheet and replacement.is_file()
    assert sheet.read_bytes() == original
    assert (business.directory / "ACCOUNTS.md").read_bytes() == accounts
    assert business_rows(business)[:-1] == before
    assert business_admin.request("GET", "/api/admin/posts").status_code == 401
    assert employee.request("GET", "/api/messages").status_code == 200
    with business.db() as connection:
        assert connection.execute("SELECT * FROM account_mfa WHERE user_id='admin'").fetchone() is None
        assert connection.execute("SELECT lifecycle FROM account_security WHERE user_id='admin'").fetchone()[0] == "pending"
        assert connection.execute("SELECT case_reference FROM enrollment_grants WHERE user_id='admin'").fetchone()[0] == "CASE-MFA-RECOVERY"
    assert raw_login(business, payload).status_code == 401
    business.complete_enrollment("admin", sheet_grant(replacement))
    with business.db() as connection:
        current = dict(connection.execute("SELECT * FROM account_mfa WHERE user_id='admin'").fetchone())
    assert previous["secret_ciphertext"] != current["secret_ciphertext"] and previous["generation"] != current["generation"]
    assert raw_login(business, payload).status_code == 401
    assert business.login("admin").request("GET", "/api/admin/posts").status_code == 200


def test_failed_setup_sheet_write_rolls_back_reset_and_session_revocation(business, business_admin, monkeypatch):
    with business.db() as connection:
        previous = tuple(connection.execute("SELECT * FROM account_mfa").fetchone())

    def refuse(*args, **kwargs):
        raise OSError("Simulated private-file failure")

    monkeypatch.setattr(mfa, "create_private_file", refuse)
    with pytest.raises(OSError):
        mfa.setup_admin_mfa(business.directory, reset=True, case_reference="CASE-MFA-RECOVERY")
    with business.db() as connection:
        assert tuple(connection.execute("SELECT * FROM account_mfa").fetchone()) == previous
    assert business_admin.request("GET", "/api/admin/posts").status_code == 200


def test_mfa_secret_never_appears_in_api_assets_or_provision_console(business, business_seed, business_admin):
    secret = synthetic_secret(business)
    assert secret not in business_seed.output
    assert not (business.directory / "ADMIN_MFA_SETUP.md").exists()
    assert all(secret not in path.read_text() for path in business.directory.glob("*.md"))
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
    secret = synthetic_secret(business)
    output = io.StringIO()
    with redirect_stdout(output):
        assert module.main(["--data-dir", str(business.directory), "--setup-admin-mfa"]) == 0
        assert module.main(["--data-dir", str(business.directory), "--reset-admin-mfa", "--case-ref", "CASE-CLI-MFA"]) == 0
    assert secret not in output.getvalue() and "otpauth://" not in output.getvalue()
    assert "ADMIN_ENROLLMENT" in output.getvalue()
    assert sheet_grant(business.directory / "ADMIN_ENROLLMENT.md") not in output.getvalue()


def downgrade_v2(business):
    with business.db() as connection:
        downgrade_enrollment_schema(connection)
        for table in ("security_sink_receipts", "security_outbox", "security_denial_budget", "security_events"):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DROP TABLE session_predecessors")
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
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
        assert connection.execute("SELECT COUNT(*) FROM account_mfa").fetchone()[0] == 0
    admin = business.client(migrated)
    admin.cookies.set(COOKIE_NAME, business_admin.client.cookies.get(COOKIE_NAME))
    assert admin.get("/api/admin/posts").status_code == 401
    assert employee.request("GET", "/api/messages").status_code == 200
    assert raw_login(business, {"username": "admin", "password": business.credentials["admin"]}).status_code == 401
    sheet = mfa.setup_admin_mfa(business.directory)
    assert sheet.is_file()
    business.complete_enrollment("admin", sheet_grant(sheet))
    assert business.login("admin").request("GET", "/api/admin/posts").status_code == 200


def test_mfa_migration_failure_rolls_back_ddl_and_admin_session_deletion(business, business_admin, monkeypatch):
    downgrade_v2(business)
    with business.raw_db() as connection:
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
    with business.raw_db() as connection:
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
