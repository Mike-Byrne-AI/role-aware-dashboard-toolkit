"""Enrollment authority is expiring, single-use, transactional and policy-bound."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
from threading import Event
from types import SimpleNamespace

import pytest

pyotp = pytest.importorskip("pyotp")
pytest.importorskip("fastapi")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "business_dashboard"))

from business import db, enrollment, security  # noqa: E402
from business.secret_store import SecretStore, create_key_file, default_key_path  # noqa: E402

PASSWORD = "Chosen separate enrollment password 592!"
SEED = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@contextmanager
def workspace(version=10):
    with tempfile.TemporaryDirectory(prefix="radt-enrollment-policy-") as temporary:
        # Resolve the owned temp root before creating private child paths.
        directory = Path(temporary).resolve(strict=True) / "private"
        db.validate_data_dir(directory, create=True)
        identity = secrets.token_bytes(32)
        create_key_file(directory)
        db.create_private_file(directory / "identity.key", identity)
        db.create_private_file(directory / "business.sqlite3", b"")
        store = SecretStore(directory, identity)
        connection = sqlite3.connect(directory / "business.sqlite3")
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript("BEGIN IMMEDIATE;\n" + {7: db.SCHEMA_V7, 8: db.SCHEMA_V8, 9: db.SCHEMA_V9, 10: db.SCHEMA}[version])
            connection.execute("INSERT INTO mfa_key_binding VALUES(1,?)", (store.create_binding(),))
            for name, role in (("operator", "admin"), ("employee", "employee")):
                connection.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?,0)", (
                    name, name, "Fictional " + name, "!enrollment-pending!", role, security.principal_for_user(name, identity),
                ))
                if version in (8, 9, 10):
                    connection.execute("INSERT INTO account_security VALUES(?,'pending',0,NULL,NULL)", (name,))
            connection.commit()
        finally:
            connection.close()
        yield directory


@pytest.fixture
def policy(monkeypatch):
    with workspace() as directory:
        state = SimpleNamespace(database=db.Database(directory), now=1_800_000_000.0)
        monkeypatch.setattr(enrollment, "current_time", lambda: state.now)
        monkeypatch.setattr(pyotp, "random_base32", lambda: SEED)
        yield state


def issue(policy, name="operator", purpose="initial", **kwargs):
    with policy.database.transaction() as connection:
        return enrollment.issue_grant(connection, name, purpose=purpose, **kwargs)


def start(policy, name="operator", grant=None):
    grant = grant or issue(policy, name)
    return enrollment.start_enrollment(policy.database, name, grant)


def finish(policy, begun, password=PASSWORD, otp=None):
    return enrollment.complete_enrollment(policy.database, begun.token, begun.csrf, password,
                                          otp or pyotp.TOTP(begun.secret).at(policy.now))


def rows(policy, table):
    with policy.database.transaction() as connection:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")]


def test_initial_grant_only_establishes_purpose_bound_enrollment_and_completion_never_logs_in(policy):
    grant = issue(policy)
    begun = start(policy, grant=grant)
    assert begun.expires_at == policy.now + enrollment.ENROLLMENT_SECONDS
    assert begun.token not in repr(begun) and begun.secret not in repr(begun) and begun.csrf not in repr(begun)
    assert grant not in str(rows(policy, "enrollment_grants"))
    assert begun.secret not in str(rows(policy, "enrollment_sessions"))
    assert rows(policy, "sessions") == rows(policy, "account_mfa") == []
    with policy.database.transaction() as connection:
        user = connection.execute("SELECT * FROM users WHERE id='operator'").fetchone()
        assert not enrollment.account_can_authenticate(connection, user)
        assert not security.verify_password(user["password_hash"], grant)
    with pytest.raises(enrollment.EnrollmentError):
        start(policy, grant=grant)
    finish(policy, begun)
    assert rows(policy, "sessions") == rows(policy, "enrollment_grants") == rows(policy, "enrollment_sessions") == []
    with policy.database.transaction() as connection:
        user = connection.execute("SELECT * FROM users WHERE id='operator'").fetchone()
        factor = connection.execute("SELECT * FROM account_mfa WHERE user_id='operator'").fetchone()
        assert enrollment.account_can_authenticate(connection, user)
        assert enrollment.requires_mfa(connection, user)
        assert security.verify_password(user["password_hash"], PASSWORD)
        assert factor["last_counter"] == int(policy.now // 30)
        assert policy.database.mfa_secrets.decrypt(factor["secret_ciphertext"], user["id"], factor["generation"]) == begun.secret
        assert connection.execute("SELECT lifecycle FROM account_security WHERE user_id='operator'").fetchone()[0] == "active"
    assert [row["code"] for row in rows(policy, "security_events")] == [
        "enrollment_issued", "enrollment_started", "enrollment_completed",
    ]
    with pytest.raises(enrollment.EnrollmentError):
        finish(policy, begun)


@pytest.mark.parametrize("offset", [enrollment.GRANT_SECONDS, -1])
def test_expired_or_future_grant_refuses_seed_disclosure_and_preserves_attempt_charge(policy, offset):
    grant = issue(policy)
    policy.now += offset
    with pytest.raises(enrollment.EnrollmentError):
        start(policy, grant=grant)
    assert rows(policy, "enrollment_sessions") == []
    assert rows(policy, "enrollment_grants")[0]["claimed_at"] is None
    assert rows(policy, "login_limits")[0]["attempts"] == 1


def test_failed_start_budget_persists_and_reissue_does_not_reset_it(policy):
    grant = issue(policy)
    for _ in range(8):
        with pytest.raises(enrollment.EnrollmentError) as denied:
            start(policy, grant="A" * 43)
        assert denied.value.status_code == 403
    grant = issue(policy)
    with pytest.raises(enrollment.EnrollmentError) as limited:
        start(policy, grant=grant)
    assert (limited.value.status_code, limited.value.retry_after) == (429, 300)
    policy.now += 301
    assert start(policy, grant=grant)


def test_simultaneous_claims_disclose_only_one_seed_and_create_one_session(policy):
    grant = issue(policy)

    def claim():
        try:
            return start(policy, grant=grant)
        except enrollment.EnrollmentError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: claim(), range(2)))
    assert sum(result is not None for result in results) == 1
    assert len(rows(policy, "enrollment_sessions")) == 1
    assert rows(policy, "login_limits")[0]["attempts"] == 1


@pytest.mark.parametrize("change", ["csrf", "token"])
def test_unverified_enrollment_context_cannot_reach_password_screening(policy, monkeypatch, change):
    begun = start(policy)
    monkeypatch.setattr(enrollment, "password_policy_error", lambda *a, **k: pytest.fail("Unverified request screened a password"))
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.complete_enrollment(policy.database, "A" * 43 if change == "token" else begun.token,
                                       "wrong" if change == "csrf" else begun.csrf, "short", "000000")
    assert rows(policy, "account_mfa") == []
    if change == "csrf":
        assert rows(policy, "login_limits")[0]["attempts"] == 1


@pytest.mark.parametrize("password", [None, False, 5, "short", "passwordpassword"])
def test_bad_new_password_is_a_safe_durable_failure(policy, password):
    begun = start(policy)
    with pytest.raises(enrollment.EnrollmentError) as denied:
        finish(policy, begun, password=password)
    assert denied.value.status_code == 422
    assert rows(policy, "login_limits")[0]["attempts"] == 1
    assert rows(policy, "account_mfa") == []


def test_initial_grant_can_never_become_permanent_password(policy):
    grant = issue(policy)
    begun = start(policy, grant=grant)
    with pytest.raises(enrollment.EnrollmentError, match="distinct from your enrollment code"):
        finish(policy, begun, password=grant)
    assert rows(policy, "account_mfa") == []


@pytest.mark.parametrize("offset", [-30, 30])
def test_completion_accepts_only_current_totp_step(policy, offset):
    begun = start(policy)
    code = pyotp.TOTP(begun.secret).at(policy.now + offset)
    assert code != pyotp.TOTP(begun.secret).at(policy.now)
    with pytest.raises(enrollment.EnrollmentError):
        finish(policy, begun, otp=code)
    assert rows(policy, "account_mfa") == []
    assert rows(policy, "login_limits")[0]["attempts"] == 1


@pytest.mark.parametrize("change", ["expired", "disabled", "user_revision", "security_revision", "grant_revoked", "grant_unclaimed", "grant_hash"])
def test_invalidated_or_expired_enrollment_cannot_complete(policy, change):
    begun = start(policy)
    if change == "expired":
        policy.now += enrollment.ENROLLMENT_SECONDS
    else:
        with policy.database.transaction() as connection:
            connection.execute({
                "disabled": "UPDATE users SET active=0 WHERE id='operator'",
                "user_revision": "UPDATE users SET revision=revision+1 WHERE id='operator'",
                "security_revision": "UPDATE account_security SET revision=revision+1 WHERE user_id='operator'",
                "grant_revoked": "DELETE FROM enrollment_grants",
                "grant_unclaimed": "UPDATE enrollment_grants SET claimed_at=NULL",
                "grant_hash": "UPDATE enrollment_grants SET secret_hash='changed'",
            }[change])
    with pytest.raises(enrollment.EnrollmentError):
        finish(policy, begun)
    assert rows(policy, "account_mfa") == []


def test_recovery_requires_retained_case_and_cannot_relabel_as_initial_or_enable_account(policy):
    finish(policy, start(policy))
    with pytest.raises(ValueError, match="case reference"):
        issue(policy, purpose="recovery")
    grant = issue(policy, purpose="recovery", case_reference="CASE-20261102-001")
    assert rows(policy, "account_mfa") == []
    assert any(row["case_reference"] == "CASE-20261102-001" for row in rows(policy, "enrollment_decisions"))
    with pytest.raises(ValueError, match="reviewed migration or recovery"):
        issue(policy)
    with policy.database.transaction() as connection:
        connection.execute("UPDATE users SET active=0 WHERE id='operator'")
    issue(policy, purpose="recovery", case_reference="CASE-20261102-002")
    with pytest.raises(enrollment.EnrollmentError):
        start(policy, grant=grant)
    assert next(row for row in rows(policy, "users") if row["id"] == "operator")["active"] == 0


def test_recovery_reissue_and_discarded_grants_still_refuse_former_password(policy):
    finish(policy, start(policy))
    issue(policy, purpose="recovery", case_reference="CASE-recovery-1")
    # Recovery reconciliation discards ephemeral capabilities, but retains
    # current account-security state. The retired hash is not login authority.
    with policy.database.transaction() as connection:
        connection.execute("DELETE FROM enrollment_grants")
        user = connection.execute("SELECT * FROM users WHERE id='operator'").fetchone()
        assert not security.verify_password(user["password_hash"], PASSWORD)
        assert not enrollment.account_can_authenticate(connection, user)
    grant = issue(policy, purpose="recovery", case_reference="CASE-recovery-2")
    begun = start(policy, grant=grant)
    with pytest.raises(enrollment.EnrollmentError, match="distinct from your previous password"):
        finish(policy, begun)
    finish(policy, begun, password="A newly chosen recovery password 834!")
    with policy.database.transaction() as connection:
        assert connection.execute("SELECT retired_password_hash FROM account_security WHERE user_id='operator'").fetchone()[0] is None


def test_migration_cannot_keep_previous_password_as_new_enrollment_password(policy):
    with policy.database.transaction() as connection:
        connection.execute("UPDATE authentication_policy SET mode='transition'")
        connection.execute("UPDATE account_security SET lifecycle='legacy'")
        connection.execute("UPDATE users SET password_hash=? WHERE id='operator'", (security.hash_password(PASSWORD),))
    begun = start(policy, grant=issue(policy, purpose="migration"))
    with pytest.raises(enrollment.EnrollmentError, match="distinct from your previous password"):
        finish(policy, begun)


def test_issuance_and_completion_audit_faults_roll_back_changes_but_completion_attempt_stays_charged(policy, monkeypatch):
    original = enrollment.record_event

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("Synthetic event failure")

    monkeypatch.setattr(enrollment, "record_event", fail)
    with pytest.raises(sqlite3.OperationalError):
        issue(policy)
    assert rows(policy, "enrollment_grants") == rows(policy, "enrollment_decisions") == []
    monkeypatch.setattr(enrollment, "record_event", original)
    begun = start(policy)
    before = rows(policy, "account_security")
    monkeypatch.setattr(enrollment, "record_event", fail)
    with pytest.raises(sqlite3.OperationalError):
        finish(policy, begun)
    assert rows(policy, "account_security") == before
    assert rows(policy, "account_mfa") == []
    assert len(rows(policy, "enrollment_sessions")) == 1
    assert rows(policy, "login_limits")[0]["attempts"] == 1


def test_reissue_during_password_work_cannot_complete_old_claim(policy, monkeypatch):
    begun = start(policy)
    entered, release = Event(), Event()
    original = security.hash_password

    def held(password):
        entered.set()
        assert release.wait(5)
        return original(password)

    monkeypatch.setattr(security, "hash_password", held)
    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(finish, policy, begun)
        try:
            assert entered.wait(5)
            replacement = issue(policy)
        finally:
            release.set()
        with pytest.raises(enrollment.EnrollmentError):
            result.result(timeout=5)
    assert rows(policy, "account_mfa") == []
    assert start(policy, grant=replacement)


def test_migration_grant_preserves_legacy_access_but_completion_enforces_mfa_and_strict_readiness(policy):
    with policy.database.transaction() as connection:
        connection.execute("UPDATE authentication_policy SET mode='transition'")
        connection.execute("UPDATE account_security SET lifecycle='legacy'")
        user = connection.execute("SELECT * FROM users WHERE id='employee'").fetchone()
        assert enrollment.account_can_authenticate(connection, user)
        assert not enrollment.requires_mfa(connection, user)
        assert enrollment.readiness(connection)["ready"] is False
        with pytest.raises(enrollment.EnrollmentError):
            enrollment.activate_strict(connection)
    grant = issue(policy, "employee", "migration")
    with policy.database.transaction() as connection:
        user = connection.execute("SELECT * FROM users WHERE id='employee'").fetchone()
        assert enrollment.account_can_authenticate(connection, user)
    finish(policy, start(policy, "employee", grant=grant))
    with policy.database.transaction() as connection:
        user = connection.execute("SELECT * FROM users WHERE id='employee'").fetchone()
        assert enrollment.requires_mfa(connection, user)
        assert enrollment.readiness(connection)["ready"] is False
    finish(policy, start(policy, "operator", grant=issue(policy, "operator", "migration")))
    with policy.database.transaction() as connection:
        assert enrollment.readiness(connection)["ready"] is True
        connection.execute("INSERT INTO sessions VALUES('synthetic','employee',1,1,9999999999)")
        assert enrollment.activate_strict(connection)["mode"] == "strict"
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    with pytest.raises(ValueError, match="legacy accounts"):
        issue(policy, "employee", "migration")


def test_strict_readiness_requires_confirmed_factor_and_active_administrator(policy):
    for name in ("operator", "employee"):
        finish(policy, start(policy, name))
    with policy.database.transaction() as connection:
        assert enrollment.readiness(connection)["ready"] is True
        connection.execute("DELETE FROM account_mfa WHERE user_id='employee'")
        assert enrollment.readiness(connection)["ready"] is False
        connection.execute("UPDATE users SET active=0 WHERE id='employee'")
        assert enrollment.readiness(connection)["ready"] is True
        connection.execute("UPDATE users SET active=0 WHERE id='operator'")
        assert enrollment.readiness(connection)["ready"] is False


def test_missing_policy_fails_closed_even_for_active_account(policy):
    finish(policy, start(policy))
    with policy.database.transaction() as connection:
        user = connection.execute("SELECT * FROM users WHERE id='operator'").fetchone()
        connection.execute("DELETE FROM authentication_policy")
        for operation in (enrollment.account_can_authenticate, enrollment.requires_mfa):
            with pytest.raises(ValueError, match="policy is missing"):
                operation(connection, user)


def test_schema_seven_requires_explicit_migration_and_preserves_ciphertext_accounts_and_sessions():
    with workspace(7) as directory:
        identity = (directory / "identity.key").read_bytes()
        key_before = default_key_path(directory).read_bytes()
        store = SecretStore(directory, identity)
        generation = "a" * 32
        factor = ("operator", store.encrypt(SEED, "operator", generation), generation, 12)
        old_session = ("old-session", "operator", 100.0, 100.0, 9999999999.0)
        connection = sqlite3.connect(directory / "business.sqlite3")
        try:
            connection.execute("INSERT INTO admin_mfa VALUES(?,?,?,?)", factor)
            connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", old_session)
            connection.execute("INSERT INTO session_mfa VALUES(?,?)", (old_session[0], generation))
            connection.execute("INSERT INTO session_security VALUES(?,?,?,'totp')", (old_session[0], "b" * 32, 100.0))
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(ValueError, match="explicit reviewed migration to schema ten"):
            db.Database(directory)
        migrated = db.Database(directory, migrate=True)
        with migrated.transaction() as connection:
            db._require_schema(connection, 10)
            assert connection.execute("SELECT mode FROM authentication_policy").fetchone()[0] == "transition"
            assert {row[0] for row in connection.execute("SELECT lifecycle FROM account_security")} == {"legacy"}
            assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
            assert tuple(connection.execute("SELECT * FROM account_mfa").fetchone()) == factor
            assert tuple(connection.execute("SELECT * FROM sessions").fetchone()) == old_session
        assert default_key_path(directory).read_bytes() == key_before
        assert (directory / "identity.key").read_bytes() == identity


def test_schema_eight_migration_fault_rolls_back_all_ddl_and_version(monkeypatch):
    with workspace(7) as directory:
        original = db._apply_enrollment_migration

        def interrupted(connection):
            original(connection)
            raise sqlite3.OperationalError("Synthetic enrollment migration interruption")

        monkeypatch.setattr(db, "_apply_enrollment_migration", interrupted)
        with pytest.raises(ValueError, match="invalid or incomplete"):
            db.Database(directory, migrate=True)
        connection = sqlite3.connect(directory / "business.sqlite3")
        connection.row_factory = sqlite3.Row
        try:
            db._require_schema(connection, 7)
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
        finally:
            connection.close()
