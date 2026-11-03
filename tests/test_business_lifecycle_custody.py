"""Account/pending MFA custody and restore boundaries with disposable storage."""

from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import tempfile

import pytest

pyotp = pytest.importorskip("pyotp")
pytest.importorskip("cryptography")
pytest.importorskip("fastapi")

APPLICATION = Path(__file__).resolve().parents[1] / "examples/business_dashboard"
sys.path.insert(0, str(APPLICATION))

from business import db as storage, mfa  # noqa: E402
from business.db import Database, create_private_file  # noqa: E402
from business.secret_store import SecretStore, create_key_file  # noqa: E402
from business.security import hash_password, principal_for_user  # noqa: E402
import rotate_mfa_key as rotation  # noqa: E402

SPEC = importlib.util.spec_from_file_location("lifecycle_custody_backup", APPLICATION / "backup.py")
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


@dataclass
class Custody:
    root: Path
    directory: Path
    key: Path
    identity: bytes = field(repr=False)
    seeds: dict = field(repr=False)
    database: Database = field(repr=False)


@pytest.fixture
def custody():
    with tempfile.TemporaryDirectory(prefix="radt-lifecycle-custody-") as temporary:
        root = Path(temporary)
        directory = root / "runtime"
        directory.mkdir(mode=0o700)
        identity = secrets.token_bytes(32)
        create_private_file(directory / "identity.key", identity)
        key = create_key_file(directory, root / "keys" / "original.key")
        store = SecretStore(directory, identity, key)
        create_private_file(directory / "business.sqlite3", b"")
        seeds = {name: pyotp.random_base32() for name in ("owner", "worker", "pending")}
        with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
            connection.row_factory = sqlite3.Row
            connection.executescript(storage.SCHEMA)
            for name, role, lifecycle in (("owner", "admin", "active"), ("worker", "employee", "active"),
                                           ("pending", "employee", "pending")):
                connection.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?,0)",
                                   (name, name, name.title(), "!synthetic-unusable-password!", role,
                                    principal_for_user(name, identity)))
                connection.execute("INSERT INTO account_security(user_id,lifecycle,revision,completed_at) VALUES(?,?,0,?)",
                                   (name, lifecycle, 1.0 if lifecycle == "active" else None))
                if lifecycle == "active":
                    generation = secrets.token_hex(16)
                    connection.execute("INSERT INTO account_mfa VALUES(?,?,?,0)",
                                       (name, store.encrypt(seeds[name], name, generation), generation))
            connection.execute("INSERT INTO mfa_key_binding VALUES(1,?)", (store.create_binding(),))
            generation = secrets.token_hex(16)
            connection.execute("INSERT INTO enrollment_grants VALUES(?,?,?,?,?,?,?,?,?)",
                               ("pending", "a" * 64, "initial", 0, 0, 1.0, 86401.0, 2.0, None))
            connection.execute("INSERT INTO enrollment_sessions VALUES(?,?,?,?,?,?,?,?,?)",
                               ("b" * 64, "pending", "a" * 64, 0, 0, 2.0, 602.0,
                                store.encrypt(seeds["pending"], "enrollment:pending", generation), generation))
            connection.execute("INSERT INTO enrollment_decisions VALUES(?,?,?,?,?)",
                               ("c" * 32, "pending", "initial", None, 1.0))
            connection.commit()
        yield Custody(root, directory, key, identity, seeds, Database(directory, mfa_key_file=key))


def rows(directory, table):
    with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
        return connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()


def fingerprint(directory):
    with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
        return hashlib.sha256("\n".join(connection.iterdump()).encode()).hexdigest()


@pytest.fixture
def fixed_recovery_clock(custody, monkeypatch):
    # These tests isolate full-database rollback/no-op behavior. Clock-floor
    # persistence is covered separately; do not apply this to custody migration,
    # backup, restore or encryption-key rotation tests.
    from business import browser_flow

    now = rows(custody.directory, "browser_flow_state")[0][2]
    monkeypatch.setattr(browser_flow, "current_time", lambda: now)


@pytest.mark.parametrize("user_id", ["owner", "worker"])
def test_totp_accepts_only_current_step_once_for_every_role(custody, monkeypatch, user_id):
    now = 1_800_000_000.0
    monkeypatch.setattr(mfa, "current_time", lambda: now)
    totp = pyotp.TOTP(custody.seeds[user_id])
    previous, current, future = (totp.at(now + offset) for offset in (-30, 0, 30))
    assert len({previous, current, future}) == 3
    with custody.database.transaction() as connection:
        assert mfa.verify_account_code(connection, user_id, previous, custody.database.mfa_secrets) is None
        assert mfa.verify_account_code(connection, user_id, future, custody.database.mfa_secrets) is None
        assert mfa.verify_account_code(connection, user_id, current, custody.database.mfa_secrets)
        assert mfa.verify_account_code(connection, user_id, current, custody.database.mfa_secrets) is None
    now += 30
    with custody.database.transaction() as connection:
        assert mfa.verify_account_code(connection, user_id, current, custody.database.mfa_secrets) is None
        assert mfa.verify_account_code(connection, user_id, future, custody.database.mfa_secrets)


@pytest.mark.parametrize("now", [-1, float("nan"), float("inf")])
def test_invalid_clock_does_not_consume_totp(custody, monkeypatch, now):
    before = rows(custody.directory, "account_mfa")
    monkeypatch.setattr(mfa, "current_time", lambda: now)
    with custody.database.transaction() as connection:
        assert mfa.verify_account_code(connection, "owner", "123456", custody.database.mfa_secrets) is None
    assert rows(custody.directory, "account_mfa") == before


@pytest.mark.parametrize("table", ["account_mfa", "enrollment_sessions"])
def test_key_validation_includes_account_and_pending_seed_contexts(custody, table):
    with custody.database.transaction() as connection:
        column = "user_id"
        target = "worker" if table == "account_mfa" else "pending"
        row = connection.execute(f"SELECT * FROM {table} WHERE {column}=?", (target,)).fetchone()
        # Valid ciphertext with the wrong account/context is still invalid.
        ciphertext = custody.database.mfa_secrets.encrypt(custody.seeds[target], "other-context", row["generation"])
        connection.execute(f"UPDATE {table} SET secret_ciphertext=? WHERE {column}=?", (ciphertext, target))
    with pytest.raises(ValueError, match="ciphertext|encryption key"):
        Database(custody.directory, mfa_key_file=custody.key)


def test_rotation_reencrypts_pending_and_confirmed_seeds_atomically(custody):
    original = custody.database.mfa_secrets
    unchanged = {table: rows(custody.directory, table) for table in
                 ("users", "account_security", "authentication_policy", "enrollment_grants", "enrollment_decisions")}
    replacement = custody.key.with_name("replacement.key")
    old_key_digest = hashlib.sha256(custody.key.read_bytes()).hexdigest()
    result = rotation.rotate_mfa_key(custody.directory, current_mfa_key_file=custody.key,
                                    new_mfa_key_file=replacement, maintenance_confirmed=True)
    assert result["enrollments_reencrypted"] == 2
    assert result["pending_enrollments_reencrypted"] == 1
    assert hashlib.sha256(custody.key.read_bytes()).hexdigest() == old_key_digest
    current = Database(custody.directory, mfa_key_file=replacement)
    with current.readonly_snapshot() as connection:
        for row in connection.execute("SELECT * FROM account_mfa"):
            assert current.mfa_secrets.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"]) == custody.seeds[row["user_id"]]
        row = connection.execute("SELECT * FROM enrollment_sessions").fetchone()
        assert current.mfa_secrets.decrypt(row["secret_ciphertext"], "enrollment:pending", row["generation"]) == custody.seeds["pending"]
        with pytest.raises(ValueError):
            original.decrypt(row["secret_ciphertext"], "enrollment:pending", row["generation"])
    assert all(rows(custody.directory, table) == before for table, before in unchanged.items())
    with pytest.raises(ValueError):
        Database(custody.directory, mfa_key_file=custody.key)


def test_pending_seed_rotation_failure_rolls_back_all_rows_and_key_binding(custody, monkeypatch):
    before = fingerprint(custody.directory)
    original_encrypt = SecretStore.encrypt

    def fail_pending(self, secret, user_id, generation):
        if user_id.startswith("enrollment:"):
            raise RuntimeError("synthetic pending seed interruption")
        return original_encrypt(self, secret, user_id, generation)

    monkeypatch.setattr(SecretStore, "encrypt", fail_pending)
    replacement = custody.key.with_name("failed-replacement.key")
    with pytest.raises(RuntimeError, match="interruption"):
        rotation.rotate_mfa_key(custody.directory, current_mfa_key_file=custody.key,
                                new_mfa_key_file=replacement, maintenance_confirmed=True)
    assert fingerprint(custody.directory) == before
    assert replacement.is_file() and custody.key.is_file()
    Database(custody.directory, mfa_key_file=custody.key)
    with pytest.raises(ValueError):
        Database(custody.directory, mfa_key_file=replacement)


def test_restore_keeps_current_policy_and_lifecycle_but_no_enrollment_capability(custody):
    from business.enrollment import issue_grant

    archive = custody.root / "archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    with custody.database.transaction() as connection:
        connection.execute("UPDATE users SET password_hash=?,revision=revision+1 WHERE id='worker'",
                           (hash_password("Retired recovery password 2947!"),))
        issue_grant(connection, "worker", purpose="recovery", case_reference="CASE-TEST-1")
        connection.execute("UPDATE authentication_policy SET revision=revision+1")
        security = connection.execute("SELECT * FROM account_security WHERE user_id='worker'").fetchone()
        assert security["lifecycle"] == "pending" and security["retired_password_hash"] is not None
    current = {table: rows(custody.directory, table) for table in
               ("users", "account_security", "authentication_policy", "account_mfa", "enrollment_decisions")}
    before = fingerprint(custody.directory), fingerprint(archive)
    restored = custody.root / "restored"
    backup.restore_backup(archive, restored, mfa_key_file=custody.key, security_source=custody.directory)
    assert all(rows(restored, table) == value for table, value in current.items())
    assert rows(restored, "enrollment_grants") == [] and rows(restored, "enrollment_sessions") == []
    assert rows(restored, "sessions") == []
    assert (fingerprint(custody.directory), fingerprint(archive)) == before
    Database(restored, mfa_key_file=custody.key)


def schema_archive(custody, version):
    archive = backup._new_directory(custody.root / f"archive-{version}")
    create_private_file(archive / "business.sqlite3", b"")
    create_private_file(archive / "identity.key", custody.identity)
    with closing(backup._connect(archive / "business.sqlite3", readonly=False)) as connection:
        # Construct the original SQL contract, not a reversed ALTER TABLE:
        # SQLite's identifier quoting changes during rename are significant to
        # the exact historical schema verifier.
        connection.executescript({5: storage.SCHEMA_V5, 6: storage.SCHEMA_V6, 7: storage.SCHEMA_V7,
                                  8: storage.SCHEMA_V8, 9: storage.SCHEMA_V9}[version])
        connection.execute("BEGIN IMMEDIATE")
        tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid").fetchall()
        with custody.database.readonly_snapshot() as current:
            for table in tables:
                name = table["name"]
                incoming = "account_mfa" if name == "admin_mfa" else name
                if name == "security_outbox":
                    values = current.execute(
                        "SELECT event_id,attempts,next_attempt_at,acknowledged_at,last_error "
                        "FROM security_delivery_obligations WHERE destination_id='local-v1'"
                    ).fetchall()
                else:
                    values = current.execute(f"SELECT * FROM {incoming}").fetchall()
                connection.execute(f"DELETE FROM {name}")
                if values:
                    marks = ",".join("?" for _ in values[0])
                    connection.executemany(f"INSERT INTO {name} VALUES({marks})", [tuple(value) for value in values])
        backup._validate(connection, custody.identity, custody.database.mfa_secrets, schema_version=version)
        connection.commit()
    manifest = {"format": "westbridge-backup-v1", "schema": version, "created_at": storage.utc_now(),
                "encrypted": False, "external_mfa_key_included": False,
                "files": {name: backup._digest(archive / name) for name in backup.FILES}}
    create_private_file(archive / "manifest.json", json.dumps(manifest).encode())
    return archive


@pytest.mark.parametrize("version", [5, 6, 7, 8, 9])
def test_old_archive_requires_explicit_upgrade_then_current_lifecycle_reconciliation(custody, version):
    archive = schema_archive(custody, version)
    digests = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in archive.iterdir()}
    output = custody.root / "restored"
    with pytest.raises(backup.BackupError, match="manifest is unsupported"):
        backup.restore_backup(archive, output, mfa_key_file=custody.key, security_source=custody.directory)
    assert not output.exists()
    backup.restore_backup(archive, output, mfa_key_file=custody.key, security_source=custody.directory,
                          upgrade_backup_schema=True)
    Database(output, mfa_key_file=custody.key)
    assert rows(output, "account_security") == rows(custody.directory, "account_security")
    assert rows(output, "authentication_policy") == rows(custody.directory, "authentication_policy")
    assert rows(output, "enrollment_grants") == rows(output, "enrollment_sessions") == []
    receipt = json.loads((output / "restore.json").read_text())
    assert receipt["backup_schema"] == version and receipt["restored_schema"] == 10 and receipt["schema_upgraded"]
    assert {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in archive.iterdir()} == digests


def test_only_pending_administrator_cannot_reopen_restore(custody):
    archive = custody.root / "archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    with custody.database.transaction() as connection:
        connection.execute("UPDATE account_security SET lifecycle='pending',completed_at=NULL WHERE user_id='owner'")
    output = custody.root / "refused"
    with pytest.raises(backup.BackupError, match="usable enrolled administrator"):
        backup.restore_backup(archive, output, mfa_key_file=custody.key, security_source=custody.directory)
    assert not output.exists()


def test_offline_admin_recovery_issues_expiring_grant_not_a_trusted_factor(custody, capsys):
    from business import enrollment

    with custody.database.transaction() as connection:
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", ("e" * 64, "owner", 1.0, 1.0, 28801.0))
    sheet = mfa.setup_admin_mfa(custody.directory, mfa_key_file=custody.key, reset=True, case_reference="CASE-UNIT-1")
    content = sheet.read_text()
    grant = re.search(r"Enrollment grant: `([A-Za-z0-9_-]{43})`", content).group(1)
    assert "Manual setup key" not in content and "otpauth" not in content
    assert capsys.readouterr().out == ""
    with custody.database.readonly_snapshot() as connection:
        row = connection.execute("SELECT * FROM enrollment_grants WHERE user_id='owner'").fetchone()
        assert row["secret_hash"] == enrollment._hash(grant, "grant")
        assert row["expires_at"] - row["created_at"] == 86400
        assert row["purpose"] == "recovery" and row["case_reference"] == "CASE-UNIT-1"
        assert connection.execute("SELECT lifecycle FROM account_security WHERE user_id='owner'").fetchone()[0] == "pending"
        assert connection.execute("SELECT password_hash FROM users WHERE id='owner'").fetchone()[0] == "!enrollment-pending!"
        assert connection.execute("SELECT 1 FROM account_mfa WHERE user_id='owner'").fetchone() is None
        assert connection.execute("SELECT 1 FROM sessions WHERE user_id='owner'").fetchone() is None
        assert connection.execute("SELECT code FROM security_events ORDER BY sequence DESC").fetchone()[0] == "enrollment_issued"
        assert connection.execute("SELECT case_reference FROM enrollment_decisions WHERE user_id='owner'").fetchone()[0] == "CASE-UNIT-1"


def test_admin_recovery_requires_case_reference_before_mutation(custody, fixed_recovery_clock):
    before = fingerprint(custody.directory)
    with pytest.raises(ValueError, match="case reference"):
        mfa.setup_admin_mfa(custody.directory, mfa_key_file=custody.key, reset=True)
    assert fingerprint(custody.directory) == before
    assert list(custody.directory.glob("ADMIN_ENROLLMENT*")) == []


@pytest.mark.parametrize("boundary", ["sheet", "event"])
def test_failed_recovery_receipt_or_sheet_rolls_back_all_authority_changes(custody, monkeypatch, boundary, fixed_recovery_clock):
    from business import enrollment

    before = fingerprint(custody.directory)

    def fail(*args, **kwargs):
        raise OSError("synthetic recovery publication failure")

    if boundary == "sheet":
        monkeypatch.setattr(mfa, "create_private_file", fail)
    else:
        monkeypatch.setattr(enrollment, "record_event", fail)
    with pytest.raises(OSError, match="publication failure"):
        mfa.setup_admin_mfa(custody.directory, mfa_key_file=custody.key, reset=True, case_reference="CASE-UNIT-2")
    assert fingerprint(custody.directory) == before
    assert list(custody.directory.glob("ADMIN_ENROLLMENT*")) == []


def test_setup_does_not_replace_an_existing_admin_factor(custody, fixed_recovery_clock):
    before = fingerprint(custody.directory)
    assert mfa.setup_admin_mfa(custody.directory, mfa_key_file=custody.key) is None
    assert fingerprint(custody.directory) == before


def test_setup_missing_legacy_admin_factor_issues_migration_without_promoting_access(custody):
    with custody.database.transaction() as connection:
        connection.execute("UPDATE authentication_policy SET mode='transition'")
        connection.execute("UPDATE account_security SET lifecycle='legacy',completed_at=NULL WHERE user_id='owner'")
        connection.execute("DELETE FROM account_mfa WHERE user_id='owner'")
    sheet = mfa.setup_admin_mfa(custody.directory, mfa_key_file=custody.key)
    assert sheet.is_file()
    with custody.database.readonly_snapshot() as connection:
        assert connection.execute("SELECT lifecycle FROM account_security WHERE user_id='owner'").fetchone()[0] == "legacy"
        assert connection.execute("SELECT purpose FROM enrollment_grants WHERE user_id='owner'").fetchone()[0] == "migration"
        assert connection.execute("SELECT 1 FROM account_mfa WHERE user_id='owner'").fetchone() is None


@pytest.mark.parametrize("version", [5, 6, 7, 8, 9])
def test_malformed_historical_schema_is_rejected_before_enrollment_upgrade(custody, monkeypatch, version):
    archive = schema_archive(custody, version)
    with closing(backup._connect(archive / "business.sqlite3", readonly=False)) as connection, connection:
        connection.execute("DROP INDEX submission_limits_time")
    manifest_file = archive / "manifest.json"
    manifest = json.loads(manifest_file.read_text())
    manifest["files"]["business.sqlite3"] = backup._digest(archive / "business.sqlite3")
    manifest_file.write_text(json.dumps(manifest))
    before = fingerprint(archive), fingerprint(custody.directory)
    monkeypatch.setattr(backup, "_apply_enrollment_migration", lambda connection: pytest.fail("Invalid archive reached migration"))
    output = custody.root / "refused-malformed"
    with pytest.raises(ValueError, match="schema"):
        backup.restore_backup(archive, output, mfa_key_file=custody.key, security_source=custody.directory,
                              upgrade_backup_schema=True)
    assert not output.exists() and (fingerprint(archive), fingerprint(custody.directory)) == before
