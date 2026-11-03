"""Explicit restoration of unchanged prior-schema archives with current authority."""

from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3

import pytest
from tools.business_login_client import login_post

from tests.test_business_dashboard import (
    ORIGIN, business as business, business_seed as business_seed,
)
from business.app import create_app
from business.db import Database, create_private_file, utc_now
from business import db as storage
from business.secret_store import SecretStore, default_key_path
from business.security import hash_password
from business.security_events import dispatch_pending, record_event


SCRIPT = Path(__file__).resolve().parents[1] / "examples/business_dashboard/backup.py"
SPEC = importlib.util.spec_from_file_location("business_backup_schema_upgrade", SCRIPT)
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


def _rows(directory, table):
    with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
        return connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()


def _fingerprint(directory):
    # Hashes keep even disposable credential material out of assertion output.
    with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
        return hashlib.sha256("\n".join(connection.iterdump()).encode()).hexdigest()


def _archive_bytes(bundle):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in bundle.iterdir()}


def _schema_archive(business, version=5):
    """Build an exact prior-schema fixture; never downgrade the current workspace."""
    bundle = backup._new_directory(business.directory.parent / f"schema-{version}-archive")
    create_private_file(bundle / "business.sqlite3", b"")
    create_private_file(bundle / "identity.key", (business.directory / "identity.key").read_bytes())
    with closing(backup._connect(bundle / "business.sqlite3", readonly=False)) as connection:
        # Construct the original SQL contract rather than reversing ALTER TABLE,
        # which retains SQLite's renamed-identifier quoting in sqlite_master.
        connection.executescript({5: storage.SCHEMA_V5, 6: storage.SCHEMA_V6, 7: storage.SCHEMA_V7,
                                  8: storage.SCHEMA_V8, 9: storage.SCHEMA_V9}[version])
        connection.execute("BEGIN IMMEDIATE")
        tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid").fetchall()
        with business.app.state.database.readonly_snapshot() as current:
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
                    placeholders = ",".join("?" for _ in values[0])
                    connection.executemany(f"INSERT INTO {name} VALUES({placeholders})", [tuple(row) for row in values])
        backup._validate(connection, business.app.state.database.identity_key,
                         business.app.state.database.mfa_secrets, schema_version=version)
        connection.commit()
    manifest = {"format": "westbridge-backup-v1", "schema": version, "created_at": utc_now(),
                "encrypted": False, "external_mfa_key_included": False,
                "files": {name: backup._digest(bundle / name) for name in backup.FILES}}
    create_private_file(bundle / "manifest.json", json.dumps(manifest).encode() + b"\n")
    return bundle


def _refresh_manifest(bundle, **changes):
    path = bundle / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest.update(changes)
    manifest["files"] = {name: backup._digest(bundle / name) for name in backup.FILES}
    path.write_bytes(json.dumps(manifest).encode() + b"\n")


@pytest.mark.parametrize("archive_version", [5, 6, 7, 8, 9])
def test_prior_schema_archive_requires_explicit_restore_upgrade(business, archive_version):
    bundle = _schema_archive(business, archive_version)
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    output = business.directory.parent / "default-refusal"
    with pytest.raises(backup.BackupError, match="manifest is unsupported"):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              security_source=business.directory)
    assert not output.exists()
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


def test_archive_upgrade_cannot_implicitly_upgrade_current_security_authority(business):
    bundle = _schema_archive(business, 6)
    # The fixture has no active writer. Replace it with an exact historical
    # schema-six workspace so refusal tests version policy, not malformed SQL.
    shutil.copyfile(bundle / "business.sqlite3", business.directory / "business.sqlite3")
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    output = business.directory.parent / "old-current-source-refusal"
    with pytest.raises(ValueError, match="explicit reviewed migration to schema ten"):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              security_source=business.directory, upgrade_backup_schema=True)
    assert not output.exists()
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


@pytest.mark.parametrize("archive_journal_mode", ["DELETE", "WAL"])
@pytest.mark.parametrize("archive_version", [5, 6, 7, 8, 9])
def test_prior_schema_restore_keeps_old_business_data_and_current_security_authority(business, archive_journal_mode, archive_version):
    dispatch_pending(business.app.state.database)
    with business.db() as connection:
        connection.execute("UPDATE contacts SET notes='Historical business notes' WHERE id='contact-1'")
        connection.execute(
            "INSERT INTO passkey_credentials VALUES(?,?,?,?,?,?,?,?,?,?,NULL,0)",
            (b"revoked-archive-credential", "admin", "a" * 32, b"synthetic-handle", b"synthetic-key",
             0, 0, 0, "Historical synthetic credential", 1.0),
        )
    bundle = _schema_archive(business, archive_version)
    with closing(sqlite3.connect(bundle / "business.sqlite3")) as connection:
        connection.execute("PRAGMA journal_mode=" + archive_journal_mode)
    _refresh_manifest(bundle)
    replacement_password = "Current authority password 93724!"
    with business.db() as connection:
        connection.execute("UPDATE contacts SET notes='Newer business notes' WHERE id='contact-1'")
        connection.execute("UPDATE users SET password_hash=?,revision=revision+1 WHERE id='alex'",
                           (hash_password(replacement_password),))
        connection.execute("UPDATE users SET active=0,revision=revision+1 WHERE id='blair'")
        connection.execute("DELETE FROM passkey_credentials")
        connection.execute("INSERT INTO login_limits VALUES('current-opaque-budget',12345,7)")
        connection.execute("INSERT INTO submission_limits(key_hash,submitted_at) VALUES('current-opaque-peer',12345)")
        record_event(connection, "account_disabled")
    assert dispatch_pending(business.app.state.database)["delivered"] == 1
    with business.db() as connection:
        record_event(connection, "editing_paused")
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    output = business.directory.parent / "reconciled-upgrade"
    result = backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                                   security_source=business.directory, upgrade_backup_schema=True)
    assert result == {"quarantined": False, "sessions_revoked": True, "frozen": True}
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before
    for table in ("users", "account_mfa", "mfa_key_binding", "passkey_credentials", "login_limits",
                  "submission_limits", "security_events", "security_delivery_identity", "security_destinations",
                  "security_event_payloads", "security_delivery_obligations", "security_sink_receipts",
                  "security_denial_budget", "account_security", "authentication_policy", "enrollment_decisions"):
        assert _rows(output, table) == _rows(business.directory, table)
    assert _rows(output, "contacts") == _rows(bundle, "contacts")
    for table in ("sessions", "session_mfa", "session_security", "session_passkey", "passkey_challenges", "session_predecessors",
                  "enrollment_grants", "enrollment_sessions"):
        assert _rows(output, table) == []
    receipt = json.loads((output / "restore.json").read_text())
    assert (receipt["backup_schema"], receipt["restored_schema"], receipt["schema_upgraded"]) == (archive_version, 10, True)
    restored = Database(output, mfa_key_file=default_key_path(business.directory))
    assert dispatch_pending(restored) == {"delivered": 1, "failed": 0, "pending": 0}
    app = create_app(output, public_origin=ORIGIN, mfa_key_file=default_key_path(business.directory))
    client = business.client(app)
    headers = {"Origin": ORIGIN}
    assert login_post(client, headers=headers,
                       json=business.login_payload("alex")).status_code == 401
    current = login_post(client, headers=headers,
                          json=business.login_payload("alex", replacement_password))
    assert current.status_code == 200 and current.json()["frozen"] is True
    assert login_post(business.client(app), headers=headers,
                                    json=business.login_payload("blair")).status_code == 401
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


@pytest.mark.parametrize("archive_version", [5, 6, 7, 8, 9])
def test_schema_upgrade_without_current_authority_remains_quarantined(business, archive_version):
    bundle = _schema_archive(business, archive_version)
    before = _archive_bytes(bundle)
    output = business.directory.parent / "quarantined-upgrade"
    result = backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                                   upgrade_backup_schema=True)
    assert result == {"quarantined": True, "sessions_revoked": True, "frozen": True}
    assert (output / backup.QUARANTINE).is_file()
    assert all(row[5] == 0 and row[3] == "!restore-quarantined!" for row in _rows(output, "users"))
    with pytest.raises(ValueError, match="quarantined"):
        Database(output, mfa_key_file=default_key_path(business.directory), migrate=True)
    assert _rows(output, "contacts") == _rows(bundle, "contacts")
    assert _archive_bytes(bundle) == before


@pytest.mark.parametrize("archive_version", [5, 6, 7, 8, 9])
def test_schema_upgrade_validates_original_and_current_mfa_keys_separately(business, archive_version):
    bundle = _schema_archive(business, archive_version)
    old_key = default_key_path(business.directory)
    new_key = old_key.with_name("current-rotated.key")
    create_private_file(new_key, b"r" * 32)
    current_secrets = SecretStore(business.directory, business.app.state.database.identity_key, new_key)
    with business.db() as connection:
        for row in connection.execute("SELECT * FROM account_mfa").fetchall():
            secret = business.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
            connection.execute("UPDATE account_mfa SET secret_ciphertext=? WHERE user_id=?",
                               (current_secrets.encrypt(secret, row["user_id"], row["generation"]), row["user_id"]))
        connection.execute("UPDATE mfa_key_binding SET ciphertext=? WHERE id=1", (current_secrets.create_binding(),))
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    refused = business.directory.parent / "wrong-original-key"
    with pytest.raises(ValueError, match="ciphertext|encryption key"):
        backup.restore_backup(bundle, refused, mfa_key_file=new_key, security_source=business.directory,
                              upgrade_backup_schema=True)
    assert not refused.exists()
    output = business.directory.parent / "keys-reconciled-upgrade"
    backup.restore_backup(bundle, output, mfa_key_file=new_key, backup_mfa_key_file=old_key,
                          security_source=business.directory, upgrade_backup_schema=True)
    Database(output, mfa_key_file=new_key)
    with pytest.raises(ValueError, match="ciphertext|encryption key"):
        Database(output, mfa_key_file=old_key)
    assert _rows(output, "account_mfa") == _rows(business.directory, "account_mfa")
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


@pytest.mark.parametrize("version", [4, 11, "5", 5.0, True])
def test_explicit_upgrade_refuses_other_or_malformed_archive_versions(business, version):
    bundle = _schema_archive(business)
    _refresh_manifest(bundle, schema=version)
    before = _archive_bytes(bundle)
    output = business.directory.parent / "unsupported-upgrade"
    with pytest.raises(backup.BackupError, match="manifest is unsupported"):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              upgrade_backup_schema=True)
    assert not output.exists() and _archive_bytes(bundle) == before


@pytest.mark.parametrize("damage", ["DROP INDEX submission_limits_time", "CREATE TABLE unexpected(value TEXT)",
                                    "PRAGMA user_version=4"])
@pytest.mark.parametrize("archive_version", [5, 6, 7, 8, 9])
def test_prior_schema_contract_is_validated_before_migration_ddl(business, monkeypatch, damage, archive_version):
    bundle = _schema_archive(business, archive_version)
    with closing(backup._connect(bundle / "business.sqlite3", readonly=False)) as connection, connection:
        connection.execute(damage)
    _refresh_manifest(bundle)
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    monkeypatch.setattr(backup, "_apply_event_migration", lambda connection: pytest.fail("Invalid archive reached migration"))
    monkeypatch.setattr(backup, "_apply_session_predecessor_migration", lambda connection: pytest.fail("Invalid archive reached migration"))
    monkeypatch.setattr(backup, "_apply_enrollment_migration", lambda connection: pytest.fail("Invalid archive reached migration"))
    monkeypatch.setattr(backup, "_apply_delivery_migration", lambda connection: pytest.fail("Invalid archive reached migration"))
    monkeypatch.setattr(backup, "_apply_browser_flow_migration", lambda connection: pytest.fail("Invalid archive reached migration"))
    output = business.directory.parent / "malformed-upgrade"
    with pytest.raises(ValueError):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              security_source=business.directory, upgrade_backup_schema=True)
    assert not output.exists()
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


@pytest.mark.parametrize("archive_version", [5, 6, 7, 8, 9])
def test_failed_staged_migration_never_publishes_usable_output_or_changes_sources(business, monkeypatch, archive_version):
    bundle = _schema_archive(business, archive_version)
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    name = {8: "_apply_delivery_migration", 9: "_apply_browser_flow_migration"}.get(archive_version, "_apply_enrollment_migration")
    original = getattr(backup, name)

    def fail_after_ddl(connection):
        original(connection)
        raise sqlite3.OperationalError("synthetic migration interruption")

    monkeypatch.setattr(backup, name, fail_after_ddl)
    output = business.directory.parent / "failed-upgrade"
    with pytest.raises(sqlite3.OperationalError, match="interruption"):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              security_source=business.directory, upgrade_backup_schema=True)
    assert not output.exists()
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


@pytest.mark.parametrize("archive_version", [5, 6, 7, 8, 9])
def test_explicit_upgrade_cli_preserves_quarantine_without_a_security_source(business, capsys, archive_version):
    bundle = _schema_archive(business, archive_version)
    output = business.directory.parent / "cli-quarantine"
    assert backup.main(["restore", str(bundle), "--output", str(output), "--mfa-key-file",
                        str(default_key_path(business.directory)), "--upgrade-backup-schema"]) == 0
    assert capsys.readouterr().out == "Restored offline in quarantine. No account can sign in.\n"
    assert (output / backup.QUARANTINE).exists()
