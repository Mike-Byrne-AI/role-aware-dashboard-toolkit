"""Explicit restoration of unchanged schema-five archives with current authority."""

from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest

from tests.test_business_dashboard import (
    ORIGIN, business as business, business_seed as business_seed,
)
from business.app import create_app
from business.db import Database, create_private_file, utc_now
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


def _schema_five_archive(business):
    """Build an exact prior-schema fixture; never downgrade the current workspace."""
    bundle = backup._new_directory(business.directory.parent / "schema-five-archive")
    backup._snapshot(business.directory / "business.sqlite3", bundle / "business.sqlite3")
    create_private_file(bundle / "identity.key", (business.directory / "identity.key").read_bytes())
    with closing(backup._connect(bundle / "business.sqlite3", readonly=False)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        for table in ("security_sink_receipts", "security_outbox", "security_denial_budget", "security_events"):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version=5")
        backup._validate(connection, business.app.state.database.identity_key,
                         business.app.state.database.mfa_secrets, schema_version=5)
        connection.commit()
    manifest = {"format": "westbridge-backup-v1", "schema": 5, "created_at": utc_now(),
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


def test_schema_five_archive_requires_explicit_restore_upgrade(business):
    bundle = _schema_five_archive(business)
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    output = business.directory.parent / "default-refusal"
    with pytest.raises(backup.BackupError, match="manifest is unsupported"):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              security_source=business.directory)
    assert not output.exists()
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


def test_schema_five_restore_keeps_old_business_data_and_current_security_authority(business):
    with business.db() as connection:
        connection.execute("UPDATE contacts SET notes='Historical business notes' WHERE id='contact-1'")
        connection.execute(
            "INSERT INTO passkey_credentials VALUES(?,?,?,?,?,?,?,?,?,?,NULL,0)",
            (b"revoked-archive-credential", "admin", "a" * 32, b"synthetic-handle", b"synthetic-key",
             0, 0, 0, "Historical synthetic credential", 1.0),
        )
    bundle = _schema_five_archive(business)
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
    for table in ("users", "admin_mfa", "mfa_key_binding", "passkey_credentials", "login_limits",
                  "submission_limits", "security_events", "security_outbox", "security_sink_receipts",
                  "security_denial_budget"):
        assert _rows(output, table) == _rows(business.directory, table)
    assert _rows(output, "contacts") == _rows(bundle, "contacts")
    for table in ("sessions", "session_mfa", "session_security", "session_passkey", "passkey_challenges"):
        assert _rows(output, table) == []
    receipt = json.loads((output / "restore.json").read_text())
    assert (receipt["backup_schema"], receipt["restored_schema"], receipt["schema_upgraded"]) == (5, 6, True)
    restored = Database(output, mfa_key_file=default_key_path(business.directory))
    assert dispatch_pending(restored) == {"delivered": 1, "failed": 0, "pending": 0}
    app = create_app(output, public_origin=ORIGIN, mfa_key_file=default_key_path(business.directory))
    client = business.client(app)
    headers = {"Origin": ORIGIN}
    assert client.post("/api/login", headers=headers,
                       json={"username": "alex", "password": business.credentials["alex"]}).status_code == 401
    current = client.post("/api/login", headers=headers,
                          json={"username": "alex", "password": replacement_password})
    assert current.status_code == 200 and current.json()["frozen"] is True
    assert business.client(app).post("/api/login", headers=headers,
                                    json={"username": "blair", "password": business.credentials["blair"]}).status_code == 401
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


def test_schema_upgrade_without_current_authority_remains_quarantined(business):
    bundle = _schema_five_archive(business)
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


def test_schema_upgrade_validates_original_and_current_mfa_keys_separately(business):
    bundle = _schema_five_archive(business)
    old_key = default_key_path(business.directory)
    new_key = old_key.with_name("current-rotated.key")
    create_private_file(new_key, b"r" * 32)
    current_secrets = SecretStore(business.directory, business.app.state.database.identity_key, new_key)
    with business.db() as connection:
        for row in connection.execute("SELECT * FROM admin_mfa").fetchall():
            secret = business.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
            connection.execute("UPDATE admin_mfa SET secret_ciphertext=? WHERE user_id=?",
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
    assert _rows(output, "admin_mfa") == _rows(business.directory, "admin_mfa")
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


@pytest.mark.parametrize("version", [4, 7, "5", 5.0, True])
def test_explicit_upgrade_refuses_other_or_malformed_archive_versions(business, version):
    bundle = _schema_five_archive(business)
    _refresh_manifest(bundle, schema=version)
    before = _archive_bytes(bundle)
    output = business.directory.parent / "unsupported-upgrade"
    with pytest.raises(backup.BackupError, match="manifest is unsupported"):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              upgrade_backup_schema=True)
    assert not output.exists() and _archive_bytes(bundle) == before


@pytest.mark.parametrize("damage", ["DROP INDEX submission_limits_time", "CREATE TABLE unexpected(value TEXT)",
                                    "PRAGMA user_version=4"])
def test_schema_five_contract_is_validated_before_migration_ddl(business, monkeypatch, damage):
    bundle = _schema_five_archive(business)
    with closing(backup._connect(bundle / "business.sqlite3", readonly=False)) as connection, connection:
        connection.execute(damage)
    _refresh_manifest(bundle)
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    monkeypatch.setattr(backup, "_apply_event_migration", lambda connection: pytest.fail("Invalid archive reached migration"))
    output = business.directory.parent / "malformed-upgrade"
    with pytest.raises(ValueError):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              security_source=business.directory, upgrade_backup_schema=True)
    assert not output.exists()
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


def test_failed_staged_migration_never_publishes_usable_output_or_changes_sources(business, monkeypatch):
    bundle = _schema_five_archive(business)
    before = _archive_bytes(bundle), _fingerprint(business.directory)
    original = backup._apply_event_migration

    def fail_after_ddl(connection):
        original(connection)
        raise sqlite3.OperationalError("synthetic migration interruption")

    monkeypatch.setattr(backup, "_apply_event_migration", fail_after_ddl)
    output = business.directory.parent / "failed-upgrade"
    with pytest.raises(sqlite3.OperationalError, match="interruption"):
        backup.restore_backup(bundle, output, mfa_key_file=default_key_path(business.directory),
                              security_source=business.directory, upgrade_backup_schema=True)
    assert not output.exists()
    assert (_archive_bytes(bundle), _fingerprint(business.directory)) == before


def test_explicit_upgrade_cli_preserves_quarantine_without_a_security_source(business, capsys):
    bundle = _schema_five_archive(business)
    output = business.directory.parent / "cli-quarantine"
    assert backup.main(["restore", str(bundle), "--output", str(output), "--mfa-key-file",
                        str(default_key_path(business.directory)), "--upgrade-backup-schema"]) == 0
    assert capsys.readouterr().out == "Restored offline in quarantine. No account can sign in.\n"
    assert (output / backup.QUARANTINE).exists()
