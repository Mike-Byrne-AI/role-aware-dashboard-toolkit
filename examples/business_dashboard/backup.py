"""Offline application backup and new-directory recovery for Westbridge.

Bundles contain private, unencrypted business data and the identity key. Keep
them in private storage and encrypt retained copies separately. The independent
MFA encryption key is never copied. Checksums detect corruption, not forgery.
An old backup cannot establish current access: restoration either stays offline
in quarantine or reconciles credentials and grants from an explicitly trusted
current security source. Stop the old service before switching to a restore.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time

from business.db import (
    Database, _require_schema, check_private_file, create_private_file,
    record_activity, utc_now, validate_data_dir,
)
from business.secret_store import SecretStore
from business.security import TransactionAccessStore, principal_for_user
from role_aware_dashboard_toolkit.access_store import AccessStoreError

SCHEMA_VERSION = 5
FILES = ("business.sqlite3", "identity.key")
QUARANTINE = "RESTORE_QUARANTINE"
MAX_MANIFEST_BYTES = 16384
SNAPSHOT_SECONDS = 30


class BackupError(ValueError):
    """Safe operator-facing failure without credential contents."""


def _directory(value) -> Path:
    directory = validate_data_dir(value)
    if any((parent / ".git").exists() for parent in (directory, *directory.parents)):
        raise BackupError("Keep backups and restored data outside Git working trees.")
    return directory


def _new_directory(value) -> Path:
    directory = Path(os.path.abspath(Path(value).expanduser()))
    _directory(directory.parent)
    if os.path.lexists(directory):
        raise BackupError("Destination exists; choose a new directory. Nothing was overwritten.")
    directory.mkdir(mode=0o700)
    return _directory(directory)


def _identity(directory) -> bytes:
    path = directory / "identity.key"
    check_private_file(path)
    with path.open("rb") as stream:
        value = stream.read(33)
    if len(value) != 32:
        raise BackupError("The identity key is invalid; preserve the original storage.")
    return value


def _digest(path) -> str:
    check_private_file(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _connect(path, *, readonly=True):
    check_private_file(path)
    connection = sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _validate(connection, identity, secrets):
    if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        raise BackupError("Only reviewed current-schema storage can be backed up or restored.")
    if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
        raise BackupError("The database failed its integrity check.")
    _require_schema(connection, SCHEMA_VERSION)
    users = connection.execute("SELECT id,principal FROM users").fetchall()
    if not users or any(row["principal"] != principal_for_user(row["id"], identity) for row in users):
        raise BackupError("The database and original identity key do not match.")
    secrets.validate_database(connection)
    # A read transaction is required by the same adapter used by the app.
    try:
        TransactionAccessStore(connection).read_freeze()
    except AccessStoreError:
        raise BackupError("The database access state is incomplete or invalid.") from None


def _snapshot(source, destination):
    """Use SQLite's backup API, including committed WAL data, with a deadline."""
    create_private_file(destination, b"")
    started = time.monotonic()

    def progress(status, remaining, total):
        if time.monotonic() - started > SNAPSHOT_SECONDS:
            raise BackupError("Snapshot deadline exceeded; no complete backup was published.")

    with closing(_connect(source)) as incoming, closing(_connect(destination, readonly=False)) as outgoing:
        incoming.backup(outgoing, pages=128, progress=progress, sleep=0.05)


def create_backup(data_dir, output, *, mfa_key_file=None):
    """Create a new consistent bundle. Never copy setup sheets or the MFA key."""
    source = Database(_directory(data_dir), mfa_key_file=mfa_key_file)
    identity = _identity(source.directory)
    destination = _new_directory(output)
    incomplete = destination / "BACKUP_INCOMPLETE"
    create_private_file(incomplete, b"Incomplete backup: do not restore.\n")
    _snapshot(source.path, destination / "business.sqlite3")
    create_private_file(destination / "identity.key", identity)
    with closing(_connect(destination / "business.sqlite3")) as connection:
        connection.execute("BEGIN")
        _validate(connection, identity, source.mfa_secrets)
    if not hmac.compare_digest(identity, _identity(source.directory)):
        raise BackupError("The identity key changed during backup; preserve the incomplete bundle.")
    manifest = {
        "format": "westbridge-backup-v1", "schema": SCHEMA_VERSION,
        "created_at": utc_now(), "encrypted": False, "external_mfa_key_included": False,
        "files": {name: _digest(destination / name) for name in FILES},
    }
    create_private_file(destination / "manifest.json", json.dumps(manifest, indent=2).encode() + b"\n")
    incomplete.unlink()
    return manifest


def _bundle(directory):
    directory = _directory(directory)
    if {path.name for path in directory.iterdir()} != {*FILES, "manifest.json"}:
        raise BackupError("Backup is incomplete or contains unexpected files.")
    manifest_path = directory / "manifest.json"
    check_private_file(manifest_path)
    with manifest_path.open("rb") as stream:
        content = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(content) > MAX_MANIFEST_BYTES:
        raise BackupError("Backup manifest is too large.")
    try:
        manifest = json.loads(content)
    except (ValueError, UnicodeError, RecursionError):
        raise BackupError("Backup manifest is invalid.") from None
    if (not isinstance(manifest, dict) or manifest.get("format") != "westbridge-backup-v1"
            or manifest.get("schema") != SCHEMA_VERSION or manifest.get("encrypted") is not False
            or manifest.get("external_mfa_key_included") is not False
            or not isinstance(manifest.get("files"), dict) or set(manifest["files"]) != set(FILES)):
        raise BackupError("Backup manifest is unsupported.")
    if any(manifest["files"][name] != _digest(directory / name) for name in FILES):
        raise BackupError("Backup checksums do not match; preserve the original bundle.")
    return directory, manifest


def _replace_rows(destination, source, table):
    # Table names are fixed internal constants, never manifest or CLI input.
    rows = source.execute(f"SELECT * FROM {table}").fetchall()
    destination.execute(f"DELETE FROM {table}")
    if rows:
        placeholders = ",".join("?" for _ in rows[0])
        destination.executemany(f"INSERT INTO {table} VALUES({placeholders})", [tuple(row) for row in rows])


def _reconcile(destination, current, identity, secrets):
    _validate(current, identity, secrets)
    restored_ids = {row[0] for row in destination.execute("SELECT id FROM users")}
    current_ids = {row[0] for row in current.execute("SELECT id FROM users")}
    if restored_ids != current_ids:
        raise BackupError("Account sets differ; explicit account migration is required before recovery.")
    if current.execute("SELECT 1 FROM users WHERE role='admin' AND active=1").fetchone() is None:
        raise BackupError("Current security source has no active administrator.")
    if current.execute("SELECT 1 FROM users u WHERE role='admin' AND active=1 "
                       "AND NOT EXISTS(SELECT 1 FROM admin_mfa m WHERE m.user_id=u.id)").fetchone():
        raise BackupError("Every active current administrator must have an authenticator.")
    # Match user IDs and current principal bindings, then restore every current
    # user field, including disabled state, passwords, roles and revision.
    fields = "username=?,name=?,password_hash=?,role=?,active=?,principal=?,revision=?"
    for row in current.execute("SELECT * FROM users"):
        destination.execute(f"UPDATE users SET {fields} WHERE id=?", tuple(row)[1:] + (row["id"],))
    for table in ("admin_mfa", "mfa_key_binding", "passkey_credentials", "login_limits", "submission_limits"):
        _replace_rows(destination, current, table)
    revision = current.execute("SELECT freeze_revision FROM settings WHERE id=1").fetchone()[0]
    destination.execute("UPDATE settings SET frozen=1,freeze_revision=?,changed_by=NULL WHERE id=1", (revision + 1,))


def restore_backup(bundle, output, *, mfa_key_file=None, backup_mfa_key_file=None, security_source=None):
    """Restore business records with current security state, or keep offline.

    security_source is an explicit operator assertion of current authority. It
    must be an existing reviewed workspace, not another historical backup. Its
    write transaction remains held through reconciliation/publication. Sources
    are never changed. Reconciled restores remain frozen and contain no sessions.
    """
    source, manifest = _bundle(bundle)
    identity = _identity(source)
    old_secrets = SecretStore(source, identity, backup_mfa_key_file or mfa_key_file)
    current_directory = _directory(security_source) if security_source else None
    if current_directory and (current_directory == source or (current_directory / "manifest.json").exists()):
        raise BackupError("A historical backup cannot be the current security source.")
    current = Database(current_directory, mfa_key_file=mfa_key_file) if current_directory else None
    if current and not hmac.compare_digest(identity, current.identity_key):
        raise BackupError("Current security source uses a different identity key.")
    output = Path(os.path.abspath(Path(output).expanduser()))
    _directory(output.parent)
    if os.path.lexists(output):
        raise BackupError("Destination exists; choose a new directory. Nothing was overwritten.")
    # Stage validation and reconciliation before creating the requested output.
    # The private staging copy is disposable; never remove either source.
    with tempfile.TemporaryDirectory(prefix=".westbridge-restore-", dir=output.parent) as temporary:
        staged = Path(temporary)
        _snapshot(source / "business.sqlite3", staged / "business.sqlite3")
        # SQLite backup may normalize page metadata. Validate the staged schema
        # and state below; verify the original bundle remained unchanged.
        if manifest["files"]["business.sqlite3"] != _digest(source / "business.sqlite3"):
            raise BackupError("Backup changed during restoration.")
        create_private_file(staged / "identity.key", identity)
        with closing(_connect(staged / "business.sqlite3", readonly=False)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            _validate(connection, identity, old_secrets)
            for table in ("passkey_challenges", "session_passkey", "session_security", "session_mfa", "sessions"):
                connection.execute(f"DELETE FROM {table}")
            if current:
                # Hold source security stable until the completed new workspace
                # is published. No source statements modify rows.
                with current.transaction() as security:
                    _reconcile(connection, security, identity, current.mfa_secrets)
                    _finish_restore(connection, staged, output, identity, current.mfa_secrets,
                                    source, manifest, quarantined=False)
            else:
                connection.execute("UPDATE users SET active=0,password_hash='!restore-quarantined!',revision=revision+1")
                connection.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1,changed_by=NULL WHERE id=1")
                _finish_restore(connection, staged, output, identity, old_secrets,
                                source, manifest, quarantined=True)
    return {"quarantined": current is None, "sessions_revoked": True, "frozen": True}


def _finish_restore(connection, staged, output, identity, secrets, source, manifest, *, quarantined):
    record_activity(connection, "Local operator", "Restored workspace in quarantine" if quarantined else
                    "Restored workspace with current security state", "All sessions revoked; editing paused")
    _validate(connection, identity, secrets)
    if any(manifest["files"][name] != _digest(source / name) for name in FILES):
        raise BackupError("Backup changed during restoration.")
    connection.commit()
    destination = _new_directory(output)
    create_private_file(destination / QUARANTINE, b"Recovery is offline until current security reconciliation succeeds.\n")
    # Include the committing connection's WAL, if present. Copying only the
    # main SQLite file here would lose reconciliation and session revocation.
    # Any failure leaves the marker in place and is not a usable workspace.
    _snapshot(staged / "business.sqlite3", destination / "business.sqlite3")
    create_private_file(destination / "identity.key", identity)
    with closing(_connect(destination / "business.sqlite3")) as completed:
        completed.execute("BEGIN")
        _validate(completed, identity, secrets)
        if completed.execute("SELECT 1 FROM sessions").fetchone():
            raise BackupError("Restored session revocation could not be verified.")
        if not TransactionAccessStore(completed).read_freeze().frozen:
            raise BackupError("Restored editing pause could not be verified.")
    receipt = {"format": "westbridge-restore-v1", "restored_at": utc_now(),
               "backup_database_sha256": manifest["files"]["business.sqlite3"],
               "quarantined": quarantined, "sessions_revoked": True, "frozen": True}
    create_private_file(destination / "restore.json", json.dumps(receipt, indent=2).encode() + b"\n")
    if not quarantined:
        (destination / QUARANTINE).unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("backup", help="Create a new private consistent backup bundle")
    backup.add_argument("data_dir")
    backup.add_argument("--output", required=True)
    backup.add_argument("--mfa-key-file", required=True, help="Independent MFA key outside the bundle")
    restore = commands.add_parser("restore", help="Restore into a new directory, frozen with every session revoked")
    restore.add_argument("bundle")
    restore.add_argument("--output", required=True)
    restore.add_argument("--mfa-key-file", required=True, help="Current independent MFA key (original key for quarantine)")
    restore.add_argument("--backup-mfa-key-file", help="Original backup MFA key when the current key has rotated")
    restore.add_argument("--security-source", help="Explicitly trusted current workspace; omission keeps restore offline")
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            create_backup(args.data_dir, args.output, mfa_key_file=args.mfa_key_file)
            print("Consistent private backup created. Encrypt retained copies; hold the MFA key separately.")
        else:
            result = restore_backup(args.bundle, args.output, mfa_key_file=args.mfa_key_file,
                                    backup_mfa_key_file=args.backup_mfa_key_file, security_source=args.security_source)
            print("Restored offline in quarantine. No account can sign in." if result["quarantined"] else
                  "Restored with current security state. All sessions revoked; editing paused. Verify before switching hosts.")
    except (ValueError, OSError, sqlite3.Error):
        print("Backup/recovery refused. Check private paths, keys, schema, bundle integrity and current security source; "
              "preserve any incomplete output for private inspection.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
