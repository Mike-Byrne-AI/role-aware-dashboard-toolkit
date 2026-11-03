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
    Database, _apply_browser_flow_migration, _apply_delivery_migration, _apply_enrollment_migration, _apply_event_migration,
    _apply_session_predecessor_migration, _require_schema,
    check_private_file, create_private_file,
    record_activity, utc_now, validate_data_dir,
)
from business.secret_store import SecretStore
from business.security import TransactionAccessStore, principal_for_user
from role_aware_dashboard_toolkit.access_store import AccessStoreError

SCHEMA_VERSION = 10
FILES = ("business.sqlite3", "identity.key")
QUARANTINE = "RESTORE_QUARANTINE"
MAX_MANIFEST_BYTES = 16384
SNAPSHOT_SECONDS = 30


class BackupError(ValueError):
    """Safe operator-facing failure without credential contents."""


def current_time():
    """Isolate the restore observation from unrelated fixture/session clocks."""
    return time.time()


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


def _connect(path, *, readonly=True, immutable=False):
    if immutable and not readonly:
        raise BackupError("An immutable archive connection must be read-only.")
    check_private_file(path)
    query = "?mode=ro" if readonly else "?mode=rw"
    if immutable:
        query += "&immutable=1"
    connection = sqlite3.connect(path.as_uri() + query, uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _validate(connection, identity, secrets, *, schema_version=SCHEMA_VERSION):
    if schema_version not in (5, 6, 7, 8, 9, SCHEMA_VERSION) or connection.execute("PRAGMA user_version").fetchone()[0] != schema_version:
        raise BackupError("Only reviewed current-schema storage can be backed up or restored.")
    if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
        raise BackupError("The database failed its integrity check.")
    _require_schema(connection, schema_version)
    users = connection.execute("SELECT id,principal FROM users").fetchall()
    if not users or any(row["principal"] != principal_for_user(row["id"], identity) for row in users):
        raise BackupError("The database and original identity key do not match.")
    secrets.validate_database(connection)
    if schema_version >= 9:
        from business.event_destinations import validate_delivery_state

        validate_delivery_state(connection)
    if schema_version == 10:
        from business.browser_flow import validate_state

        # Backups can preserve a future rejection floor for offline recovery.
        # Structural validity must not silently lower it to the local clock.
        validate_state(connection)
    # A read transaction is required by the same adapter used by the app.
    try:
        TransactionAccessStore(connection).read_freeze()
    except AccessStoreError:
        raise BackupError("The database access state is incomplete or invalid.") from None


def _snapshot(source, destination, *, frozen_bundle=False):
    """Use SQLite's backup API, including committed WAL data, with a deadline."""
    create_private_file(destination, b"")
    started = time.monotonic()

    def progress(status, remaining, total):
        if time.monotonic() - started > SNAPSHOT_SECONDS:
            raise BackupError("Snapshot deadline exceeded; no complete backup was published.")

    # Only restore's validated three-file archive is immutable: no journal
    # dependency exists, its digest is checked before/after copying, and its
    # operator must keep it unchanged. Normal live snapshots retain locking and
    # include committed WAL data. Immutable archive reads must not add sidecars
    # beside an old standalone bundle whose database still has a WAL header.
    with closing(_connect(source, immutable=frozen_bundle)) as incoming, closing(_connect(destination, readonly=False)) as outgoing:
        incoming.backup(outgoing, pages=128, progress=progress, sleep=0.05)
        # A backup inherits the source's WAL header. A later read-only open can
        # then leave WAL/SHM sidecars, violating the standalone bundle contract.
        # Normalize only the newly created destination while we own its sole
        # writer; never delete a WAL file or change the source's journal mode.
        if outgoing.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
            raise BackupError("The new snapshot could not be made standalone; preserve the incomplete output.")


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
    if {path.name for path in destination.iterdir()} != {*FILES, "manifest.json", "BACKUP_INCOMPLETE"}:
        raise BackupError("The new backup contains unexpected files; preserve the incomplete output.")
    incomplete.unlink()
    return manifest


def _bundle(directory, *, upgrade_backup_schema=False):
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
    allowed_schemas = {5, 6, 7, 8, 9, SCHEMA_VERSION} if upgrade_backup_schema else {SCHEMA_VERSION}
    if (not isinstance(manifest, dict) or manifest.get("format") != "westbridge-backup-v1"
            or type(manifest.get("schema")) is not int or manifest["schema"] not in allowed_schemas
            or manifest.get("encrypted") is not False
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
    policy = current.execute("SELECT mode FROM authentication_policy WHERE id=1").fetchone()
    if policy is None:
        raise BackupError("Current authentication policy is missing.")
    # A pending recovery is not administrator access. Preserve transition
    # policy without promoting legacy accounts, while strict/active accounts
    # require a confirmed factor. At least one administrator must remain usable.
    usable_admin = current.execute(
        "SELECT 1 FROM users u JOIN account_security s ON s.user_id=u.id "
        "WHERE u.role='admin' AND u.active=1 AND "
        "(s.lifecycle='active' OR (?='transition' AND s.lifecycle='legacy')) AND "
        "(EXISTS(SELECT 1 FROM account_mfa m WHERE m.user_id=u.id "
        "AND (m.last_counter>=0 OR (?='transition' AND s.lifecycle='legacy'))) "
        "OR EXISTS(SELECT 1 FROM passkey_credentials p WHERE p.user_id=u.id)) LIMIT 1",
        (policy["mode"], policy["mode"]),
    ).fetchone()
    if usable_admin is None:
        raise BackupError("Current security source has no usable enrolled administrator.")
    # Match user IDs and current principal bindings, then restore every current
    # user field, including disabled state, passwords, roles and revision.
    fields = "username=?,name=?,password_hash=?,role=?,active=?,principal=?,revision=?"
    for row in current.execute("SELECT * FROM users"):
        destination.execute(f"UPDATE users SET {fields} WHERE id=?", tuple(row)[1:] + (row["id"],))
    for table in ("account_mfa", "account_security", "authentication_policy", "enrollment_decisions", "mfa_key_binding",
                  "passkey_credentials", "login_limits", "submission_limits"):
        _replace_rows(destination, current, table)
    # Security evidence and delivery acknowledgements belong to the current
    # security source, not the historical business snapshot. Preserve them
    # together so restore cannot resurrect an old delivery obligation.
    for table in ("security_delivery_obligations", "security_sink_receipts", "security_event_payloads",
                  "security_events", "security_destinations", "security_delivery_identity", "security_denial_budget"):
        destination.execute(f"DELETE FROM {table}")
    for table in ("security_delivery_identity", "security_destinations", "security_events", "security_event_payloads",
                  "security_delivery_obligations", "security_sink_receipts", "security_denial_budget"):
        _replace_rows(destination, current, table)
    # A pruned source still owns its sequence high-water mark. Restoring older
    # business data must not reuse a previous event sequence or routing cutoff.
    sequence = current.execute(
        "SELECT MAX(COALESCE((SELECT seq FROM sqlite_sequence WHERE name='security_events'),0),"
        "COALESCE((SELECT MAX(sequence) FROM security_events),0))"
    ).fetchone()[0]
    destination.execute("DELETE FROM sqlite_sequence WHERE name='security_events'")
    destination.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('security_events',?)", (sequence,))
    revision = current.execute("SELECT freeze_revision FROM settings WHERE id=1").fetchone()[0]
    destination.execute("UPDATE settings SET frozen=1,freeze_revision=?,changed_by=NULL WHERE id=1", (revision + 1,))


def restore_backup(bundle, output, *, mfa_key_file=None, backup_mfa_key_file=None, security_source=None,
                   upgrade_backup_schema=False):
    """Restore business records with current security state, or keep offline.

    security_source is an explicit operator assertion of current authority. It
    must be an existing reviewed workspace, not another historical backup. Its
    write transaction remains held through reconciliation/publication. Sources
    are never changed. Reconciled restores remain frozen and contain no sessions.
    Explicit upgrade_backup_schema permits only validated schema-five through
    -nine archives to become schema ten inside the private restore transaction. Startup and
    backup creation never implicitly migrate older storage.
    """
    if type(upgrade_backup_schema) is not bool:
        raise BackupError("Backup schema upgrade must be an explicit boolean choice.")
    from business.browser_flow import reset_after_restore
    source, manifest = _bundle(bundle, upgrade_backup_schema=upgrade_backup_schema)
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
        _snapshot(source / "business.sqlite3", staged / "business.sqlite3", frozen_bundle=True)
        # SQLite backup may normalize page metadata. Validate the staged schema
        # and state below; verify the original bundle remained unchanged.
        if manifest["files"]["business.sqlite3"] != _digest(source / "business.sqlite3"):
            raise BackupError("Backup changed during restoration.")
        create_private_file(staged / "identity.key", identity)
        with closing(_connect(staged / "business.sqlite3", readonly=False)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            _validate(connection, identity, old_secrets, schema_version=manifest["schema"])
            if manifest["schema"] == 5:
                # The original archive stays unchanged. DDL, revocation and
                # current-authority reconciliation share this staged transaction.
                _apply_event_migration(connection)
                _validate(connection, identity, old_secrets, schema_version=6)
            if manifest["schema"] < 7:
                _apply_session_predecessor_migration(connection)
                _validate(connection, identity, old_secrets, schema_version=7)
            if manifest["schema"] < 8:
                _apply_enrollment_migration(connection)
                _validate(connection, identity, old_secrets, schema_version=8)
            if manifest["schema"] < 9:
                _apply_delivery_migration(connection)
                _validate(connection, identity, old_secrets, schema_version=9)
            if manifest["schema"] < 10:
                _apply_browser_flow_migration(connection)
                _validate(connection, identity, old_secrets)
            # Neither historical nor current activation/recovery capabilities
            # may survive restoration. Pending accounts remain pending and need
            # a fresh, reviewed offline grant after the restored host is accepted.
            archived_floor = connection.execute("SELECT rejection_time_floor FROM browser_flow_state WHERE id=1").fetchone()[0]
            # Flow creators reference users. Drop transient binding/flow rows
            # before any current-account reconciliation, never copy them back.
            for table in ("session_browser_flow", "browser_login_flows", "enrollment_sessions", "enrollment_grants", "passkey_challenges", "session_predecessors", "session_passkey",
                          "session_security", "session_mfa", "sessions"):
                connection.execute(f"DELETE FROM {table}")
            if current:
                # Hold source security stable until the completed new workspace
                # is published. No source statements modify rows.
                # Offline custody must also inspect a source whose clock is
                # behind its floor. The application's transaction entry would
                # mutate/observe that clock; a checked explicit write lock keeps
                # current authority stable in WAL mode without changing it.
                with closing(_connect(current.path, readonly=False)) as security:
                    security.execute("BEGIN IMMEDIATE")
                    _reconcile(connection, security, identity, current.mfa_secrets)
                    current_floor = security.execute("SELECT rejection_time_floor FROM browser_flow_state WHERE id=1").fetchone()[0]
                    quarantined = not reset_after_restore(connection, current_floor, now=current_time())
                    _finish_restore(connection, staged, output, identity, current.mfa_secrets,
                                    source, manifest, quarantined=quarantined)
            else:
                quarantined = True
                reset_after_restore(connection, archived_floor, now=current_time())
                connection.execute("UPDATE users SET active=0,password_hash='!restore-quarantined!',revision=revision+1")
                connection.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1,changed_by=NULL WHERE id=1")
                _finish_restore(connection, staged, output, identity, old_secrets,
                                source, manifest, quarantined=True)
    return {"quarantined": quarantined, "sessions_revoked": True, "frozen": True}


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
        if any(completed.execute(f"SELECT 1 FROM {table}").fetchone() for table in
               ("sessions", "session_predecessors", "session_browser_flow", "browser_login_flows", "enrollment_grants", "enrollment_sessions")):
            raise BackupError("Restored session, browser-flow and enrollment revocation could not be verified.")
        if not TransactionAccessStore(completed).read_freeze().frozen:
            raise BackupError("Restored editing pause could not be verified.")
    receipt = {"format": "westbridge-restore-v1", "restored_at": utc_now(),
               "backup_database_sha256": manifest["files"]["business.sqlite3"],
               "backup_schema": manifest["schema"], "restored_schema": SCHEMA_VERSION,
               "schema_upgraded": manifest["schema"] != SCHEMA_VERSION,
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
    restore.add_argument("--upgrade-backup-schema", action="store_true",
                         help="Explicitly upgrade a validated schema-five through -nine archive only in private restore staging")
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            create_backup(args.data_dir, args.output, mfa_key_file=args.mfa_key_file)
            print("Consistent private backup created. Encrypt retained copies; hold the MFA key separately.")
        else:
            result = restore_backup(args.bundle, args.output, mfa_key_file=args.mfa_key_file,
                                    backup_mfa_key_file=args.backup_mfa_key_file, security_source=args.security_source,
                                    upgrade_backup_schema=args.upgrade_backup_schema)
            print("Restored offline in quarantine. No account can sign in." if result["quarantined"] else
                  "Restored with current security state. All sessions revoked; editing paused. Verify before switching hosts.")
    except (ValueError, OSError, sqlite3.Error):
        print("Backup/recovery refused. Check private paths, keys, schema, bundle integrity and current security source; "
              "preserve any incomplete output for private inspection.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
