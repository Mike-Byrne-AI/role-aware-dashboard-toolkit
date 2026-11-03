"""Offline, atomic rotation of Westbridge's independent MFA encryption key.

Close ingress and stop every application/background writer before using this
tool. The maintenance flag records the operator's assertion, not evidence that
the host is stopped. Preserve a consistent backup and its original key first.
Identity-key changes and recovery from exposed authenticator seeds are separate
operations; this command preserves existing authentication and access state.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sqlite3
import sys

from business.db import Database, _require_schema, record_activity
from business.secret_store import SecretStore, create_key_file, key_path
from business.security_events import record_event


class RotationError(ValueError):
    """An operator-facing refusal that never includes credential contents."""


def _new_key_path(directory, selected):
    path = key_path(directory, selected)
    if os.path.lexists(path):
        raise RotationError("The replacement key path exists; choose a new path and preserve both keys.")
    # key_path rejects the current runtime directory and source/Git trees.
    # Also refuse other recognizable runtime/backup directories enclosing it.
    for parent in path.parents:
        if (parent / "business.sqlite3").exists() or (parent / "manifest.json").exists():
            raise RotationError("Keep the replacement key outside runtime and backup directories.")
    return path


def _reencrypt(connection, original, replacement):
    rows = connection.execute("SELECT * FROM account_mfa ORDER BY user_id").fetchall()
    for row in rows:
        secret = original.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
        ciphertext = replacement.encrypt(secret, row["user_id"], row["generation"])
        connection.execute("UPDATE account_mfa SET secret_ciphertext=? WHERE user_id=?", (ciphertext, row["user_id"]))
    pending = connection.execute("SELECT * FROM enrollment_sessions ORDER BY user_id").fetchall()
    for row in pending:
        context = "enrollment:" + row["user_id"]
        secret = original.decrypt(row["secret_ciphertext"], context, row["generation"])
        ciphertext = replacement.encrypt(secret, context, row["generation"])
        connection.execute("UPDATE enrollment_sessions SET secret_ciphertext=? WHERE token_hash=?",
                           (ciphertext, row["token_hash"]))
    binding = replacement.create_binding()
    connection.execute("UPDATE mfa_key_binding SET ciphertext=? WHERE id=1", (binding,))
    replacement.validate_database(connection)
    try:
        original.check_binding(binding)
    except ValueError:
        pass
    else:
        raise RotationError("The replacement key must be independent of the original key.")
    return len(rows), len(pending)


def rotate_mfa_key(data_dir, *, current_mfa_key_file, new_mfa_key_file, maintenance_confirmed=False):
    """Generate a separate key and commit all ciphertext and binding together.

    A failed attempt preserves the original database authority and any newly
    created key for investigation. A committed attempt preserves both files;
    it never changes service configuration or restarts/reopens the application.
    The new path must not exist. Never use this as an identity-key rotation.
    """
    if maintenance_confirmed is not True:
        raise RotationError("Close ingress and stop all workers, then explicitly confirm maintenance.")
    if not current_mfa_key_file or not new_mfa_key_file:
        raise RotationError("Explicit current and replacement MFA key paths are required.")
    database = Database(data_dir, mfa_key_file=current_mfa_key_file)
    destination = _new_key_path(database.directory, new_mfa_key_file)
    connection = database._connect()
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=0")
        # Fail promptly on a held writer. In WAL mode this does not exclude
        # readers, so it cannot replace the operator's closed-ingress check.
        connection.execute("BEGIN EXCLUSIVE")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        _require_schema(connection, version)
        if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
            raise RotationError("The database failed its integrity check; preserve existing state.")
        database.mfa_secrets.validate_database(connection)
        # On POSIX, creation flushes the key and all new directory entries;
        # any publication failure aborts before ciphertext changes begin.
        created = create_key_file(database.directory, destination)
        replacement = SecretStore(database.directory, database.identity_key, created)
        count, pending_count = _reencrypt(connection, database.mfa_secrets, replacement)
        record_activity(connection, "Local operator", "Rotated MFA encryption key", "Account and pending enrollments")
        record_event(connection, "mfa_key_rotated")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {"format": "westbridge-mfa-rotation-v1", "enrollments_reencrypted": count,
            "pending_enrollments_reencrypted": pending_count,
            "original_key_preserved": True, "authority_preserved": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_dir", type=Path, help="Existing private runtime directory")
    parser.add_argument("--current-mfa-key-file", required=True, type=Path, help="Existing external encryption key; preserved")
    parser.add_argument("--new-mfa-key-file", required=True, type=Path, help="New external key path; must not exist")
    parser.add_argument("--maintenance-confirmed", action="store_true",
                        help="Assert that ingress is closed, every worker is stopped, and a protected backup exists")
    args = parser.parse_args(argv)
    try:
        result = rotate_mfa_key(args.data_dir, current_mfa_key_file=args.current_mfa_key_file,
                                new_mfa_key_file=args.new_mfa_key_file,
                                maintenance_confirmed=args.maintenance_confirmed)
    except (ValueError, OSError, sqlite3.Error, KeyboardInterrupt):
        print("MFA-key rotation refused or interrupted. Preserve the database and both key paths; "
              "verify which key matches before restarting. Check maintenance, private paths, keys and storage. "
              "Do not overwrite a key or repeat an uncertain cutover.", file=sys.stderr)
        return 1
    print(f"MFA encryption-key rotation committed for {result['enrollments_reencrypted']} enrollment(s). "
          "Original key preserved. Keep ingress closed; configure the replacement key, restart every worker "
          "and verify sign-in and backup recovery before reopening.")
    if os.name != "posix":
        print("Directory-entry durability is not verified on this platform; file flushing alone does not "
              "establish recovery from host failure or power loss.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
