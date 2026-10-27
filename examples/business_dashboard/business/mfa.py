"""Host-owned administrator TOTP enrollment and replay-resistant verification."""

from __future__ import annotations

from pathlib import Path
import secrets
import time

import pyotp

from .db import Database, create_private_file, record_activity

ISSUER = "Westbridge"
INTERVAL = 30


def current_time():
    """A separate clock keeps deterministic tests isolated from session clocks."""
    return time.time()


def verify_admin_code(connection, user_id, code, secret_store):
    """Consume a valid step in the caller's write transaction exactly once."""
    if not connection.in_transaction:
        raise ValueError("MFA verification requires an active transaction.")
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdecimal():
        return None
    row = connection.execute("SELECT * FROM admin_mfa WHERE user_id=?", (user_id,)).fetchone()
    if row is None:
        return None
    counter = int(current_time() // INTERVAL)
    secret = secret_store.decrypt(row["secret_ciphertext"], user_id, row["generation"])
    totp = pyotp.TOTP(secret, interval=INTERVAL)
    for candidate in (counter + 1, counter, counter - 1):
        if candidate > row["last_counter"] and candidate >= 0 and totp.verify(code, for_time=candidate * INTERVAL):
            updated = connection.execute(
                "UPDATE admin_mfa SET last_counter=? WHERE user_id=? AND last_counter<?",
                (candidate, user_id, candidate),
            )
            return row["generation"] if updated.rowcount == 1 else None
    return None


def enroll_in_transaction(connection, directory: Path, secret_store, *, reset=False):
    """Write a private setup sheet before committing; never overwrite a sheet."""
    if not connection.in_transaction:
        raise ValueError("MFA enrollment requires an active transaction.")
    users = connection.execute("SELECT id,username FROM users WHERE role='admin' ORDER BY id").fetchall()
    enrollments = []
    for user in users:
        existing = connection.execute("SELECT 1 FROM admin_mfa WHERE user_id=?", (user["id"],)).fetchone()
        if existing and not reset:
            continue
        secret, generation = pyotp.random_base32(), secrets.token_hex(16)
        connection.execute(
            "INSERT INTO admin_mfa(user_id,secret_ciphertext,generation,last_counter) VALUES(?,?,?,-1) "
            "ON CONFLICT(user_id) DO UPDATE SET secret_ciphertext=excluded.secret_ciphertext,generation=excluded.generation,last_counter=-1",
            (user["id"], secret_store.encrypt(secret, user["id"], generation), generation),
        )
        connection.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        enrollments.append((user["username"], secret))
    if not enrollments:
        return None
    sheet = (
        "# Westbridge private administrator authenticator setup\n\n"
        "Keep this file private. Anyone with this secret can generate your sign-in codes.\n"
        "Use these settings only if the enrollment command completed successfully.\n"
        "Add each account to an authenticator app using the manual setup key or the otpauth URI.\n"
        "Algorithm: SHA-1. Digits: 6. Period: 30 seconds. Keep the host and phone clocks correct.\n"
        "After enrollment, store this file offline securely or remove it securely from the host.\n"
    )
    for username, secret in enrollments:
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)
        sheet += f"\n## {username}\n\nManual setup key: `{secret}`\n\nAuthenticator URI: `{uri}`\n"
    output = directory / "ADMIN_MFA_SETUP.md"
    if output.exists() or output.is_symlink():
        output = directory / f"ADMIN_MFA_SETUP-{secrets.token_hex(8)}.md"
    create_private_file(output, sheet.encode())
    return output


def setup_admin_mfa(data_dir, *, reset=False, mfa_key_file=None):
    """Local recovery is deliberately unavailable through an HTTP endpoint."""
    database = Database(data_dir, mfa_key_file=mfa_key_file)
    with database.transaction() as connection:
        sheet = enroll_in_transaction(connection, database.directory, database.mfa_secrets, reset=reset)
        if sheet:
            record_activity(connection, "Local operator", "Reset admin authenticator" if reset else "Enrolled admin authenticator", "Administrator access")
    return sheet
