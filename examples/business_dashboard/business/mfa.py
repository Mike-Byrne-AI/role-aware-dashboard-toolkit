"""Host-owned account TOTP enrollment and replay-resistant verification."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import math
import secrets
import time

import pyotp

from .db import Database, create_private_file, record_activity

ISSUER = "Westbridge"
INTERVAL = 30


def current_time():
    """A separate clock keeps deterministic tests isolated from session clocks."""
    return time.time()


def verify_account_code(connection, user_id, code, secret_store):
    """Consume only the current 30-second step in the caller's transaction.

    Accepting either neighboring step extends a code's usable lifetime beyond
    its displayed period. Clock synchronization is an operator prerequisite;
    verification never silently widens that period.
    """
    if not connection.in_transaction:
        raise ValueError("MFA verification requires an active transaction.")
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdecimal():
        return None
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version not in (5, 6, 7, 8, 9, 10):
        raise ValueError("MFA verification requires a reviewed storage schema.")
    table = "account_mfa" if version in (8, 9, 10) else "admin_mfa"
    row = connection.execute(f"SELECT * FROM {table} WHERE user_id=?", (user_id,)).fetchone()
    if row is None:
        return None
    now = current_time()
    if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
        return None
    counter = int(now // INTERVAL)
    secret = secret_store.decrypt(row["secret_ciphertext"], user_id, row["generation"])
    totp = pyotp.TOTP(secret, interval=INTERVAL)
    if counter > row["last_counter"] and totp.verify(code, for_time=counter * INTERVAL):
        updated = connection.execute(
            f"UPDATE {table} SET last_counter=? WHERE user_id=? AND last_counter<?",
            (counter, user_id, counter),
        )
        return row["generation"] if updated.rowcount == 1 else None
    return None


def enroll_in_transaction(connection, directory: Path, secret_store, *, reset=False, case_reference=None):
    """Issue expiring grants on a private sheet, never install a trusted factor.

    Kept as the offline administrator setup entry point. A grant must be claimed
    and completed with a chosen password and a proven authenticator before it
    becomes account authority. The existing secret store is never used to mint
    a trusted seed here.
    """
    from .enrollment import issue_grant

    if not connection.in_transaction:
        raise ValueError("MFA enrollment requires an active transaction.")
    if reset and not case_reference:
        raise ValueError("Recovery requires a reviewed operator case reference.")
    users = connection.execute("SELECT id,username FROM users WHERE role='admin' AND active=1 ORDER BY id").fetchall()
    enrollments = []
    for user in users:
        if not reset:
            state = connection.execute("SELECT lifecycle FROM account_security WHERE user_id=?", (user["id"],)).fetchone()
            existing = connection.execute("SELECT 1 FROM account_mfa WHERE user_id=?", (user["id"],)).fetchone()
            passkey = connection.execute("SELECT 1 FROM passkey_credentials WHERE user_id=?", (user["id"],)).fetchone()
            if existing or passkey or state is None or state["lifecycle"] != "legacy":
                continue
        purpose = "recovery" if reset else "migration"
        grant = issue_grant(connection, user["id"], purpose=purpose, case_reference=case_reference)
        expires_at = connection.execute("SELECT expires_at FROM enrollment_grants WHERE user_id=?", (user["id"],)).fetchone()[0]
        enrollments.append((user["username"], grant, expires_at))
    if not enrollments:
        return None
    sheet = (
        "# Westbridge private administrator enrollment\n\n"
        "Keep this file private. Each single-use grant can begin account enrollment until its expiry.\n"
        "Use a grant only if the issuing command completed successfully and the recipient's identity was verified.\n"
        "Open the configured Westbridge site directly and choose account enrollment.\n"
        "Choose a new password and prove possession of the displayed authenticator before access is activated.\n"
        "Recovery revokes existing credentials and sessions; issuing this sheet does not restore sign-in.\n"
    )
    for username, grant, expires_at in enrollments:
        expiry = datetime.fromtimestamp(expires_at, timezone.utc).isoformat()
        sheet += f"\n## {username}\n\nEnrollment grant: `{grant}`\n\nExpires at: {expiry}\n"
    output = directory / "ADMIN_ENROLLMENT.md"
    if output.exists() or output.is_symlink():
        output = directory / f"ADMIN_ENROLLMENT-{secrets.token_hex(8)}.md"
    create_private_file(output, sheet.encode())
    return output


def setup_admin_mfa(data_dir, *, reset=False, mfa_key_file=None, case_reference=None):
    """Issue offline enrollment/recovery grants; completion proves the new factor."""
    database = Database(data_dir, mfa_key_file=mfa_key_file)
    with database.transaction() as connection:
        sheet = enroll_in_transaction(connection, database.directory, database.mfa_secrets,
                                      reset=reset, case_reference=case_reference)
        if sheet:
            record_activity(connection, "Local operator", "Issued admin recovery enrollment" if reset else
                            "Issued admin migration enrollment", "Administrator access remains subject to enrollment")
    return sheet
