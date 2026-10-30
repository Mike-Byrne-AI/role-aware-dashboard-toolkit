"""Session verification freshness, separate from activity and bearer tokens."""

import math
import secrets
import time

from fastapi import HTTPException

VERIFICATION_SECONDS = 5 * 60


def current_time():
    return time.time()


def record_verification(connection, hashed, now, method):
    if not math.isfinite(now) or now < 0 or method not in ("password", "totp", "passkey"):
        raise ValueError("Invalid session verification state.")
    connection.execute(
        "INSERT INTO session_security VALUES(?,?,?,?) ON CONFLICT(token_hash) "
        "DO UPDATE SET verified_at=excluded.verified_at,method=excluded.method",
        (hashed, secrets.token_hex(16), now, method),
    )


def verification_expiry(connection, hashed):
    row = connection.execute(
        "SELECT verified_at FROM session_security WHERE token_hash=?", (hashed,),
    ).fetchone()
    if not row:
        return 0
    verified = row["verified_at"]
    now = current_time()
    if (type(verified) not in (int, float) or not math.isfinite(verified)
            or verified <= 0 or verified > now or now >= verified + VERIFICATION_SECONDS):
        return 0
    return verified + VERIFICATION_SECONDS


def require_recent(connection, hashed):
    if not verification_expiry(connection, hashed):
        raise HTTPException(
            403, "Verify your identity again before this sensitive action.",
            headers={"X-Reauthentication-Required": "true"},
        )
