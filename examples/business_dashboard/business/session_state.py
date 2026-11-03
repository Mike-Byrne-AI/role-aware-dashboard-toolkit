"""Session verification freshness, separate from activity and bearer tokens."""

import math
import secrets

from fastapi import HTTPException

VERIFICATION_SECONDS = 5 * 60
MAX_SESSION_PREDECESSORS = 32
MAX_PREDECESSORS = 10_000


def current_time():
    from .browser_flow import current_time as flow_time
    return flow_time()


def record_verification(connection, hashed, now, method):
    if not math.isfinite(now) or now < 0 or method not in ("password", "totp", "passkey"):
        raise ValueError("Invalid session verification state.")
    connection.execute(
        "INSERT INTO session_security VALUES(?,?,?,?) ON CONFLICT(token_hash) "
        "DO UPDATE SET verified_at=excluded.verified_at,method=excluded.method",
        (hashed, secrets.token_hex(16), now, method),
    )


def _trim_predecessors(connection, now):
    # Preserve the bounded rotation inventory. These hashes never authenticate
    # and no longer select a full-login replacement: only the purpose-bound
    # browser flow chooses its current public session head.
    connection.execute(
        "DELETE FROM session_predecessors WHERE expires_at<=? OR public_id NOT IN "
        "(SELECT public_id FROM session_security)", (now,),
    )


def rotate_session(connection, hashed, now, method, identity_key):
    """Replace an already verified live bearer within its action transaction.

    Keep the public inventory identity, original absolute expiry and revocation
    bindings. An audit/commit failure rolls all of this back. There is no grace
    period or authentication alias for the old token, including lost responses.
    """
    from .security import SESSION_SECONDS, _live, authenticate, token_hash
    from .browser_flow import checked_time, require_bound_session

    if (type(now) not in (int, float) or not math.isfinite(now) or now < 0
            or method not in ("password", "totp", "passkey")):
        raise ValueError("Invalid session verification state.")
    _live(connection, hashed, identity_key)
    flow = require_bound_session(connection, hashed)
    now = checked_time(connection)
    session = connection.execute("SELECT * FROM sessions WHERE token_hash=?", (hashed,)).fetchone()
    security = connection.execute("SELECT * FROM session_security WHERE token_hash=?", (hashed,)).fetchone()
    if security is None:
        raise HTTPException(401, "Please sign in again.")
    _trim_predecessors(connection, now)
    family_count = connection.execute(
        "SELECT COUNT(*) FROM session_predecessors WHERE public_id=?", (security["public_id"],),
    ).fetchone()[0]
    total = connection.execute("SELECT COUNT(*) FROM session_predecessors").fetchone()[0]
    if family_count >= MAX_SESSION_PREDECESSORS or total >= MAX_PREDECESSORS:
        raise HTTPException(409, "This session cannot be verified again. Sign in again to continue.")
    token = secrets.token_urlsafe(32)
    replacement = token_hash(token)
    expiry = min(session["expires_at"], session["created_at"] + SESSION_SECONDS, flow["expires_at"])
    connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (
        replacement, session["user_id"], session["created_at"], now, expiry,
    ))
    for table in ("session_mfa", "session_passkey"):
        connection.execute(f"UPDATE {table} SET token_hash=? WHERE token_hash=?", (replacement, hashed))
    connection.execute(
        "UPDATE session_security SET token_hash=?,verified_at=?,method=? WHERE token_hash=?",
        (replacement, now, method, hashed),
    )
    connection.execute("INSERT INTO session_predecessors VALUES(?,?,?)", (hashed, security["public_id"], expiry))
    connection.execute("DELETE FROM passkey_challenges WHERE binding_hash=?", (hashed,))
    connection.execute("DELETE FROM sessions WHERE token_hash=?", (hashed,))
    auth = authenticate(connection, token, identity_key)
    auth.authorize("can_view_team")
    result = {**auth.session_payload(), "ok": True,
              "verification_expires_at": verification_expiry(connection, replacement)}
    return token, expiry, result


def set_rotated_cookie(response, origin, token, expiry):
    from .security import session_cookie_name
    from .browser_flow import current_time as flow_time

    response.set_cookie(session_cookie_name(origin), token, max_age=max(0, math.floor(expiry - flow_time())),
                        httponly=True, secure=origin.scheme == "https", samesite="strict", path="/")


def verification_expiry(connection, hashed):
    from .browser_flow import bound_session, checked_time

    row = connection.execute(
        "SELECT verified_at FROM session_security WHERE token_hash=?", (hashed,),
    ).fetchone()
    if not row:
        return 0
    verified = row["verified_at"]
    now = current_time()
    checked = checked_time(connection, now)
    bound = bound_session(connection, hashed, now=now)
    if type(verified) in (int, float) and math.isfinite(verified) and bound is not None:
        verified, now = math.floor(verified), checked
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
