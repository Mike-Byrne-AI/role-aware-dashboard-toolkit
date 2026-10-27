"""Own-session visibility, revocation and bounded fresh authentication."""

import re

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .db import record_activity
from .mfa import verify_admin_code
from .models import Empty, Reauthentication
from .security import COOKIE_NAME, IDLE_SECONDS, SESSION_SECONDS, _live, token_hash, verify_password
from .session_state import current_time, record_verification, require_recent, verification_expiry
from .work_limits import BoundedWork


def install_session_routes(app, database, authorized):
    # Imported at installation to keep authentication primitives independent
    # from route composition. Use the same durable reservation semantics.
    from .auth_routes import (
        _identity_state, _limit_key, _limit_response, _mfa_generation,
        _release_success, _reservation_valid, _reserve,
    )
    metrics = app.state.security_metrics
    work = BoundedWork(1, "Identity verification", on_event=lambda event: metrics.record("reauth_" + event))

    @app.get("/api/security/sessions")
    def sessions(request: Request):
        with authorized(request) as (connection, auth):
            hashed = token_hash(request.cookies[COOKIE_NAME])
            rows = connection.execute(
                "SELECT s.*,v.public_id,v.method FROM sessions s JOIN session_security v "
                "ON v.token_hash=s.token_hash WHERE s.user_id=? ORDER BY s.created_at DESC,v.public_id",
                (auth.user["id"],),
            ).fetchall()
            visible = []
            for row in rows:
                try:
                    _live(connection, row["token_hash"], database.identity_key)
                except HTTPException:
                    continue
                visible.append({
                    "id": row["public_id"], "current": row["token_hash"] == hashed,
                    "created_at": row["created_at"], "last_seen": row["last_seen"],
                    "expires_at": min(row["expires_at"], row["last_seen"] + IDLE_SECONDS,
                                      row["created_at"] + SESSION_SECONDS),
                    "method": row["method"],
                })
            return {"sessions": visible, "verification_expires_at": verification_expiry(connection, hashed)}

    def perform_verification(payload, request):
        with authorized(request, csrf=True) as (connection, auth):
            key = _limit_key(database, "reauthentication", auth.user["id"])
            reserved = _reserve(connection, key, current_time())
            if reserved is None:
                metrics.record("reauth_budget_denied")
                return _limit_response("identity-verification")
            before = _identity_state(auth.user)
            generation = _mfa_generation(connection, auth.user)
            password_hash = auth.user["password_hash"]
        if not verify_password(password_hash, payload.current_password):
            metrics.record("reauth_rejected")
            return JSONResponse({"detail": "The verification details are incorrect."}, status_code=403)
        with authorized(request, csrf=True) as (connection, auth):
            if (_identity_state(auth.user) != before
                    or _mfa_generation(connection, auth.user) != generation):
                metrics.record("reauth_identity_changed")
                raise HTTPException(409, "The account changed. Sign in again.")
            now = current_time()
            if not _reservation_valid(connection, key, reserved, now):
                metrics.record("reauth_reservation_expired")
                return _limit_response("identity-verification")
            method = "password"
            if auth.user["role"] == "admin":
                if verify_admin_code(connection, auth.user["id"], payload.otp, database.mfa_secrets) is None:
                    metrics.record("reauth_rejected")
                    return JSONResponse({"detail": "The verification details are incorrect."}, status_code=403)
                method = "totp"
            hashed = token_hash(request.cookies[COOKIE_NAME])
            record_verification(connection, hashed, now, method)
            _release_success(connection, key, reserved)
            record_activity(connection, auth.user["name"], "Verified identity", "Own session")
            result = {"ok": True, "verification_expires_at": verification_expiry(connection, hashed)}
        metrics.record("reauth_succeeded")
        return result

    @app.post("/api/security/reauthenticate")
    async def reauthenticate(payload: Reauthentication, request: Request):
        return await work.run(perform_verification, payload, request)

    @app.post("/api/security/sessions/{identifier}/revoke")
    def revoke(identifier: str, payload: Empty, request: Request):
        with authorized(request, csrf=True) as (connection, auth):
            hashed = token_hash(request.cookies[COOKIE_NAME])
            if not re.fullmatch(r"[0-9a-f]{32}", identifier):
                raise HTTPException(404, "The session was not found.")
            target = connection.execute(
                "SELECT s.token_hash FROM sessions s JOIN session_security v ON v.token_hash=s.token_hash "
                "WHERE v.public_id=? AND s.user_id=?", (identifier, auth.user["id"]),
            ).fetchone()
            if target is None:
                raise HTTPException(404, "The session was not found.")
            own = target["token_hash"] == hashed
            if not own:
                require_recent(connection, hashed)
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (target["token_hash"],))
            record_activity(connection, auth.user["name"], "Revoked session", "Own current session" if own else "Own other session")
            # Do not clear cookies in a delayed response: a newer login wins.
            return {"ok": True, "current_session_revoked": own}
