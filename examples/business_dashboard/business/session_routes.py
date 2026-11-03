"""Own-session visibility, revocation and bounded fresh authentication."""

import re

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .db import record_activity
from .mfa import verify_account_code
from .models import Empty, Reauthentication
from .security import IDLE_SECONDS, SESSION_SECONDS, _live, read_session_token, session_cookie_name, token_hash, verify_password
from .session_state import current_time, require_recent, rotate_session, set_rotated_cookie, verification_expiry
from .work_limits import BoundedWork
from .security_events import record_event, terminate_own_session
from .browser_flow import require_bound_session


def install_session_routes(app, database, authorized, origin):
    from .enrollment import requires_mfa
    # Imported at installation to keep authentication primitives independent
    # from route composition. Use the same durable reservation semantics.
    from .auth_routes import (
        _identity_state, _limit_key, _limit_response, _mfa_generation,
        _release_success, _reservation_valid, _reserve,
    )
    metrics = app.state.security_metrics
    cookie_name = session_cookie_name(origin)
    work = BoundedWork(1, "Identity verification", on_event=lambda event: metrics.record("reauth_" + event))

    @app.get("/api/security/sessions")
    def sessions(request: Request):
        with authorized(request) as (connection, auth):
            hashed = token_hash(read_session_token(request, cookie_name))
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

    def perform_verification(payload, request, response):
        with authorized(request, csrf=True) as (connection, auth):
            require_bound_session(connection, token_hash(read_session_token(request, cookie_name)))
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
            require_bound_session(connection, token_hash(read_session_token(request, cookie_name)))
            if (_identity_state(auth.user) != before
                    or _mfa_generation(connection, auth.user) != generation):
                metrics.record("reauth_identity_changed")
                raise HTTPException(409, "The account changed. Sign in again.")
            now = current_time()
            if not _reservation_valid(connection, key, reserved, now):
                metrics.record("reauth_reservation_expired")
                return _limit_response("identity-verification")
            method = "password"
            if requires_mfa(connection, auth.user):
                generation = verify_account_code(connection, auth.user["id"], payload.otp, database.mfa_secrets)
                if generation is None:
                    metrics.record("reauth_rejected")
                    return JSONResponse({"detail": "The verification details are incorrect."}, status_code=403)
                method = "totp"
            hashed = token_hash(read_session_token(request, cookie_name))
            if method == "totp":
                connection.execute("INSERT INTO session_mfa VALUES(?,?) ON CONFLICT(token_hash) "
                                   "DO UPDATE SET generation=excluded.generation", (hashed, generation))
            token, expiry, result = rotate_session(connection, hashed, now, method, database.identity_key)
            _release_success(connection, key, reserved)
            record_activity(connection, auth.user["name"], "Verified identity", "Own session")
            record_event(connection, "identity_verified", actor=auth.user["principal"], method=method)
        metrics.record("reauth_succeeded")
        set_rotated_cookie(response, origin, token, expiry)
        return result

    @app.post("/api/security/reauthenticate")
    async def reauthenticate(payload: Reauthentication, request: Request, response: Response):
        return await work.run(perform_verification, payload, request, response)

    @app.post("/api/security/sessions/{identifier}/revoke")
    def revoke(identifier: str, payload: Empty, request: Request):
        with authorized(request, csrf=True) as (connection, auth):
            hashed = token_hash(read_session_token(request, cookie_name))
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
            terminate_own_session(connection, "session_revoked", hashed=target["token_hash"],
                                  actor=auth.user["principal"])
            record_activity(connection, auth.user["name"], "Revoked session", "Own current session" if own else "Own other session")
            # Do not clear cookies in a delayed response: a newer login wins.
            return {"ok": True, "current_session_revoked": own}
