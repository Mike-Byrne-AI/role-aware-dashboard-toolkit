"""Account-scoped authentication limits and session lifecycle operations."""

import hashlib
import hmac
import logging
import secrets
import time

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .db import record_activity
from .mfa import verify_admin_code
from .models import Login, PasswordChange
from .security import (
    COOKIE_NAME, ROLES, SESSION_SECONDS, authenticate, dummy_password_check,
    hash_password, token_hash, verify_password,
)
from .work_limits import BoundedWork

ATTEMPT_LIMIT = 8
ATTEMPT_WINDOW_SECONDS = 300
LOGGER = logging.getLogger(__name__)


def current_time():
    """Keep the limit clock independently controllable in regression tests."""
    return time.time()


def _limit_key(database, namespace, subject):
    return hmac.new(
        database.identity_key, (namespace + ":" + subject).encode(), hashlib.sha256,
    ).hexdigest()


def _reserve(connection, key, now):
    row = connection.execute(
        "SELECT window_start,attempts FROM login_limits WHERE key_hash=?", (key,),
    ).fetchone()
    if row and row["window_start"] <= now - ATTEMPT_WINDOW_SECONDS:
        # Only expire this namespace's key: other routes can share this table.
        connection.execute("DELETE FROM login_limits WHERE key_hash=?", (key,))
        row = None
    if row and row["attempts"] >= ATTEMPT_LIMIT:
        return None
    connection.execute(
        "INSERT INTO login_limits VALUES(?,?,1) "
        "ON CONFLICT(key_hash) DO UPDATE SET attempts=attempts+1", (key, now),
    )
    if row and row["attempts"] == ATTEMPT_LIMIT - 1:
        LOGGER.warning("An authentication attempt budget reached its capacity.")
    return row["window_start"] if row else now


def _reservation_valid(connection, key, reserved_window, now):
    row = connection.execute(
        "SELECT window_start,attempts FROM login_limits WHERE key_hash=?", (key,),
    ).fetchone()
    return bool(
        row and row["window_start"] == reserved_window and row["attempts"] > 0
        and now < reserved_window + ATTEMPT_WINDOW_SECONDS
    )


def _release_success(connection, key, reserved_window):
    # A concurrent failure remains charged, including one still doing its KDF.
    # A completion from an old window must never reduce a new window's budget.
    connection.execute(
        "UPDATE login_limits SET attempts=attempts-1 "
        "WHERE key_hash=? AND window_start=? AND attempts>0", (key, reserved_window),
    )
    connection.execute(
        "DELETE FROM login_limits WHERE key_hash=? AND window_start=? AND attempts=0",
        (key, reserved_window),
    )


def _identity_state(user):
    return tuple(user[key] for key in ("id", "password_hash", "role", "active", "principal", "revision"))


def _mfa_generation(connection, user):
    if user["role"] != "admin":
        return None
    row = connection.execute("SELECT generation FROM admin_mfa WHERE user_id=?", (user["id"],)).fetchone()
    return row["generation"] if row else None


def _limit_response(action):
    return JSONResponse(
        {"detail": f"Too many {action} attempts. Please wait five minutes."},
        status_code=429, headers={"Retry-After": str(ATTEMPT_WINDOW_SECONDS)},
    )


def install_auth_routes(app, database, authorized, origin):
    """Register login and password routes using the host's transaction boundary."""
    work = BoundedWork(2, "Authentication")

    def perform_login(payload, request, response):
        username = payload.username.casefold()
        now = current_time()
        with database.transaction() as connection:
            user = connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            # Keep the original account namespace so an upgrade cannot reset
            # existing limits. Shared proxy/NAT peers are not account identity;
            # neither their failure history nor caller-supplied forwarding
            # headers may deny an unrelated user's sign-in.
            key = _limit_key(database, "account", username)
            reserved_window = _reserve(connection, key, now) if user else None
            if user and reserved_window is None:
                return _limit_response("sign-in")
            generation_before = _mfa_generation(connection, user) if user else None
        # Reserve before expensive work, then release the SQLite write lock.
        # Crashes/failures keep their durable charge until the window expires.
        if not user:
            # No attacker-chosen persistent buckets for nonexistent identities.
            dummy_password_check(payload.password)
        valid = verify_password(user["password_hash"], payload.password) if user else False
        if not valid or user["active"] != 1 or user["role"] not in ROLES:
            return JSONResponse({"detail": "The sign-in details are incorrect."}, status_code=401)
        with database.transaction() as connection:
            current = connection.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
            if (not current or _identity_state(current) != _identity_state(user)
                    or _mfa_generation(connection, current) != generation_before):
                return JSONResponse({"detail": "The sign-in details are incorrect."}, status_code=401)
            now = current_time()
            if not _reservation_valid(connection, key, reserved_window, now):
                return _limit_response("sign-in")
            generation = None
            if current["role"] == "admin":
                generation = verify_admin_code(connection, current["id"], payload.otp)
                if generation is None:
                    return JSONResponse({"detail": "The sign-in details are incorrect."}, status_code=401)
            session_now = time.time()
            connection.execute(
                "DELETE FROM sessions WHERE expires_at<=? OR last_seen<?",
                (session_now, session_now - 1800),
            )
            old = request.cookies.get(COOKIE_NAME)
            if old:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(old),))
            connection.execute(
                "DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions "
                "WHERE user_id=? ORDER BY created_at DESC LIMIT -1 OFFSET 7)", (user["id"],),
            )
            token = secrets.token_urlsafe(32)
            connection.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?)",
                (token_hash(token), user["id"], session_now, session_now, session_now + SESSION_SECONDS),
            )
            if generation:
                connection.execute("INSERT INTO session_mfa VALUES(?,?)", (token_hash(token), generation))
            auth = authenticate(connection, token, database.identity_key)
            auth.authorize("can_view_team")
            record_activity(connection, user["name"], "Signed in", "Workspace")
            result = auth.session_payload()
            _release_success(connection, key, reserved_window)
        response.set_cookie(
            COOKIE_NAME, token, max_age=SESSION_SECONDS, httponly=True,
            secure=origin.scheme == "https", samesite="strict", path="/",
        )
        return result

    def perform_password(payload, request, response):
        with authorized(request, csrf=True) as (connection, auth):
            now = current_time()
            key = _limit_key(database, "password-change", auth.user["id"])
            reserved_window = _reserve(connection, key, now)
            if reserved_window is None:
                return _limit_response("password-change")
            before = _identity_state(auth.user)
            stored_password = auth.user["password_hash"]
        if not verify_password(stored_password, payload.current_password):
            return JSONResponse({"detail": "The current password is incorrect."}, status_code=403)
        replacement = hash_password(payload.new_password)
        with authorized(request, csrf=True) as (connection, auth):
            # Revocation, role/credential changes and session rotation during
            # password work must be rechecked before the write can take place.
            if _identity_state(auth.user) != before:
                raise HTTPException(409, "The account changed. Refresh before trying again.")
            if not _reservation_valid(connection, key, reserved_window, current_time()):
                return _limit_response("password-change")
            connection.execute(
                "UPDATE users SET password_hash=?,revision=revision+1 WHERE id=?",
                (replacement, auth.user["id"]),
            )
            connection.execute("DELETE FROM sessions WHERE user_id=?", (auth.user["id"],))
            _release_success(connection, key, reserved_window)
            record_activity(connection, auth.user["name"], "Changed password", "Own account")
        response.delete_cookie(
            COOKIE_NAME, path="/", secure=origin.scheme == "https", httponly=True, samesite="strict",
        )
        return {"ok": True}

    @app.post("/api/login")
    async def login(payload: Login, request: Request, response: Response):
        return await work.run(perform_login, payload, request, response)

    @app.post("/api/password")
    async def password(payload: PasswordChange, request: Request, response: Response):
        return await work.run(perform_password, payload, request, response)
