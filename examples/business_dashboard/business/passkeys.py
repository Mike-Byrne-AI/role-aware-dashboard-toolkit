"""WebAuthn ceremonies verified by py_webauthn, with durable one-use challenges."""

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Annotated

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import StringConstraints
from webauthn import (
    base64url_to_bytes, generate_authentication_options, generate_registration_options,
    options_to_json, verify_authentication_response, verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria, CredentialDeviceType, PublicKeyCredentialDescriptor,
    ResidentKeyRequirement, UserVerificationRequirement,
)

from .auth_routes import _identity_state
from .db import record_activity
from .models import Empty, RequestModel
from .security import COOKIE_NAME, IDLE_SECONDS, ROLES, SESSION_SECONDS, authenticate, token_hash
from .session_state import record_verification, require_recent, verification_expiry
from .work_limits import BoundedWork

CHALLENGE_SECONDS = 120
MAX_LOGIN_CHALLENGES = 256
MAX_SESSION_CHALLENGES = 64
MAX_CREDENTIALS = 8
ALGORITHMS = [COSEAlgorithmIdentifier.ECDSA_SHA_256, COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256]
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
# Malformed CBOR arrays can escape the verifier's own exception hierarchy.
_INVALID = (WebAuthnException, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError, OverflowError)


class Ceremony(RequestModel):
    request_id: Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{32}$")]
    credential: dict


class Registration(Ceremony):
    name: Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=80)]


def current_time():
    return time.time()


def _user_handle(database, user_id):
    # Stable opaque WebAuthn account identifier, not a username or bearer token.
    return hmac.new(database.identity_key, b"westbridge-passkey-user\0" + user_id.encode(), hashlib.sha256).digest()


def preauth_cookie_name(origin):
    return "__Host-westbridge_passkey_preauth" if origin.scheme == "https" else "westbridge_passkey_preauth"


def _preauth_csrf(database, token):
    return hmac.new(database.identity_key, b"westbridge-passkey-preauth\0" + token.encode(), hashlib.sha256).hexdigest()


def _failed():
    return JSONResponse({"detail": "Passkey verification failed or expired. Start again."}, status_code=403)


def _public(row):
    return {
        "id": row["public_id"], "name": row["name"], "created_at": row["created_at"],
        "last_used_at": row["last_used_at"], "backup_eligible": bool(row["backup_eligible"]),
        "backed_up": bool(row["backed_up"]),
    }


def _issue(connection, purpose, binding, user=None, *, metrics=None):
    now = current_time()
    connection.execute("DELETE FROM passkey_challenges WHERE created_at<=? OR created_at>?",
                       (now - CHALLENGE_SECONDS, now))
    connection.execute("DELETE FROM passkey_challenges WHERE purpose=? AND binding_hash=?", (purpose, binding))
    if purpose == "login":
        count = connection.execute("SELECT COUNT(*) FROM passkey_challenges WHERE purpose='login'").fetchone()[0]
        capacity = MAX_LOGIN_CHALLENGES
    else:
        count = connection.execute("SELECT COUNT(*) FROM passkey_challenges WHERE purpose<>'login'").fetchone()[0]
        capacity = MAX_SESSION_CHALLENGES
    if count >= capacity:
        if metrics is not None:
            metrics.record("passkey_challenge_capacity_denied")
        raise HTTPException(429, "Passkey requests are temporarily busy. Try again shortly.",
                            headers={"Retry-After": str(CHALLENGE_SECONDS)})
    identifier, challenge = secrets.token_hex(16), secrets.token_bytes(32)
    connection.execute("INSERT INTO passkey_challenges VALUES(?,?,?,?,?,?,?)", (
        identifier, purpose, challenge, binding, user["id"] if user else None,
        user["revision"] if user else None, now,
    ))
    return identifier, challenge


def _take(connection, identifier, purpose, binding):
    row = connection.execute(
        "SELECT * FROM passkey_challenges WHERE id=? AND purpose=? AND binding_hash=?",
        (identifier, purpose, binding),
    ).fetchone()
    if row is None:
        return None
    # The caller commits this deletion before cryptographic work, including
    # unsuccessful attempts. A foreign cookie/session cannot consume the row.
    connection.execute("DELETE FROM passkey_challenges WHERE id=?", (identifier,))
    if not _challenge_current(row):
        return None
    return row


def _challenge_current(challenge):
    now = current_time()
    return now - CHALLENGE_SECONDS < challenge["created_at"] <= now


def _client_data(credential):
    data = json.loads(base64url_to_bytes(credential["response"]["clientDataJSON"]))
    if not isinstance(data, dict) or data.get("crossOrigin", False) is not False or "topOrigin" in data:
        raise ValueError("Cross-origin ceremonies are not supported.")


def _registration(credential, challenge, rp_id, origin):
    _client_data(credential)
    result = verify_registration_response(
        credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
        expected_origin=origin, require_user_verification=True, supported_pub_key_algs=ALGORITHMS,
    )
    if (result.credential_id != base64url_to_bytes(credential["rawId"])
            or not 1 <= len(result.credential_id) <= 1024 or len(result.credential_public_key) > 4096):
        raise ValueError("Invalid credential bounds.")
    return result


def _assertion(credential, challenge, stored, rp_id, origin, *, discoverable):
    _client_data(credential)
    handle = credential["response"].get("userHandle")
    if discoverable and not handle:
        raise ValueError("Discoverable authentication requires an account handle.")
    if handle is not None and not hmac.compare_digest(base64url_to_bytes(handle), stored["user_handle"]):
        raise ValueError("Credential account handle does not match.")
    result = verify_authentication_response(
        credential=credential, expected_challenge=challenge, expected_rp_id=rp_id, expected_origin=origin,
        credential_public_key=stored["public_key"],
        # Syncable credentials can have nonmonotonic or always-zero counters.
        # Fresh one-use challenges and signature/UV checks remain mandatory;
        # device-bound credentials retain the library's monotonic counter check.
        credential_current_sign_count=0 if stored["backup_eligible"] else stored["sign_count"],
        require_user_verification=True,
    )
    eligible = result.credential_device_type == CredentialDeviceType.MULTI_DEVICE
    if result.credential_id != stored["credential_id"] or eligible != bool(stored["backup_eligible"]):
        raise ValueError("Credential identity or backup eligibility changed.")
    return result


def _credential(connection, response):
    try:
        identifier = base64url_to_bytes(response["rawId"])
        if not 1 <= len(identifier) <= 1024:
            return None
    except _INVALID:
        return None
    return connection.execute("SELECT * FROM passkey_credentials WHERE credential_id=?", (identifier,)).fetchone()


def _advance(connection, stored, result):
    # Compare revision as well as counter: always-zero synced keys must not
    # silently overwrite a concurrent verification/removal decision.
    updated = connection.execute(
        "UPDATE passkey_credentials SET sign_count=?,backed_up=?,last_used_at=?,revision=revision+1 "
        "WHERE credential_id=? AND user_id=? AND public_key=? AND revision=?",
        (max(stored["sign_count"], result.new_sign_count), int(result.credential_backed_up), current_time(),
         stored["credential_id"], stored["user_id"], stored["public_key"], stored["revision"]),
    )
    return updated.rowcount == 1


def install_passkey_routes(app, database, authorized, origin, public_origin):
    rp_id = origin.hostname
    metrics = app.state.security_metrics
    options_work = BoundedWork(2, "Passkey options",
                              on_event=lambda event: metrics.record("passkey_options_" + event))
    verification_work = BoundedWork(2, "Passkey verification",
                                   on_event=lambda event: metrics.record("passkey_verification_" + event))

    def failed():
        metrics.record("passkey_rejected")
        return _failed()

    def options(payload, request, response, purpose):
        if purpose == "login":
            cookie = request.cookies.get(preauth_cookie_name(origin), "")
            if _TOKEN.fullmatch(cookie) is None:
                cookie = secrets.token_urlsafe(32)
            with database.transaction() as connection:
                identifier, challenge = _issue(connection, purpose, token_hash(cookie), metrics=metrics)
            generated = generate_authentication_options(
                rp_id=rp_id, challenge=challenge, timeout=CHALLENGE_SECONDS * 1000,
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            response.set_cookie(preauth_cookie_name(origin), cookie, max_age=CHALLENGE_SECONDS,
                                httponly=True, secure=origin.scheme == "https", samesite="strict", path="/")
            return {"request_id": identifier, "options": json.loads(options_to_json(generated)),
                    "expires_in": CHALLENGE_SECONDS, "csrf": _preauth_csrf(database, cookie)}
        with authorized(request, csrf=True) as (connection, auth):
            if purpose == "register":
                require_recent(connection, token_hash(request.cookies[COOKIE_NAME]))
            rows = connection.execute("SELECT * FROM passkey_credentials WHERE user_id=?", (auth.user["id"],)).fetchall()
            if purpose == "register" and len(rows) >= MAX_CREDENTIALS:
                metrics.record("passkey_credential_capacity_denied")
                raise HTTPException(409, "Remove an old passkey before adding another.")
            if purpose == "reauth" and not rows:
                raise HTTPException(409, "Add a passkey before using it to verify your identity.")
            identifier, challenge = _issue(connection, purpose, token_hash(request.cookies[COOKIE_NAME]), auth.user, metrics=metrics)
            descriptors = [PublicKeyCredentialDescriptor(id=row["credential_id"]) for row in rows]
            if purpose == "register":
                generated = generate_registration_options(
                    rp_id=rp_id, rp_name="Westbridge", user_name=auth.user["username"],
                    user_display_name=auth.user["name"], user_id=_user_handle(database, auth.user["id"]),
                    challenge=challenge, timeout=CHALLENGE_SECONDS * 1000, exclude_credentials=descriptors,
                    supported_pub_key_algs=ALGORITHMS,
                    authenticator_selection=AuthenticatorSelectionCriteria(
                        resident_key=ResidentKeyRequirement.REQUIRED, require_resident_key=True,
                        user_verification=UserVerificationRequirement.REQUIRED,
                    ),
                )
            else:
                generated = generate_authentication_options(
                    rp_id=rp_id, challenge=challenge, timeout=CHALLENGE_SECONDS * 1000,
                    allow_credentials=descriptors, user_verification=UserVerificationRequirement.REQUIRED,
                )
        return {"request_id": identifier, "options": json.loads(options_to_json(generated)), "expires_in": CHALLENGE_SECONDS}

    def register(payload, request):
        with authorized(request, csrf=True) as (connection, auth):
            hashed = token_hash(request.cookies[COOKIE_NAME])
            require_recent(connection, hashed)
            challenge = _take(connection, payload.request_id, "register", hashed)
            before = _identity_state(auth.user)
        if challenge is None or challenge["user_id"] != auth.user["id"] or challenge["user_revision"] != auth.user["revision"]:
            return failed()
        try:
            verified = _registration(payload.credential, challenge["challenge"], rp_id, public_origin)
        except _INVALID:
            return failed()
        with authorized(request, csrf=True) as (connection, auth):
            require_recent(connection, hashed)
            if _identity_state(auth.user) != before or not _challenge_current(challenge):
                return failed()
            count = connection.execute("SELECT COUNT(*) FROM passkey_credentials WHERE user_id=?", (auth.user["id"],)).fetchone()[0]
            if count >= MAX_CREDENTIALS:
                metrics.record("passkey_credential_capacity_denied")
                raise HTTPException(409, "Remove an old passkey before adding another.")
            if connection.execute("SELECT 1 FROM passkey_credentials WHERE credential_id=?", (verified.credential_id,)).fetchone():
                return failed()
            connection.execute("INSERT INTO passkey_credentials VALUES(?,?,?,?,?,?,?,?,?,?,NULL,0)", (
                verified.credential_id, auth.user["id"], secrets.token_hex(16), _user_handle(database, auth.user["id"]),
                verified.credential_public_key, verified.sign_count,
                int(verified.credential_device_type == CredentialDeviceType.MULTI_DEVICE),
                int(verified.credential_backed_up), payload.name, current_time(),
            ))
            row = connection.execute("SELECT * FROM passkey_credentials WHERE credential_id=?", (verified.credential_id,)).fetchone()
            record_activity(connection, auth.user["name"], "Added passkey", "Own account")
            result = {"ok": True, "passkey": _public(row)}
        metrics.record("passkey_registered")
        return result

    def verify(payload, request, response, purpose):
        if purpose == "login":
            cookie = request.cookies.get(preauth_cookie_name(origin), "")
            supplied = request.headers.get("x-passkey-csrf", "")
            if (_TOKEN.fullmatch(cookie) is None or not supplied.isascii()
                    or not hmac.compare_digest(supplied, _preauth_csrf(database, cookie))):
                return failed()
            with database.transaction() as connection:
                challenge = _take(connection, payload.request_id, purpose, token_hash(cookie))
                stored = _credential(connection, payload.credential) if challenge else None
                user = connection.execute("SELECT * FROM users WHERE id=?", (stored["user_id"],)).fetchone() if stored else None
                before = _identity_state(user) if user else None
        else:
            with authorized(request, csrf=True) as (connection, auth):
                challenge = _take(connection, payload.request_id, purpose, token_hash(request.cookies[COOKIE_NAME]))
                stored = _credential(connection, payload.credential) if challenge else None
                user, before = auth.user, _identity_state(auth.user)
        if (challenge is None or stored is None or user is None or user["active"] != 1 or user["role"] not in ROLES
                or stored["user_id"] != user["id"]
                or (purpose != "login" and (challenge["user_id"] != user["id"] or challenge["user_revision"] != user["revision"]))):
            return failed()
        try:
            verified = _assertion(payload.credential, challenge["challenge"], stored, rp_id, public_origin,
                                  discoverable=purpose == "login")
        except _INVALID:
            return failed()
        if purpose == "reauth":
            with authorized(request, csrf=True) as (connection, auth):
                if (_identity_state(auth.user) != before or not _challenge_current(challenge)
                        or not _advance(connection, stored, verified)):
                    return failed()
                hashed = token_hash(request.cookies[COOKIE_NAME])
                connection.execute("INSERT INTO session_passkey VALUES(?,?) ON CONFLICT(token_hash) "
                                   "DO UPDATE SET credential_id=excluded.credential_id", (hashed, stored["credential_id"]))
                record_verification(connection, hashed, current_time(), "passkey")
                record_activity(connection, auth.user["name"], "Verified identity with passkey", "Own session")
                result = {"ok": True, "verification_expires_at": verification_expiry(connection, hashed)}
            metrics.record("passkey_reauth_succeeded")
            return result
        with database.transaction() as connection:
            current = connection.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
            if (not current or _identity_state(current) != before or not _challenge_current(challenge)
                    or not _advance(connection, stored, verified)):
                return failed()
            now = current_time()
            connection.execute("DELETE FROM sessions WHERE expires_at<=? OR last_seen<?", (now, now - IDLE_SECONDS))
            old = request.cookies.get(COOKIE_NAME)
            if old:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(old),))
            connection.execute("DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions "
                               "WHERE user_id=? ORDER BY created_at DESC LIMIT -1 OFFSET 7)", (user["id"],))
            token = secrets.token_urlsafe(32)
            hashed = token_hash(token)
            connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (hashed, user["id"], now, now, now + SESSION_SECONDS))
            connection.execute("INSERT INTO session_passkey VALUES(?,?)", (hashed, stored["credential_id"]))
            record_verification(connection, hashed, now, "passkey")
            auth = authenticate(connection, token, database.identity_key)
            auth.authorize("can_view_team")
            result = auth.session_payload()
            record_activity(connection, user["name"], "Signed in with passkey", "Workspace")
        metrics.record("passkey_login_succeeded")
        response.set_cookie(COOKIE_NAME, token, max_age=SESSION_SECONDS, httponly=True,
                            secure=origin.scheme == "https", samesite="strict", path="/")
        return result

    @app.get("/api/security/passkeys")
    def list_credentials(request: Request):
        with authorized(request) as (connection, auth):
            rows = connection.execute("SELECT * FROM passkey_credentials WHERE user_id=? ORDER BY created_at,public_id", (auth.user["id"],))
            return {"passkeys": [_public(row) for row in rows], "max_credentials": MAX_CREDENTIALS, "rp_id": rp_id}

    @app.post("/api/security/passkeys/{identifier}/remove")
    def remove(identifier: str, payload: Empty, request: Request):
        with authorized(request, csrf=True) as (connection, auth):
            hashed = token_hash(request.cookies[COOKIE_NAME])
            require_recent(connection, hashed)
            row = connection.execute("SELECT credential_id FROM passkey_credentials WHERE public_id=? AND user_id=?",
                                     (identifier, auth.user["id"])).fetchone() if _ID.fullmatch(identifier) else None
            if row is None:
                raise HTTPException(404, "The passkey was not found.")
            own = connection.execute("SELECT 1 FROM session_passkey WHERE token_hash=? AND credential_id=?", (hashed, row[0])).fetchone() is not None
            connection.execute("DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM session_passkey WHERE credential_id=?)", (row[0],))
            connection.execute("DELETE FROM passkey_credentials WHERE credential_id=?", (row[0],))
            record_activity(connection, auth.user["name"], "Removed passkey", "Own account")
            result = {"ok": True, "current_session_revoked": own}
        metrics.record("passkey_removed")
        return result

    @app.post("/api/security/passkeys/register/options")
    async def register_options(payload: Empty, request: Request, response: Response):
        return await options_work.run(options, payload, request, response, "register")

    @app.post("/api/security/passkeys/register/verify")
    async def register_verify(payload: Registration, request: Request):
        return await verification_work.run(register, payload, request)

    @app.post("/api/security/passkeys/reauth/options")
    async def reauth_options(payload: Empty, request: Request, response: Response):
        return await options_work.run(options, payload, request, response, "reauth")

    @app.post("/api/security/passkeys/reauth/verify")
    async def reauth_verify(payload: Ceremony, request: Request, response: Response):
        return await verification_work.run(verify, payload, request, response, "reauth")

    @app.post("/api/passkeys/login/options")
    async def login_options(payload: Empty, request: Request, response: Response):
        return await options_work.run(options, payload, request, response, "login")

    @app.post("/api/passkeys/login/verify")
    async def login_verify(payload: Ceremony, request: Request, response: Response):
        return await verification_work.run(verify, payload, request, response, "login")
