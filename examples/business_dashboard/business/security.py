"""Password sessions adapted to current toolkit identity, grants and freeze."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import math
import secrets
import sqlite3
import time

from fastapi import HTTPException
from role_aware_dashboard_toolkit.access import AccessPolicy, Identity, principal_id
from role_aware_dashboard_toolkit.access_store import AccessStoreError, FreezeConflict, FreezeState
from role_aware_dashboard_toolkit.security import RoleDef

COOKIE_NAME = "westbridge_session"
ISSUER = "westbridge-business-example"
PASSWORD_ITERATIONS = 600_000
SESSION_SECONDS = 8 * 60 * 60
IDLE_SECONDS = 30 * 60
EMPLOYEE_PERMISSIONS = {"can_view_team": True, "can_post_messages": True}
ROLES = {
    "employee": RoleDef("employee", EMPLOYEE_PERMISSIONS),
    "admin": RoleDef("admin", {**EMPLOYEE_PERMISSIONS, "can_manage_business": True, "can_manage_freeze": True}),
}


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise ValueError("Passwords must contain 12 to 128 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(stored: str, password: str) -> bool:
    try:
        method, count, salt, expected = stored.split("$")
        if method != "pbkdf2_sha256" or int(count) != PASSWORD_ITERATIONS or len(salt) != 32 or len(expected) != 64:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PASSWORD_ITERATIONS)
        return hmac.compare_digest(actual.hex(), expected)
    except (AttributeError, TypeError, ValueError):
        return False


def dummy_password_check(password: str) -> None:
    hashlib.pbkdf2_hmac("sha256", password.encode(), b"westbridge-dummy!", PASSWORD_ITERATIONS)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_for_token(token: str, key: bytes) -> str:
    return hmac.new(key, b"westbridge-csrf\0" + token.encode(), hashlib.sha256).hexdigest()


def principal_for_user(user_id: str, key: bytes) -> str:
    return principal_id(Identity(ISSUER, user_id, 253402300799), key)


class TransactionAccessStore:
    """Toolkit adapter that never escapes the host's authorization transaction."""

    def __init__(self, connection):
        self.connection = connection

    def _check(self):
        if not self.connection.in_transaction:
            raise AccessStoreError()

    def read_grants(self, principal_id):
        self._check()
        row = self.connection.execute("SELECT role FROM users WHERE principal=? AND active=1", (principal_id,)).fetchone()
        return (row["role"],) if row and row["role"] in ROLES else ()

    def replace_grants(self, principal_id, roles):
        raise AccessStoreError()

    def read_freeze(self):
        self._check()
        row = self.connection.execute("SELECT * FROM settings WHERE id=1").fetchone()
        if row is None or type(row["frozen"]) is not int or row["frozen"] not in (0, 1) or type(row["freeze_revision"]) is not int or row["freeze_revision"] < 0:
            raise AccessStoreError()
        return FreezeState(bool(row["frozen"]), row["freeze_revision"], row["changed_by"])

    def compare_and_set_freeze(self, frozen, expected_revision, changed_by):
        self._check()
        if type(frozen) is not bool or type(expected_revision) is not int or expected_revision < 0:
            raise AccessStoreError()
        self.read_freeze()
        result = self.connection.execute(
            "UPDATE settings SET frozen=?,freeze_revision=freeze_revision+1,changed_by=? WHERE id=1 AND freeze_revision=?",
            (int(frozen), changed_by, expected_revision),
        )
        if result.rowcount != 1:
            raise FreezeConflict()
        return self.read_freeze()


def _live(connection, hashed: str, key: bytes):
    if not connection.in_transaction:
        raise HTTPException(401, "Please sign in again.")
    session = connection.execute("SELECT * FROM sessions WHERE token_hash=?", (hashed,)).fetchone()
    if not session:
        raise HTTPException(401, "Please sign in again.")
    user = connection.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    now = time.time()
    times = [session["created_at"], session["last_seen"], session["expires_at"]]
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in times):
        raise HTTPException(401, "Please sign in again.")
    expiry = min(session["expires_at"], session["last_seen"] + IDLE_SECONDS, session["created_at"] + SESSION_SECONDS)
    if (not user or user["active"] != 1 or user["role"] not in ROLES or expiry <= now
            or session["created_at"] > now or session["last_seen"] > now
            or session["last_seen"] < session["created_at"]):
        raise HTTPException(401, "Please sign in again.")
    if user["role"] == "admin":
        attestation = connection.execute(
            "SELECT 1 FROM session_mfa s JOIN admin_mfa a ON a.user_id=? AND a.generation=s.generation WHERE s.token_hash=?",
            (user["id"], hashed),
        ).fetchone()
        if attestation is None:
            raise HTTPException(401, "Please sign in again.")
    identity = Identity(ISSUER, user["id"], expiry)
    if not hmac.compare_digest(user["principal"], principal_id(identity, key)):
        raise HTTPException(401, "Please sign in again.")
    return user, identity


@dataclass
class AuthContext:
    user: sqlite3.Row = field(repr=False)
    csrf: str = field(repr=False)
    policy: AccessPolicy = field(repr=False)

    def authorize(self, permission, *, write=False):
        if not self.policy.authorize(self.user["principal"], self.user["role"], permission, ROLES, write=write):
            raise HTTPException(403, "This action is not allowed. Check access and the editing pause.")

    def check_csrf(self, value):
        if not isinstance(value, str) or not value.isascii() or not hmac.compare_digest(self.csrf, value):
            raise HTTPException(403, "Request verification failed. Refresh and try again.")

    def session_payload(self):
        freeze = self.policy.store.read_freeze()
        return {"user": {key: self.user[key] for key in ("id", "username", "name", "role")},
                "csrf": self.csrf, "frozen": freeze.frozen, "freeze_revision": freeze.revision}


def authenticate(connection, token, key) -> AuthContext:
    if not isinstance(token, str) or len(token) != 43 or not token.isascii():
        raise HTTPException(401, "Please sign in again.")
    hashed = token_hash(token)
    user, _ = _live(connection, hashed, key)
    connection.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (time.time(), hashed))

    def resolve():
        try:
            return _live(connection, hashed, key)[1]
        except (HTTPException, sqlite3.Error):
            return None

    return AuthContext(user, csrf_for_token(token, key), AccessPolicy(resolve, TransactionAccessStore(connection), key))
