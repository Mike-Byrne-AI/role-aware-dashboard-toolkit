"""Password sessions and live toolkit authorization for this single-host trial.

The caller owns a BEGIN IMMEDIATE transaction spanning authentication, permission
checks, and the protected SQL operation. Nothing in this module commits. The
toolkit receives an identity only after a fresh server-side session lookup.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import re
import secrets
import sqlite3
import time

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from role_aware_dashboard_toolkit.access import (
    AccessDenied,
    AccessPolicy,
    Identity,
    principal_id,
)
from role_aware_dashboard_toolkit.access_store import (
    AccessStoreError,
    FreezeConflict,
    FreezeState,
)
from role_aware_dashboard_toolkit.security import RoleDef


COOKIE_NAME = "landscape_demo_session"
IDLE_SECONDS = 1800
ABSOLUTE_SECONDS = 28800
IDENTITY_ISSUER = "cedar-stone-landscaping-trial"

_PASSWORDS = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=1,
    hash_len=32, salt_len=16, type=Type.ID,
)
_DUMMY_HASH = _PASSWORDS.hash(secrets.token_urlsafe(32))
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_WORKER_PERMISSIONS = {
    "can_view_work": True,
    "can_signup": True,
    "can_view_messages": True,
    "can_post_messages": True,
}
ROLES = {
    "worker": RoleDef("worker", dict(_WORKER_PERMISSIONS)),
    "admin": RoleDef("admin", {
        **_WORKER_PERMISSIONS,
        "can_signup": False,
        "can_view_workers": True,
        "can_manage_users": True,
        "can_manage_jobs": True,
        "can_view_customers": True,
        "can_manage_customers": True,
        "can_view_health": True,
        "can_view_metrics": True,
        "can_manage_freeze": True,
    }),
}


class AuthError(Exception):
    """A deliberately safe HTTP-facing authentication/authorization failure."""

    def __init__(self, status_code: int, detail: str, *, code: str | None = None) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise ValueError("Passwords must contain 12 to 128 characters.")
    return _PASSWORDS.hash(password)


def verify_password(stored: str, password: str) -> bool:
    if not isinstance(password, str) or len(password) > 128:
        dummy_verify("")
        return False
    if not isinstance(stored, str) or not stored.startswith("$argon2id$"):
        dummy_verify(password)
        return False
    try:
        return bool(_PASSWORDS.verify(stored, password))
    except (InvalidHashError, VerificationError):
        return False


def dummy_verify(password: str) -> None:
    """Spend the same password-verification work for an unknown account."""
    candidate = password if isinstance(password, str) and len(password) <= 128 else ""
    try:
        _PASSWORDS.verify(_DUMMY_HASH, candidate)
    except (InvalidHashError, VerificationError):
        pass


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_for_token(token: str, identity_key: bytes) -> str:
    """Derive a CSRF synchronizer value without persisting the session bearer."""
    if not isinstance(identity_key, bytes) or len(identity_key) < 32:
        raise ValueError("Identity key must contain at least 32 bytes.")
    return hmac.new(
        identity_key, b"landscape-csrf-v1\x00" + token.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def principal_for_user(user_id: str, identity_key: bytes) -> str:
    """Provision the same opaque principal the toolkit derives at login."""
    return principal_id(Identity(IDENTITY_ISSUER, user_id, 253402300799), identity_key)


def _require_transaction(conn: sqlite3.Connection) -> None:
    if not conn.in_transaction:
        raise AccessStoreError()


def _one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> sqlite3.Row | None:
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    try:
        return cursor.execute(sql, params).fetchone()
    finally:
        cursor.close()


class TransactionAccessStore:
    """Toolkit store adapter over the host operation's existing transaction."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        _require_transaction(conn)
        self.conn = conn

    def read_grants(self, principal_id: str) -> tuple[str, ...]:
        _require_transaction(self.conn)
        user = _one(
            self.conn, "SELECT role FROM users WHERE principal = ? AND active = 1",
            (principal_id,),
        )
        if user is None or user["role"] not in ROLES:
            return ()
        return (user["role"],)

    def replace_grants(self, principal_id: str, roles: Iterable[str]) -> None:
        # Account provisioning has explicit validation in the trusted host.
        # This adapter deliberately offers no alternate elevation mechanism.
        raise AccessStoreError()

    def read_freeze(self) -> FreezeState:
        _require_transaction(self.conn)
        row = _one(self.conn, "SELECT frozen, freeze_revision, changed_by FROM settings WHERE id = 1")
        if (
            row is None or type(row["frozen"]) is not int or row["frozen"] not in (0, 1)
            or type(row["freeze_revision"]) is not int or row["freeze_revision"] < 0
        ):
            raise AccessStoreError()
        return FreezeState(bool(row["frozen"]), row["freeze_revision"], row["changed_by"])

    def compare_and_set_freeze(
        self, frozen: bool, expected_revision: int, changed_by: str,
    ) -> FreezeState:
        _require_transaction(self.conn)
        if (
            type(frozen) is not bool or type(expected_revision) is not int
            or expected_revision < 0 or not isinstance(changed_by, str) or not changed_by
        ):
            raise AccessStoreError()
        self.read_freeze()
        updated = self.conn.execute(
            "UPDATE settings SET frozen = ?, freeze_revision = freeze_revision + 1, "
            "changed_by = ? WHERE id = 1 AND freeze_revision = ?",
            (int(frozen), changed_by, expected_revision),
        )
        if updated.rowcount != 1:
            raise FreezeConflict()
        return self.read_freeze()


def _live_session(
    conn: sqlite3.Connection, hashed_token: str, identity_key: bytes, current: float,
) -> tuple[sqlite3.Row, sqlite3.Row, Identity]:
    _require_transaction(conn)
    session = _one(conn, "SELECT * FROM sessions WHERE token_hash = ?", (hashed_token,))
    if session is None:
        raise AuthError(401, "Please sign in again.")
    user = _one(conn, "SELECT * FROM users WHERE id = ?", (session["user_id"],))
    if user is None or user["active"] != 1 or user["role"] not in ROLES:
        raise AuthError(401, "Please sign in again.")
    timestamps = [session["created_at"], session["last_seen"], session["expires_at"]]
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in timestamps):
        raise AuthError(401, "Please sign in again.")
    expires = min(
        session["created_at"] + ABSOLUTE_SECONDS,
        session["last_seen"] + IDLE_SECONDS,
        session["expires_at"],
    )
    if current >= expires or session["created_at"] > current or session["last_seen"] < session["created_at"]:
        raise AuthError(401, "Please sign in again.")
    identity = Identity(IDENTITY_ISSUER, user["id"], expires)
    expected_principal = principal_id(identity, identity_key)
    if not isinstance(user["principal"], str) or not hmac.compare_digest(expected_principal, user["principal"]):
        raise AuthError(401, "Please sign in again.")
    return session, user, identity


@dataclass(frozen=True)
class AuthContext:
    user: sqlite3.Row = field(repr=False)
    token_hash: str = field(repr=False)
    csrf_token: str = field(repr=False)
    policy: AccessPolicy = field(repr=False)
    principal: str = field(repr=False)
    role: str

    def authorize(self, permission: str, *, write: bool = False) -> None:
        if not self.policy.authorize(self.principal, self.role, permission, ROLES, write=write):
            raise AuthError(403, "This action is not allowed.")

    def check_csrf(self, provided: str | None) -> None:
        try:
            principal = self.policy.identify()
        except AccessDenied:
            raise AuthError(401, "Please sign in again.") from None
        if (
            not hmac.compare_digest(principal, self.principal)
            or not isinstance(provided, str) or not provided.isascii()
            or not hmac.compare_digest(provided, self.csrf_token)
        ):
            raise AuthError(403, "Request verification failed. Refresh and try again.")

    def freeze(self) -> FreezeState:
        try:
            if not hmac.compare_digest(self.policy.identify(), self.principal):
                raise AccessDenied()
            return self.policy.store.read_freeze()
        except (AccessDenied, AccessStoreError):
            raise AuthError(403, "This action is not allowed.") from None


def authenticate(
    conn: sqlite3.Connection, token: str | None, identity_key: bytes, *, now: float | None = None,
) -> AuthContext:
    if not isinstance(token, str) or _TOKEN_PATTERN.fullmatch(token) is None:
        raise AuthError(401, "Please sign in again.")
    current = time.time() if now is None else now
    hashed = token_hash(token)
    session, user, _identity = _live_session(conn, hashed, identity_key, current)
    csrf = csrf_for_token(token, identity_key)
    if not isinstance(session["csrf_hash"], str) or not hmac.compare_digest(session["csrf_hash"], token_hash(csrf)):
        raise AuthError(401, "Please sign in again.")
    conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (current, hashed))

    def resolve_identity() -> Identity | None:
        # Every toolkit check returns to the live session and account records.
        # The same SQLite write transaction prevents a reset/revoke racing the
        # host mutation. Never resolve from browser roles or a cached grant.
        try:
            _, _, identity = _live_session(
                conn, hashed, identity_key, time.time() if now is None else now,
            )
            return identity
        except (AuthError, AccessStoreError, sqlite3.Error):
            return None

    policy = AccessPolicy(resolve_identity, TransactionAccessStore(conn), identity_key)
    return AuthContext(user, hashed, csrf, policy, user["principal"], user["role"])
