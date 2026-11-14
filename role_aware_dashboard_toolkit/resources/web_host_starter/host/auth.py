"""Local operator-issued access tokens. Replace this module for a verified IdP.

Tokens are high-entropy credentials, never passwords. Only digests are stored;
every request checks expiry and current grants inside the business transaction.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import time

from role_aware_dashboard_toolkit.access import AccessDenied, AccessPolicy, Identity, principal_id
from role_aware_dashboard_toolkit.access_store import AccessStoreError, FreezeConflict, FreezeState
from role_aware_dashboard_toolkit.security import RoleDef


ROLES = {
    "Viewer": RoleDef("Viewer", {"can_read_items": True}),
    "Operator": RoleDef("Operator", {"can_read_items": True, "can_edit_items": True}),
    "Manager": RoleDef("Manager", {
        "can_read_items": True, "can_edit_items": True, "can_create_items": True,
        "can_manage_freeze": True, "can_read_history": True,
    }),
}
ISSUER = "radt-local-web-host"


class AuthenticationRequired(RuntimeError):
    """A missing, revoked or expired bearer token."""


def subject_name(subject: str) -> str:
    if not isinstance(subject, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", subject):
        raise ValueError("Use a lowercase account ID with at most 64 letters, digits, _ or -.")
    return subject


class TransactionAccessStore:
    """AccessPolicy store adapter sharing the host's SQLite transaction."""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def _check(self):
        if not self.connection.in_transaction:
            raise AccessStoreError()

    def read_grants(self, principal: str) -> tuple[str, ...]:
        self._check()
        return tuple(row[0] for row in self.connection.execute(
            "SELECT role FROM grants WHERE principal = ?", (principal,)))

    def replace_grants(self, principal: str, roles) -> None:
        raise AccessStoreError()  # Use the trusted operator command.

    def read_freeze(self) -> FreezeState:
        self._check()
        row = self.connection.execute("SELECT * FROM freeze WHERE id = 1").fetchone()
        if row is None or row["frozen"] not in (0, 1) or row["revision"] < 0:
            raise AccessStoreError()
        return FreezeState(bool(row["frozen"]), row["revision"], row["changed_by"])

    def compare_and_set_freeze(self, frozen: bool, expected_revision: int,
                              changed_by: str) -> FreezeState:
        self._check()
        if (type(frozen) is not bool or type(expected_revision) is not int
                or not 0 <= expected_revision < 9223372036854775807):
            raise AccessStoreError()
        changed = self.connection.execute(
            "UPDATE freeze SET frozen = ?, revision = revision + 1, changed_by = ? "
            "WHERE id = 1 AND revision = ?", (int(frozen), changed_by, expected_revision))
        if changed.rowcount != 1:
            raise FreezeConflict()
        return self.read_freeze()


def grant(connection: sqlite3.Connection, key: bytes, subject: str, role: str | None) -> None:
    subject = subject_name(subject)
    if role is not None and role not in ROLES:
        raise ValueError("Choose Viewer, Operator or Manager.")
    principal = principal_id(Identity(ISSUER, subject, time.time() + 60), key)
    connection.execute("DELETE FROM grants WHERE principal = ?", (principal,))
    if role is not None:
        connection.execute("INSERT INTO grants VALUES (?, ?)", (principal, role))


def issue_token(connection: sqlite3.Connection, key: bytes, subject: str, role: str,
                *, lifetime: int = 3600) -> str:
    if type(lifetime) is not int or not 60 <= lifetime <= 86400:
        raise ValueError("Token lifetime must be 60 to 86400 seconds.")
    grant(connection, key, subject, role)
    token = secrets.token_urlsafe(32)
    connection.execute("DELETE FROM tokens WHERE expires_at <= ?", (time.time(),))
    connection.execute("INSERT INTO tokens VALUES (?, ?, ?)",
                       (hashlib.sha256(token.encode("ascii")).hexdigest(), subject, time.time() + lifetime))
    return token


def revoke(connection: sqlite3.Connection, key: bytes, subject: str) -> None:
    grant(connection, key, subject, None)
    connection.execute("DELETE FROM tokens WHERE subject = ?", (subject,))


class RequestActor:
    def __init__(self, connection: sqlite3.Connection, key: bytes, token: str):
        self.connection, self.key, self.token = connection, key, token
        identity = self.resolve()
        self.subject = identity.subject
        self.principal = principal_id(identity, key)
        self.store = TransactionAccessStore(connection)
        self.policy = AccessPolicy(self.resolve, self.store, key)
        roles = self.policy.assigned_roles(self.principal)
        if len(roles) != 1 or roles[0] not in ROLES:
            raise AccessDenied()
        self.role = roles[0]

    def resolve(self) -> Identity:
        if not isinstance(self.token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", self.token):
            raise AuthenticationRequired()
        row = self.connection.execute(
            "SELECT subject, expires_at FROM tokens WHERE digest = ?",
            (hashlib.sha256(self.token.encode("ascii")).hexdigest(),),
        ).fetchone()
        if row is None or row["expires_at"] <= time.time():
            raise AuthenticationRequired()
        return Identity(ISSUER, row["subject"], row["expires_at"])

    def require(self, permission: str, *, write: bool = False, owner: str | None = None) -> str:
        # An operator's edit authority applies only to records assigned to them.
        if owner is not None and self.role == "Operator" and owner != self.subject:
            raise AccessDenied()
        if not self.policy.authorize(self.principal, self.role, permission, ROLES, write=write):
            raise AccessDenied()
        return self.principal
