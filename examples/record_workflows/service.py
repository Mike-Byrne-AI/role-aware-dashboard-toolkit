"""Host-owned SQLite reference for two actions sharing one protected recipe.

Use synthetic data in a host-controlled local directory. This example is not a
login server, a production filesystem policy, or a distributed work scheduler.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid

from role_aware_dashboard_toolkit.access import AccessDenied, AccessPolicy, Identity, principal_id
from role_aware_dashboard_toolkit.access_store import AccessStoreError, FreezeConflict, FreezeState
from role_aware_dashboard_toolkit.security import RoleDef

from .actions import ActionValidation, ChangeResult, execute_change


ROLES = {
    "Viewer": RoleDef("Viewer", {"can_read_items": True}),
    "Operator": RoleDef("Operator", {"can_read_items": True, "can_edit_items": True}),
    "Manager": RoleDef("Manager", {
        "can_read_items": True, "can_edit_items": True, "can_manage_freeze": True,
    }),
}


@dataclass(frozen=True)
class WorkItemRules:
    """Trusted domain choices, never values accepted from a visitor request."""

    transitions: tuple[tuple[str, str], ...] = (
        ("scheduled", "completed"), ("scheduled", "cancelled"),
        ("completed", "scheduled"), ("cancelled", "scheduled"),
    )
    reason_required_for: frozenset[str] = frozenset({"cancelled"})
    reschedulable_states: frozenset[str] = frozenset({"scheduled"})


class _TransactionAccessStore:
    """AccessPolicy adapter that participates in the business transaction."""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def _check(self) -> None:
        if not self.connection.in_transaction:
            raise AccessStoreError()

    def read_grants(self, principal: str) -> tuple[str, ...]:
        self._check()
        rows = self.connection.execute(
            "SELECT role FROM grants WHERE principal = ? ORDER BY role", (principal,),
        ).fetchall()
        return tuple(row[0] for row in rows)

    def replace_grants(self, principal: str, roles: Iterable[str]) -> None:
        # Provisioning goes through the explicit trusted host method below.
        raise AccessStoreError()

    def read_freeze(self) -> FreezeState:
        self._check()
        row = self.connection.execute("SELECT * FROM freeze WHERE id = 1").fetchone()
        if row is None or row["frozen"] not in (0, 1) or row["revision"] < 0:
            raise AccessStoreError()
        return FreezeState(bool(row["frozen"]), row["revision"], row["changed_by"])

    def compare_and_set_freeze(
        self, frozen: bool, expected_revision: int, changed_by: str,
    ) -> FreezeState:
        self._check()
        if type(frozen) is not bool or type(expected_revision) is not int or expected_revision < 0:
            raise AccessStoreError()
        updated = self.connection.execute(
            "UPDATE freeze SET frozen = ?, revision = revision + 1, changed_by = ? "
            "WHERE id = 1 AND revision = ?", (int(frozen), changed_by, expected_revision),
        )
        if updated.rowcount != 1:
            raise FreezeConflict()
        return self.read_freeze()


class WorkSession:
    """Host-owned, actor-bound session; discard it at every login/logout boundary."""

    def __init__(self, owner: WorkItems, resolver: Callable[[], Identity | None], actor: str):
        self._owner = owner
        self._resolver = resolver
        self._actor = actor
        self._closed = False

    def close(self) -> None:
        self._closed = True


def _schedule(value: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ActionValidation("Supply an ISO date and time with its UTC offset.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OverflowError):
        raise ActionValidation("Supply an ISO date and time with its UTC offset.") from None


class WorkItems:
    """Durable single-host records, live authorization and audit in one database.

    Every service operation uses BEGIN IMMEDIATE, including grant and freeze
    changes. All cooperating processes must use this boundary and local disk.
    Keep the supplied identity key in trusted protected host configuration.
    """

    def __init__(self, path: Path, *, identity_key: bytes, rules: WorkItemRules | None = None):
        self._path = Path(path)
        self._identity_key = identity_key
        self._rules = rules or WorkItemRules()
        # Validate the key without contacting an identity provider.
        AccessPolicy(lambda: None, None, identity_key)
        with self._transaction() as connection:
            for statement in (
                "CREATE TABLE IF NOT EXISTS grants (principal TEXT NOT NULL, role TEXT NOT NULL, "
                "PRIMARY KEY (principal, role))",
                "CREATE TABLE IF NOT EXISTS freeze (id INTEGER PRIMARY KEY CHECK(id = 1), "
                "frozen INTEGER NOT NULL CHECK(frozen IN (0,1)), revision INTEGER NOT NULL, "
                "changed_by TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, label TEXT NOT NULL, "
                "starts_at TEXT NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL)",
                "CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, item_id TEXT NOT NULL "
                "REFERENCES items(id), action TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL, "
                "before_json TEXT NOT NULL, after_json TEXT NOT NULL)",
            ):
                connection.execute(statement)
            connection.execute("INSERT OR IGNORE INTO freeze VALUES (1, 1, 0, '')")

    @contextmanager
    def _transaction(self):
        connection = sqlite3.connect(self._path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def provision(self, identity: Identity, roles: Iterable[str]) -> None:
        """Trusted operator setup only; an empty role list revokes the account."""
        roles = tuple(roles)
        if len(set(roles)) != len(roles) or any(role not in ROLES for role in roles):
            raise ValueError("Choose distinct roles defined by the host.")
        actor = principal_id(identity, self._identity_key)
        with self._transaction() as connection:
            connection.execute("DELETE FROM grants WHERE principal = ?", (actor,))
            connection.executemany(
                "INSERT INTO grants VALUES (?, ?)", ((actor, role) for role in roles),
            )

    def open_session(self, resolver: Callable[[], Identity | None]) -> WorkSession:
        """Bind to a current verified account; constructing Identity is not verification."""
        with self._transaction() as connection:
            policy = AccessPolicy(resolver, _TransactionAccessStore(connection), self._identity_key)
            return WorkSession(self, resolver, policy.identify())

    def _policy(self, connection: sqlite3.Connection, session: WorkSession) -> AccessPolicy:
        if not isinstance(session, WorkSession) or session._owner is not self or session._closed:
            raise AccessDenied()
        return AccessPolicy(session._resolver, _TransactionAccessStore(connection), self._identity_key)

    def _authorizer(
        self, connection: sqlite3.Connection, session: WorkSession,
        role: str, permission: str, *, write: bool = False,
    ) -> Callable[[], str]:
        def authorize() -> str:
            policy = self._policy(connection, session)
            if not policy.authorize(session._actor, role, permission, ROLES, write=write):
                raise AccessDenied()
            return session._actor
        return authorize

    def create_item(self, *, label: str, starts_at: str) -> dict:
        """Trusted synthetic/operator fixture creation, not a visitor endpoint."""
        if not isinstance(label, str) or not label.strip() or len(label) > 120:
            raise ActionValidation("A label must contain 1 to 120 characters.")
        record = {"id": uuid.uuid4().hex, "label": label.strip(),
                  "starts_at": _schedule(starts_at), "status": "scheduled", "revision": 0}
        with self._transaction() as connection:
            connection.execute("INSERT INTO items VALUES (?, ?, ?, ?, ?)", tuple(record.values()))
        return record

    @staticmethod
    def _load(connection: sqlite3.Connection, item_id: str) -> dict:
        row = connection.execute(
            "SELECT id, label, starts_at, status, revision FROM items WHERE id = ?", (item_id,),
        ).fetchone()
        if row is None:
            raise ActionValidation("The requested item does not exist.")
        # Explicit business-field selection: no provider claims, tokens or secrets.
        return dict(row)

    def read(self, session: WorkSession, role: str, item_id: str) -> dict:
        with self._transaction() as connection:
            self._authorizer(connection, session, role, "can_read_items")()
            return self._load(connection, item_id)

    def _change(
        self, session: WorkSession, role: str, item_id: str, *, expected_revision: int,
        action: str, propose: Callable[[dict], dict], reason: str, require_reason: bool = False,
    ) -> ChangeResult:
        with self._transaction() as connection:
            def save(record, revision):
                return connection.execute(
                    "UPDATE items SET starts_at = ?, status = ?, revision = ? "
                    "WHERE id = ? AND revision = ?",
                    (record["starts_at"], record["status"], record["revision"], item_id, revision),
                ).rowcount == 1

            def audit(result):
                connection.execute(
                    "INSERT INTO history (item_id, action, actor, reason, before_json, after_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (item_id, action, result.actor, result.reason,
                     json.dumps(result.before, sort_keys=True), json.dumps(result.after, sort_keys=True)),
                )

            return execute_change(
                connection=connection, expected_revision=expected_revision,
                authorize=self._authorizer(connection, session, role, "can_edit_items", write=True),
                load=lambda: self._load(connection, item_id), propose=propose, save=save,
                audit=audit, reason=reason, require_reason=require_reason,
            )

    def reschedule(
        self, session: WorkSession, role: str, item_id: str, *, expected_revision: int,
        starts_at: str, reason: str = "",
    ) -> ChangeResult:
        def propose(record):
            if record["status"] not in self._rules.reschedulable_states:
                raise ActionValidation("Reopen this item before rescheduling it.")
            return {"starts_at": _schedule(starts_at)}
        return self._change(
            session, role, item_id, expected_revision=expected_revision,
            action="rescheduled", propose=propose, reason=reason,
        )

    def change_status(
        self, session: WorkSession, role: str, item_id: str, *, expected_revision: int,
        status: str, reason: str = "",
    ) -> ChangeResult:
        def propose(record):
            if not isinstance(status, str):
                raise ActionValidation("Choose a supported status.")
            if record["status"] != status and (record["status"], status) not in self._rules.transitions:
                raise ActionValidation("This status change is not allowed.")
            return {"status": status}
        return self._change(
            session, role, item_id, expected_revision=expected_revision,
            action="status_changed", propose=propose, reason=reason,
            require_reason=isinstance(status, str) and status in self._rules.reason_required_for,
        )

    def freeze_state(self, session: WorkSession, role: str) -> FreezeState:
        with self._transaction() as connection:
            self._authorizer(connection, session, role, "can_read_items")()
            return _TransactionAccessStore(connection).read_freeze()

    def change_freeze(
        self, session: WorkSession, role: str, frozen: bool, expected_revision: int,
    ) -> FreezeState:
        with self._transaction() as connection:
            self._authorizer(connection, session, role, "can_manage_freeze")()
            return self._policy(connection, session).change_freeze(
                session._actor, role, frozen, expected_revision, ROLES,
            )

    def audit_events(self, session: WorkSession, role: str) -> tuple[dict, ...]:
        with self._transaction() as connection:
            self._authorizer(connection, session, role, "can_manage_freeze")()
            rows = connection.execute("SELECT * FROM history ORDER BY id").fetchall()
            return tuple({
                "id": row["id"], "item_id": row["item_id"], "action": row["action"],
                "actor": row["actor"], "reason": row["reason"],
                "before": json.loads(row["before_json"]), "after": json.loads(row["after_json"]),
            } for row in rows)
