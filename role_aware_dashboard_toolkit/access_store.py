"""Server-owned role grants and an application-wide freeze switch.

Store mutation methods are trusted operator APIs, never browser endpoints.
Only opaque principal IDs, role names, and freeze metadata are persisted.
SQLite is intended for a single application on one host, on a local disk.
Protect its directory and backups with deployment access controls. On POSIX,
new files use mode 0600; on Windows the operator must restrict the directory
ACL. Python's chmod does not establish equivalent Windows privacy.
"""

from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterable
from contextlib import closing, contextmanager
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from threading import RLock
from typing import Iterator, Protocol


class AccessStoreError(RuntimeError):
    """Storage failed closed; details may contain private deployment data."""

    def __init__(self) -> None:
        super().__init__("Access storage is unavailable or invalid.")


class FreezeConflict(RuntimeError):
    """Another session changed freeze state after the caller read it."""

    def __init__(self) -> None:
        super().__init__("Freeze state changed. Refresh before trying again.")


@dataclass(frozen=True)
class FreezeState:
    frozen: bool
    revision: int
    changed_by: str | None = None


class AccessStore(Protocol):
    def read_grants(self, principal_id: str) -> tuple[str, ...]: ...

    def replace_grants(self, principal_id: str, roles: Iterable[str]) -> None: ...

    def read_freeze(self) -> FreezeState: ...

    def compare_and_set_freeze(
        self, frozen: bool, expected_revision: int, changed_by: str
    ) -> FreezeState: ...


_DEFAULT_ROLES = ("Admin", "Operator", "Approver", "Auditor", "Viewer")
_PRINCIPAL = re.compile(r"[0-9a-f]{64}\Z")
_ROLE = re.compile(r"[A-Za-z][A-Za-z0-9 _.-]{0,63}\Z")
_MAX_REVISION = (1 << 63) - 2


def _validate_principal(principal_id: str) -> None:
    if not isinstance(principal_id, str) or not _PRINCIPAL.fullmatch(principal_id):
        raise AccessStoreError()


def _allowed_roles(roles: Iterable[str]) -> tuple[str, ...]:
    if isinstance(roles, (str, bytes)):
        raise AccessStoreError()
    try:
        result = tuple(islice(roles, 65))
        valid = (
            0 < len(result) <= 64
            and all(
                isinstance(role, str)
                and _ROLE.fullmatch(role)
                and role == role.strip()
                and role.casefold() != "unauthenticated"
                for role in result
            )
            and len(result) == len(set(result))
        )
    except Exception:
        raise AccessStoreError() from None
    if not valid:
        raise AccessStoreError()
    return result


def _validate_roles(roles: Iterable[str], allowed: tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(roles, (str, bytes)):
        raise AccessStoreError()
    try:
        result = tuple(islice(roles, len(allowed) + 1))
        valid = (
            len(result) <= len(allowed)
            and all(isinstance(role, str) and role in allowed for role in result)
            and len(result) == len(set(result))
        )
    except Exception:
        raise AccessStoreError() from None
    if not valid:
        raise AccessStoreError()
    return result


def _validate_freeze_arguments(frozen: bool, revision: int, changed_by: str) -> None:
    if type(frozen) is not bool or type(revision) is not int:
        raise AccessStoreError()
    if revision < 0 or revision >= _MAX_REVISION:
        raise AccessStoreError()
    _validate_principal(changed_by)


class InMemoryAccessStore:
    """Process-local store for testing; share one instance across sessions.

    Restarting discards grants and returns to frozen. Use SQLite for durable
    assignments and freeze shared by multiple worker processes.
    """

    def __init__(self, *, allowed_roles: Iterable[str] = _DEFAULT_ROLES) -> None:
        self._allowed = _allowed_roles(allowed_roles)
        self._grants: dict[str, tuple[str, ...]] = {}
        self._freeze = FreezeState(True, 0)
        self._lock = RLock()

    def read_grants(self, principal_id: str) -> tuple[str, ...]:
        _validate_principal(principal_id)
        with self._lock:
            return self._grants.get(principal_id, ())

    def replace_grants(self, principal_id: str, roles: Iterable[str]) -> None:
        _validate_principal(principal_id)
        valid_roles = _validate_roles(roles, self._allowed)
        with self._lock:
            if valid_roles:
                self._grants[principal_id] = valid_roles
            else:
                self._grants.pop(principal_id, None)

    def read_freeze(self) -> FreezeState:
        with self._lock:
            return self._freeze

    def compare_and_set_freeze(
        self, frozen: bool, expected_revision: int, changed_by: str
    ) -> FreezeState:
        _validate_freeze_arguments(frozen, expected_revision, changed_by)
        with self._lock:
            if self._freeze.revision != expected_revision:
                raise FreezeConflict()
            self._freeze = FreezeState(frozen, expected_revision + 1, changed_by)
            return self._freeze


_SCHEMA = {
    "grants": (
        "CREATE TABLE grants (principal_id TEXT NOT NULL, role TEXT NOT NULL, "
        "position INTEGER NOT NULL, PRIMARY KEY (principal_id, role))"
    ),
    "freeze_state": (
        "CREATE TABLE freeze_state (id INTEGER PRIMARY KEY CHECK (id = 1), "
        "frozen INTEGER NOT NULL CHECK (frozen IN (0, 1)), "
        "revision INTEGER NOT NULL CHECK (revision >= 0), changed_by TEXT)"
    ),
}


class SQLiteAccessStore:
    """Durable local access store; opening never creates or repairs a database.

    Use ``create`` once from a trusted provisioning step. A missing/corrupt
    store, unknown schema, or invalid row raises a fixed safe error. Restoring
    an old backup also restores its old grants/freeze: operators must review
    both before serving requests after recovery.
    """

    def __init__(
        self, path: str | Path, *, allowed_roles: Iterable[str] = _DEFAULT_ROLES
    ) -> None:
        self._allowed = _allowed_roles(allowed_roles)
        self._path = Path(path).absolute()
        # Validate now and on every subsequent connection. No cached grants.
        with self._connection():
            pass

    @classmethod
    def create(
        cls, path: str | Path, *, allowed_roles: Iterable[str] = _DEFAULT_ROLES
    ) -> SQLiteAccessStore:
        allowed = _allowed_roles(allowed_roles)
        target = Path(path).absolute()
        try:
            # Exclusive creation prevents accidental reset of live policy.
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with closing(sqlite3.connect(target.as_uri() + "?mode=rw", uri=True)) as connection:
                with connection:
                    connection.execute("PRAGMA trusted_schema = OFF")
                    for statement in _SCHEMA.values():
                        connection.execute(statement)
                    connection.execute("PRAGMA user_version = 1")
                    connection.execute(
                        "INSERT INTO freeze_state VALUES (1, 1, 0, NULL)"
                    )
        except (OSError, sqlite3.Error, ValueError):
            # A failed initialization remains invalid; never silently reseed.
            raise AccessStoreError() from None
        return cls(target, allowed_roles=allowed)

    @contextmanager
    def _connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            if self._path.is_symlink() or not self._path.is_file():
                raise AccessStoreError()
            if os.name == "posix" and self._path.stat().st_mode & 0o077:
                raise AccessStoreError()
            connection = sqlite3.connect(
                self._path.as_uri() + "?mode=rw", uri=True, timeout=5
            )
            connection.execute("PRAGMA trusted_schema = OFF")
            if write:
                connection.execute("PRAGMA secure_delete = ON")
            if not write:
                connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            self._validate_database(connection)
            yield connection
            connection.commit()
        except (OSError, sqlite3.Error, ValueError):
            raise AccessStoreError() from None
        finally:
            if connection is not None:
                connection.close()

    def _validate_database(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone() != (1,):
            raise AccessStoreError()
        objects = connection.execute(
            "SELECT name, type, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
        ).fetchmany(len(_SCHEMA) + 1)
        if len(objects) != len(_SCHEMA) or any(
            kind != "table" or name not in _SCHEMA or sql != _SCHEMA[name]
            for name, kind, sql in objects
        ):
            raise AccessStoreError()
        self._read_freeze(connection)

    @staticmethod
    def _read_freeze(connection: sqlite3.Connection) -> FreezeState:
        rows = connection.execute(
            "SELECT id, frozen, revision, changed_by FROM freeze_state"
        ).fetchmany(2)
        if len(rows) != 1:
            raise AccessStoreError()
        identifier, frozen, revision, changed_by = rows[0]
        if (
            identifier != 1
            or type(frozen) is not int
            or frozen not in (0, 1)
            or type(revision) is not int
            or not 0 <= revision <= _MAX_REVISION
        ):
            raise AccessStoreError()
        if changed_by is not None:
            _validate_principal(changed_by)
        return FreezeState(bool(frozen), revision, changed_by)

    def read_grants(self, principal_id: str) -> tuple[str, ...]:
        _validate_principal(principal_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT role, position FROM grants WHERE principal_id = ? "
                "ORDER BY position", (principal_id,)
            ).fetchmany(65)
        if len(rows) > 64 or [position for _, position in rows] != list(range(len(rows))):
            raise AccessStoreError()
        return _validate_roles((role for role, _ in rows), self._allowed)

    def replace_grants(self, principal_id: str, roles: Iterable[str]) -> None:
        _validate_principal(principal_id)
        valid_roles = _validate_roles(roles, self._allowed)
        with self._connection(write=True) as connection:
            connection.execute("DELETE FROM grants WHERE principal_id = ?", (principal_id,))
            connection.executemany(
                "INSERT INTO grants (principal_id, role, position) VALUES (?, ?, ?)",
                [(principal_id, role, index) for index, role in enumerate(valid_roles)],
            )

    def read_freeze(self) -> FreezeState:
        with self._connection() as connection:
            return self._read_freeze(connection)

    def compare_and_set_freeze(
        self, frozen: bool, expected_revision: int, changed_by: str
    ) -> FreezeState:
        _validate_freeze_arguments(frozen, expected_revision, changed_by)
        with self._connection(write=True) as connection:
            current = self._read_freeze(connection)
            if current.revision != expected_revision:
                raise FreezeConflict()
            connection.execute(
                "UPDATE freeze_state SET frozen = ?, revision = ?, changed_by = ? WHERE id = 1",
                (int(frozen), expected_revision + 1, changed_by),
            )
            return FreezeState(frozen, expected_revision + 1, changed_by)
