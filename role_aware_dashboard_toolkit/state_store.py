"""Revisioned live control state for one application or tenant.

Values must be JSON-compatible with string object keys. Callers must exclude
secrets and sensitive controls; this is not a secret store. SQLite coordinates
processes on one host using a trusted local disk, not a network filesystem.
Protect the directory and backups with OS access controls, including Windows
ACLs. State commits do not include audit records or external host operations.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from ._json_safety import strict_json_loads
from .access_store import _has_extended_acl


_MAX_REVISION = 2**63 - 1
_SCHEMA = (
    "CREATE TABLE control_state (id INTEGER PRIMARY KEY CHECK (id = 1), "
    "revision INTEGER NOT NULL CHECK (revision >= 0), values_json TEXT NOT NULL)"
)


class StateStoreError(RuntimeError):
    """State storage is missing, invalid, busy, or otherwise unavailable."""

    def __init__(self) -> None:
        super().__init__("Control state storage is unavailable or invalid.")


class StateConflict(RuntimeError):
    """A writer used a revision that is no longer current; nothing was saved."""

    def __init__(self) -> None:
        super().__init__("Control state changed. Refresh before trying again.")


@dataclass(frozen=True)
class StateSnapshot:
    """A revision and detached JSON values; editing values cannot edit a store."""

    values: dict[str, Any] = field(repr=False)
    revision: int


class StateStore(Protocol):
    """Replace one complete state atomically, rejecting an outdated revision."""

    def read(self) -> StateSnapshot: ...

    def compare_and_set(
        self, values: Mapping[str, Any], expected_revision: int
    ) -> StateSnapshot: ...


def _encode_values(values: Mapping[str, Any]) -> str:
    def check_keys(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("Control state object keys must be strings.")
                check_keys(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                check_keys(item)

    if not isinstance(values, Mapping):
        raise ValueError("Control state must be a JSON object with string keys.")
    try:
        check_keys(values)
        return json.dumps(dict(values), allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError, OverflowError):
        raise ValueError("Control state must contain finite JSON values and string object keys.") from None


def _validate_expected_revision(revision: int) -> None:
    if type(revision) is not int or not 0 <= revision < _MAX_REVISION:
        raise ValueError("Expected state revision must be a nonnegative, incrementable integer.")


class InMemoryStateStore:
    """Thread-safe process-local state; restarting discards its values/revision."""

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        self._json = _encode_values({} if values is None else values)
        self._revision = 0
        self._lock = RLock()

    def read(self) -> StateSnapshot:
        with self._lock:
            return StateSnapshot(strict_json_loads(self._json), self._revision)

    def compare_and_set(
        self, values: Mapping[str, Any], expected_revision: int
    ) -> StateSnapshot:
        _validate_expected_revision(expected_revision)
        encoded = _encode_values(values)
        with self._lock:
            if expected_revision != self._revision:
                raise StateConflict()
            self._json = encoded
            self._revision += 1
            return StateSnapshot(strict_json_loads(self._json), self._revision)


class SQLiteStateStore:
    """Durable state with transactional revision checks on a local SQLite file.

    ``create`` exclusively initializes an absent path. Construction only opens
    an existing, valid database, and never resets missing or damaged state.
    Backups restore the saved values AND revision; stop writers and reconcile
    any external effects before making a restored database available again.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).absolute()
        self.read()

    @classmethod
    def create(
        cls, path: str | Path, *, values: Mapping[str, Any] | None = None
    ) -> SQLiteStateStore:
        encoded = _encode_values({} if values is None else values)
        target = Path(path).absolute()
        try:
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            with closing(sqlite3.connect(target.as_uri() + "?mode=rw", uri=True)) as connection:
                with connection:
                    connection.execute("PRAGMA trusted_schema = OFF")
                    connection.execute("PRAGMA synchronous = FULL")
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(_SCHEMA)
                    connection.execute("INSERT INTO control_state VALUES (1, 0, ?)", (encoded,))
                    connection.execute("PRAGMA user_version = 1")
        except (OSError, sqlite3.Error, ValueError):
            # Preserve a failed initialization for explicit operator repair.
            raise StateStoreError() from None
        return cls(target)

    @contextmanager
    def _connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            info = os.lstat(self._path)
            if not stat.S_ISREG(info.st_mode):
                raise StateStoreError()
            if os.name == "posix" and (
                info.st_mode & 0o077 or info.st_uid not in {os.geteuid(), 0}
            ):
                raise StateStoreError()
            if _has_extended_acl(self._path):
                raise StateStoreError()
            mode = "rw" if write else "ro"
            connection = sqlite3.connect(self._path.as_uri() + f"?mode={mode}", uri=True, timeout=5)
            connection.execute("PRAGMA trusted_schema = OFF")
            if write:
                connection.execute("PRAGMA synchronous = FULL")
            else:
                connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            self._validate_database(connection)
            yield connection
            connection.commit()
        except (OSError, sqlite3.Error, ValueError, RecursionError):
            raise StateStoreError() from None
        finally:
            if connection is not None:
                connection.close()  # also rolls back an unsuccessful transaction

    @staticmethod
    def _validate_database(connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone() != (1,):
            raise StateStoreError()
        objects = connection.execute(
            "SELECT name, type, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
        ).fetchmany(2)
        if objects != [("control_state", "table", _SCHEMA)]:
            raise StateStoreError()

    @staticmethod
    def _read_snapshot(connection: sqlite3.Connection) -> StateSnapshot:
        rows = connection.execute("SELECT id, revision, values_json FROM control_state").fetchmany(2)
        if len(rows) != 1:
            raise StateStoreError()
        identifier, revision, encoded = rows[0]
        if identifier != 1 or type(revision) is not int or not 0 <= revision <= _MAX_REVISION:
            raise StateStoreError()
        if not isinstance(encoded, str):
            raise StateStoreError()
        values = strict_json_loads(encoded)
        if not isinstance(values, dict):
            raise StateStoreError()
        return StateSnapshot(values, revision)

    def read(self) -> StateSnapshot:
        with self._connection() as connection:
            return self._read_snapshot(connection)

    def compare_and_set(
        self, values: Mapping[str, Any], expected_revision: int
    ) -> StateSnapshot:
        _validate_expected_revision(expected_revision)
        encoded = _encode_values(values)
        with self._connection(write=True) as connection:
            current = self._read_snapshot(connection)
            if expected_revision != current.revision:
                raise StateConflict()
            revision = current.revision + 1
            connection.execute(
                "UPDATE control_state SET revision = ?, values_json = ? WHERE id = 1",
                (revision, encoded),
            )
        return StateSnapshot(strict_json_loads(encoded), revision)


__all__ = [
    "InMemoryStateStore", "SQLiteStateStore", "StateConflict", "StateSnapshot",
    "StateStore", "StateStoreError",
]
