"""Private SQLite storage with one transaction per authorized operation."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import stat

from role_aware_dashboard_toolkit.access_store import AccessStoreError

SOURCE_ROOTS = {Path(__file__).absolute().parents[3], Path(__file__).resolve().parents[3]}
SCHEMA_V1 = """
CREATE TABLE users (
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','employee')),
 active INTEGER NOT NULL CHECK(active IN (0,1)), principal TEXT UNIQUE NOT NULL,
 revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0)
);
CREATE TABLE sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 created_at REAL NOT NULL, last_seen REAL NOT NULL, expires_at REAL NOT NULL
);
CREATE TABLE settings (
 id INTEGER PRIMARY KEY CHECK(id=1), frozen INTEGER NOT NULL CHECK(frozen IN (0,1)),
 freeze_revision INTEGER NOT NULL CHECK(freeze_revision>=0), changed_by TEXT
);
INSERT INTO settings VALUES (1,0,0,NULL);
CREATE TABLE events (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL,
 location TEXT NOT NULL, notes TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
 archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1))
);
CREATE TABLE assignments (
 event_id TEXT NOT NULL REFERENCES events(id), user_id TEXT NOT NULL REFERENCES users(id),
 PRIMARY KEY(event_id,user_id)
);
CREATE TABLE messages (
 id TEXT PRIMARY KEY, author_id TEXT NOT NULL REFERENCES users(id),
 body TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE contacts (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, company TEXT NOT NULL, email TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('New','Contacted','Proposal','Won')),
 value REAL NOT NULL CHECK(value>=0), notes TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE posts (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, category TEXT NOT NULL,
 published INTEGER NOT NULL CHECK(published IN (0,1)), published_at TEXT,
 revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE revenue (month TEXT PRIMARY KEY, revenue REAL NOT NULL, cost REAL NOT NULL);
CREATE TABLE activity (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
 target TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE login_limits (key_hash TEXT PRIMARY KEY, window_start REAL NOT NULL, attempts INTEGER NOT NULL);
PRAGMA user_version=1;
"""

SUBMISSION_SCHEMA = """
CREATE TABLE submissions (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
 submitted_at TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0),
 post_id TEXT UNIQUE REFERENCES posts(id),
 CHECK((status='approved' AND post_id IS NOT NULL) OR (status<>'approved' AND post_id IS NULL))
);
CREATE TABLE submission_limits (
 id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT NOT NULL, submitted_at REAL NOT NULL
);
CREATE INDEX submission_limits_time ON submission_limits(submitted_at);
CREATE INDEX submission_limits_address ON submission_limits(key_hash,submitted_at);
"""
SCHEMA_V2 = SCHEMA_V1 + SUBMISSION_SCHEMA + "PRAGMA user_version=2;\n"
MFA_SCHEMA = """
CREATE TABLE admin_mfa (
 user_id TEXT PRIMARY KEY REFERENCES users(id), secret TEXT NOT NULL,
 generation TEXT NOT NULL, last_counter INTEGER NOT NULL DEFAULT -1 CHECK(last_counter>=-1)
);
CREATE TABLE session_mfa (
 token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
 generation TEXT NOT NULL
);
"""
SCHEMA = SCHEMA_V2 + MFA_SCHEMA + "PRAGMA user_version=3;\n"


def _schema_objects(connection):
    return {
        (row["type"], row["name"], row["tbl_name"]): " ".join(row["sql"].split())
        for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
    }


def _require_schema(connection, version):
    """Compare every table, constraint, index and trigger before applying DDL."""
    expected = sqlite3.connect(":memory:")
    expected.row_factory = sqlite3.Row
    try:
        expected.executescript({1: SCHEMA_V1, 2: SCHEMA_V2, 3: SCHEMA}[version])
        if _schema_objects(connection) != _schema_objects(expected):
            raise ValueError("Business database schema is incomplete or unsupported; existing state was preserved.")
    finally:
        expected.close()
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ValueError("Business database contains inconsistent references; existing state was preserved.")


def _execute_schema(connection, schema):
    # executescript commits any current transaction first; execute each complete
    # trusted statement instead, so DDL and user_version roll back together.
    statement = ""
    for line in schema.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""


def _apply_submission_migration(connection):
    _execute_schema(connection, SUBMISSION_SCHEMA)
    connection.execute("PRAGMA user_version=2")


def _apply_mfa_migration(connection):
    _execute_schema(connection, MFA_SCHEMA)
    # A previously issued admin session proves only a password. Administrators
    # must enroll on the local host before signing in again; employee data and
    # sessions are preserved.
    connection.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE role='admin')")
    connection.execute("PRAGMA user_version=3")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_data_dir(value: str | Path, *, create: bool = False) -> Path:
    """Reject source storage and redirected paths; POSIX storage must be private."""
    directory = Path(os.path.abspath(Path(value).expanduser()))
    resolved = directory.resolve()
    for root in SOURCE_ROOTS:
        if any(item == root or root in item.parents for item in (directory, resolved)):
            raise ValueError("Keep runtime data and credentials outside the entire source tree.")
    for item in (directory, *directory.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("Runtime storage must not use symbolic links or junctions.")
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not directory.is_dir():
        raise ValueError("Storage is not provisioned. Run with --provision first.")
    info = directory.stat()
    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("Runtime directory must be owned by this user with mode 0700.")
    return directory


def check_private_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Runtime files must be regular files without links.")
    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("Runtime files must be owned by this user with mode 0600.")


def create_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


class Database:
    """Open existing initialized state only; never repair/reseed on startup."""

    def __init__(self, data_dir: str | Path):
        self.directory = validate_data_dir(data_dir)
        self.path = self.directory / "business.sqlite3"
        key_path = self.directory / "identity.key"
        try:
            check_private_file(self.path)
            check_private_file(key_path)
            self.identity_key = key_path.read_bytes()
        except OSError:
            raise ValueError("Storage is missing or incomplete; preserve it and investigate.") from None
        if len(self.identity_key) != 32:
            raise ValueError("Identity key is invalid; preserve the existing state.")
        try:
            self._validate_schema()
        except (sqlite3.Error, AccessStoreError):
            raise ValueError("Business database is invalid or incomplete; preserve it and investigate.") from None

    def _validate_schema(self):
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (1, 2, 3):
                raise ValueError("Unsupported or incomplete business database.")
            _require_schema(connection, version)
            from .security import TransactionAccessStore, principal_for_user
            TransactionAccessStore(connection).read_freeze()
            users = connection.execute("SELECT id,principal FROM users").fetchall()
            if not users or any(row["principal"] != principal_for_user(row["id"], self.identity_key) for row in users):
                raise ValueError("Database and identity key do not match.")
            if version == 1:
                _apply_submission_migration(connection)
                _require_schema(connection, 2)
            if version < 3:
                _apply_mfa_migration(connection)
                _require_schema(connection, 3)

    @contextmanager
    def transaction(self):
        validate_data_dir(self.directory)
        check_private_file(self.path)
        for suffix in ("-journal", "-wal", "-shm"):
            auxiliary = Path(str(self.path) + suffix)
            if auxiliary.exists() or auxiliary.is_symlink():
                check_private_file(auxiliary)
        connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


def record_activity(connection, actor: str, action: str, target: str) -> None:
    connection.execute(
        "INSERT INTO activity(actor,action,target,created_at) VALUES(?,?,?,?)",
        (actor, action, target, utc_now()),
    )
