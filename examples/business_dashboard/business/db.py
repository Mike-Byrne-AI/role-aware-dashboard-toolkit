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
SCHEMA_V3 = SCHEMA_V2 + MFA_SCHEMA + "PRAGMA user_version=3;\n"
RECEIPT_SCHEMA = """
CREATE TABLE create_receipts (
 user_id TEXT NOT NULL REFERENCES users(id), endpoint TEXT NOT NULL,
 key_hash TEXT NOT NULL, request_hash TEXT NOT NULL, response_json TEXT NOT NULL,
 created_at REAL NOT NULL, PRIMARY KEY(user_id,endpoint,key_hash)
);
CREATE INDEX create_receipts_time ON create_receipts(created_at);
"""
SCHEMA_V4 = SCHEMA_V3 + RECEIPT_SCHEMA + "PRAGMA user_version=4;\n"
SECURITY_SCHEMA = """
ALTER TABLE admin_mfa RENAME COLUMN secret TO secret_ciphertext;
CREATE TABLE mfa_key_binding (
 id INTEGER PRIMARY KEY CHECK(id=1), ciphertext TEXT NOT NULL
);
CREATE TABLE session_security (
 token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
 public_id TEXT UNIQUE NOT NULL, verified_at REAL NOT NULL CHECK(verified_at>=0),
 method TEXT NOT NULL CHECK(method IN ('password','totp','passkey'))
);
CREATE TABLE passkey_credentials (
 credential_id BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 public_id TEXT UNIQUE NOT NULL, user_handle BLOB NOT NULL, public_key BLOB NOT NULL,
 sign_count INTEGER NOT NULL CHECK(sign_count>=0),
 backup_eligible INTEGER NOT NULL CHECK(backup_eligible IN (0,1)),
 backed_up INTEGER NOT NULL CHECK(backed_up IN (0,1)),
 name TEXT NOT NULL, created_at REAL NOT NULL, last_used_at REAL,
 revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0)
);
CREATE INDEX passkey_credentials_user ON passkey_credentials(user_id);
CREATE TABLE passkey_challenges (
 id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('register','login','reauth')),
 challenge BLOB NOT NULL, binding_hash TEXT NOT NULL,
 user_id TEXT REFERENCES users(id), user_revision INTEGER, created_at REAL NOT NULL,
 CHECK((purpose='login' AND user_id IS NULL AND user_revision IS NULL)
  OR (purpose<>'login' AND user_id IS NOT NULL AND user_revision IS NOT NULL))
);
CREATE INDEX passkey_challenges_time ON passkey_challenges(created_at);
CREATE UNIQUE INDEX passkey_challenges_binding ON passkey_challenges(purpose,binding_hash);
CREATE TABLE session_passkey (
 token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
 credential_id BLOB NOT NULL REFERENCES passkey_credentials(credential_id)
);
"""
SCHEMA_V5 = SCHEMA_V4 + SECURITY_SCHEMA + "PRAGMA user_version=5;\n"
SCHEMA = SCHEMA_V5


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
        expected.executescript({1: SCHEMA_V1, 2: SCHEMA_V2, 3: SCHEMA_V3, 4: SCHEMA_V4, 5: SCHEMA_V5}[version])
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


def _apply_receipt_migration(connection):
    _execute_schema(connection, RECEIPT_SCHEMA)
    connection.execute("PRAGMA user_version=4")


def _apply_security_migration(connection, secret_store):
    # All row conversion, DDL, binding and the schema version share the caller's
    # transaction. This is not secure erasure of old SQLite pages or backups.
    rows = connection.execute("SELECT * FROM admin_mfa").fetchall()
    encrypted = [
        (secret_store.encrypt(row["secret"], row["user_id"], row["generation"]), row["user_id"])
        for row in rows
    ]
    _execute_schema(connection, SECURITY_SCHEMA)
    connection.executemany("UPDATE admin_mfa SET secret_ciphertext=? WHERE user_id=?", encrypted)
    connection.execute("INSERT INTO mfa_key_binding VALUES(1,?)", (secret_store.create_binding(),))
    # Historical MFA established a login, not freshness for a new sensitive
    # operation. Existing sessions stay usable but must explicitly reverify.
    connection.execute(
        "INSERT INTO session_security SELECT s.token_hash,lower(hex(randomblob(16))),0,"
        "CASE WHEN m.token_hash IS NULL THEN 'password' ELSE 'totp' END "
        "FROM sessions s LEFT JOIN session_mfa m ON m.token_hash=s.token_hash"
    )
    secret_store.validate_database(connection)
    connection.execute("PRAGMA user_version=5")


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

    def __init__(self, data_dir: str | Path, *, mfa_key_file=None, migrate=False):
        self.directory = validate_data_dir(data_dir)
        if os.path.lexists(self.directory / "RESTORE_QUARANTINE"):
            raise ValueError("Restored storage is quarantined; reconcile current security state before serving it.")
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
        from .secret_store import SecretStore
        self.mfa_secrets = SecretStore(self.directory, self.identity_key, mfa_key_file)
        try:
            self._validate_schema(migrate=migrate)
        except (sqlite3.Error, AccessStoreError):
            raise ValueError("Business database is invalid or incomplete; preserve it and investigate.") from None

    def _validate_schema(self, *, migrate=False):
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (1, 2, 3, 4, 5):
                raise ValueError("Unsupported or incomplete business database.")
            _require_schema(connection, version)
            if version < 5 and not migrate:
                raise ValueError("Existing storage requires an explicit reviewed migration to schema five.")
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
            if version < 4:
                _apply_receipt_migration(connection)
                _require_schema(connection, 4)
            if version < 5:
                _apply_security_migration(connection, self.mfa_secrets)
                _require_schema(connection, 5)
            self.mfa_secrets.validate_database(connection)

    def _connect(self, *, readonly=False):
        validate_data_dir(self.directory)
        check_private_file(self.path)
        for suffix in ("-journal", "-wal", "-shm"):
            auxiliary = Path(str(self.path) + suffix)
            if auxiliary.exists() or auxiliary.is_symlink():
                check_private_file(auxiliary)
        mode = "ro" if readonly else "rw"
        connection = sqlite3.connect(self.path.as_uri() + "?mode=" + mode, uri=True, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def transaction(self):
        connection = self._connect()
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

    @contextmanager
    def readonly_snapshot(self):
        """Read coherent public state without reserving the database's writer.

        The first SELECT establishes the snapshot shared by subsequent reads.
        This context cannot update sessions or authorize a later mutation; those
        operations must retain the current-state checks in transaction().
        """
        connection = self._connect(readonly=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            yield connection
        finally:
            connection.close()


def record_activity(connection, actor: str, action: str, target: str) -> None:
    connection.execute(
        "INSERT INTO activity(actor,action,target,created_at) VALUES(?,?,?,?)",
        (actor, action, target, utc_now()),
    )
