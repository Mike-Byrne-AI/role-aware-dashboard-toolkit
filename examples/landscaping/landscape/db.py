"""Private single-host storage; authorization and actions share a transaction."""

from __future__ import annotations

import os
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .paths import validate_data_dir


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','worker')),
 active INTEGER NOT NULL CHECK(active IN (0,1)), principal TEXT UNIQUE NOT NULL,
 created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 csrf_hash TEXT NOT NULL, created_at REAL NOT NULL, last_seen REAL NOT NULL,
 expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS settings (
 id INTEGER PRIMARY KEY CHECK(id=1), frozen INTEGER NOT NULL CHECK(frozen IN (0,1)),
 freeze_revision INTEGER NOT NULL CHECK(freeze_revision>=0), changed_by TEXT
);
INSERT OR IGNORE INTO settings VALUES (1,0,0,NULL);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, customer TEXT NOT NULL, site TEXT NOT NULL, service TEXT NOT NULL,
 starts_at TEXT NOT NULL, hours REAL NOT NULL CHECK(hours>0),
 pay REAL NOT NULL CHECK(pay>=0),
 capacity INTEGER NOT NULL DEFAULT 2 CHECK(typeof(capacity)='integer' AND capacity BETWEEN 1 AND 10),
 archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1)),
 revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revision)='integer' AND revision>=0),
 lifecycle TEXT NOT NULL DEFAULT 'scheduled' CHECK(lifecycle IN ('scheduled','completed','cancelled'))
);
CREATE INDEX IF NOT EXISTS jobs_start ON jobs(starts_at);
CREATE TABLE IF NOT EXISTS job_signups (
 job_id TEXT NOT NULL REFERENCES jobs(id), user_id TEXT NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL, PRIMARY KEY(job_id,user_id)
);
CREATE INDEX IF NOT EXISTS job_signups_user ON job_signups(user_id);
CREATE TABLE IF NOT EXISTS job_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES jobs(id),
 actor TEXT NOT NULL, action TEXT NOT NULL, reason TEXT NOT NULL,
 before_json TEXT NOT NULL, after_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS job_history_job ON job_history(job_id,id);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, author_id TEXT NOT NULL REFERENCES users(id),
 body TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, contact TEXT NOT NULL, service TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('Lead','Contacted','Booked','Completed')),
 value REAL NOT NULL CHECK(value>=0), notes TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
 actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_limits (
 key_hash TEXT PRIMARY KEY, window_start REAL NOT NULL, failures INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS telemetry (
 id INTEGER PRIMARY KEY CHECK(id=1), requests INTEGER NOT NULL,
 denied_requests INTEGER NOT NULL, failed_logins INTEGER NOT NULL
);
INSERT OR IGNORE INTO telemetry VALUES (1,0,0,0);
CREATE TABLE IF NOT EXISTS request_samples (
 id INTEGER PRIMARY KEY AUTOINCREMENT, milliseconds REAL NOT NULL
);
"""

SCHEMA_VERSION = 4
_LEGACY_JOB_COLUMNS = (
    "id", "owner_id", "customer", "site", "service", "starts_at", "hours", "pay",
    "status", "signed_by",
)
_SHARED_JOB_COLUMNS = (
    "id", "customer", "site", "service", "starts_at", "hours", "pay", "capacity",
)
_MANAGED_JOB_COLUMNS = (*_SHARED_JOB_COLUMNS, "archived", "revision")
_LIFECYCLE_JOB_COLUMNS = (*_MANAGED_JOB_COLUMNS, "lifecycle")


def _schema_statements(connection: sqlite3.Connection) -> None:
    """Execute the trusted schema without executescript's implicit commit."""
    statement = ""
    for line in SCHEMA.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    if statement.strip():
        raise ValueError("The database schema is incomplete.")


def _initialize_schema(connection: sqlite3.Connection) -> None:
    """Initialize or migrate within the caller's existing write transaction.

    Legacy assignment and status fields are retained verbatim in a private
    archive. The archive is never read after migration and is not a source of
    authorization or future enrollments. Signup timestamps use migration time
    because the legacy table did not record when someone signed up.
    """
    if not connection.in_transaction:
        raise ValueError("Schema initialization requires a write transaction.")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, 1, 2, 3, SCHEMA_VERSION):
        raise ValueError("The trial database schema version is not supported.")
    columns = tuple(row["name"] for row in connection.execute("PRAGMA table_info(jobs)"))
    legacy = columns == _LEGACY_JOB_COLUMNS
    if columns and not legacy and columns not in (_SHARED_JOB_COLUMNS, _MANAGED_JOB_COLUMNS, _LIFECYCLE_JOB_COLUMNS):
        raise ValueError("The trial jobs schema is not supported.")
    if version == 2 and columns != _SHARED_JOB_COLUMNS:
        raise ValueError("The shared schedule schema is incomplete.")
    if version == 3 and columns != _MANAGED_JOB_COLUMNS:
        raise ValueError("The managed schedule schema is incomplete.")
    if version == SCHEMA_VERSION and columns != _LIFECYCLE_JOB_COLUMNS:
        raise ValueError("The job lifecycle schema is incomplete.")
    if legacy:
        # A previous successful migration has neither a legacy jobs table nor
        # an opportunity to replay archived memberships. Any mixed state is
        # rejected instead of guessing and potentially restoring a cancellation.
        if connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type='table' "
            "AND name IN ('job_legacy_archive','job_signups') LIMIT 1"
        ).fetchone():
            raise ValueError("The legacy schedule has conflicting migration data.")
        connection.execute(
            "CREATE TABLE job_legacy_archive ("
            "id TEXT PRIMARY KEY, owner_id TEXT, customer TEXT, site TEXT, service TEXT, "
            "starts_at TEXT, hours REAL, pay REAL, status TEXT, signed_by TEXT)"
        )
        connection.execute("INSERT INTO job_legacy_archive SELECT * FROM jobs")
        connection.execute("DROP TABLE jobs")

    if columns == _SHARED_JOB_COLUMNS:
        # ALTER preserves the existing jobs, enrollment references and all
        # authentication data. Both additions commit together with the version.
        connection.execute(
            "ALTER TABLE jobs ADD COLUMN archived INTEGER NOT NULL DEFAULT 0 "
            "CHECK(archived IN (0,1))"
        )
        connection.execute(
            "ALTER TABLE jobs ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 "
            "CHECK(typeof(revision)='integer' AND revision>=0)"
        )

    if columns in (_SHARED_JOB_COLUMNS, _MANAGED_JOB_COLUMNS):
        connection.execute(
            "ALTER TABLE jobs ADD COLUMN lifecycle TEXT NOT NULL DEFAULT 'scheduled' "
            "CHECK(lifecycle IN ('scheduled','completed','cancelled'))"
        )

    _schema_statements(connection)

    if legacy:
        connection.execute(
            "INSERT INTO jobs(id,customer,site,service,starts_at,hours,pay,capacity) "
            "SELECT id,customer,site,service,starts_at,hours,pay,2 FROM job_legacy_archive"
        )
        connection.execute(
            "INSERT INTO job_signups(job_id,user_id,created_at) "
            "SELECT id,signed_by,? FROM job_legacy_archive WHERE signed_by IS NOT NULL",
            (utc_now(),),
        )
    signup_columns = tuple(row["name"] for row in connection.execute("PRAGMA table_info(job_signups)"))
    if signup_columns != ("job_id", "user_id", "created_at"):
        raise ValueError("The shared enrollment schema is not supported.")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ValueError("The trial database contains inconsistent references.")
    connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add_audit(conn, actor: str, action: str, target: str, outcome: str = "allowed") -> None:
    """Only call with trusted event names and non-secret account/record identifiers."""
    conn.execute(
        "INSERT INTO audit(created_at,actor,action,target,outcome) VALUES(?,?,?,?,?)",
        (utc_now(), actor, action, target, outcome),
    )


def _check_private(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("Trial storage must use a private directory and regular private files.")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError("Trial storage must be owned by the application user.")


class Database:
    def __init__(self, data_dir: str | Path):
        requested = validate_data_dir(data_dir)
        requested.mkdir(mode=0o700, parents=True, exist_ok=True)
        _check_private(requested, directory=True)
        self.directory = requested.resolve()
        self.path = self.directory / "landscape.sqlite3"
        key_path = self.directory / "identity.key"
        database_present = self.path.exists() or self.path.is_symlink()
        key_present = key_path.exists() or key_path.is_symlink()
        if database_present != key_present:
            raise ValueError("Existing storage is incomplete; preserve its original database and identity key.")
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            _check_private(key_path)
        else:
            with os.fdopen(fd, "wb") as key_file:
                key_file.write(secrets.token_bytes(32))
                key_file.flush()
                os.fsync(key_file.fileno())
        _check_private(key_path)
        self.identity_key = key_path.read_bytes()
        if len(self.identity_key) != 32:
            raise ValueError("Invalid private identity key.")
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            _check_private(self.path)
        else:
            os.close(fd)
        with self.transaction() as connection:
            _initialize_schema(connection)

    def connect(self):
        _check_private(self.path)
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=15000")
        return connection

    @contextmanager
    def transaction(self):
        connection = self.connect()
        try:
            # Serialize authorization, session revocation, freeze and effects on this host.
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_request(self, status: int, milliseconds: float, route: str) -> None:
        with self.transaction() as conn:
            denied = int(status in (401, 403, 429))
            conn.execute(
                "UPDATE telemetry SET requests=requests+1,denied_requests=denied_requests+? WHERE id=1",
                (denied,),
            )
            conn.execute("INSERT INTO request_samples(milliseconds) VALUES(?)", (milliseconds,))
            conn.execute("DELETE FROM request_samples WHERE id <= (SELECT COALESCE(MAX(id),0)-1000 FROM request_samples)")
            if denied:
                # Route templates only: never log request bodies, cookies, headers or query strings.
                add_audit(conn, "request", "request.denied", route[:120], "denied")


def rate_key(identity_key: bytes, category: str, value: str) -> str:
    import hashlib
    import hmac

    return hmac.new(identity_key, f"login-limit:{category}:{value}".encode(), hashlib.sha256).hexdigest()


def rate_blocked(conn, keys: list[tuple[str, int]], now: float) -> bool:
    for key, limit in keys:
        row = conn.execute("SELECT window_start,failures FROM login_limits WHERE key_hash=?", (key,)).fetchone()
        if row and now - row["window_start"] < 900 and row["failures"] >= limit:
            return True
    return False


def rate_failure(conn, keys: list[tuple[str, int]], now: float, *, login: bool = True) -> None:
    conn.execute("DELETE FROM login_limits WHERE window_start<?", (now - 900,))
    for key, _ in keys:
        conn.execute(
            "INSERT INTO login_limits(key_hash,window_start,failures) VALUES(?,?,1) "
            "ON CONFLICT(key_hash) DO UPDATE SET failures=failures+1",
            (key, now),
        )
    if login:
        conn.execute("UPDATE telemetry SET failed_logins=failed_logins+1 WHERE id=1")
