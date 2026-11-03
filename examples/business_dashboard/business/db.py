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


class RuntimeKeyError(ValueError, AccessStoreError):
    """A previously opened worker can no longer prove current key custody."""

    def __init__(self, message: str) -> None:
        # AccessStoreError's initializer takes no message. Initialize the shared
        # exception base explicitly so both catch contracts work on every Python.
        Exception.__init__(self, message)


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
EVENT_SCHEMA = """
CREATE TABLE security_events (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
 occurred_at REAL NOT NULL, code TEXT NOT NULL, outcome TEXT NOT NULL,
 reason TEXT NOT NULL, actor TEXT, target TEXT, method TEXT NOT NULL
);
CREATE INDEX security_events_time ON security_events(occurred_at);
CREATE TABLE security_outbox (
 event_id TEXT PRIMARY KEY REFERENCES security_events(id) ON DELETE CASCADE,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
 next_attempt_at REAL NOT NULL DEFAULT 0, delivered_at REAL,
 last_error TEXT CHECK(last_error IS NULL OR last_error='delivery_failed')
);
CREATE INDEX security_outbox_pending ON security_outbox(delivered_at,next_attempt_at);
CREATE TABLE security_sink_receipts (
 event_id TEXT PRIMARY KEY REFERENCES security_events(id) ON DELETE CASCADE,
 received_at REAL NOT NULL, payload_json TEXT NOT NULL
);
CREATE TABLE security_denial_budget (
 id INTEGER PRIMARY KEY CHECK(id=1), window INTEGER NOT NULL,
 admitted INTEGER NOT NULL CHECK(admitted>=0)
);
"""
SCHEMA_V6 = SCHEMA_V5 + EVENT_SCHEMA + "PRAGMA user_version=6;\n"
SESSION_PREDECESSOR_SCHEMA = """
CREATE TABLE session_predecessors (
 predecessor_hash TEXT PRIMARY KEY, public_id TEXT NOT NULL, expires_at REAL NOT NULL
);
CREATE INDEX session_predecessors_public_id ON session_predecessors(public_id);
"""
SCHEMA_V7 = SCHEMA_V6 + SESSION_PREDECESSOR_SCHEMA + "PRAGMA user_version=7;\n"
ENROLLMENT_SCHEMA = """
ALTER TABLE admin_mfa RENAME TO account_mfa;
CREATE TABLE account_security (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 lifecycle TEXT NOT NULL CHECK(lifecycle IN ('legacy','pending','active')),
 revision INTEGER NOT NULL CHECK(revision>=0), completed_at REAL,
 retired_password_hash TEXT
);
CREATE TABLE authentication_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 mode TEXT NOT NULL CHECK(mode IN ('transition','strict')),
 revision INTEGER NOT NULL CHECK(revision>=0)
);
INSERT INTO authentication_policy VALUES(1,'strict',0);
CREATE TABLE enrollment_grants (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 secret_hash TEXT UNIQUE NOT NULL,
 purpose TEXT NOT NULL CHECK(purpose IN ('initial','migration','recovery')),
 user_revision INTEGER NOT NULL CHECK(user_revision>=0),
 security_revision INTEGER NOT NULL CHECK(security_revision>=0),
 created_at REAL NOT NULL, expires_at REAL NOT NULL, claimed_at REAL,
 case_reference TEXT,
 CHECK(purpose<>'recovery' OR case_reference IS NOT NULL)
);
CREATE TABLE enrollment_decisions (
 event_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 purpose TEXT NOT NULL CHECK(purpose IN ('initial','migration','recovery')),
 case_reference TEXT, occurred_at REAL NOT NULL,
 CHECK(purpose<>'recovery' OR case_reference IS NOT NULL)
);
CREATE TABLE enrollment_sessions (
 token_hash TEXT PRIMARY KEY,
 user_id TEXT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 grant_hash TEXT NOT NULL,
 user_revision INTEGER NOT NULL CHECK(user_revision>=0),
 security_revision INTEGER NOT NULL CHECK(security_revision>=0),
 created_at REAL NOT NULL, expires_at REAL NOT NULL,
 secret_ciphertext TEXT NOT NULL, generation TEXT NOT NULL
);
"""
SCHEMA_V8 = SCHEMA_V7 + ENROLLMENT_SCHEMA + "PRAGMA user_version=8;\n"
DELIVERY_SCHEMA = """
CREATE TABLE security_delivery_identity (
 id INTEGER PRIMARY KEY CHECK(id=1),
 source_id TEXT UNIQUE NOT NULL CHECK(length(source_id)=32 AND source_id NOT GLOB '*[^0-9a-f]*'),
 heartbeat_sequence INTEGER NOT NULL CHECK(typeof(heartbeat_sequence)='integer' AND heartbeat_sequence>=0)
);
INSERT INTO security_delivery_identity VALUES(1,lower(hex(randomblob(16))),0);
CREATE TABLE security_destinations (
 destination_id TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('local','https')),
 state TEXT NOT NULL CHECK(state IN ('active','retired')),
 collector_id TEXT, endpoint TEXT,
 config_revision INTEGER NOT NULL CHECK(typeof(config_revision)='integer' AND config_revision>=0),
 enabled_at REAL NOT NULL CHECK(enabled_at>=0 AND enabled_at<=253402300799.0),
 backfill_cutoff_sequence INTEGER NOT NULL CHECK(typeof(backfill_cutoff_sequence)='integer' AND backfill_cutoff_sequence>=0),
 backfill_retained_count INTEGER NOT NULL CHECK(typeof(backfill_retained_count)='integer' AND backfill_retained_count>=0),
 CHECK((kind='local' AND destination_id='local-v1' AND state='active' AND collector_id IS NULL AND endpoint IS NULL AND config_revision=0)
  OR (kind='https' AND length(destination_id)=32 AND destination_id NOT GLOB '*[^0-9a-f]*'
   AND length(collector_id)=32 AND collector_id NOT GLOB '*[^0-9a-f]*' AND collector_id IS NOT NULL
   AND endpoint IS NOT NULL AND length(endpoint)<=2048 AND config_revision>0))
);
INSERT INTO security_destinations VALUES('local-v1','local','active',NULL,NULL,0,0.0,0,0);
CREATE UNIQUE INDEX security_destinations_active_https ON security_destinations(kind) WHERE kind='https' AND state='active';
CREATE TABLE security_event_payloads (
 event_id TEXT PRIMARY KEY REFERENCES security_events(id) ON DELETE CASCADE,
 protocol_version INTEGER NOT NULL CHECK(typeof(protocol_version)='integer' AND protocol_version=1),
 canonical_payload BLOB NOT NULL CHECK(typeof(canonical_payload)='blob' AND length(canonical_payload)<=2048),
 payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
 UNIQUE(event_id,payload_sha256)
);
CREATE TABLE security_delivery_obligations (
 destination_id TEXT NOT NULL REFERENCES security_destinations(destination_id),
 event_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
 payload_sha256 TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('live','retained_backfill')),
 queued_at REAL NOT NULL CHECK(queued_at>=0 AND queued_at<=253402300799.0),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempts)='integer' AND attempts>=0),
 next_attempt_at REAL NOT NULL DEFAULT 0 CHECK(next_attempt_at>=0 AND next_attempt_at<=253402300799.0),
 acknowledged_at REAL CHECK(acknowledged_at IS NULL OR (acknowledged_at>=0 AND acknowledged_at<=253402300799.0)),
 receiver_receipt_id TEXT CHECK(receiver_receipt_id IS NULL OR (length(receiver_receipt_id)=32 AND receiver_receipt_id NOT GLOB '*[^0-9a-f]*')),
 last_error TEXT CHECK(last_error IS NULL OR last_error IN ('delivery_failed','config_unavailable','transport_failed','tls_failed',
  'remote_auth_failed','remote_conflict','remote_capacity','remote_throttled','remote_unavailable','invalid_receipt')),
 PRIMARY KEY(destination_id,event_id),
 FOREIGN KEY(event_id,payload_sha256) REFERENCES security_event_payloads(event_id,payload_sha256) ON DELETE CASCADE
);
CREATE INDEX security_delivery_pending ON security_delivery_obligations(destination_id,acknowledged_at,next_attempt_at);
CREATE INDEX security_delivery_event_pending ON security_delivery_obligations(event_id,acknowledged_at);
CREATE TRIGGER security_event_payloads_immutable BEFORE UPDATE ON security_event_payloads
 BEGIN SELECT RAISE(ABORT,'Security event payloads are immutable'); END;
CREATE TRIGGER security_events_immutable BEFORE UPDATE ON security_events
 BEGIN SELECT RAISE(ABORT,'Security events are immutable'); END;
CREATE TRIGGER security_delivery_identity_immutable BEFORE UPDATE OF id,source_id ON security_delivery_identity
 BEGIN SELECT RAISE(ABORT,'Security source identity is immutable'); END;
CREATE TRIGGER security_heartbeat_monotonic BEFORE UPDATE OF heartbeat_sequence ON security_delivery_identity
 WHEN NEW.heartbeat_sequence<=OLD.heartbeat_sequence
 BEGIN SELECT RAISE(ABORT,'Security heartbeat sequence must increase'); END;
CREATE TRIGGER security_destinations_immutable BEFORE UPDATE OF destination_id,kind,collector_id,endpoint,enabled_at,backfill_cutoff_sequence,backfill_retained_count ON security_destinations
 BEGIN SELECT RAISE(ABORT,'Security destination identity is immutable'); END;
CREATE TRIGGER security_obligations_immutable BEFORE UPDATE OF destination_id,event_id,payload_sha256,kind,queued_at ON security_delivery_obligations
 BEGIN SELECT RAISE(ABORT,'Security delivery obligation identity is immutable'); END;
DROP TABLE security_outbox;
"""
SCHEMA_V9 = SCHEMA_V8 + DELIVERY_SCHEMA + "PRAGMA user_version=9;\n"
BROWSER_FLOW_SCHEMA = """
CREATE TABLE browser_flow_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 epoch TEXT NOT NULL CHECK(length(epoch)=64 AND epoch NOT GLOB '*[^0-9a-f]*'),
 rejection_time_floor INTEGER NOT NULL CHECK(typeof(rejection_time_floor)='integer' AND rejection_time_floor>=0 AND rejection_time_floor<=253402300799)
);
INSERT INTO browser_flow_state VALUES(1,lower(hex(randomblob(32))),CAST(strftime('%s','now') AS INTEGER));
CREATE TABLE browser_login_flows (
 flow_hash TEXT PRIMARY KEY CHECK(length(flow_hash)=64 AND flow_hash NOT GLOB '*[^0-9a-f]*'),
 issued_at INTEGER NOT NULL CHECK(typeof(issued_at)='integer' AND issued_at>=0 AND issued_at<=253402271999),
 expires_at INTEGER NOT NULL CHECK(typeof(expires_at)='integer' AND expires_at=issued_at+28800),
 generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation>=0 AND generation<=2147483647),
 closed INTEGER NOT NULL CHECK(closed IN (0,1)),
 created_by_user_id TEXT NOT NULL REFERENCES users(id)
);
CREATE INDEX browser_login_flows_creator ON browser_login_flows(created_by_user_id);
CREATE TABLE session_browser_flow (
 public_id TEXT PRIMARY KEY REFERENCES session_security(public_id) ON DELETE CASCADE,
 flow_hash TEXT UNIQUE NOT NULL REFERENCES browser_login_flows(flow_hash)
);
CREATE TRIGGER browser_flow_binding_closed AFTER DELETE ON session_browser_flow
 BEGIN UPDATE browser_login_flows SET closed=1 WHERE flow_hash=OLD.flow_hash; END;
CREATE TRIGGER browser_flow_identity_immutable BEFORE UPDATE OF flow_hash,issued_at,expires_at,created_by_user_id ON browser_login_flows
 BEGIN SELECT RAISE(ABORT,'Browser flow identity is immutable'); END;
CREATE TRIGGER browser_flow_closed_monotonic BEFORE UPDATE OF closed ON browser_login_flows WHEN NEW.closed<OLD.closed
 BEGIN SELECT RAISE(ABORT,'Closed browser flows cannot reopen'); END;
CREATE TRIGGER browser_flow_generation_monotonic BEFORE UPDATE OF generation ON browser_login_flows WHEN NEW.generation<OLD.generation
 BEGIN SELECT RAISE(ABORT,'Browser flow generation cannot decrease'); END;
CREATE TRIGGER browser_flow_floor_monotonic BEFORE UPDATE OF rejection_time_floor ON browser_flow_state WHEN NEW.rejection_time_floor<OLD.rejection_time_floor
 BEGIN SELECT RAISE(ABORT,'Browser flow time cannot decrease'); END;
"""
SCHEMA_V10 = SCHEMA_V9 + BROWSER_FLOW_SCHEMA + "PRAGMA user_version=10;\n"
SCHEMA = SCHEMA_V10


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
        expected.executescript({1: SCHEMA_V1, 2: SCHEMA_V2, 3: SCHEMA_V3, 4: SCHEMA_V4,
                               5: SCHEMA_V5, 6: SCHEMA_V6, 7: SCHEMA_V7, 8: SCHEMA_V8,
                               9: SCHEMA_V9, 10: SCHEMA_V10}[version])
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


def _apply_event_migration(connection):
    _execute_schema(connection, EVENT_SCHEMA)
    connection.execute("PRAGMA user_version=6")


def _apply_session_predecessor_migration(connection):
    # Existing sessions retain their identity and lifetime. Predecessors are
    # populated only by subsequent explicit reverification, never as authority.
    _execute_schema(connection, SESSION_PREDECESSOR_SCHEMA)
    connection.execute("PRAGMA user_version=7")


def _apply_enrollment_migration(connection):
    # Existing credential provenance is unknown. Preserve legacy access until
    # explicit per-account enrollment; migration never claims it was verified.
    _execute_schema(connection, ENROLLMENT_SCHEMA)
    connection.execute("UPDATE authentication_policy SET mode='transition' WHERE id=1")
    connection.execute("INSERT INTO account_security SELECT id,'legacy',0,NULL,NULL FROM users")
    connection.execute("PRAGMA user_version=8")


def _apply_delivery_migration(connection):
    """Preserve every local obligation and freeze retained event bytes once."""
    from .event_destinations import freeze_retained_events, validate_delivery_state

    if not connection.in_transaction:
        raise ValueError("Security delivery migration requires a transaction.")
    previous = [dict(row) for row in connection.execute("SELECT * FROM security_outbox")]
    identifiers = {row[0] for row in connection.execute("SELECT id FROM security_events")}
    if {row["event_id"] for row in previous} != identifiers:
        raise ValueError("An existing security event has no local delivery obligation.")
    _execute_schema(connection, DELIVERY_SCHEMA)
    freeze_retained_events(connection, previous)
    connection.execute("PRAGMA user_version=9")
    validate_delivery_state(connection)


def _apply_browser_flow_migration(connection):
    """Explicit stopped-writer barrier; legacy sessions require binding for reauth."""
    from .browser_flow import checked_time, validate_state

    if not connection.in_transaction:
        raise ValueError("Browser flow migration requires a transaction.")
    _execute_schema(connection, BROWSER_FLOW_SCHEMA)
    # Historical challenges did not bind the new browser generation. Ordinary
    # existing sessions keep their existing lifetime, never an implicit flow.
    connection.execute("DELETE FROM passkey_challenges")
    checked_time(connection)
    connection.execute("PRAGMA user_version=10")
    validate_state(connection)


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
    if not stat.S_ISREG(info.st_mode) or info.st_nlink not in (0, 1):
        raise ValueError("Runtime files must be regular files without links.")
    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("Runtime files must be owned by this user with mode 0600.")
    if info.st_nlink == 0:
        # Linux may resolve an inode, then observe its metadata after unlink.
        # Required files still fail; only optional SQLite sidecars catch this.
        raise FileNotFoundError("Runtime file was removed during validation.")


def create_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def sync_directory(directory: Path) -> bool:
    """Flush a published directory entry on POSIX; failures must stop cutover.

    Python's portable Windows file API does not supply directory fsync. False
    explicitly leaves directory-entry durability unverified on that platform;
    flushing file contents alone is not a host/power-loss durability guarantee.
    """
    if os.name != "posix":
        return False
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(directory, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ValueError("Key publication requires an ordinary directory.")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return True


class Database:
    """Open existing initialized state only; never repair/reseed on startup."""

    def __init__(self, data_dir: str | Path, *, mfa_key_file=None, migrate=False):
        self._initialized = False
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
        self._initialized = True

    def _validate_schema(self, *, migrate=False):
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10):
                raise ValueError("Unsupported or incomplete business database.")
            _require_schema(connection, version)
            if version < 10 and not migrate:
                raise ValueError("Existing storage requires an explicit reviewed migration to schema ten; stop all old writers first.")
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
            if version < 6:
                _apply_event_migration(connection)
                _require_schema(connection, 6)
            if version < 7:
                _apply_session_predecessor_migration(connection)
                _require_schema(connection, 7)
            if version < 8:
                _apply_enrollment_migration(connection)
                _require_schema(connection, 8)
            if version < 9:
                _apply_delivery_migration(connection)
                _require_schema(connection, 9)
            if version < 10:
                _apply_browser_flow_migration(connection)
                _require_schema(connection, 10)
            from .browser_flow import validate_state
            validate_state(connection)
            from .event_destinations import validate_delivery_state
            validate_delivery_state(connection)
            self.mfa_secrets.validate_database(connection)

    def _connect(self, *, readonly=False):
        validate_data_dir(self.directory)
        check_private_file(self.path)
        for suffix in ("-journal", "-wal", "-shm"):
            auxiliary = Path(str(self.path) + suffix)
            try:
                check_private_file(auxiliary)
            except FileNotFoundError:
                # SQLite can remove a sidecar when another connection commits
                # or closes. Missing auxiliaries are ordinary; invalid links,
                # ownership and permission failures must still fail closed.
                pass
        mode = "ro" if readonly else "rw"
        connection = sqlite3.connect(self.path.as_uri() + "?mode=" + mode, uri=True, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _require_current_key(self, connection):
        if self._initialized:
            row = connection.execute("SELECT ciphertext FROM mfa_key_binding WHERE id=1").fetchone()
            if row is None:
                raise RuntimeKeyError("MFA encryption key binding is missing; preserve existing state.")
            try:
                self.mfa_secrets.check_binding(row[0])
            except ValueError:
                raise RuntimeKeyError("MFA ciphertext or encryption key is invalid; preserve existing state.") from None

    @contextmanager
    def transaction(self):
        connection = self._connect()
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            if self._initialized:
                from .browser_flow import checked_time, observe_clock, preserve_observed_time
                # The outer writer lock protects both entry and later clock
                # observations. Rolling back just the operation savepoint keeps
                # a competing request from reviving expired authority between
                # authorization rollback and committing its rejection boundary.
                with observe_clock(connection) as observed:
                    connection.execute("BEGIN IMMEDIATE")
                    self._require_current_key(connection)
                    if connection.execute("PRAGMA user_version").fetchone()[0] != 10:
                        raise ValueError("Business storage changed schema; stop all writers and investigate.")
                    checked_time(connection)
                    connection.execute("SAVEPOINT browser_flow_operation")
                    try:
                        yield connection
                    except BaseException:
                        connection.execute("ROLLBACK TO SAVEPOINT browser_flow_operation")
                        preserve_observed_time(connection, observed)
                        connection.execute("RELEASE SAVEPOINT browser_flow_operation")
                        connection.commit()
                        raise
                    else:
                        connection.execute("RELEASE SAVEPOINT browser_flow_operation")
                        connection.commit()
                return
            connection.execute("BEGIN IMMEDIATE")
            self._require_current_key(connection)
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
            self._require_current_key(connection)
            yield connection
        finally:
            connection.close()


def record_activity(connection, actor: str, action: str, target: str) -> None:
    connection.execute(
        "INSERT INTO activity(actor,action,target,created_at) VALUES(?,?,?,?)",
        (actor, action, target, utc_now()),
    )
