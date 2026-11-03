"""Private SQLite custody, explicit provisioning and bounded write transactions."""

from contextlib import contextmanager, closing
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import secrets
import sqlite3
import time

from .private_files import check_private_file, private_directory, private_file_metadata, write_private
from .schema import SCHEMA, VERSION

ID = re.compile(r"[0-9a-f]{32}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
MAX_STORAGE_BYTES = 512 * 1024 * 1024


class ServiceError(Exception):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)


def moment(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 253402300799:
        raise ServiceError("unavailable")
    return float(value)


def identifier(value):
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise ValueError("Use an opaque 32-character lowercase hexadecimal identity.")
    return value


def verifier(token):
    if not isinstance(token, str) or TOKEN.fullmatch(token) is None:
        raise ServiceError("unauthenticated", 401)
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _schema(connection):
    return tuple(tuple(row) for row in connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"))


with closing(sqlite3.connect(":memory:")) as _expected:
    _expected.executescript(SCHEMA)
    EXPECTED_SCHEMA = _schema(_expected)


@dataclass(frozen=True)
class Provisioned:
    service_id: str
    source_id: str
    destination_id: str
    ingest_token: str = field(repr=False)
    operator_token: str = field(repr=False)


def provision(directory, *, kind, source_id, destination_id, peer_id=None, service_id=None,
              now=None, max_events=100_000, max_bytes=512 * 1024 * 1024, max_cases=1000,
              max_transitions=10_000, heartbeat_timeout=90, backlog_threshold=300,
              inbox_id=None, alert_destination_id=None, alert_endpoint=None):
    if kind not in {"collector", "inbox"}:
        raise ValueError("Choose collector or inbox.")
    source_id, destination_id = identifier(source_id), identifier(destination_id)
    service_id = identifier(service_id or secrets.token_hex(16))
    peer_id = identifier(peer_id or source_id)
    for value in (max_events, max_bytes, max_cases, max_transitions, heartbeat_timeout, backlog_threshold):
        if type(value) is not int or value < 1:
            raise ValueError("Capacity and timing limits must be positive integers.")
    if not 1024 * 1024 <= max_bytes <= MAX_STORAGE_BYTES:
        raise ValueError("Storage capacity must be between one and 512 MiB for this reference.")
    if kind == "collector" and (inbox_id is None or alert_destination_id is None):
        raise ValueError("Collector provisioning requires a reviewed inbox identity and destination.")
    if inbox_id is not None:
        identifier(inbox_id)
        identifier(alert_destination_id)
    if alert_endpoint is not None:
        from .event_wire import load_transport
        if load_transport().endpoint_origin(alert_endpoint)[1] != "/v1/alerts":
            raise ValueError("Notification endpoint must be the fixed HTTPS alert intake.")
    now = moment(time.time() if now is None else now)
    path = private_directory(directory, create=True)
    write_private(path / "PROVISION_INCOMPLETE", b"Provisioning has not completed. Preserve this installation.\n")
    write_private(path / "state.sqlite3", b"")
    ingest, operator = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with closing(sqlite3.connect(path / "state.sqlite3")) as connection:
        connection.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
        connection.execute("INSERT INTO settings VALUES(1,?,?,?,?,?,?,?,?,?,?)", (
            kind, service_id, source_id, now, max_events, max_bytes, max_cases, max_transitions,
            heartbeat_timeout, backlog_threshold,
        ))
        connection.execute("INSERT INTO channels VALUES(?,?,1)", (destination_id, peer_id))
        connection.executemany("INSERT INTO credentials VALUES(?,?,?,NULL)", (
            (verifier(ingest), "ingest", destination_id), (verifier(operator), "operator", None),
        ))
        connection.execute("INSERT INTO clock_state VALUES(1,?)", (now,))
        if kind == "collector":
            connection.execute("INSERT INTO alert_destination VALUES(1,?,?,?)", (inbox_id, alert_destination_id, alert_endpoint))
        connection.commit()
    # The CLI prints paths only; plaintext tokens are confined to private files.
    write_private(path / "ingest.token", (ingest + "\n").encode("ascii"))
    write_private(path / "operator.token", (operator + "\n").encode("ascii"))
    (path / "PROVISION_INCOMPLETE").unlink()
    return Provisioned(service_id, source_id, destination_id, ingest, operator)


class Store:
    def __init__(self, directory, *, clock=time.time, allow_quarantine=False):
        self.directory = private_directory(directory)
        self.path = check_private_file(self.directory / "state.sqlite3")
        self.clock = clock
        if (self.directory / "PROVISION_INCOMPLETE").exists():
            raise ValueError("Provisioning is incomplete; preserve storage for explicit operator recovery.")
        if (self.directory / "RESTORE_QUARANTINE").exists() and not allow_quarantine:
            raise ValueError("Restored collector custody is quarantined; continuity requires independent review.")
        with self.read() as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] != VERSION or _schema(connection) != EXPECTED_SCHEMA:
                raise ValueError("Unsupported or damaged collector schema; preserve storage.")
            if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
                raise ValueError("Collector integrity validation failed.")
            settings = connection.execute("SELECT * FROM settings WHERE id=1").fetchone()
            if settings is None or connection.execute("PRAGMA foreign_key_check").fetchone():
                raise ValueError("Collector authority is incomplete.")
            self.settings = dict(settings)
            identifier(self.settings["service_id"])
            identifier(self.settings["source_id"])
            moment(self.settings["created_at"])
            for key in ("max_events", "max_bytes", "max_cases", "max_transitions", "heartbeat_timeout", "backlog_threshold"):
                if type(self.settings[key]) is not int or not 1 <= self.settings[key] <= 2**63 - 1:
                    raise ValueError("Collector configuration is invalid.")
            if not 1024 * 1024 <= self.settings["max_bytes"] <= MAX_STORAGE_BYTES:
                raise ValueError("Collector capacity is invalid.")
            if connection.execute("SELECT 1 FROM credentials WHERE role='operator'").fetchone() is None:
                raise ValueError("Collector operator authority is missing.")

    def _connect(self, readonly=False):
        check_private_file(self.path)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            try:
                check_private_file(sidecar)
            except FileNotFoundError:
                # SQLite owns these optional files and may unlink them while
                # another connection opens. Unsafe metadata still fails closed.
                pass
        connection = sqlite3.connect(self.path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True, timeout=1)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if not readonly:
            connection.execute("PRAGMA synchronous=FULL")
            # DELETE journaling plus a conservative page ceiling reserves room
            # for rollback journals and operational control writes.
            if connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "delete":
                connection.close()
                raise ValueError("Collector journal mode must remain DELETE.")
            size = connection.execute("PRAGMA page_size").fetchone()[0]
            pages = self.settings["max_bytes"] // (3 * size)
            connection.execute(f"PRAGMA max_page_count={pages}")
        return connection

    @contextmanager
    def read(self):
        with closing(self._connect(True)) as connection:
            connection.execute("BEGIN")
            yield connection

    @contextmanager
    def transaction(self):
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def now(self):
        return moment(self.clock())

    def advance_clock(self, connection, now):
        previous = connection.execute("SELECT last_time FROM clock_state WHERE id=1").fetchone()
        if previous is None or now < previous[0]:
            raise ServiceError("unavailable")
        connection.execute("UPDATE clock_state SET last_time=? WHERE id=1", (now,))

    def disk_bytes(self):
        total = private_file_metadata(self.path).st_size
        for suffix in ("-journal", "-wal", "-shm"):
            try:
                info = private_file_metadata(Path(str(self.path) + suffix))
            except FileNotFoundError:
                continue
            total += info.st_size
        return total

    def event_byte_capacity(self, connection):
        """Reserve database pages for alert/heartbeat control before hard full.

        SQLite's hard page ceiling is one third of the file budget, leaving
        rollback-journal headroom. Event admission additionally reserves up to
        a quarter of that database allowance for operational records.
        """
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        pages = connection.execute("PRAGMA page_count").fetchone()[0]
        free = connection.execute("PRAGMA freelist_count").fetchone()[0]
        ceiling = (self.settings["max_bytes"] // (3 * page_size)) * page_size
        reserve = min(ceiling // 4, max(65536, (self.settings["max_cases"] + self.settings["max_transitions"]) * 4096))
        return (pages - free) * page_size, ceiling - reserve

    def event_storage_full(self, connection):
        used, limit = self.event_byte_capacity(connection)
        return used + 32768 > limit or self.disk_bytes() + 65536 > self.settings["max_bytes"]

    def authenticate(self, token, role):
        with self.read() as connection:
            return self.authenticate_in(connection, token, role)

    def authenticate_in(self, connection, token, role):
        digest, now = verifier(token), self.now()
        clock = connection.execute("SELECT last_time FROM clock_state WHERE id=1").fetchone()
        if clock is None or role == "ingest" and now < clock[0]:
            raise ServiceError("unavailable")
        matched = None
        for row in connection.execute("SELECT * FROM credentials WHERE role=?", (role,)):
            if hmac.compare_digest(digest, row["verifier"]) and (row["expires_at"] is None or now < row["expires_at"]):
                matched = dict(row)
        if matched is None:
            raise ServiceError("unauthenticated", 401)
        if role == "operator":
            return None
        channel = connection.execute("SELECT * FROM channels WHERE destination_id=? AND active=1", (matched["destination_id"],)).fetchone()
        if channel is None:
            raise ServiceError("unauthenticated", 401)
        return dict(channel)

    def reserve_intake(self, namespace):
        rate, burst = (10.0, 20.0) if namespace == "events" else (1.0, 4.0)
        with self.transaction() as connection:
            now = self.now()
            row = connection.execute("SELECT * FROM rate_limits WHERE namespace=?", (namespace,)).fetchone()
            if row and now < row["updated_at"]:
                raise ServiceError("unavailable")
            available = burst if row is None else min(burst, row["tokens"] + (now - row["updated_at"]) * rate)
            if available < 1:
                raise ServiceError("capacity_busy", 429)
            connection.execute("INSERT INTO rate_limits VALUES(?,?,?) ON CONFLICT(namespace) DO UPDATE SET tokens=excluded.tokens,updated_at=excluded.updated_at",
                               (namespace, available - 1, now))

    def rotate_ingest(self, destination_id, *, overlap_seconds=0):
        if type(overlap_seconds) is not int or not 0 <= overlap_seconds <= 300:
            raise ValueError("Credential overlap must be zero through 300 seconds.")
        now, token = self.now(), secrets.token_urlsafe(32)
        with self.transaction() as connection:
            self.advance_clock(connection, now)
            if connection.execute("SELECT 1 FROM channels WHERE destination_id=? AND active=1", (destination_id,)).fetchone() is None:
                raise ValueError("Unknown active destination.")
            connection.execute("DELETE FROM credentials WHERE role='ingest' AND destination_id=? AND expires_at IS NOT NULL", (destination_id,))
            connection.execute("UPDATE credentials SET expires_at=? WHERE role='ingest' AND destination_id=?", (now + overlap_seconds, destination_id))
            if overlap_seconds == 0:
                connection.execute("DELETE FROM credentials WHERE role='ingest' AND destination_id=?", (destination_id,))
            connection.execute("INSERT INTO credentials VALUES(?,'ingest',?,NULL)", (verifier(token), destination_id))
        return token

    def register_channel(self, destination_id, *, peer_id=None):
        """Offline owner operation; never reachable with a writer credential."""
        destination_id = identifier(destination_id)
        peer_id = identifier(peer_id or self.settings["source_id"])
        token = secrets.token_urlsafe(32)
        with self.transaction() as connection:
            if connection.execute("SELECT COUNT(*) FROM channels").fetchone()[0] >= 32:
                raise ValueError("The bounded channel registry is full.")
            if connection.execute("SELECT 1 FROM channels WHERE destination_id=?", (destination_id,)).fetchone():
                raise ValueError("Destination identities are immutable.")
            connection.execute("INSERT INTO channels VALUES(?,?,1)", (destination_id, peer_id))
            connection.execute("INSERT INTO credentials VALUES(?,'ingest',?,NULL)", (verifier(token), destination_id))
        return token

    def configure_alert_endpoint(self, endpoint):
        from .event_wire import load_transport
        if load_transport().endpoint_origin(endpoint)[1] != "/v1/alerts":
            raise ValueError("Notification endpoint must be the fixed HTTPS alert intake.")
        with self.transaction() as connection:
            row = connection.execute("SELECT endpoint FROM alert_destination WHERE id=1").fetchone()
            if row is None or row[0] not in (None, endpoint):
                raise ValueError("The alert destination endpoint is immutable.")
            connection.execute("UPDATE alert_destination SET endpoint=? WHERE id=1", (endpoint,))

    def retire_channel(self, destination_id):
        """Offline retirement preserves accepted events and routing receipts."""
        identifier(destination_id)
        with self.transaction() as connection:
            if connection.execute("SELECT 1 FROM channels WHERE destination_id=?", (destination_id,)).fetchone() is None:
                raise ValueError("Unknown channel.")
            connection.execute("UPDATE channels SET active=0 WHERE destination_id=?", (destination_id,))
            connection.execute("DELETE FROM credentials WHERE role='ingest' AND destination_id=?", (destination_id,))


def safe_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
