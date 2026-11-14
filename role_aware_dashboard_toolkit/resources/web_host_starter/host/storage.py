"""Explicit single-host storage initialization; never initialize during startup."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import stat


APP_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1


class StorageUnavailable(RuntimeError):
    """Safe public failure; host logs and operator checks diagnose the storage."""


def data_path(value: str | Path) -> Path:
    if not value:
        raise ValueError("Set RADT_DATA_DIR to initialized storage outside the application.")
    original = Path(value).expanduser().absolute()
    # Resolve ordinary parent aliases such as macOS /var, but reject a linked
    # application data directory itself and any directory under the app source.
    if original.is_symlink() or (
        original.exists() and getattr(original.lstat(), "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ):
        raise ValueError("Use an ordinary private data directory.")
    path = original.resolve()
    if path == APP_ROOT or APP_ROOT in path.parents:
        raise ValueError("Keep runtime storage outside the generated application.")
    return path


def _private_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    ):
        raise StorageUnavailable("Storage must contain ordinary private files.")
    if os.name != "nt" and (stat.S_IMODE(info.st_mode) & 0o077):
        raise StorageUnavailable("Restrict storage files to their owner.")


def read_key(directory: Path) -> bytes:
    try:
        if not directory.is_dir() or directory.is_symlink():
            raise StorageUnavailable("Initialized private storage is required.")
        if os.name != "nt" and stat.S_IMODE(directory.stat().st_mode) & 0o077:
            raise StorageUnavailable("Restrict the storage directory to its owner.")
        _private_file(directory / "identity.key")
        _private_file(directory / "records.sqlite3")
        key = (directory / "identity.key").read_bytes()
        if len(key) != 32:
            raise StorageUnavailable("The identity key is invalid.")
        return key
    except OSError:
        raise StorageUnavailable("Initialized private storage is unavailable.") from None


@contextmanager
def transaction(directory: Path, key: bytes):
    """Every cooperating token/grant/freeze/record writer takes this same lock."""
    if read_key(directory) != key:
        raise StorageUnavailable("Storage identity changed; restart after operator review.")
    connection = sqlite3.connect(
        (directory / "records.sqlite3").as_uri() + "?mode=rw", uri=True,
        timeout=10, isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        metadata = connection.execute("SELECT version, key_sha256 FROM metadata").fetchall()
        if (len(metadata) != 1 or metadata[0]["version"] != SCHEMA_VERSION
                or metadata[0]["key_sha256"] != hashlib.sha256(key).hexdigest()):
            raise StorageUnavailable("Storage schema or identity does not match this host.")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize(value: str | Path) -> Path:
    """Create a new directory only; keep any partial failure for inspection."""
    directory = data_path(value)
    directory.mkdir(mode=0o700, exist_ok=False)
    key = secrets.token_bytes(32)
    for name, payload in (("identity.key", key), ("records.sqlite3", b"")):
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
    connection = sqlite3.connect(directory / "records.sqlite3")
    try:
        connection.executescript("""
            CREATE TABLE metadata (version INTEGER NOT NULL, key_sha256 TEXT NOT NULL);
            CREATE TABLE tokens (digest TEXT PRIMARY KEY, subject TEXT NOT NULL,
                                 expires_at REAL NOT NULL);
            CREATE TABLE grants (principal TEXT PRIMARY KEY, role TEXT NOT NULL);
            CREATE TABLE freeze (id INTEGER PRIMARY KEY CHECK(id = 1),
                                 frozen INTEGER NOT NULL CHECK(frozen IN (0, 1)),
                                 revision INTEGER NOT NULL, changed_by TEXT NOT NULL);
            CREATE TABLE items (id TEXT PRIMARY KEY, label TEXT NOT NULL,
                                starts_at TEXT NOT NULL, status TEXT NOT NULL,
                                revision INTEGER NOT NULL, owner TEXT NOT NULL);
            CREATE TABLE history (id INTEGER PRIMARY KEY, item_id TEXT NOT NULL REFERENCES items(id),
                                  action TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL,
                                  before_json TEXT NOT NULL, after_json TEXT NOT NULL);
            INSERT INTO freeze VALUES (1, 1, 0, '');
        """)
        connection.execute("INSERT INTO metadata VALUES (?, ?)",
                           (SCHEMA_VERSION, hashlib.sha256(key).hexdigest()))
        connection.commit()
    finally:
        connection.close()
    return directory
