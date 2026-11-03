"""Consistent private backups; every restore starts quarantined without a bypass."""

from contextlib import closing
import hashlib
import json
import os
import sqlite3
import time

from .private_files import check_private_file, private_directory, write_private
from .schema import VERSION
from .storage import MAX_STORAGE_BYTES, Store, safe_json


def _digest(path):
    path = check_private_file(path)
    if path.stat().st_size > MAX_STORAGE_BYTES:
        raise ValueError("Collector snapshot exceeds the reference storage ceiling.")
    digest, count = hashlib.sha256(), 0
    deadline = time.monotonic() + 30
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            count += len(chunk)
            if count > MAX_STORAGE_BYTES or time.monotonic() > deadline:
                raise ValueError("Collector snapshot exceeded its storage or time boundary.")
            digest.update(chunk)
    return digest.hexdigest()


def _archive(source):
    if {path.name for path in source.iterdir()} != {"state.sqlite3", "manifest.json"}:
        raise ValueError("Collector archive contains unexpected files or SQLite sidecars.")
    manifest = check_private_file(source / "manifest.json")
    if manifest.stat().st_size > 4096:
        raise ValueError("Collector manifest is too large.")
    with manifest.open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError("Collector manifest is too large.")
    value = json.loads(raw)
    if safe_json(value) + b"\n" != raw:
        raise ValueError("Collector manifest is not the fixed canonical format.")
    return value


def _copy_snapshot(source, destination, expected):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    digest, count = hashlib.sha256(), 0
    deadline = time.monotonic() + 30
    with check_private_file(source).open("rb") as incoming, os.fdopen(os.open(destination, flags, 0o600), "wb") as outgoing:
        for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
            count += len(chunk)
            if count > MAX_STORAGE_BYTES or time.monotonic() > deadline:
                raise ValueError("Collector snapshot copy exceeded its resource boundary.")
            outgoing.write(chunk)
            digest.update(chunk)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    if digest.hexdigest() != expected:
        raise ValueError("Collector snapshot changed while copying; output remains quarantined.")


def create_backup(directory, output):
    store = Store(directory)
    destination = private_directory(output, create=True)
    write_private(destination / "state.sqlite3", b"")
    deadline = time.monotonic() + 30
    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise ValueError("Collector snapshot deadline exceeded; preserve incomplete output.")
    with store.read() as source, closing(sqlite3.connect(destination / "state.sqlite3")) as target:
        source.execute("SELECT COUNT(*) FROM settings").fetchone()
        source.backup(target, pages=64, progress=progress, sleep=0.01)
    digest = _digest(destination / "state.sqlite3")
    manifest = {"format": "collector-backup-v1", "schema": VERSION, "service_id": store.settings["service_id"],
                "kind": store.settings["kind"], "database_sha256": digest}
    write_private(destination / "manifest.json", safe_json(manifest) + b"\n")
    return destination


def restore_quarantined(bundle, output):
    source = private_directory(bundle)
    data_path = check_private_file(source / "state.sqlite3")
    manifest = _archive(source)
    if (not isinstance(manifest, dict) or set(manifest) != {"format", "schema", "service_id", "kind", "database_sha256"}
            or manifest["format"] != "collector-backup-v1" or type(manifest["schema"]) is not int or manifest["schema"] != VERSION):
        raise ValueError("Unsupported collector backup.")
    if _digest(data_path) != manifest["database_sha256"]:
        raise ValueError("Collector backup integrity mismatch.")
    # Marker exists before any database can be published. There is no ingest-
    # token or automatic CLI operation that can assert lost-ledger continuity.
    destination = private_directory(output, create=True)
    write_private(destination / "RESTORE_QUARANTINE", b"Accepted-ledger continuity must be independently established before reuse.\n")
    _copy_snapshot(data_path, destination / "state.sqlite3", manifest["database_sha256"])
    if _archive(source) != manifest:
        raise ValueError("Collector manifest changed during restore; output remains quarantined.")
    restored = Store(destination, allow_quarantine=True)
    if restored.settings["service_id"] != manifest["service_id"] or restored.settings["kind"] != manifest["kind"]:
        raise ValueError("Collector backup identity mismatch; output remains quarantined.")
    write_private(destination / "restore.json", safe_json({"quarantined": True, "database_sha256": manifest["database_sha256"],
                                                           "scope": "ledger continuity unverified"}) + b"\n")
    return destination
