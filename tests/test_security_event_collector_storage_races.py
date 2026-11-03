"""SQLite sidecars may disappear; required and unsafe files must fail closed."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import stat
from threading import Barrier
from types import SimpleNamespace

import pytest

from tests.test_security_event_collector import pair as pair, tmp_path as tmp_path
from collector import private_files, storage


def sidecar_for(store):
    path = Path(str(store.path) + "-journal")
    private_files.write_private(path, b"")
    return path


def metadata(path, **changes):
    current = path.lstat()
    values = {name: getattr(current, name) for name in ("st_mode", "st_nlink", "st_uid", "st_size")}
    values["st_file_attributes"] = getattr(current, "st_file_attributes", 0)
    return SimpleNamespace(**(values | changes))


def test_optional_sidecar_disappearing_before_metadata_does_not_refuse_connection(pair, monkeypatch):
    store = pair[0].store
    sidecar = sidecar_for(store)
    original = storage.check_private_file
    observed = []

    def disappear(path):
        if path == sidecar:
            observed.append(path)
            path.unlink()
        return original(path)

    monkeypatch.setattr(storage, "check_private_file", disappear)
    with closing(store._connect(True)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 1
    assert observed == [sidecar]


def test_optional_sidecar_disappearing_during_metadata_does_not_refuse_connection(pair, monkeypatch):
    store = pair[0].store
    sidecar = sidecar_for(store)
    original = Path.lstat
    observed = []

    def disappear(path):
        if path == sidecar:
            observed.append(path)
            path.unlink()
            raise FileNotFoundError("Synthetic unlink while resolving sidecar metadata")
        return original(path)

    monkeypatch.setattr(Path, "lstat", disappear)
    with closing(store._connect(True)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 1
    assert observed == [sidecar]


def test_byte_accounting_uses_one_validated_metadata_snapshot_if_sidecar_is_unlinked(pair, monkeypatch):
    store = pair[0].store
    sidecar = sidecar_for(store)
    sidecar.write_bytes(b"sidecar")
    database_size = store.path.stat().st_size
    original = Path.lstat
    observed = []

    def disappear(path):
        if path == sidecar:
            observed.append(path)
            result = original(path)
            path.unlink()
            return result
        return original(path)

    # Patch the metadata boundary itself: lstat need not delegate to Path.stat.
    monkeypatch.setattr(Path, "lstat", disappear)
    assert store.disk_bytes() == database_size + len(b"sidecar")
    assert observed == [sidecar]
    assert not sidecar.exists()


@pytest.mark.parametrize("operation", ["connect", "bytes"])
def test_optional_zero_link_regular_metadata_is_disappearance_only(pair, monkeypatch, operation):
    store = pair[0].store
    sidecar = sidecar_for(store)
    database_size = store.path.stat().st_size
    unlinked = metadata(sidecar, st_nlink=0)
    original = Path.lstat
    observed = []

    def disappear(path):
        if path == sidecar:
            observed.append(path)
            path.unlink()
            return unlinked
        return original(path)

    monkeypatch.setattr(Path, "lstat", disappear)
    if operation == "connect":
        with closing(store._connect(True)) as connection:
            assert connection.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 1
    else:
        assert store.disk_bytes() == database_size
    assert observed == [sidecar]


@pytest.mark.parametrize("operation", ["connect", "bytes"])
@pytest.mark.parametrize("kind", ["directory", "symlink", "reparse", "hardlink", "permissions", "owner"])
def test_unsafe_optional_metadata_is_never_treated_as_absence(pair, monkeypatch, operation, kind):
    store = pair[0].store
    sidecar = sidecar_for(store)
    # Even zero-link metadata cannot hide an unsafe type, owner or permissions.
    changes = {"st_nlink": 0, "st_uid": 1000, "st_mode": stat.S_IFREG | 0o600, "st_file_attributes": 0}
    changes.update({
        "directory": {"st_mode": stat.S_IFDIR | 0o700}, "symlink": {"st_mode": stat.S_IFLNK | 0o600},
        "reparse": {"st_file_attributes": stat.FILE_ATTRIBUTE_REPARSE_POINT}, "hardlink": {"st_nlink": 2},
        "permissions": {"st_mode": stat.S_IFREG | 0o640}, "owner": {"st_uid": 1001},
    }[kind])
    unsafe = metadata(sidecar, **changes)
    original = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path: unsafe if path == sidecar else original(path))
    monkeypatch.setattr(private_files, "os", SimpleNamespace(name="posix", geteuid=lambda: 1000))
    # The actual required database is also owned by our simulated uid.
    required = metadata(store.path, st_uid=1000, st_mode=stat.S_IFREG | 0o600)
    monkeypatch.setattr(Path, "lstat", lambda path: unsafe if path == sidecar else required if path == store.path else original(path))
    with pytest.raises(ValueError):
        if operation == "connect":
            with closing(store._connect(True)):
                pytest.fail("Unsafe optional metadata admitted a connection")
        else:
            store.disk_bytes()


@pytest.mark.parametrize("operation", ["connect", "bytes", "required_file"])
@pytest.mark.parametrize("disappearance", ["missing", "zero_link"])
def test_required_database_disappearance_always_fails_closed(pair, monkeypatch, operation, disappearance):
    store = pair[0].store
    original = Path.lstat
    unlinked = metadata(store.path, st_nlink=0)
    if disappearance == "missing":
        store.path.unlink()
    else:
        monkeypatch.setattr(Path, "lstat", lambda path: unlinked if path == store.path else original(path))
    with pytest.raises(FileNotFoundError):
        if operation == "connect":
            with closing(store._connect(True)):
                pytest.fail("Missing required database admitted a connection")
        elif operation == "bytes":
            store.disk_bytes()
        else:
            private_files.check_private_file(store.path)


def test_required_token_or_backup_file_never_uses_optional_disappearance_policy(tmp_path):
    for name in ("ingest.token", "backup.sqlite3"):
        with pytest.raises(FileNotFoundError):
            private_files.check_private_file(tmp_path / name)


def test_real_delete_journal_creation_and_cleanup_with_concurrent_reads_and_accounting(pair):
    store = pair[0].store
    barrier = Barrier(3)
    minimum_size = store.path.stat().st_size

    def writer():
        for number in range(100):
            with store.transaction() as connection:
                connection.execute("INSERT INTO rate_limits VALUES('storage-race',?,?) ON CONFLICT(namespace) "
                                   "DO UPDATE SET tokens=excluded.tokens,updated_at=excluded.updated_at", (number, 1700000000.0))
                barrier.wait(timeout=10)
            # Commit/unlink overlaps both readers' metadata work. Rendezvous
            # before SQL reads avoids testing repeated writer lock starvation.
            barrier.wait(timeout=10)
            barrier.wait(timeout=10)
        return 100

    def reader():
        for _ in range(100):
            barrier.wait(timeout=10)
            assert minimum_size <= store.disk_bytes() <= store.settings["max_bytes"]
            with closing(store._connect(True)):
                pass
            barrier.wait(timeout=10)
            with store.read() as connection:
                assert connection.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 1
            barrier.wait(timeout=10)
        return 100

    with ThreadPoolExecutor(max_workers=3) as workers:
        futures = [workers.submit(writer), workers.submit(reader), workers.submit(reader)]
        assert [future.result(timeout=30) for future in futures] == [100, 100, 100]
    with store.read() as connection:
        assert connection.execute("SELECT tokens FROM rate_limits WHERE namespace='storage-race'").fetchone()[0] == 99
