"""Public snapshots remain coherent without reserving SQLite's single writer."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import sqlite3

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    business as business, business_seed as business_seed,
)
from business.security import TransactionAccessStore  # noqa: E402


def test_public_reads_complete_while_another_connection_reserves_the_writer(business):
    client = business.client()
    paths = ("/healthz", "/api/public/posts")
    expected = {path: client.get(path).json() for path in paths}
    with closing(sqlite3.connect(business.app.state.database.path, timeout=1)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1")
        with ThreadPoolExecutor(max_workers=2) as executor:
            pending = {path: executor.submit(client.get, path) for path in paths}
            try:
                # A write reservation and uncommitted changes must not obstruct
                # either public read. This is a lock test, not a load benchmark.
                responses = {path: future.result(timeout=2) for path, future in pending.items()}
                assert all(response.status_code == 200 for response in responses.values())
                assert {path: response.json() for path, response in responses.items()} == expected
            finally:
                writer.rollback()


@pytest.mark.parametrize("statement", [
    "UPDATE settings SET frozen=1",
    "DELETE FROM posts",
    "CREATE TABLE unexpected_write(value TEXT)",
])
def test_readonly_snapshot_rejects_mutations(business, statement):
    database = business.app.state.database
    before = business.client().get("/api/public/posts").json()
    with database.readonly_snapshot() as connection:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute(statement)
    assert business.client().get("/api/public/posts").json() == before
    with database.transaction() as connection:
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE name='unexpected_write'").fetchone() is None


def test_public_freeze_and_posts_use_the_same_snapshot(business, monkeypatch):
    database = business.app.state.database
    client = business.client()
    before = client.get("/api/public/posts").json()
    assert before["posts"] and before["accepting_submissions"] is True
    # WAL is confined to this disposable fixture: it permits a writer to commit
    # between two reads, making a missing explicit read transaction observable.
    with closing(sqlite3.connect(database.path)) as setup:
        assert setup.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    original = TransactionAccessStore.read_freeze
    updated = False

    def change_after_freeze_read(store):
        nonlocal updated
        freeze = original(store)
        if not updated:
            updated = True
            with database.transaction() as writer:
                writer.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1")
                writer.execute("UPDATE posts SET published=0,revision=revision+1")
        return freeze

    monkeypatch.setattr(TransactionAccessStore, "read_freeze", change_after_freeze_read)
    assert client.get("/api/public/posts").json() == before
    after = client.get("/api/public/posts").json()
    assert after == {**before, "posts": [], "accepting_submissions": False}


@pytest.mark.parametrize("path", ["/healthz", "/api/public/posts"])
@pytest.mark.parametrize("damage", [
    "missing-settings", "invalid-freeze", "invalid-revision", "missing-database", "corrupt-database",
])
def test_damaged_storage_fails_closed_without_recreation_or_diagnostics(business, path, damage):
    database = business.app.state.database
    if damage == "missing-database":
        database.path.unlink()
    elif damage == "corrupt-database":
        database.path.write_bytes(b"DISPOSABLE_STORAGE_DIAGNOSTIC_CANARY")
    else:
        with database.transaction() as connection:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute({
                "missing-settings": "DELETE FROM settings",
                "invalid-freeze": "UPDATE settings SET frozen=2",
                "invalid-revision": "UPDATE settings SET freeze_revision=1.5",
            }[damage])
    response = business.client().get(path)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert "DISPOSABLE_STORAGE_DIAGNOSTIC_CANARY" not in response.text
    assert "posts" not in response.json()
    if path == "/healthz":
        assert response.json() == {"status": "unavailable"}
    if damage == "missing-database":
        assert not database.path.exists()
