"""Isolated legacy migration preserves identity/data and commits all-or-nothing."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import sqlite3
import time

from fastapi.testclient import TestClient
import pytest

from .conftest import COOKIE

TABLES = ("users", "sessions", "settings", "messages", "customers", "audit", "login_limits", "telemetry", "request_samples")


def snapshot(path):
    with closing(sqlite3.connect(path)) as connection:
        return {table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall() for table in (*TABLES, "jobs")}


@dataclass
class Legacy:
    directory: Path
    original: dict = field(repr=False)
    token: str = field(repr=False)
    identity_key: bytes = field(repr=False)
    alex_id: str

    @property
    def path(self):
        return self.directory / "landscape.sqlite3"


@pytest.fixture
def legacy(tmp_path, seeded_template):
    from landscape.security import csrf_for_token, new_token, token_hash

    template, _ = seeded_template
    directory = tmp_path / "legacy"
    directory.mkdir(mode=0o700)
    shutil.copy2(template / "identity.key", directory / "identity.key")
    identity_key = (directory / "identity.key").read_bytes()
    path = directory / "landscape.sqlite3"
    token = new_token()
    with closing(sqlite3.connect(path)) as connection, closing(sqlite3.connect(template / "landscape.sqlite3")) as source:
        connection.executescript(Path(__file__).with_name("legacy_schema.sql").read_text())
        for table in TABLES:
            rows = source.execute(f"SELECT * FROM {table}").fetchall()
            connection.execute(f"DELETE FROM {table}")
            if rows:
                placeholders = ",".join("?" for _ in rows[0])
                connection.executemany(f"INSERT INTO {table} VALUES({placeholders})", rows)
        users = dict(connection.execute("SELECT username,id FROM users"))
        now = time.time()
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)", (token_hash(token), users["alex"], token_hash(csrf_for_token(token, identity_key)), now, now, now + 28800))
        connection.execute("UPDATE settings SET frozen=1,freeze_revision=7,changed_by=?", (users["admin"],))
        connection.execute("INSERT INTO messages(author_id,body,created_at) VALUES(?,?,?)", (users["alex"], "Keep this legacy message", datetime.now(timezone.utc).isoformat()))
        connection.execute("UPDATE telemetry SET requests=17,denied_requests=3,failed_logins=2")
        connection.execute("INSERT INTO login_limits VALUES(?,?,?)", ("synthetic-limit-hash", now, 2))
        for number, owner in enumerate(("alex", "blair", "casey")):
            signed = users[owner] if number < 2 else None
            starts_at = (datetime.now(timezone.utc) + timedelta(days=number + 1)).isoformat()
            connection.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?)", (f"legacy-job-{number}", users[owner], f"Legacy customer {number}", f"{number} Legacy Lane", "mowing", starts_at, 1.5 + number, 70 + number, "signed_up" if signed else "available", signed))
        connection.commit()
    path.chmod(0o600)
    return Legacy(directory, snapshot(path), token, identity_key, users["alex"])


def test_migration_preserves_accounts_sessions_records_and_never_restores_cancelled_membership(legacy):
    from landscape.db import Database

    Database(legacy.directory)
    after = snapshot(legacy.path)
    for table in TABLES:
        assert after[table] == legacy.original[table], f"Migration changed legacy {table}"
    assert (legacy.directory / "identity.key").read_bytes() == legacy.identity_key
    expected = [(row[0], row[2], row[3], row[4], row[5], row[6], row[7], 2, 0, 0, "scheduled") for row in legacy.original["jobs"]]
    assert after["jobs"] == expected
    with closing(sqlite3.connect(legacy.path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT * FROM job_legacy_archive ORDER BY rowid").fetchall() == legacy.original["jobs"]
        memberships = set(connection.execute("SELECT job_id,user_id FROM job_signups"))
        assert memberships == {(row[0], row[9]) for row in legacy.original["jobs"] if row[9] is not None}
        connection.execute("DELETE FROM job_signups WHERE job_id=? AND user_id=?", ("legacy-job-0", legacy.alex_id))
        connection.commit()
    Database(legacy.directory)
    Database(legacy.directory)
    with closing(sqlite3.connect(legacy.path)) as connection:
        assert connection.execute("SELECT 1 FROM job_signups WHERE job_id='legacy-job-0'").fetchone() is None
        assert connection.execute("SELECT COUNT(*) FROM job_signups").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    # The unexpired pre-migration bearer still identifies its original account.
    from landscape.app import create_app
    with TestClient(create_app(legacy.directory, testing=True)) as client:
        client.cookies.set(COOKIE, legacy.token)
        response = client.get("/api/session")
        assert response.status_code == 200
        assert response.json()["user"]["id"] == legacy.alex_id
        assert response.json()["frozen"] is True and response.json()["freeze_revision"] == 7


def test_migration_failure_after_ddl_rolls_back_every_legacy_table(legacy, monkeypatch):
    from landscape import db

    original = db._schema_statements

    def fail_after_new_schema(connection):
        assert connection.in_transaction
        assert connection.execute("SELECT COUNT(*) FROM job_legacy_archive").fetchone()[0] == 3
        original(connection)
        raise RuntimeError("Synthetic migration interruption")

    monkeypatch.setattr(db, "_schema_statements", fail_after_new_schema)
    with pytest.raises(RuntimeError, match="Synthetic migration interruption"):
        db.Database(legacy.directory)
    assert snapshot(legacy.path) == legacy.original
    with closing(sqlite3.connect(legacy.path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        assert "job_legacy_archive" not in tables and "job_signups" not in tables
    monkeypatch.setattr(db, "_schema_statements", original)
    db.Database(legacy.directory)
    with closing(sqlite3.connect(legacy.path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4


def test_concurrent_initializers_do_not_duplicate_or_lose_legacy_enrollments(legacy):
    from landscape.db import Database

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(Database, legacy.directory) for _ in range(3)]
        for future in futures:
            future.result(timeout=20)
    with closing(sqlite3.connect(legacy.path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM job_signups").fetchone()[0] == 2
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    after = snapshot(legacy.path)
    for table in TABLES:
        assert after[table] == legacy.original[table], f"Concurrent initialization changed {table}"


@pytest.fixture
def shared_v2(tmp_path, seeded_template):
    """Reproduce the shipped shared schedule schema without new job columns."""
    template, _ = seeded_template
    directory = tmp_path / "shared-v2"
    shutil.copytree(template, directory)
    with closing(sqlite3.connect(directory / "landscape.sqlite3")) as connection:
        connection.execute("DROP TABLE job_history")
        connection.execute("ALTER TABLE jobs DROP COLUMN lifecycle")
        connection.execute("ALTER TABLE jobs DROP COLUMN revision")
        connection.execute("ALTER TABLE jobs DROP COLUMN archived")
        connection.execute("PRAGMA user_version=2")
        connection.commit()
    return directory


def test_v2_migration_preserves_accounts_sessions_and_memberships_without_reseeding(shared_v2):
    from landscape.db import Database

    path = shared_v2 / "landscape.sqlite3"
    before = snapshot(path)
    key = (shared_v2 / "identity.key").read_bytes()
    handoff = (shared_v2 / "TRIAL_ACCOUNTS.md").read_bytes()
    with closing(sqlite3.connect(path)) as connection:
        memberships = connection.execute("SELECT * FROM job_signups ORDER BY rowid").fetchall()
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(Database, shared_v2) for _ in range(3)]
        for future in futures:
            future.result(timeout=20)
    after = snapshot(path)
    for table in TABLES:
        assert after[table] == before[table], f"Migration changed shared schedule {table}"
    assert after["jobs"] == [(*row, 0, 0, "scheduled") for row in before["jobs"]]
    assert (shared_v2 / "identity.key").read_bytes() == key
    assert (shared_v2 / "TRIAL_ACCOUNTS.md").read_bytes() == handoff
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT * FROM job_signups ORDER BY rowid").fetchall() == memberships
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        job_id, user_id, _ = memberships[0]
        connection.execute("DELETE FROM job_signups WHERE job_id=? AND user_id=?", (job_id, user_id))
        connection.execute("UPDATE jobs SET archived=1,revision=12 WHERE id=?", (job_id,))
        connection.commit()
    Database(shared_v2)
    Database(shared_v2)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT archived,revision FROM jobs WHERE id=?", (job_id,)).fetchone() == (1, 12)
        assert connection.execute("SELECT 1 FROM job_signups WHERE job_id=? AND user_id=?", (job_id, user_id)).fetchone() is None


def test_v2_migration_rolls_back_column_changes_and_version_together(shared_v2, monkeypatch):
    from landscape import db

    path = shared_v2 / "landscape.sqlite3"
    before = snapshot(path)
    original = db._schema_statements

    def fail_after_column_addition(connection):
        assert {row["name"] for row in connection.execute("PRAGMA table_info(jobs)")} >= {"archived", "revision"}
        original(connection)
        raise RuntimeError("Synthetic shared migration interruption")

    monkeypatch.setattr(db, "_schema_statements", fail_after_column_addition)
    with pytest.raises(RuntimeError, match="Synthetic shared migration interruption"):
        db.Database(shared_v2)
    assert snapshot(path) == before
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert "archived" not in {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
    monkeypatch.setattr(db, "_schema_statements", original)
    db.Database(shared_v2)
    assert snapshot(path)["jobs"] == [(*row, 0, 0, "scheduled") for row in before["jobs"]]


@pytest.fixture
def managed_v3(tmp_path, seeded_template):
    """Reproduce the shipped admin management release and its retained crew."""
    template, _ = seeded_template
    directory = tmp_path / "managed-v3"
    shutil.copytree(template, directory)
    with closing(sqlite3.connect(directory / "landscape.sqlite3")) as connection:
        connection.execute("DROP TABLE job_history")
        connection.execute("ALTER TABLE jobs DROP COLUMN lifecycle")
        connection.execute("UPDATE jobs SET archived=1,revision=9 WHERE id=(SELECT id FROM jobs ORDER BY id LIMIT 1)")
        connection.execute("PRAGMA user_version=3")
        connection.commit()
    return directory


def test_v3_migration_preserves_archives_revisions_and_crew(managed_v3):
    from landscape.db import Database

    path = managed_v3 / "landscape.sqlite3"
    before = snapshot(path)
    with closing(sqlite3.connect(path)) as connection:
        crew = connection.execute("SELECT * FROM job_signups ORDER BY rowid").fetchall()
    Database(managed_v3)
    Database(managed_v3)
    after = snapshot(path)
    assert after["jobs"] == [(*row, "scheduled") for row in before["jobs"]]
    for table in TABLES:
        assert after[table] == before[table]
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert connection.execute("SELECT * FROM job_signups ORDER BY rowid").fetchall() == crew
        assert connection.execute("SELECT COUNT(*) FROM job_history").fetchone()[0] == 0


def test_v3_migration_rolls_back_lifecycle_history_and_version(managed_v3, monkeypatch):
    from landscape import db

    path = managed_v3 / "landscape.sqlite3"
    before = snapshot(path)
    original = db._schema_statements

    def fail_after_schema(connection):
        original(connection)
        raise RuntimeError("Synthetic lifecycle migration interruption")

    monkeypatch.setattr(db, "_schema_statements", fail_after_schema)
    with pytest.raises(RuntimeError, match="Synthetic lifecycle migration interruption"):
        db.Database(managed_v3)
    assert snapshot(path) == before
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert connection.execute("SELECT name FROM sqlite_schema WHERE name='job_history'").fetchone() is None
    monkeypatch.setattr(db, "_schema_statements", original)
    db.Database(managed_v3)
    assert snapshot(path)["jobs"] == [(*row, "scheduled") for row in before["jobs"]]
