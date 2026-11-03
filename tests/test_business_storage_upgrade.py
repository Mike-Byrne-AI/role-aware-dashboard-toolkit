"""Receipt schema upgrades preserve synthetic business state and identity."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    ORIGIN, business as business, business_admin as business_admin,
    business_seed as business_seed, downgrade_enrollment_schema,
)
from business import db  # noqa: E402
from business.app import create_app  # noqa: E402


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
@pytest.mark.parametrize("readonly", [False, True])
def test_connect_tolerates_auxiliary_file_removed_during_validation(business, monkeypatch, suffix, readonly):
    database = business.app.state.database
    auxiliary = Path(str(database.path) + suffix)
    db.create_private_file(auxiliary, b"")
    check = db.check_private_file
    removed = []

    def concurrent_removal(path):
        if path == auxiliary:
            auxiliary.unlink()
            removed.append(path)
        check(path)

    monkeypatch.setattr(db, "check_private_file", concurrent_removal)
    connection = database._connect(readonly=readonly)
    try:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()
    assert removed == [auxiliary]


@pytest.mark.parametrize("failure", [PermissionError, ValueError])
def test_connect_preserves_auxiliary_file_security_failures(business, monkeypatch, failure):
    database = business.app.state.database
    auxiliary = Path(str(database.path) + "-journal")
    db.create_private_file(auxiliary, b"")
    check = db.check_private_file

    def rejected_auxiliary(path):
        if path == auxiliary:
            raise failure("Disposable auxiliary file security failure")
        check(path)

    monkeypatch.setattr(db, "check_private_file", rejected_auxiliary)
    with pytest.raises(failure, match="security failure"):
        database._connect()


def test_connect_does_not_ignore_missing_main_database(business, monkeypatch):
    database = business.app.state.database
    check = db.check_private_file

    def missing_database(path):
        if path == database.path:
            raise FileNotFoundError("Disposable main database missing")
        check(path)

    monkeypatch.setattr(db, "check_private_file", missing_database)
    with pytest.raises(FileNotFoundError, match="main database missing"):
        database._connect()


def _replace_stat(info, *, mode=None, nlink=None, uid=None):
    fields = list(info)
    for index, value in ((0, mode), (3, nlink), (4, uid)):
        if value is not None:
            fields[index] = value
    return os.stat_result(fields)


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
@pytest.mark.parametrize("readonly", [False, True])
def test_connect_tolerates_auxiliary_unlinked_during_lstat(business, monkeypatch, suffix, readonly):
    database = business.app.state.database
    auxiliary = Path(str(database.path) + suffix)
    db.create_private_file(auxiliary, b"")
    unlinked_info = _replace_stat(auxiliary.lstat(), nlink=0)
    lstat = Path.lstat
    observed = []

    def unlinked_after_lookup(path, *args, **kwargs):
        if path == auxiliary and not observed:
            # Linux can resolve the inode before unlink, then read its metadata
            # afterward. Model that result without depending on thread timing.
            auxiliary.unlink()
            observed.append(path)
            return unlinked_info
        return lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", unlinked_after_lookup)
    connection = database._connect(readonly=readonly)
    try:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()
    assert observed == [auxiliary]


@pytest.mark.parametrize("damage", [
    "symlink", "fifo", "directory", "extra-link",
    pytest.param("public-mode", marks=pytest.mark.skipif(os.name != "posix", reason="POSIX private mode check")),
    pytest.param("other-owner", marks=pytest.mark.skipif(os.name != "posix", reason="POSIX ownership check")),
])
def test_connect_rejects_unsafe_auxiliary_metadata_even_with_zero_links(business, monkeypatch, damage):
    database = business.app.state.database
    auxiliary = Path(str(database.path) + "-journal")
    db.create_private_file(auxiliary, b"")
    info = auxiliary.lstat()
    modes = {"symlink": stat.S_IFLNK, "fifo": stat.S_IFIFO, "directory": stat.S_IFDIR}
    metadata = _replace_stat(
        info, nlink=2 if damage == "extra-link" else 0,
        mode=(modes[damage] | 0o600) if damage in modes else
             (stat.S_IFREG | 0o644) if damage == "public-mode" else None,
        uid=info.st_uid + 1 if damage == "other-owner" else None,
    )
    lstat = Path.lstat

    def unsafe_metadata(path, *args, **kwargs):
        return metadata if path == auxiliary else lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", unsafe_metadata)
    with pytest.raises(ValueError, match="Runtime files must"):
        database._connect()


def test_zero_link_required_database_is_refused_before_sqlite_open(business, monkeypatch):
    database = business.app.state.database
    metadata = _replace_stat(database.path.lstat(), nlink=0)
    lstat = Path.lstat

    def unlinked_database(path, *args, **kwargs):
        return metadata if path == database.path else lstat(path, *args, **kwargs)

    def forbidden_open(*args, **kwargs):
        pytest.fail("Missing required database reached SQLite")

    monkeypatch.setattr(Path, "lstat", unlinked_database)
    monkeypatch.setattr(db.sqlite3, "connect", forbidden_open)
    with pytest.raises((ValueError, FileNotFoundError)):
        database._connect()
    # Other mandatory file callers use the same strict helper.
    with pytest.raises((ValueError, FileNotFoundError)):
        db.check_private_file(database.path)


def test_connect_rejects_a_real_hardlinked_auxiliary(business):
    database = business.app.state.database
    target = database.directory / "disposable-sidecar-target"
    auxiliary = Path(str(database.path) + "-journal")
    db.create_private_file(target, b"")
    auxiliary.hardlink_to(target)
    with pytest.raises(ValueError, match="without links"):
        database._connect()


def _downgrade_v3(trial):
    with trial.db() as connection:
        downgrade_enrollment_schema(connection)
        connection.execute("DELETE FROM session_mfa WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id<>'admin')")
        connection.execute("DELETE FROM admin_mfa WHERE user_id<>'admin'")
        rows = connection.execute("SELECT * FROM admin_mfa").fetchall()
        for row in rows:
            secret = trial.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
            connection.execute("UPDATE admin_mfa SET secret_ciphertext=? WHERE user_id=?", (secret, row["user_id"]))
        connection.execute("ALTER TABLE admin_mfa RENAME COLUMN secret_ciphertext TO secret")
        for table in ("security_sink_receipts", "security_outbox", "security_denial_budget", "security_events"):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DROP TABLE session_predecessors")
        connection.execute("DROP TABLE session_passkey")
        connection.execute("DROP TABLE passkey_challenges")
        connection.execute("DROP TABLE passkey_credentials")
        connection.execute("DROP TABLE session_security")
        connection.execute("DROP TABLE mfa_key_binding")
        connection.execute("DROP TABLE create_receipts")
        connection.execute("PRAGMA user_version=3")


def _snapshot(trial):
    with trial.raw_db() as connection:
        renamed = connection.execute("SELECT name FROM sqlite_master WHERE name='account_mfa'").fetchone()
        mfa_table = "account_mfa" if renamed else "admin_mfa"
        # Only fixed internal table names; secret material never enters assertion output.
        data = {
            table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")]
            for table in ("users", "sessions", "settings", "events", "assignments", "messages", "contacts",
                          "posts", "revenue", "activity", "login_limits", "submissions", "submission_limits",
                          "session_mfa")
        }
        data["admin_mfa"] = []
        for row in connection.execute(f"SELECT * FROM {mfa_table} ORDER BY user_id"):
            secret = (trial.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
                      if "secret_ciphertext" in row.keys() else row["secret"])
            data["admin_mfa"].append((row["user_id"], secret, row["generation"], row["last_counter"]))
    files = {
        name: hashlib.sha256((trial.directory / name).read_bytes()).hexdigest()
        for name in ("identity.key", "ACCOUNTS.md")
    }
    return hashlib.sha256(json.dumps({"data": data, "files": files}, sort_keys=True).encode()).hexdigest()


def _schema(trial):
    with trial.raw_db() as connection:
        return (connection.execute("PRAGMA user_version").fetchone()[0],
                [tuple(row) for row in connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name")])


def test_v3_upgrade_preserves_data_admin_and_employee_sessions_and_identity(business, business_admin):
    employee = business.login("alex")
    assert employee.request("POST", "/api/messages", json={"body": "History retained across upgrade"}).status_code == 201
    _downgrade_v3(business)
    before = _snapshot(business)
    with pytest.raises(ValueError, match="explicit"):
        create_app(business.directory, public_origin=ORIGIN)
    db.Database(business.directory, migrate=True)
    replacement = create_app(business.directory, public_origin=ORIGIN)
    assert _snapshot(business) == before
    with business.db() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
        assert connection.execute("SELECT COUNT(*) FROM create_receipts").fetchone()[0] == 0
        assert connection.execute("PRAGMA foreign_key_check").fetchone() is None
    admin_client = business.client(replacement)
    admin_client.cookies.update(business_admin.client.cookies)
    assert admin_client.get("/api/admin/contacts").status_code == 200
    assert employee.request("GET", "/api/messages").status_code == 200
    # Opening already upgraded storage is idempotent and does not reset sessions.
    before = _snapshot(business)
    db.Database(business.directory)
    assert _snapshot(business) == before


@pytest.mark.parametrize("damage", ["receipt-table-collision", "missing-existing-index"])
def test_v3_upgrade_refuses_unexpected_schema_before_any_ddl(business, damage):
    _downgrade_v3(business)
    with business.raw_db() as connection:
        if damage == "receipt-table-collision":
            connection.execute("CREATE TABLE create_receipts(preserved TEXT)")
            connection.execute("INSERT INTO create_receipts VALUES('Keep existing data')")
        else:
            connection.execute("DROP INDEX submission_limits_time")
    schema_before, data_before = _schema(business), _snapshot(business)
    with pytest.raises(ValueError):
        db.Database(business.directory, migrate=True)
    assert _schema(business) == schema_before
    assert _snapshot(business) == data_before
    if damage == "receipt-table-collision":
        with business.raw_db() as connection:
            assert connection.execute("SELECT preserved FROM create_receipts").fetchone()[0] == "Keep existing data"


def test_v3_upgrade_ddl_and_version_roll_back_together_on_storage_failure(business, business_admin, monkeypatch):
    _downgrade_v3(business)
    schema_before, data_before = _schema(business), _snapshot(business)
    apply = db._apply_receipt_migration

    def fail(connection):
        apply(connection)
        raise sqlite3.OperationalError("Synthetic upgrade failure")

    with monkeypatch.context() as patch:
        patch.setattr(db, "_apply_receipt_migration", fail)
        with pytest.raises(ValueError):
            db.Database(business.directory, migrate=True)
    assert _schema(business) == schema_before
    assert _snapshot(business) == data_before
    db.Database(business.directory, migrate=True)
    assert _schema(business)[0] == 10
    assert _snapshot(business) == data_before


def _cli():
    path = Path(__file__).resolve().parents[1] / "examples/business_dashboard/run.py"
    spec = importlib.util.spec_from_file_location("business_storage_upgrade_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_explicit_upgrade_cli_exits_without_listener_provisioning_or_secret_output(business, monkeypatch, capsys):
    import uvicorn
    from business import mfa, seed

    def forbidden(*args, **kwargs):
        pytest.fail("Upgrade unexpectedly started a listener or provisioned credentials")

    monkeypatch.setattr(uvicorn, "run", forbidden)
    monkeypatch.setattr(seed, "provision", forbidden)
    monkeypatch.setattr(mfa, "setup_admin_mfa", forbidden)
    _downgrade_v3(business)
    before = _snapshot(business)
    assert _cli().main(["--data-dir", str(business.directory), "--migrate-storage"]) == 0
    captured = capsys.readouterr()
    assert captured.out == (
        "Existing storage validated and upgraded to schema ten. Keep all older writers stopped; mixed schema versions are unsupported. "
        "Existing sessions remain usable, but reverification requires browser-flow bootstrap. Legacy access remains in transition until "
        "reviewed enrollment and explicit strict activation. Old backups and SQLite remnants may still contain plaintext MFA seeds. Remote security-event delivery requires separate explicit activation.\n"
    )
    assert captured.err == ""
    assert _schema(business)[0] == 10
    assert _snapshot(business) == before


def test_upgrade_cli_refuses_unsupported_version_without_mutating_storage(business, monkeypatch, capsys):
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: pytest.fail("Invalid storage started a listener"))
    with business.db() as connection:
        connection.execute("PRAGMA user_version=99")
    before = _schema(business), _snapshot(business)
    assert _cli().main(["--data-dir", str(business.directory), "--migrate-storage"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Cannot start: Unsupported or incomplete business database.\n"
    assert (_schema(business), _snapshot(business)) == before
