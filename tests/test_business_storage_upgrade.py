"""Receipt schema upgrades preserve synthetic business state and identity."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    ORIGIN, business as business, business_admin as business_admin,
    business_seed as business_seed,
)
from business import db  # noqa: E402
from business.app import create_app  # noqa: E402


def _downgrade_v3(trial):
    with trial.db() as connection:
        rows = connection.execute("SELECT * FROM admin_mfa").fetchall()
        for row in rows:
            secret = trial.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
            connection.execute("UPDATE admin_mfa SET secret_ciphertext=? WHERE user_id=?", (secret, row["user_id"]))
        connection.execute("ALTER TABLE admin_mfa RENAME COLUMN secret_ciphertext TO secret")
        connection.execute("DROP TABLE session_passkey")
        connection.execute("DROP TABLE passkey_challenges")
        connection.execute("DROP TABLE passkey_credentials")
        connection.execute("DROP TABLE session_security")
        connection.execute("DROP TABLE mfa_key_binding")
        connection.execute("DROP TABLE create_receipts")
        connection.execute("PRAGMA user_version=3")


def _snapshot(trial):
    with trial.db() as connection:
        # Only fixed internal table names; secret material never enters assertion output.
        data = {
            table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")]
            for table in ("users", "sessions", "settings", "events", "assignments", "messages", "contacts",
                          "posts", "revenue", "activity", "login_limits", "submissions", "submission_limits",
                          "session_mfa")
        }
        data["admin_mfa"] = []
        for row in connection.execute("SELECT * FROM admin_mfa ORDER BY user_id"):
            secret = (trial.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
                      if "secret_ciphertext" in row.keys() else row["secret"])
            data["admin_mfa"].append((row["user_id"], secret, row["generation"], row["last_counter"]))
    files = {
        name: hashlib.sha256((trial.directory / name).read_bytes()).hexdigest()
        for name in ("identity.key", "ACCOUNTS.md", "ADMIN_MFA_SETUP.md")
    }
    return hashlib.sha256(json.dumps({"data": data, "files": files}, sort_keys=True).encode()).hexdigest()


def _schema(trial):
    with trial.db() as connection:
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
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
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
    with business.db() as connection:
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
        with business.db() as connection:
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
    assert _schema(business)[0] == 5
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
    assert captured.out == "Existing storage validated and upgraded to schema five. Old backups and SQLite remnants may still contain plaintext MFA seeds.\n"
    assert captured.err == ""
    assert _schema(business)[0] == 5
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
