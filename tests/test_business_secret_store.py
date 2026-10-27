"""Real AES-GCM, separated key custody and atomic migration using fake accounts."""

import importlib.util
import os
from pathlib import Path
import secrets
import sqlite3

import pytest

pytest.importorskip("cryptography")

from tests.test_business_dashboard import (  # noqa: E402
    business as business, business_seed as business_seed,
)
from business import db  # noqa: E402
from business.secret_store import SecretStore, create_key_file, default_key_path, key_path  # noqa: E402


def _cli():
    path = Path(__file__).resolve().parents[1] / "examples/business_dashboard/run.py"
    spec = importlib.util.spec_from_file_location("business_secret_store_cli", path)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    return cli


def _enrollment(business):
    with business.db() as connection:
        return dict(connection.execute("SELECT * FROM admin_mfa WHERE user_id='admin'").fetchone())


def _legacy_four(business):
    row = _enrollment(business)
    secret = business.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], "admin", row["generation"])
    with business.db() as connection:
        connection.execute("DROP TABLE session_passkey")
        connection.execute("DROP TABLE passkey_challenges")
        connection.execute("DROP TABLE passkey_credentials")
        connection.execute("DROP TABLE session_security")
        connection.execute("DROP TABLE mfa_key_binding")
        connection.execute("ALTER TABLE admin_mfa RENAME COLUMN secret_ciphertext TO secret")
        connection.execute("UPDATE admin_mfa SET secret=? WHERE user_id='admin'", (secret,))
        connection.execute("PRAGMA user_version=4")
    return secret


def _snapshot(business):
    with business.db() as connection:
        return (
            connection.execute("PRAGMA user_version").fetchone()[0],
            [tuple(row) for row in connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name")],
            [tuple(row) for row in connection.execute("SELECT * FROM admin_mfa")],
            [tuple(row) for row in connection.execute("SELECT * FROM sessions ORDER BY token_hash")],
        )


def test_real_aesgcm_uses_random_nonces_and_binds_user_and_generation(business):
    store = business.app.state.database.mfa_secrets
    fake = "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"
    first, second = [store.encrypt(fake, "admin", "generation") for _ in range(2)]
    assert first != second and fake not in first
    assert store.decrypt(first, "admin", "generation") == fake
    for user, generation in (("other-user", "generation"), ("admin", "other-generation")):
        with pytest.raises(ValueError, match="ciphertext or encryption key"):
            store.decrypt(first, user, generation)
    for damaged in (fake, "v2." + first[3:], first[:-4] + "AAAA", "v1.not-base64!"):
        with pytest.raises(ValueError, match="ciphertext or encryption key"):
            store.decrypt(damaged, "admin", "generation")


def test_provisioned_database_contains_ciphertext_and_key_is_separate(business):
    row = _enrollment(business)
    store = business.app.state.database.mfa_secrets
    secret = store.decrypt(row["secret_ciphertext"], "admin", row["generation"])
    assert row["secret_ciphertext"].startswith("v1.")
    assert secret.encode() not in (business.directory / "business.sqlite3").read_bytes()
    assert business.directory not in store.path.parents
    assert store.path == default_key_path(business.directory)
    assert store.path.read_bytes() != (business.directory / "identity.key").read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        create_key_file(business.directory)


@pytest.mark.parametrize("failure", ["missing", "short", "wrong", "identity-key"])
def test_startup_refuses_missing_wrong_or_reused_key_without_repair(business, failure):
    path = default_key_path(business.directory)
    before = _snapshot(business)
    if failure == "missing":
        path.unlink()
    else:
        path.write_bytes(b"short" if failure == "short" else
                         (business.directory / "identity.key").read_bytes() if failure == "identity-key" else secrets.token_bytes(32))
    with pytest.raises(ValueError):
        db.Database(business.directory)
    assert _snapshot(business) == before
    if failure == "missing":
        assert not path.exists()


def test_wrong_key_rejected_even_when_no_admin_is_enrolled(business):
    with business.db() as connection:
        connection.execute("DELETE FROM admin_mfa")
    default_key_path(business.directory).write_bytes(secrets.token_bytes(32))
    with pytest.raises(ValueError, match="ciphertext or encryption key"):
        db.Database(business.directory)


def test_key_inside_runtime_or_source_is_rejected(business):
    for path in (business.directory / "key.bin", next(iter(db.SOURCE_ROOTS)) / "key.bin"):
        with pytest.raises(ValueError, match="outside source and runtime"):
            key_path(business.directory, path)


def test_hardlinked_key_is_rejected(business):
    original = default_key_path(business.directory)
    alternative = original.with_name("linked.key")
    os.link(original, alternative)
    with pytest.raises(ValueError, match="without links"):
        SecretStore(business.directory, business.app.state.database.identity_key, alternative)


@pytest.mark.skipif(os.name != "nt", reason="Windows path parsing")
@pytest.mark.parametrize("name", ["NUL", "mfa.key:alternate", "mfa.key.", "mfa.key "])
def test_windows_key_aliases_are_rejected(business, name):
    with pytest.raises(ValueError, match="ordinary MFA key filename"):
        key_path(business.directory, default_key_path(business.directory).with_name(name))


def test_explicit_migration_encrypts_preserves_and_backfills_stale_sessions(business):
    employee, admin = business.login("alex"), business.login("admin")
    secret = _legacy_four(business)
    before = _snapshot(business)
    with pytest.raises(ValueError, match="explicit reviewed migration"):
        db.Database(business.directory)
    assert _snapshot(business) == before
    migrated = db.Database(business.directory, migrate=True)
    row = _enrollment(business)
    assert migrated.mfa_secrets.decrypt(row["secret_ciphertext"], "admin", row["generation"]) == secret
    assert _snapshot(business)[0] == 5
    assert _snapshot(business)[3] == before[3]
    with business.db() as connection:
        sessions = connection.execute("SELECT * FROM session_security").fetchall()
        assert len(sessions) == 2
        assert {row["method"] for row in sessions} == {"password", "totp"}
        assert all(row["verified_at"] == 0 and len(row["public_id"]) == 32 for row in sessions)
        assert connection.execute("PRAGMA foreign_key_check").fetchone() is None
    assert employee.request("GET", "/api/messages").status_code == 200
    assert admin.request("GET", "/api/admin/posts").status_code == 200
    # Opening again validates existing encryption instead of reencrypting it.
    before = _snapshot(business)
    db.Database(business.directory)
    assert _snapshot(business) == before


def test_encryption_migration_failure_rolls_back_ddl_rows_and_version(business, monkeypatch):
    _legacy_four(business)
    before = _snapshot(business)
    migrate = db._apply_security_migration
    completed = []

    def fail_after_conversion(connection, store):
        migrate(connection, store)
        completed.append(True)
        raise sqlite3.OperationalError("Synthetic migration failure")

    monkeypatch.setattr(db, "_apply_security_migration", fail_after_conversion)
    with pytest.raises(ValueError):
        db.Database(business.directory, migrate=True)
    assert completed == [True]
    assert _snapshot(business) == before


def test_binding_rejects_another_database_identity(business):
    store = SecretStore(business.directory, secrets.token_bytes(32))
    row = _enrollment(business)
    with pytest.raises(ValueError, match="ciphertext or encryption key"):
        store.decrypt(row["secret_ciphertext"], "admin", row["generation"])
    with business.db() as connection:
        with pytest.raises(ValueError, match="ciphertext or encryption key"):
            store.validate_database(connection)


def test_hosted_preflight_requires_explicit_key_and_validates_encryption(business):
    from hosting import pilot

    configuration = pilot.Configuration("https://business.invalid", "business.invalid", business.directory, 10000)
    with pytest.raises(ValueError, match="BUSINESS_MFA_KEY_FILE"):
        pilot.inspect_existing_storage(configuration)
    configuration = pilot.Configuration(configuration.public_origin, configuration.hostname, business.directory,
                                        10000, default_key_path(business.directory))
    pilot.inspect_existing_storage(configuration)
    default_key_path(business.directory).write_bytes(secrets.token_bytes(32))
    with pytest.raises(ValueError, match="ciphertext or encryption key"):
        pilot.inspect_existing_storage(configuration)


def test_quarantined_restore_never_starts(business):
    (business.directory / "RESTORE_QUARANTINE").write_text("Reconciliation required.")
    with pytest.raises(ValueError, match="quarantined"):
        db.Database(business.directory)


def test_cli_requires_explicit_key_creation_and_migration_without_listening(business, monkeypatch, capsys):
    import uvicorn

    cli = _cli()
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: pytest.fail("Migration opened a listener"))
    _legacy_four(business)
    original = default_key_path(business.directory)
    original.unlink()
    assert cli.main(["--data-dir", str(business.directory), "--migrate-storage"]) == 1
    assert not original.exists()
    assert cli.main(["--data-dir", str(business.directory), "--create-mfa-key"]) == 0
    assert original.is_file()
    assert cli.main(["--data-dir", str(business.directory), "--migrate-storage"]) == 0
    assert _snapshot(business)[0] == 5
    out = capsys.readouterr()
    assert "Old backups and SQLite remnants" in out.out
    assert "External MFA encryption key created" in out.out


@pytest.mark.parametrize("hostname", [None, "127.0.0.1", "localhost"])
def test_cli_loopback_hostname_matches_real_app_host_origin_and_passkey_rp(business, monkeypatch, hostname):
    import uvicorn
    from fastapi.testclient import TestClient

    launches = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: launches.append((app, kwargs)))
    args = ["--data-dir", str(business.directory), "--port", "8092"]
    if hostname is not None:
        args += ["--hostname", hostname]
    assert _cli().main(args) == 0
    assert len(launches) == 1
    application, listener = launches[0]
    assert listener == {"host": "127.0.0.1", "port": 8092, "proxy_headers": False, "access_log": False, "workers": 1}
    selected = hostname or "127.0.0.1"
    other = "localhost" if selected == "127.0.0.1" else "127.0.0.1"
    origin = f"http://{selected}:8092"
    with TestClient(application, base_url=origin) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/healthz", headers={"Host": f"{other}:8092"}).status_code == 400
        payload = {"username": "alex", "password": business.credentials["alex"]}
        assert client.post("/api/login", json=payload, headers={"Origin": f"http://{other}:8092"}).status_code == 403
        assert client.post("/api/login", json=payload, headers={"Origin": origin}).status_code == 200
        inventory = client.get("/api/security/passkeys")
        assert inventory.status_code == 200
        assert inventory.json()["rp_id"] == selected


@pytest.mark.parametrize("hostname", ["0.0.0.0", "example.invalid", "https://localhost", "localhost:8091"])
def test_cli_rejects_arbitrary_hostname_before_app_or_listener(monkeypatch, hostname):
    import uvicorn
    from business import app

    monkeypatch.setattr(app, "create_app", lambda *a, **kw: pytest.fail("Invalid hostname created an app"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: pytest.fail("Invalid hostname opened a listener"))
    with pytest.raises(SystemExit) as error:
        _cli().main(["--hostname", hostname])
    assert error.value.code == 2
