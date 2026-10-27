"""Consistent recovery with disposable accounts; no existing runtime data."""

from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import zipfile

import pytest

from tests.test_business_dashboard import (
    ORIGIN, business as business, business_admin as business_admin, business_seed as business_seed,
)
from business.db import Database
from business.secret_store import SecretStore, default_key_path
from business.security import COOKIE_NAME, hash_password, principal_for_user
from business.app import create_app
from business import mfa

SCRIPT = Path(__file__).resolve().parents[1] / "examples/business_dashboard/backup.py"
SPEC = importlib.util.spec_from_file_location("business_backup", SCRIPT)
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


def _rows(directory, table):
    with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
        return connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()


def _fingerprint(directory):
    # Digests keep synthetic credentials out of failure output.
    with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
        return hashlib.sha256("\n".join(connection.iterdump()).encode()).hexdigest()


def _make_backup(trial):
    output = trial.directory.parent / "backup"
    backup.create_backup(trial.directory, output, mfa_key_file=default_key_path(trial.directory))
    return output


def test_backup_captures_committed_wal_records_and_excludes_external_secrets(business):
    before_identity = hashlib.sha256((business.directory / "identity.key").read_bytes()).hexdigest()
    with closing(sqlite3.connect(business.directory / "business.sqlite3")) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("INSERT INTO messages VALUES('wal-record','alex','Committed WAL business record','2026-10-27')")
        writer.commit()
        before = _fingerprint(business.directory)
        output = _make_backup(business)
        assert _fingerprint(output) == before
    assert _fingerprint(business.directory) == before
    assert {item.name for item in output.iterdir()} == {"business.sqlite3", "identity.key", "manifest.json"}
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["external_mfa_key_included"] is False
    assert manifest["encrypted"] is False
    assert manifest["files"]["identity.key"] == before_identity
    assert default_key_path(business.directory).is_file()


@pytest.mark.parametrize("journal_mode", ["DELETE", "WAL"])
def test_quarantine_preserves_business_data_revokes_sessions_and_cannot_start(business, business_admin, journal_mode):
    with closing(sqlite3.connect(business.directory / "business.sqlite3")) as connection:
        connection.execute("PRAGMA journal_mode=" + journal_mode)
    employee = business.login("alex")
    output = _make_backup(business)
    before = _fingerprint(output)
    restored = business.directory.parent / "restored"
    result = backup.restore_backup(output, restored, mfa_key_file=default_key_path(business.directory))
    assert result == {"quarantined": True, "sessions_revoked": True, "frozen": True}
    assert (restored / backup.QUARANTINE).is_file()
    assert all(row[5] == 0 and row[3] == "!restore-quarantined!" for row in _rows(restored, "users"))
    for table in ("sessions", "session_mfa", "session_security", "session_passkey", "passkey_challenges"):
        assert _rows(restored, table) == []
    for table in ("messages", "events", "assignments", "contacts", "posts", "admin_mfa", "mfa_key_binding"):
        assert _rows(restored, table) == _rows(output, table)
    assert _fingerprint(output) == before
    with pytest.raises(ValueError, match="quarantined"):
        Database(restored, mfa_key_file=default_key_path(business.directory))
    assert employee.request("GET", "/api/messages").status_code == 200


def test_reconciled_restore_uses_current_password_disable_mfa_limits_and_revokes_old_sessions(business, business_admin):
    employee = business.login("alex")
    old_cookie = employee.client.cookies.get(COOKIE_NAME)
    output = _make_backup(business)
    old_mfa = hashlib.sha256(json.dumps(_rows(output, "admin_mfa")).encode()).hexdigest()
    new_password = "Disposable recovered password 93724!"
    with business.db() as connection:
        connection.execute("UPDATE users SET password_hash=?,revision=revision+1 WHERE id='alex'", (hash_password(new_password),))
        connection.execute("UPDATE users SET active=0,revision=revision+1 WHERE id='blair'")
        connection.execute("INSERT INTO login_limits VALUES('current-opaque-budget',12345,7)")
        connection.execute("INSERT INTO submission_limits(key_hash,submitted_at) VALUES('current-opaque-peer',12345)")
    mfa.setup_admin_mfa(business.directory, reset=True)
    current_state = _fingerprint(business.directory)
    backup_state = _fingerprint(output)
    restored = business.directory.parent / "reconciled"
    result = backup.restore_backup(output, restored, security_source=business.directory,
                                   mfa_key_file=default_key_path(business.directory))
    assert not result["quarantined"]
    assert not (restored / backup.QUARANTINE).exists()
    assert _fingerprint(business.directory) == current_state
    assert _fingerprint(output) == backup_state
    for table in ("users", "admin_mfa", "mfa_key_binding", "passkey_credentials", "login_limits", "submission_limits"):
        assert _rows(restored, table) == _rows(business.directory, table)
    assert hashlib.sha256(json.dumps(_rows(restored, "admin_mfa")).encode()).hexdigest() != old_mfa
    for table in ("sessions", "session_mfa", "session_security", "session_passkey", "passkey_challenges"):
        assert _rows(restored, table) == []
    restored_app = create_app(restored, public_origin=ORIGIN, mfa_key_file=default_key_path(business.directory))
    client = business.client(restored_app)
    assert client.get("/api/messages", headers={"Cookie": f"{COOKIE_NAME}={old_cookie}"}).status_code == 401
    assert client.post("/api/login", json={"username": "alex", "password": business.credentials["alex"]},
                       headers={"Origin": ORIGIN}).status_code == 401
    signed_in = client.post("/api/login", json={"username": "alex", "password": new_password}, headers={"Origin": ORIGIN})
    assert signed_in.status_code == 200
    assert signed_in.json()["frozen"] is True
    assert client.post("/api/messages", json={"body": "Must remain frozen"},
                       headers={"Origin": ORIGIN, "X-CSRF-Token": signed_in.json()["csrf"]}).status_code == 403
    assert business.client(restored_app).post("/api/login", json={"username": "blair", "password": business.credentials["blair"]},
                                            headers={"Origin": ORIGIN}).status_code == 401


@pytest.mark.parametrize("damage", ["checksum", "missing-key", "wrong-key", "different-identity", "different-users", "backup-as-authority"])
def test_restore_refuses_mismatch_before_creating_output(business, damage):
    bundle = _make_backup(business)
    restored = business.directory.parent / "must-not-exist"
    key = default_key_path(business.directory)
    current = business.directory
    if damage == "checksum":
        with (bundle / "business.sqlite3").open("ab") as stream:
            stream.write(b"corrupt")
    elif damage == "missing-key":
        key = key.with_name("absent.key")
    elif damage == "wrong-key":
        wrong = key.with_name("wrong.key")
        backup.create_private_file(wrong, b"x" * 32)
        key = wrong
    elif damage == "different-identity":
        # Current Database rejects a key that no longer binds its own principals.
        (business.directory / "identity.key").write_bytes(b"y" * 32)
    elif damage == "different-users":
        with business.db() as connection:
            connection.execute("INSERT INTO users VALUES('new-user','new-user','New fictional user',"
                               "'invalid-password','employee',0,?,0)",
                               (principal_for_user('new-user', business.app.state.database.identity_key),))
    elif damage == "backup-as-authority":
        current = bundle
    before = _fingerprint(business.directory)
    with pytest.raises((ValueError, OSError)):
        backup.restore_backup(bundle, restored, security_source=current, mfa_key_file=key)
    assert not restored.exists()
    assert _fingerprint(business.directory) == before


def test_existing_output_and_incomplete_backup_never_overwritten(business):
    bundle = _make_backup(business)
    marker = bundle / "keep.txt"
    backup.create_private_file(marker, b"Existing operator file")
    before = _fingerprint(business.directory)
    with pytest.raises(ValueError):
        backup.create_backup(business.directory, bundle, mfa_key_file=default_key_path(business.directory))
    with pytest.raises(ValueError, match="unexpected"):
        backup.restore_backup(bundle, business.directory.parent / "refused", mfa_key_file=default_key_path(business.directory))
    assert marker.read_bytes() == b"Existing operator file"
    assert _fingerprint(business.directory) == before


def test_reconcile_after_external_key_rotation_uses_separate_original_and_current_keys(business):
    bundle = _make_backup(business)
    old_key = default_key_path(business.directory)
    new_key = old_key.with_name("rotated.key")
    backup.create_private_file(new_key, b"r" * 32)
    new_secrets = SecretStore(business.directory, business.app.state.database.identity_key, new_key)
    with business.db() as connection:
        for row in connection.execute("SELECT * FROM admin_mfa").fetchall():
            secret = business.app.state.database.mfa_secrets.decrypt(row["secret_ciphertext"], row["user_id"], row["generation"])
            connection.execute("UPDATE admin_mfa SET secret_ciphertext=? WHERE user_id=?",
                               (new_secrets.encrypt(secret, row["user_id"], row["generation"]), row["user_id"]))
        connection.execute("UPDATE mfa_key_binding SET ciphertext=? WHERE id=1", (new_secrets.create_binding(),))
    restored = business.directory.parent / "restored-after-key-rotation"
    result = backup.restore_backup(bundle, restored, mfa_key_file=new_key, backup_mfa_key_file=old_key,
                                   security_source=business.directory)
    assert not result["quarantined"]
    Database(restored, mfa_key_file=new_key)
    with pytest.raises(ValueError, match="ciphertext|encryption key"):
        Database(restored, mfa_key_file=old_key)
    assert _rows(restored, "admin_mfa") == _rows(business.directory, "admin_mfa")


def test_final_snapshot_failure_leaves_offline_marker_and_sources_unchanged(business, monkeypatch):
    bundle = _make_backup(business)
    restored = business.directory.parent / "failed-publication"
    before = _fingerprint(business.directory), _fingerprint(bundle)
    original = backup._snapshot

    def fail_publication(source, destination):
        if destination.parent == restored:
            raise OSError("Disposable simulated storage failure")
        return original(source, destination)

    monkeypatch.setattr(backup, "_snapshot", fail_publication)
    with pytest.raises(OSError):
        backup.restore_backup(bundle, restored, security_source=business.directory,
                              mfa_key_file=default_key_path(business.directory))
    assert (restored / backup.QUARANTINE).is_file()
    with pytest.raises(ValueError, match="quarantined"):
        Database(restored, mfa_key_file=default_key_path(business.directory))
    assert (_fingerprint(business.directory), _fingerprint(bundle)) == before


def test_restore_does_not_resurrect_removed_passkeys_or_inflight_challenges(business):
    # Structural recovery fixtures, not a substitute for WebAuthn verification.
    with business.db() as connection:
        for key, counter in ((b"removed-credential", 0), (b"retained-credential", 1)):
            connection.execute("INSERT INTO passkey_credentials VALUES(?,?,?,?,?,?,0,0,?,1,NULL,0)",
                               (key, "alex", key.decode(), b"synthetic-handle", b"synthetic-public-key", counter, "Disposable key"))
        connection.execute("INSERT INTO sessions VALUES('old-passkey-session','alex',1,1,9999999999)")
        connection.execute("INSERT INTO session_passkey VALUES('old-passkey-session',?)", (b"removed-credential",))
        connection.execute("INSERT INTO passkey_challenges VALUES('old-challenge','login',?,'old-browser',NULL,NULL,1)", (b"synthetic-challenge",))
    bundle = _make_backup(business)
    with business.db() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash='old-passkey-session'")
        connection.execute("DELETE FROM passkey_credentials WHERE credential_id=?", (b"removed-credential",))
        connection.execute("UPDATE passkey_credentials SET sign_count=20,revision=revision+1")
        connection.execute("INSERT INTO passkey_challenges VALUES('current-challenge','login',?,'current-browser',NULL,NULL,2)", (b"current-challenge",))
    before = _fingerprint(business.directory)
    restored = business.directory.parent / "passkey-reconciled"
    backup.restore_backup(bundle, restored, mfa_key_file=default_key_path(business.directory), security_source=business.directory)
    assert _rows(restored, "passkey_credentials") == _rows(business.directory, "passkey_credentials")
    assert len(_rows(restored, "passkey_credentials")) == 1
    assert _rows(restored, "passkey_credentials")[0][5] == 20
    for table in ("passkey_challenges", "session_passkey", "sessions"):
        assert _rows(restored, table) == []
    assert _fingerprint(business.directory) == before


def test_missing_access_state_reports_safe_failure_before_restore_publication(business, capsys):
    bundle = _make_backup(business)
    with closing(sqlite3.connect(bundle / "business.sqlite3")) as connection:
        connection.execute("DELETE FROM settings")
        connection.commit()
    manifest = json.loads((bundle / "manifest.json").read_text())
    manifest["files"]["business.sqlite3"] = backup._digest(bundle / "business.sqlite3")
    (bundle / "manifest.json").write_text(json.dumps(manifest))
    restored = business.directory.parent / "invalid-state"
    assert backup.main(["restore", str(bundle), "--output", str(restored),
                        "--mfa-key-file", str(default_key_path(business.directory))]) == 1
    assert not restored.exists()
    captured = capsys.readouterr()
    assert "refused" in captured.err and "Traceback" not in captured.err


def _hosting_snippet(name, directory):
    guide = SCRIPT.with_name("HOSTING.md").read_text(encoding="utf-8")
    source = guide.split(f"# staging-{name}-bundle\n", 1)[1].split("\nPY\n", 1)[0]
    return subprocess.run([sys.executable, "-B", "-c", source], capture_output=True, text=True,
                          env={**os.environ, "CUTOVER_DIR": str(directory), "PYTHONDONTWRITEBYTECODE": "1"})


def _backup_cli(*arguments):
    return subprocess.run([sys.executable, "-B", str(SCRIPT), *map(str, arguments)],
                          capture_output=True, text=True,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def test_hosting_archive_snippets_and_cli_restore_large_bundle_with_current_authority(business):
    attempt = business.directory.parent / "staging-attempt"
    attempt.mkdir(mode=0o700)
    with business.db() as connection:
        connection.execute("INSERT INTO messages VALUES('large-doc-drill','alex',?,'2026-10-27')",
                           ("Disposable archive record " * 50000,))
    key = default_key_path(business.directory)
    created = _backup_cli("backup", business.directory, "--output", attempt / "bundle", "--mfa-key-file", key)
    assert created.returncode == 0, created.stderr
    packed = _hosting_snippet("pack", attempt)
    assert packed.returncode == 0, packed.stderr
    assert (attempt / "backup.zip").stat().st_size > 1024 * 1024
    # This test verifies the documented packing boundary. Real age encryption
    # and decryption are exercised separately by the native recovery drill.
    shutil.copyfile(attempt / "backup.zip", attempt / "recovered.zip")
    unpacked = _hosting_snippet("unpack", attempt)
    assert unpacked.returncode == 0, unpacked.stderr
    assert {path.name for path in (attempt / "decrypted-bundle").iterdir()} == {*backup.FILES, "manifest.json"}
    with business.db() as connection:
        connection.execute("UPDATE users SET active=0,revision=revision+1 WHERE id='blair'")
    custody = attempt / "key-custody"
    custody.mkdir(mode=0o700)
    backup.create_private_file(custody / "mfa.key", key.read_bytes())
    restored = attempt / "restored"
    completed = _backup_cli("restore", attempt / "decrypted-bundle", "--output", restored,
                            "--mfa-key-file", custody / "mfa.key", "--security-source", business.directory)
    assert completed.returncode == 0, completed.stderr
    assert not (restored / backup.QUARANTINE).exists()
    assert _rows(restored, "users") == _rows(business.directory, "users")
    assert _rows(restored, "sessions") == []
    assert _rows(restored, "messages") == _rows(business.directory, "messages")
    Database(restored, mfa_key_file=custody / "mfa.key")
    before = _fingerprint(restored)
    assert _hosting_snippet("unpack", attempt).returncode != 0
    assert _fingerprint(restored) == before
    if os.name == "posix":
        assert (attempt / "decrypted-bundle").stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in (attempt / "decrypted-bundle").iterdir())


@pytest.mark.parametrize("damage", ["traversal", "duplicate", "missing", "compressed", "digest"])
def test_hosting_unpack_snippet_rejects_unsafe_members_before_publication(business, damage):
    attempt = business.directory.parent / "invalid-staging-attempt"
    attempt.mkdir(mode=0o700)
    names = [*backup.FILES, "manifest.json"]
    if damage == "traversal":
        names[0] = "../escaped.sqlite3"
    elif damage == "duplicate":
        names[0] = "identity.key"
    elif damage == "missing":
        names.pop()
    compression = zipfile.ZIP_DEFLATED if damage == "compressed" else zipfile.ZIP_STORED
    with zipfile.ZipFile(attempt / "recovered.zip", "x", compression=compression) as archive:
        for name in names:
            if damage == "duplicate" and name in archive.namelist():
                with pytest.warns(UserWarning, match="Duplicate name"):
                    archive.writestr(name, "Disposable archive member")
            else:
                archive.writestr(name, "Disposable archive member")
    digest = hashlib.sha256((attempt / "recovered.zip").read_bytes()).hexdigest()
    (attempt / "archive.sha256").write_text("0" * 64 if damage == "digest" else digest, encoding="ascii")
    result = _hosting_snippet("unpack", attempt)
    assert result.returncode != 0
    assert not (attempt / "decrypted-bundle").exists()
    assert not (attempt / "escaped.sqlite3").exists()


def test_hosting_pack_snippet_refuses_incomplete_bundle_without_overwrite(business):
    attempt = business.directory.parent / "invalid-pack"
    attempt.mkdir(mode=0o700)
    bundle = attempt / "bundle"
    bundle.mkdir(mode=0o700)
    (bundle / "BACKUP_INCOMPLETE").write_text("Preserve failed attempt.")
    result = _hosting_snippet("pack", attempt)
    assert result.returncode != 0
    assert not (attempt / "backup.zip").exists()
