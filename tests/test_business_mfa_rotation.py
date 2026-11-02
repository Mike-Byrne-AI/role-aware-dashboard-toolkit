"""Offline MFA-key cutover, interruption and old-backup recovery with fake data."""

from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from role_aware_dashboard_toolkit.access_store import AccessStoreError
from tests.test_business_dashboard import (
    ORIGIN, pyotp, business as business, business_admin as business_admin, business_seed as business_seed,
)
from tests.test_business_backup import backup
from business.db import Database, RuntimeKeyError, create_private_file
from business.mfa import enroll_in_transaction
from business.secret_store import SecretStore, default_key_path
from business.app import create_app
import rotate_mfa_key as rotation


SCRIPT = Path(rotation.__file__).resolve()


def _paths(business):
    original = default_key_path(business.directory)
    return original, original.with_name("replacement.key")


def _rotate(business, **options):
    original, replacement = _paths(business)
    return rotation.rotate_mfa_key(business.directory, current_mfa_key_file=original,
                                   new_mfa_key_file=replacement, maintenance_confirmed=True, **options)


def _rows(business, table):
    with closing(sqlite3.connect(business.directory / "business.sqlite3")) as connection:
        return connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()


def _fingerprint(business):
    with closing(sqlite3.connect(business.directory / "business.sqlite3")) as connection:
        return hashlib.sha256("\n".join(connection.iterdump()).encode()).hexdigest()


def _two_enrollments(business):
    with business.db() as connection:
        connection.execute("UPDATE users SET role='admin',revision=revision+1 WHERE id='alex'")
        enroll_in_transaction(connection, business.directory, business.app.state.database.mfa_secrets)


@pytest.mark.parametrize("message", [
    "MFA encryption key binding is missing; preserve existing state.",
    "MFA ciphertext or encryption key is invalid; preserve existing state.",
])
def test_runtime_key_error_preserves_diagnostic_and_both_catch_contracts(message):
    for error_type in (ValueError, AccessStoreError):
        with pytest.raises(error_type) as captured:
            raise RuntimeKeyError(message)
        assert type(captured.value) is RuntimeKeyError
        assert captured.value.args == (message,)
        assert str(captured.value) == message


@pytest.mark.parametrize("journal_mode", ["DELETE", "WAL"])
def test_rotation_preserves_identity_authority_replay_state_and_original_key(business, business_admin, journal_mode):
    _two_enrollments(business)
    with business.db() as connection:
        connection.execute("UPDATE users SET active=0,revision=revision+1 WHERE id='blair'")
        connection.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1 WHERE id=1")
    with closing(sqlite3.connect(business.directory / "business.sqlite3")) as connection:
        connection.execute("PRAGMA journal_mode=" + journal_mode)
    original, replacement = _paths(business)
    original_digest = hashlib.sha256(original.read_bytes()).hexdigest()
    identity_digest = hashlib.sha256((business.directory / "identity.key").read_bytes()).hexdigest()
    unchanged = {table: _rows(business, table) for table in (
        "users", "sessions", "session_security", "session_mfa", "settings", "passkey_credentials",
        "passkey_challenges", "session_passkey", "login_limits", "messages",
    )}
    enrollments = _rows(business, "admin_mfa")
    previous = business.app.state.database.mfa_secrets
    result = _rotate(business)
    assert result["enrollments_reencrypted"] == 2
    assert hashlib.sha256(original.read_bytes()).hexdigest() == original_digest
    assert hashlib.sha256((business.directory / "identity.key").read_bytes()).hexdigest() == identity_digest
    assert all(_rows(business, table) == value for table, value in unchanged.items())
    current = Database(business.directory, mfa_key_file=replacement)
    for old, new in zip(enrollments, _rows(business, "admin_mfa")):
        assert old[0] == new[0] and old[2:] == new[2:] and old[1] != new[1]
        assert previous.decrypt(old[1], old[0], old[2]) == current.mfa_secrets.decrypt(new[1], new[0], new[2])
    with pytest.raises(ValueError, match="ciphertext|encryption key"):
        Database(business.directory, mfa_key_file=original)
    # Existing process objects must also fail on their next protected/read-only
    # transaction; startup-only checks would miss the cached old-key worker.
    for transaction in (business.app.state.database.transaction, business.app.state.database.readonly_snapshot):
        with pytest.raises(RuntimeKeyError, match="ciphertext|encryption key"):
            with transaction():
                pytest.fail("A stale-key worker entered a transaction after cutover")
    for method, path, options in (
        ("GET", "/api/admin/users", {}),
        ("POST", "/api/messages", {"json": {"body": "Disposable stale-worker write"}}),
    ):
        response = business_admin.request(method, path, **options)
        assert response.status_code == 503
        assert response.json() == {"detail": "Access storage is unavailable."}
        assert str(business.directory) not in response.text and "Traceback" not in response.text
    assert all(_rows(business, table) == value for table, value in unchanged.items())
    assert _rows(business, "activity")[-1][2] == "Rotated MFA encryption key"
    # Exercise real password/TOTP verification against the new ciphertext/key.
    with current.transaction() as connection:
        assert connection.execute("SELECT code FROM security_events ORDER BY sequence DESC LIMIT 1").fetchone()[0] == "mfa_key_rotated"
        enrollment = dict(connection.execute("SELECT * FROM admin_mfa WHERE user_id='admin'").fetchone())
    secret = current.mfa_secrets.decrypt(enrollment["secret_ciphertext"], "admin", enrollment["generation"])
    business.mfa_time = max(business.mfa_time, (enrollment["last_counter"] + 1) * 30)
    otp = pyotp.TOTP(secret).at(business.mfa_time)
    client = business.client(create_app(business.directory, public_origin=ORIGIN, mfa_key_file=replacement))
    payload = {"username": "admin", "password": business.credentials["admin"], "otp": f"{(int(otp) + 1) % 1000000:06d}"}
    assert client.post("/api/login", json=payload, headers={"Origin": ORIGIN}).status_code == 401
    payload["otp"] = otp
    assert client.post("/api/login", json=payload, headers={"Origin": ORIGIN}).status_code == 200


def test_confirmation_is_required_before_any_creation_or_mutation(business):
    original, replacement = _paths(business)
    before = _fingerprint(business)
    with pytest.raises(rotation.RotationError, match="maintenance"):
        rotation.rotate_mfa_key(business.directory, current_mfa_key_file=original, new_mfa_key_file=replacement)
    assert not replacement.exists() and _fingerprint(business) == before


@pytest.mark.parametrize("target", ["original", "existing", "runtime", "backup", "source"])
def test_replacement_path_never_overwrites_or_enters_runtime_backup_or_source(business, target):
    original, replacement = _paths(business)
    if target == "original":
        replacement = original
    elif target == "existing":
        replacement.write_bytes(b"preserve-existing-operator-file")
    elif target == "runtime":
        replacement = business.directory / "new.key"
    elif target == "backup":
        bundle = business.directory.parent / "backup"
        backup.create_backup(business.directory, bundle, mfa_key_file=original)
        replacement = bundle / "new.key"
    elif target == "source":
        replacement = SCRIPT.parent / "never-created.key"
    old_bytes = replacement.read_bytes() if replacement.is_file() else None
    before = _fingerprint(business)
    with pytest.raises(ValueError):
        rotation.rotate_mfa_key(business.directory, current_mfa_key_file=original,
                                new_mfa_key_file=replacement, maintenance_confirmed=True)
    assert _fingerprint(business) == before
    assert replacement.read_bytes() == old_bytes if old_bytes is not None else not replacement.exists()


@pytest.mark.parametrize("stage", ["second-row", "final-validation"])
def test_interruption_rolls_back_all_ciphertext_binding_and_activity(business, monkeypatch, stage):
    _two_enrollments(business)
    original, replacement = _paths(business)
    before = _fingerprint(business)
    encrypt = SecretStore.encrypt
    validate = SecretStore.validate_database
    written = []

    def interrupt_encrypt(store, secret, user_id, generation):
        if store.path == replacement and user_id != "key-binding":
            written.append(user_id)
            if stage == "second-row" and len(written) == 2:
                raise KeyboardInterrupt()
        return encrypt(store, secret, user_id, generation)

    def interrupt_validation(store, connection):
        if store.path == replacement and stage == "final-validation":
            assert len(written) == 2
            raise OSError("Disposable interruption after binding update")
        return validate(store, connection)

    monkeypatch.setattr(SecretStore, "encrypt", interrupt_encrypt)
    monkeypatch.setattr(SecretStore, "validate_database", interrupt_validation)
    with pytest.raises((KeyboardInterrupt, OSError)):
        _rotate(business)
    monkeypatch.setattr(SecretStore, "encrypt", encrypt)
    monkeypatch.setattr(SecretStore, "validate_database", validate)
    assert replacement.is_file()  # Preserve the failed attempt, never replace it.
    assert _fingerprint(business) == before
    Database(business.directory, mfa_key_file=original)
    with pytest.raises(ValueError, match="ciphertext|encryption key"):
        Database(business.directory, mfa_key_file=replacement)


@pytest.mark.parametrize("journal_mode", ["DELETE", "WAL"])
def test_process_exit_before_commit_recovers_original_state(business, journal_mode):
    original, replacement = _paths(business)
    with closing(sqlite3.connect(business.directory / "business.sqlite3")) as connection:
        connection.execute("PRAGMA journal_mode=" + journal_mode)
    before = _fingerprint(business)
    program = """
import os, sys
sys.path.insert(0, sys.argv[1])
import rotate_mfa_key as rotation
original = rotation._reencrypt
def crash(*args):
    original(*args)
    os._exit(73)
rotation._reencrypt = crash
rotation.rotate_mfa_key(sys.argv[2], current_mfa_key_file=sys.argv[3],
                        new_mfa_key_file=sys.argv[4], maintenance_confirmed=True)
"""
    result = subprocess.run([sys.executable, "-B", "-c", program, str(SCRIPT.parent), str(business.directory),
                             str(original), str(replacement)], capture_output=True, text=True,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 73
    assert result.stdout == result.stderr == ""
    Database(business.directory, mfa_key_file=original)
    assert _fingerprint(business) == before
    assert replacement.is_file()


def test_restore_old_backup_uses_preserved_original_and_rotated_current_key(business, business_admin):
    original, replacement = _paths(business)
    bundle = business.directory.parent / "before-rotation-backup"
    backup.create_backup(business.directory, bundle, mfa_key_file=original)
    with business.db() as connection:
        connection.execute("UPDATE users SET active=0,revision=revision+1 WHERE id='blair'")
    _rotate(business)
    restored = business.directory.parent / "restored"
    result = backup.restore_backup(bundle, restored, mfa_key_file=replacement,
                                   backup_mfa_key_file=original, security_source=business.directory)
    assert result == {"quarantined": False, "sessions_revoked": True, "frozen": True}
    recovered = Database(restored, mfa_key_file=replacement)
    with recovered.transaction() as connection:
        assert connection.execute("SELECT active FROM users WHERE id='blair'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert [tuple(row) for row in connection.execute("SELECT * FROM admin_mfa ORDER BY 1")] == _rows(business, "admin_mfa")
    with pytest.raises(ValueError, match="ciphertext|encryption key"):
        Database(restored, mfa_key_file=original)


def test_cli_outputs_only_safe_status_and_refuses_uncertain_repeat(business, capsys):
    original, replacement = _paths(business)
    args = [str(business.directory), "--current-mfa-key-file", str(original),
            "--new-mfa-key-file", str(replacement), "--maintenance-confirmed"]
    assert rotation.main(args) == 0
    output = capsys.readouterr()
    assert "committed" in output.out and output.err == ""
    for key in (original, replacement):
        assert key.read_bytes().hex() not in output.out
    assert all(secret not in output.out for secret in business.credentials.values())
    assert rotation.main(args) == 1
    failed = capsys.readouterr()
    assert failed.out == "" and "Preserve" in failed.err and "Traceback" not in failed.err


def test_required_rotation_event_failure_rolls_back_key_cutover(business, monkeypatch):
    before = _fingerprint(business)

    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("Disposable required event sink failure")

    monkeypatch.setattr(rotation, "record_event", unavailable)
    with pytest.raises(sqlite3.OperationalError):
        _rotate(business)
    original, replacement = _paths(business)
    assert replacement.is_file()
    assert _fingerprint(business) == before
    Database(business.directory, mfa_key_file=original)


def test_reusing_original_key_material_is_not_accepted_as_rotation(business, monkeypatch):
    original, replacement = _paths(business)
    before = _fingerprint(business)

    def duplicate_key(directory, selected):
        create_private_file(selected, original.read_bytes())
        return selected

    monkeypatch.setattr(rotation, "create_key_file", duplicate_key)
    with pytest.raises(rotation.RotationError, match="independent"):
        _rotate(business)
    assert replacement.exists() and _fingerprint(business) == before
    Database(business.directory, mfa_key_file=original)
