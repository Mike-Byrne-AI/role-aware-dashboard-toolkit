"""The operating-proof harness must not endanger or publish its own fixture."""
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
from types import SimpleNamespace

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "operational_check.py"
_SPEC = importlib.util.spec_from_file_location("landscaping_operational_check", _SCRIPT)
operations = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = operations
_SPEC.loader.exec_module(operations)


@pytest.fixture
def storage(tmp_path, seeded_template):
    directory, _ = seeded_template
    source = tmp_path / "source"
    shutil.copytree(directory, source)
    return source


def _state(path):
    with closing(sqlite3.connect(path / "landscape.sqlite3")) as connection:
        return {name: connection.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall()
                for name in ("users", "sessions", "settings", "audit")}


def _session(path):
    from landscape.db import Database
    from landscape.security import csrf_for_token, new_token, token_hash
    import time

    db = Database(path)
    token = new_token()
    with db.transaction() as connection:
        user_id = connection.execute("SELECT id FROM users WHERE username='alex'").fetchone()[0]
        now = time.time()
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",
                           (token_hash(token), user_id, token_hash(csrf_for_token(token, db.identity_key)),
                            now, now, now + 3600))
    return db


def test_snapshot_refuses_a_running_owned_server(storage, tmp_path):
    running = operations.OwnedServer(storage, SimpleNamespace(poll=lambda: None), 1)
    destination = tmp_path / "backup"
    with pytest.raises(ValueError, match="Stop the owned server"):
        running.snapshot(destination)
    assert not destination.exists()


def test_stopped_snapshot_is_exact_private_and_independent(storage, tmp_path):
    stopped = operations.OwnedServer(storage, SimpleNamespace(poll=lambda: 0), 1)
    destination = tmp_path / "backup"
    stopped.snapshot(destination)
    assert {item.name for item in destination.iterdir()} == operations.PRIVATE_FILES
    assert destination.stat().st_mode & 0o777 == 0o700
    for name in operations.PRIVATE_FILES:
        assert (storage / name).read_bytes() == (destination / name).read_bytes()
        assert (destination / name).stat().st_mode & 0o777 == 0o600
        assert (storage / name).stat().st_ino != (destination / name).stat().st_ino


@pytest.mark.parametrize("filename", ["identity.key", "landscape.sqlite3", "TRIAL_ACCOUNTS.md"])
def test_snapshot_refuses_missing_files(storage, tmp_path, filename):
    (storage / filename).unlink()
    with pytest.raises(operations.CheckFailed, match="unexpected snapshot files"):
        operations.copy_private_snapshot(storage, tmp_path / "backup")
    assert not (tmp_path / "backup").exists()


def test_snapshot_refuses_sqlite_sidecars(storage, tmp_path):
    (storage / "landscape.sqlite3-wal").write_bytes(b"incomplete fixture")
    with pytest.raises(operations.CheckFailed, match="unexpected snapshot files"):
        operations.copy_private_snapshot(storage, tmp_path / "backup")
    assert not (tmp_path / "backup").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public_file"])
def test_snapshot_refuses_unsafe_private_files(storage, tmp_path, kind):
    key = storage / "identity.key"
    external = tmp_path / "external"
    if kind == "symlink":
        key.rename(external)
        key.symlink_to(external)
    elif kind == "hardlink":
        os.link(key, external)
    else:
        key.chmod(0o644)
    with pytest.raises((ValueError, operations.CheckFailed)):
        operations.copy_private_snapshot(storage, tmp_path / "backup")
    assert not (tmp_path / "backup").exists()


def test_snapshot_never_overwrites_existing_destination(storage, tmp_path):
    target = tmp_path / "existing"
    target.mkdir()
    marker = target / "saved-work"
    marker.write_text("retain me")
    with pytest.raises(ValueError, match="must not already exist"):
        operations.copy_private_snapshot(storage, target)
    assert marker.read_text() == "retain me"
    with pytest.raises(ValueError, match="separate"):
        operations.copy_private_snapshot(storage, storage / "nested-backup")
    assert not (storage / "nested-backup").exists()


@pytest.mark.parametrize("revoked", ["admin", "missing-worker"])
def test_reconciliation_refuses_unknown_or_admin_revocation_without_changes(storage, revoked):
    db = _session(storage)
    before = _state(storage)
    with pytest.raises(ValueError, match="known worker"):
        operations.reconcile_restore(storage, expected_key=db.identity_key, revoked_username=revoked)
    assert _state(storage) == before


def test_reconciliation_refuses_wrong_key_without_changes(storage):
    _session(storage)
    before = _state(storage)
    with pytest.raises(ValueError, match="identity key"):
        operations.reconcile_restore(storage, expected_key=b"x" * 32, revoked_username="alex")
    assert _state(storage) == before


def test_reconciliation_rolls_back_all_security_changes_when_audit_fails(storage):
    db = _session(storage)
    with db.transaction() as connection:
        connection.execute("CREATE TRIGGER deny_recovery BEFORE INSERT ON audit "
                           "WHEN NEW.action LIKE 'recovery.%' "
                           "BEGIN SELECT RAISE(ABORT,'fixture recovery failure'); END")
    before = _state(storage)
    with pytest.raises(sqlite3.IntegrityError):
        operations.reconcile_restore(storage, expected_key=db.identity_key, revoked_username="alex")
    assert _state(storage) == before


def test_reconciliation_preserves_saved_work_and_credentials_while_reapplying_denial(storage):
    db = _session(storage)
    before_work, before_accounts = operations.saved_work(storage), operations.accounts(storage)
    key = (storage / "identity.key").read_bytes()
    operations.reconcile_restore(storage, expected_key=key, revoked_username="alex")
    assert operations.saved_work(storage) == before_work
    assert operations.accounts(storage) == before_accounts
    assert (storage / "identity.key").read_bytes() == key
    with db.transaction() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT active FROM users WHERE username='alex'").fetchone()[0] == 0
        assert connection.execute("SELECT frozen FROM settings WHERE id=1").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM audit WHERE action LIKE 'recovery.%'").fetchone()[0] == 3


@pytest.mark.parametrize("values", [
    {"stage": "SECRET_EXCEPTION_CONTENT", "checks": [], "success": False},
    {"stage": "tls", "checks": ["SECRET_TOKEN_CONTENT"], "success": False},
    {"stage": "complete", "checks": list(operations.CHECKS), "success": "SECRET_PASSWORD_CONTENT"},
    {"stage": "complete", "checks": [], "success": True},
    {"stage": "tls", "checks": [operations.CHECKS[0], operations.CHECKS[0]], "success": False},
])
def test_evidence_rejects_unknown_private_values_and_false_success(tmp_path, values):
    with pytest.raises(ValueError):
        operations.write_summary(tmp_path, **values)
    assert not (tmp_path / "summary.json").exists()


def test_evidence_has_only_fixed_labels_and_cannot_overwrite(tmp_path):
    operations.write_summary(tmp_path, stage="tls", checks=[operations.CHECKS[0]], success=False)
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert set(summary) == {"scope", "success", "stage", "checks", "not_verified"}
    assert summary["scope"] == operations.SCOPE
    assert summary["success"] is False
    assert (tmp_path / "summary.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        operations.write_summary(tmp_path, stage="preflight", checks=[], success=False)


def test_main_does_not_emit_exception_payload(tmp_path, monkeypatch, capsys):
    output = tmp_path / "safe-evidence"
    monkeypatch.setattr(sys, "argv", [str(_SCRIPT), "--output-dir", str(output)])
    def fail(_out):
        raise RuntimeError("SECRET_PASSWORD_TOKEN_ACCOUNT_SHEET")
    monkeypatch.setattr(operations, "run", fail)
    assert operations.main() == 1
    captured = capsys.readouterr()
    assert "SECRET" not in captured.out + captured.err
    assert "Operational checks failed" in captured.err


def test_output_refuses_source_tree_symlink_and_existing_evidence(tmp_path):
    with pytest.raises(ValueError, match="outside"):
        operations.output_directory(str(operations.EXAMPLE_ROOT / "private-evidence"))
    target = tmp_path / "evidence"
    target.mkdir(mode=0o700)
    (target / "earlier.json").write_text("retain me")
    with pytest.raises(ValueError, match="empty"):
        operations.output_directory(str(target))
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        operations.output_directory(str(alias))
    assert (target / "earlier.json").read_text() == "retain me"
