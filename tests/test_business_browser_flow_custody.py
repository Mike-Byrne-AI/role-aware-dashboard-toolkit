"""Browser-flow authority never travels through historical business recovery."""

from contextlib import closing, contextmanager
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from tests.test_business_lifecycle_custody import (
    custody as custody, backup, fingerprint, rotation, rows, schema_archive,
)
from tests.test_business_hosting import pilot
from business import browser_flow
from business.db import Database, create_private_file


@contextmanager
def offline(directory):
    with closing(backup._connect(directory / "business.sqlite3", readonly=False)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with connection:
            yield connection


def state(directory):
    return rows(directory, "browser_flow_state")[0]


def install_bound_flow(custody):
    """Install a structurally valid synthetic current head with another creator."""
    with offline(custody.directory) as connection:
        now = connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0]
        generation = connection.execute("SELECT generation FROM account_mfa WHERE user_id='worker'").fetchone()[0]
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", ("1" * 64, "worker", now, now, now + 28800))
        connection.execute("INSERT INTO session_security VALUES(?,?,?,?)", ("1" * 64, "2" * 32, now, "totp"))
        connection.execute("INSERT INTO session_mfa VALUES(?,?)", ("1" * 64, generation))
        connection.execute("INSERT INTO browser_login_flows VALUES(?,?,?,?,?,?)", ("3" * 64, now, now + 28800, 1, 0, "owner"))
        connection.execute("INSERT INTO session_browser_flow VALUES(?,?)", ("2" * 32, "3" * 64))
        connection.execute("INSERT INTO passkey_challenges VALUES(?,?,?,?,NULL,NULL,?)", ("challenge", "login", b"fixture", "4" * 64, now))
        browser_flow.validate_state(connection)
    return now


def assert_no_transient_authority(directory):
    for table in ("browser_login_flows", "session_browser_flow", "sessions", "session_mfa", "session_security",
                  "session_passkey", "session_predecessors", "passkey_challenges", "enrollment_grants", "enrollment_sessions"):
        assert rows(directory, table) == [], table


def test_restore_discards_archived_and_current_flows_rotates_epoch_and_preserves_current_floor(custody, monkeypatch):
    now = install_bound_flow(custody)
    archive = custody.root / "flow-archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    archived_epoch = state(archive)[1]
    with offline(custody.directory) as connection:
        connection.execute("UPDATE browser_flow_state SET rejection_time_floor=?", (now + 30,))
    before = fingerprint(custody.directory), fingerprint(archive)
    monkeypatch.setattr(backup, "current_time", lambda: now + 31)
    output = custody.root / "flow-restored"
    result = backup.restore_backup(archive, output, security_source=custody.directory, mfa_key_file=custody.key)
    assert result == {"quarantined": False, "sessions_revoked": True, "frozen": True}
    assert_no_transient_authority(output)
    assert state(output)[1] not in {archived_epoch, state(custody.directory)[1]}
    assert state(output)[2] == now + 31
    assert rows(output, "users") == rows(custody.directory, "users")
    assert (fingerprint(custody.directory), fingerprint(archive)) == before
    Database(output, mfa_key_file=custody.key)


def test_restore_uses_current_floor_even_after_explicit_current_epoch_reset(custody, monkeypatch):
    now = state(custody.directory)[2]
    with offline(custody.directory) as connection:
        connection.execute("UPDATE browser_flow_state SET rejection_time_floor=?", (now + 500,))
    archive = custody.root / "old-clock-archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    # Model an explicit offline epoch reset by the trusted current authority.
    with offline(custody.directory) as connection:
        assert browser_flow.reset_after_restore(connection, now, now=now)
    current_epoch = state(custody.directory)[1]
    before = fingerprint(custody.directory), fingerprint(archive)
    monkeypatch.setattr(backup, "current_time", lambda: now + 1)
    output = custody.root / "current-clock-restored"
    assert not backup.restore_backup(archive, output, security_source=custody.directory,
                                     mfa_key_file=custody.key)["quarantined"]
    assert state(output)[2] == now + 1
    assert state(output)[1] not in {current_epoch, state(archive)[1]}
    assert (fingerprint(custody.directory), fingerprint(archive)) == before


def test_backward_clock_restore_keeps_current_authority_offline_without_lowering_floor(custody, monkeypatch):
    now = install_bound_flow(custody)
    archive = custody.root / "backward-archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    with offline(custody.directory) as connection:
        connection.execute("UPDATE browser_flow_state SET rejection_time_floor=?", (now + 100,))
    before = fingerprint(custody.directory), fingerprint(archive)
    monkeypatch.setattr(backup, "current_time", lambda: now + 50)
    output = custody.root / "backward-restored"
    result = backup.restore_backup(archive, output, security_source=custody.directory, mfa_key_file=custody.key)
    assert result["quarantined"] and (output / backup.QUARANTINE).is_file()
    assert json.loads((output / "restore.json").read_text())["quarantined"] is True
    assert state(output)[2] == now + 100
    assert rows(output, "users") == rows(custody.directory, "users")
    assert_no_transient_authority(output)
    with pytest.raises(ValueError, match="quarantined"):
        Database(output, mfa_key_file=custody.key)
    assert (fingerprint(custody.directory), fingerprint(archive)) == before


def test_restore_without_current_authority_preserves_archive_floor_and_stays_quarantined(custody, monkeypatch):
    now = install_bound_flow(custody)
    archive = custody.root / "offline-archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    before = fingerprint(archive)
    monkeypatch.setattr(backup, "current_time", lambda: now - 1)
    output = custody.root / "offline-restored"
    assert backup.restore_backup(archive, output, mfa_key_file=custody.key)["quarantined"]
    assert state(output)[2] == now and state(output)[1] != state(archive)[1]
    assert all(row[5] == 0 for row in rows(output, "users"))
    assert_no_transient_authority(output)
    assert fingerprint(archive) == before


def test_stateless_cookie_and_context_cannot_be_readmitted_after_restore(custody, monkeypatch):
    now = state(custody.directory)[2]
    with offline(custody.directory) as connection:
        context = browser_flow.bootstrap(connection, custody.identity, now=now)
        browser_flow.validate_context(connection, custody.identity, context.cookie, context.csrf, now=now)
    archive = custody.root / "stateless-archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    monkeypatch.setattr(backup, "current_time", lambda: now + 1)
    output = custody.root / "stateless-restored"
    backup.restore_backup(archive, output, security_source=custody.directory, mfa_key_file=custody.key)
    with offline(output) as connection:
        with pytest.raises(HTTPException) as denied:
            browser_flow.validate_context(connection, custody.identity, context.cookie, context.csrf, now=now + 1)
        assert denied.value.status_code == 409
        fresh = browser_flow.bootstrap(connection, custody.identity, now=now + 1)
        browser_flow.validate_context(connection, custody.identity, fresh.cookie, fresh.csrf, now=now + 1)


def test_failed_epoch_reset_never_publishes_output_or_changes_either_source(custody, monkeypatch):
    install_bound_flow(custody)
    archive = custody.root / "failure-archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    before = fingerprint(custody.directory), fingerprint(archive)
    original = browser_flow.reset_after_restore

    def fail_after_reset(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("synthetic epoch interruption")

    monkeypatch.setattr(browser_flow, "reset_after_restore", fail_after_reset)
    output = custody.root / "failed-epoch"
    with pytest.raises(RuntimeError, match="epoch interruption"):
        backup.restore_backup(archive, output, security_source=custody.directory, mfa_key_file=custody.key)
    assert not output.exists()
    assert (fingerprint(custody.directory), fingerprint(archive)) == before


@pytest.mark.parametrize("observed", [-1, float("nan"), float("inf"), browser_flow.MAX_TIME + 1])
def test_invalid_restore_clock_never_publishes_output_or_changes_either_source(custody, monkeypatch, observed):
    archive = custody.root / "invalid-clock-archive"
    backup.create_backup(custody.directory, archive, mfa_key_file=custody.key)
    before = fingerprint(custody.directory), fingerprint(archive)
    monkeypatch.setattr(backup, "current_time", lambda: observed)
    output = custody.root / "invalid-clock-output"
    with pytest.raises(ValueError, match="clock"):
        backup.restore_backup(archive, output, security_source=custody.directory, mfa_key_file=custody.key)
    assert not output.exists()
    assert (fingerprint(custody.directory), fingerprint(archive)) == before


def test_encryption_key_rotation_preserves_browser_flow_authority_and_time_floor(custody):
    install_bound_flow(custody)
    tables = ("browser_flow_state", "browser_login_flows", "session_browser_flow", "sessions", "session_security")
    before = {table: rows(custody.directory, table) for table in tables}
    replacement = custody.key.with_name("browser-flow-replacement.key")
    rotation.rotate_mfa_key(custody.directory, current_mfa_key_file=custody.key,
                            new_mfa_key_file=replacement, maintenance_confirmed=True)
    assert all(rows(custody.directory, table) == value for table, value in before.items())
    current = Database(custody.directory, mfa_key_file=replacement)
    with current.readonly_snapshot() as connection:
        browser_flow.validate_state(connection)
    with pytest.raises(ValueError, match="ciphertext|encryption key"):
        Database(custody.directory, mfa_key_file=custody.key)


def test_schema_nine_migration_is_explicit_preserves_sessions_and_discards_challenges(custody):
    install_bound_flow(custody)
    archive = schema_archive(custody, 9)
    runtime = backup._new_directory(custody.root / "schema-nine-runtime")
    for name in backup.FILES:
        create_private_file(runtime / name, (archive / name).read_bytes())
    before = fingerprint(runtime)
    sessions = rows(runtime, "sessions")
    with pytest.raises(ValueError, match="explicit reviewed migration"):
        Database(runtime, mfa_key_file=custody.key)
    assert fingerprint(runtime) == before
    database = Database(runtime, mfa_key_file=custody.key, migrate=True)
    assert rows(runtime, "sessions") == sessions and sessions
    assert rows(runtime, "passkey_challenges") == []
    assert rows(runtime, "browser_login_flows") == rows(runtime, "session_browser_flow") == []
    with database.readonly_snapshot() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
        browser_flow.validate_state(connection)


@pytest.mark.parametrize("offset", [-1, float("nan"), float("inf"), browser_flow.MAX_TIME + 1])
def test_hosting_preflight_refuses_invalid_or_backward_flow_clock_without_mutation(custody, monkeypatch, offset):
    floor = state(custody.directory)[2]
    monkeypatch.setattr(pilot, "time", SimpleNamespace(time=lambda: floor + offset))
    configuration = pilot.Configuration("https://business.example.com", "business.example.com", custody.directory, 10000, custody.key)
    before = fingerprint(custody.directory)
    with pytest.raises(ValueError, match="clock"):
        pilot.inspect_existing_storage(configuration)
    assert fingerprint(custody.directory) == before


def test_hosting_preflight_accepts_current_boundary_without_advancing_it(custody, monkeypatch):
    floor = state(custody.directory)[2]
    monkeypatch.setattr(pilot, "time", SimpleNamespace(time=lambda: floor))
    configuration = pilot.Configuration("https://business.example.com", "business.example.com", custody.directory, 10000, custody.key)
    before = fingerprint(custody.directory)
    assert pilot.inspect_existing_storage(configuration)["deployment_state"] == "enrollment_incomplete"
    assert fingerprint(custody.directory) == before
