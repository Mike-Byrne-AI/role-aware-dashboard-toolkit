"""Offline enrollment commands and honest hosted enrollment readiness."""

from tools.business_login_client import login_post

from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest

pyotp = pytest.importorskip("pyotp")
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

APPLICATION = Path(__file__).resolve().parents[1] / "examples/business_dashboard"
sys.path.insert(0, str(APPLICATION))

from fastapi.testclient import TestClient  # noqa: E402
from business import db as storage, enrollment  # noqa: E402
from business.db import Database  # noqa: E402
from business.secret_store import create_key_file  # noqa: E402
from business.security import hash_password  # noqa: E402
from business.seed import provision  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


operator = load_module("lifecycle_operator_run", APPLICATION / "run.py")
pilot = load_module("lifecycle_operator_pilot", APPLICATION / "hosting/pilot.py")
ORIGIN = "https://business.example.com"
PASSWORD = "Orchid rivers pebble autumn!2049"


@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setenv("BUSINESS_TURNSTILE_SITE_KEY", "synthetic-site-key")
    monkeypatch.setenv("BUSINESS_TURNSTILE_SECRET_KEY", "synthetic-secret-key")
    with tempfile.TemporaryDirectory(prefix="radt-lifecycle-operator-") as temporary:
        # macOS temp paths traverse /var; only this owned root is canonicalized.
        root = Path(temporary).resolve(strict=True)
        directory = root / "runtime"
        key = create_key_file(directory, root / "keys" / "mfa.key")
        configuration = pilot.Configuration(ORIGIN, "business.example.com", directory, 10000, key)
        yield SimpleNamespace(root=root, directory=directory, key=key, configuration=configuration)


def arguments(fresh, *extra):
    return ["--data-dir", str(fresh.directory), "--mfa-key-file", str(fresh.key), *extra]


def fingerprint(directory):
    with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
        return hashlib.sha256("\n".join(connection.iterdump()).encode()).hexdigest()


def _hold_browser_clock(directory, monkeypatch):
    # Scope only the rollback assertion, preserving the complete DB fingerprint.
    from business import browser_flow

    with closing(sqlite3.connect(directory / "business.sqlite3")) as connection:
        now = connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0]
    monkeypatch.setattr(browser_flow, "current_time", lambda: now)


def complete(database, username, grant):
    # This setup helper must not cross a TOTP step while password hashing runs.
    # Production still accepts only the current step; clock/replay tests own it.
    with patch.object(enrollment, "current_time", return_value=enrollment.current_time()):
        started = enrollment.start_enrollment(database, username, grant)
        enrollment.complete_enrollment(database, started.token, started.csrf, PASSWORD,
                                       pyotp.TOTP(started.secret).at(enrollment.current_time()))


def test_fresh_provision_reports_private_enrollment_without_permanent_credentials(fresh, capsys):
    assert operator.main(arguments(fresh, "--provision")) == 0
    output = capsys.readouterr().out
    sheet = fresh.directory / "ACCOUNTS.md"
    tokens = re.findall(r"\| ([A-Za-z0-9_-]{43}) \|", sheet.read_text())
    assert len(tokens) == 6 and all(token not in output for token in tokens)
    assert "24 hours" in output and "unavailable" in output
    assert not list(fresh.directory.glob("ADMIN_MFA_SETUP*"))
    database = Database(fresh.directory, mfa_key_file=fresh.key)
    with database.readonly_snapshot() as connection:
        assert connection.execute("SELECT COUNT(*) FROM account_mfa").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM users WHERE password_hash='!enrollment-pending!'").fetchone()[0] == 6
        assert enrollment.readiness(connection)["ready"] is False


def test_single_account_grant_is_unique_private_and_not_printed(fresh, capsys):
    grants = provision(fresh.directory, mfa_key_file=fresh.key)
    before = {path.name for path in fresh.directory.glob("ENROLLMENT*.md")}
    assert operator.main(arguments(fresh, "--issue-enrollment", "alex", "--purpose", "initial")) == 0
    output = capsys.readouterr().out
    created = [path for path in fresh.directory.glob("ENROLLMENT*.md") if path.name not in before]
    assert len(created) == 1
    secret = re.search(r"Enrollment grant: `([A-Za-z0-9_-]{43})`", created[0].read_text()).group(1)
    assert secret not in output and grants["alex"] not in output
    database = Database(fresh.directory, mfa_key_file=fresh.key)
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.start_enrollment(database, "alex", grants["alex"])
    assert enrollment.start_enrollment(database, "alex", secret).username == "alex"


def test_failed_grant_sheet_rolls_back_issuance_and_required_event(fresh, monkeypatch, capsys):
    provision(fresh.directory, mfa_key_file=fresh.key)
    _hold_browser_clock(fresh.directory, monkeypatch)
    before = fingerprint(fresh.directory)
    original = storage.create_private_file

    def fail_sheet(path, content):
        if path.name.startswith("ENROLLMENT"):
            raise OSError("PRIVATE_STORAGE_CANARY")
        return original(path, content)

    monkeypatch.setattr(storage, "create_private_file", fail_sheet)
    assert operator.main(arguments(fresh, "--issue-enrollment", "alex", "--purpose", "initial")) == 1
    assert fingerprint(fresh.directory) == before
    assert list(fresh.directory.glob("ENROLLMENT*.md")) == []
    assert "CANARY" not in capsys.readouterr().err


@pytest.mark.parametrize("extra", [
    ["--issue-enrollment", "alex", "--purpose", "recovery"],
    ["--reset-admin-mfa"],
    ["--issue-enrollment", "alex"],
    ["--purpose", "initial"],
])
def test_invalid_operator_arguments_refuse_before_storage_access(fresh, extra):
    with pytest.raises(SystemExit) as caught:
        operator.main(arguments(fresh, *extra))
    assert caught.value.code == 2 and not fresh.directory.exists()


def test_readiness_is_read_only_and_activation_requires_all_active_accounts(fresh, capsys, monkeypatch):
    grants = provision(fresh.directory, mfa_key_file=fresh.key)
    before = fingerprint(fresh.directory)
    assert operator.main(arguments(fresh, "--auth-readiness")) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["mode"] == "strict" and not status["ready"] and len(status["unresolved"]) == 6
    assert fingerprint(fresh.directory) == before
    with monkeypatch.context() as clock:
        _hold_browser_clock(fresh.directory, clock)
        assert operator.main(arguments(fresh, "--activate-auth-policy")) == 1
        assert fingerprint(fresh.directory) == before
    capsys.readouterr()
    database = Database(fresh.directory, mfa_key_file=fresh.key)
    for username, grant in grants.items():
        complete(database, username, grant)
    with database.transaction() as connection:
        connection.execute("UPDATE authentication_policy SET mode='transition'")
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", ("f" * 64, "admin", 1.0, 1.0, 28801.0))
    assert operator.main(arguments(fresh, "--activate-auth-policy")) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["ready"] and status["mode"] == "strict"
    with database.readonly_snapshot() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT code FROM security_events ORDER BY sequence DESC").fetchone()[0] == "authentication_policy_activated"


def test_hosted_provision_has_one_sheet_and_explicit_enrollment_only_state(fresh):
    sheet = pilot.provision(fresh.configuration)
    assert sheet == fresh.directory / "ACCOUNTS.md" and sheet.is_file()
    before = fingerprint(fresh.directory)
    status = pilot.preflight(fresh.configuration)
    assert status["deployment_state"] == "enrollment_only"
    assert not status["ready"] and status["ordinary_sign_in_accounts"] == 0
    assert status["pending_enrollments"] == 6 and status["pending_grants_unavailable"] == 0
    assert fingerprint(fresh.directory) == before


def test_pending_host_can_begin_enrollment_but_cannot_access_ordinary_routes(fresh):
    grants = provision(fresh.directory, mfa_key_file=fresh.key)
    app = pilot.create_application(fresh.configuration)
    assert app.state.startup_authentication_status["deployment_state"] == "enrollment_only"
    with TestClient(app, base_url=ORIGIN) as client:
        assert login_post(client, "/api/login", json={"username": "admin", "password": grants["admin"]},
                           headers={"Origin": ORIGIN}).status_code == 401
        response = client.post("/api/enrollment/start", json={"username": "admin", "enrollment_secret": grants["admin"]},
                               headers={"Origin": ORIGIN})
        assert response.status_code == 200
        assert "__Host-westbridge_enrollment" in client.cookies
        assert "__Host-westbridge_session" not in client.cookies
        assert client.get("/api/session").json() == {"user": None}
        assert client.get("/api/admin/users").status_code == 401


def test_expired_pending_grants_are_reported_without_promoting_or_reissuing(fresh, monkeypatch, capsys):
    provision(fresh.directory, mfa_key_file=fresh.key)
    database = Database(fresh.directory, mfa_key_file=fresh.key)
    with database.transaction() as connection:
        connection.execute("UPDATE enrollment_grants SET expires_at=created_at")
    before = fingerprint(fresh.directory)
    monkeypatch.setattr(pilot, "load_configuration", lambda: fresh.configuration)
    pilot.main(["preflight"])
    output = capsys.readouterr().out
    assert "enrollment only" in output and "fresh offline enrollment grant" in output
    assert fingerprint(fresh.directory) == before


@pytest.mark.parametrize("damage", [
    None, "missing_session", "expired_session", "grant_user_revision", "grant_security_revision",
    "session_user_revision", "session_security_revision", "grant_binding", "claimed_time",
])
def test_claimed_enrollment_availability_tracks_current_pending_capability(fresh, damage):
    grants = provision(fresh.directory, mfa_key_file=fresh.key)
    database = Database(fresh.directory, mfa_key_file=fresh.key)
    enrollment.start_enrollment(database, "alex", grants["alex"])
    with database.transaction() as connection:
        if damage == "missing_session":
            connection.execute("DELETE FROM enrollment_sessions WHERE user_id='alex'")
        elif damage == "expired_session":
            connection.execute("UPDATE enrollment_sessions SET expires_at=created_at WHERE user_id='alex'")
        elif damage in ("grant_user_revision", "grant_security_revision"):
            column = damage.removeprefix("grant_")
            connection.execute(f"UPDATE enrollment_grants SET {column}={column}+1 WHERE user_id='alex'")
        elif damage in ("session_user_revision", "session_security_revision"):
            column = damage.removeprefix("session_")
            connection.execute(f"UPDATE enrollment_sessions SET {column}={column}+1 WHERE user_id='alex'")
        elif damage == "grant_binding":
            connection.execute("UPDATE enrollment_sessions SET grant_hash=? WHERE user_id='alex'", ("f" * 64,))
        elif damage == "claimed_time":
            connection.execute("UPDATE enrollment_grants SET claimed_at=claimed_at+1 WHERE user_id='alex'")
    before = fingerprint(fresh.directory)
    status = pilot.preflight(fresh.configuration)
    assert status["pending_grants_unavailable"] == int(damage is not None)
    assert status["deployment_state"] == "enrollment_only" and not status["ready"]
    assert status["pending_enrollments"] == 6 and status["ordinary_sign_in_accounts"] == 0
    assert fingerprint(fresh.directory) == before


@pytest.mark.parametrize("damage", ["missing_lifecycle", "strict_legacy", "active_without_factor"])
def test_host_refuses_unproven_active_or_legacy_strict_authority(fresh, damage):
    provision(fresh.directory, mfa_key_file=fresh.key)
    database = Database(fresh.directory, mfa_key_file=fresh.key)
    with database.transaction() as connection:
        if damage == "missing_lifecycle":
            connection.execute("DELETE FROM account_security WHERE user_id='alex'")
        elif damage == "strict_legacy":
            connection.execute("UPDATE account_security SET lifecycle='legacy' WHERE user_id='alex'")
        else:
            connection.execute("UPDATE account_security SET lifecycle='active',completed_at=1 WHERE user_id='alex'")
    before = fingerprint(fresh.directory)
    with pytest.raises(ValueError):
        pilot.inspect_existing_storage(fresh.configuration)
    assert fingerprint(fresh.directory) == before


def test_transition_host_preserves_legacy_employee_password_access(fresh):
    grants = provision(fresh.directory, mfa_key_file=fresh.key)
    database = Database(fresh.directory, mfa_key_file=fresh.key)
    complete(database, "admin", grants["admin"])
    with database.transaction() as connection:
        connection.execute("UPDATE authentication_policy SET mode='transition'")
        connection.execute("UPDATE account_security SET lifecycle='legacy',completed_at=NULL WHERE user_id<>'admin'")
        connection.execute("UPDATE users SET password_hash=? WHERE id='alex'", (hash_password(PASSWORD),))
    before = fingerprint(fresh.directory)
    status = pilot.preflight(fresh.configuration)
    assert status["deployment_state"] == "transition" and status["mode"] == "transition"
    assert not status["ready"] and fingerprint(fresh.directory) == before
    with TestClient(pilot.create_application(fresh.configuration), base_url=ORIGIN) as client:
        response = login_post(client, "/api/login", json={"username": "alex", "password": PASSWORD}, headers={"Origin": ORIGIN})
        assert response.status_code == 200
