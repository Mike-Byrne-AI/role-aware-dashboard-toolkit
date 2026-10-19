"""Fail-closed hosted startup without real credentials or network providers."""

from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")
from fastapi.testclient import TestClient  # noqa: E402

from tests.test_business_dashboard import business_seed as business_seed  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples" / "business_dashboard" / "hosting" / "pilot.py"
SPEC = importlib.util.spec_from_file_location("business_hosting_pilot", SCRIPT)
pilot = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pilot
SPEC.loader.exec_module(pilot)

ORIGIN = "https://business.example.com"


@pytest.fixture
def hosted(business_seed, monkeypatch):
    monkeypatch.setenv("BUSINESS_TURNSTILE_SITE_KEY", "synthetic-site-key")
    monkeypatch.setenv("BUSINESS_TURNSTILE_SECRET_KEY", "synthetic-secret-key")
    with tempfile.TemporaryDirectory(prefix="radt-business-hosting-") as temporary:
        directory = Path(temporary).resolve() / "private"
        shutil.copytree(business_seed.directory, directory)
        yield pilot.Configuration(ORIGIN, "business.example.com", directory, 10000)


@contextmanager
def connection(configuration):
    database = sqlite3.connect(configuration.data_dir / "business.sqlite3")
    try:
        with database:
            yield database
    finally:
        database.close()


def snapshot(directory):
    return {path.name: path.read_bytes() for path in directory.iterdir()}


def settings(directory, **changes):
    return {"PUBLIC_ORIGIN": ORIGIN, "BUSINESS_DATA_DIR": str(directory), **changes}


def test_real_platform_guard_requires_posix():
    if os.name == "posix":
        pilot._require_posix()
    else:
        with pytest.raises(ValueError, match="POSIX"):
            pilot._require_posix()


def test_configuration_has_single_origin_and_default_port(hosted, monkeypatch):
    monkeypatch.setattr(pilot, "_require_posix", lambda: None)
    assert pilot.load_configuration(settings(hosted.data_dir)) == hosted
    assert pilot.load_configuration(settings(hosted.data_dir, PORT="12000")).port == 12000


@pytest.mark.parametrize("origin", [
    "", "http://business.example.com", "https://localhost", "https://service.localhost",
    "https://127.0.0.1", "https://[::1]", "https://business.example.com/",
    "https://business.example.com/path", "https://business.example.com:443",
    "https://business.example.com?x=1", "https://business.example.com#fragment",
    "https://user:password@business.example.com", "https://Business.example.com",
    "https://*.example.com", "https://business.example.com.", "https://bad_label.example.com",
    "https://-label.example.com", " https://business.example.com", "https://business.example.com\n",
])
def test_configuration_rejects_unsafe_origin(hosted, monkeypatch, origin):
    monkeypatch.setattr(pilot, "_require_posix", lambda: None)
    with pytest.raises(ValueError, match="canonical HTTPS"):
        pilot.load_configuration(settings(hosted.data_dir, PUBLIC_ORIGIN=origin))


@pytest.mark.parametrize("port", ["", "0", "65536", "-1", "1.5", " 10000", "+10000", "１２３"])
def test_configuration_rejects_invalid_port(hosted, monkeypatch, port):
    monkeypatch.setattr(pilot, "_require_posix", lambda: None)
    with pytest.raises(ValueError, match="PORT"):
        pilot.load_configuration(settings(hosted.data_dir, PORT=port))


@pytest.mark.parametrize("directory", ["", "relative", str(ROOT), str(ROOT / "private"), str(Path(ROOT.anchor))])
def test_configuration_refuses_source_relative_or_root_storage(monkeypatch, directory):
    monkeypatch.setattr(pilot, "_require_posix", lambda: None)
    with pytest.raises(ValueError, match="BUSINESS_DATA_DIR"):
        pilot.load_configuration(settings(directory))


def test_configuration_refuses_redirected_storage(hosted, monkeypatch):
    monkeypatch.setattr(pilot, "_require_posix", lambda: None)
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == hosted.data_dir.parent or original(path))
    with pytest.raises(ValueError, match="symbolic links"):
        pilot.load_configuration(settings(hosted.data_dir))


def test_preflight_is_read_only_and_never_calls_the_provider(hosted, monkeypatch):
    import httpx

    monkeypatch.setattr(httpx, "Client", lambda *args, **kwargs: pytest.fail("Unexpected provider request"))
    before = snapshot(hosted.data_dir)
    pilot.preflight(hosted)
    assert snapshot(hosted.data_dir) == before


@pytest.mark.parametrize("filename", ["business.sqlite3", "identity.key"])
def test_missing_private_file_is_not_recreated(hosted, filename):
    (hosted.data_dir / filename).unlink()
    before = snapshot(hosted.data_dir)
    with pytest.raises(ValueError, match="missing or incomplete"):
        pilot.create_application(hosted)
    assert snapshot(hosted.data_dir) == before


@pytest.mark.parametrize("statement", [
    "PRAGMA user_version=2",
    "DROP INDEX submission_limits_time",
    "CREATE TRIGGER unexpected AFTER INSERT ON posts BEGIN DELETE FROM users; END",
    "DELETE FROM settings",
    "UPDATE users SET active=0 WHERE role='admin'",
    "UPDATE users SET principal='wrong' WHERE id='ellis'",
    "DELETE FROM admin_mfa WHERE user_id='admin'",
    "UPDATE admin_mfa SET secret='INVALID'",
    "UPDATE admin_mfa SET generation='invalid'",
    "UPDATE admin_mfa SET last_counter=1.5",
    "INSERT INTO assignments VALUES('missing-event','alex')",
])
def test_invalid_storage_is_preserved_and_refused_before_create_app(hosted, monkeypatch, statement):
    from business import app

    with connection(hosted) as database:
        database.execute(statement)
    before = snapshot(hosted.data_dir)
    monkeypatch.setattr(app, "create_app", lambda *args, **kwargs: pytest.fail("Invalid state reached application startup"))
    with pytest.raises(ValueError):
        pilot.create_application(hosted)
    assert snapshot(hosted.data_dir) == before


@pytest.mark.parametrize("key", [b"short", b"x" * 32])
def test_invalid_or_mismatched_identity_key_is_preserved(hosted, key):
    (hosted.data_dir / "identity.key").write_bytes(key)
    before = snapshot(hosted.data_dir)
    with pytest.raises(ValueError, match="identity key"):
        pilot.inspect_existing_storage(hosted)
    assert snapshot(hosted.data_dir) == before


def test_corrupt_database_is_not_repaired(hosted):
    (hosted.data_dir / "business.sqlite3").write_bytes(b"not a database")
    before = snapshot(hosted.data_dir)
    with pytest.raises(ValueError, match="could not be validated"):
        pilot.inspect_existing_storage(hosted)
    assert snapshot(hosted.data_dir) == before


@pytest.mark.parametrize("key,value", [
    ("BUSINESS_TURNSTILE_SITE_KEY", ""), ("BUSINESS_TURNSTILE_SECRET_KEY", ""),
    ("BUSINESS_TURNSTILE_SITE_KEY", "1x00000000000000000000AA"),
    ("BUSINESS_TURNSTILE_SECRET_KEY", "1x0000000000000000000000000000000AA"),
])
def test_preflight_and_serve_refuse_missing_or_test_challenge_keys(hosted, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    before = snapshot(hosted.data_dir)
    for operation in (pilot.preflight, pilot.create_application):
        with pytest.raises(ValueError, match="Turnstile|TURNSTILE"):
            operation(hosted)
    assert snapshot(hosted.data_dir) == before


def test_provision_is_explicit_and_refuses_existing_files(hosted):
    before = snapshot(hosted.data_dir)
    with pytest.raises(ValueError, match="empty directory"):
        pilot.provision(hosted)
    assert snapshot(hosted.data_dir) == before


def test_explicit_provision_creates_private_account_and_mfa_sheets(hosted):
    target = hosted.data_dir.parent / "new-installation"
    configuration = pilot.Configuration(ORIGIN, "business.example.com", target, 10000)
    accounts, authenticator = pilot.provision(configuration)
    assert accounts.is_file() and authenticator.is_file()
    pilot.preflight(configuration)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and file modes")
@pytest.mark.parametrize("target", ["directory", "business.sqlite3", "identity.key", "ACCOUNTS.md", "ADMIN_MFA_SETUP.md"])
def test_hosted_storage_requires_private_modes(hosted, target):
    path = hosted.data_dir if target == "directory" else hosted.data_dir / target
    path.chmod(0o755 if target == "directory" else 0o644)
    with pytest.raises(ValueError, match="mode 0[67]00"):
        pilot.inspect_existing_storage(hosted)


def test_hosted_app_secure_cookies_host_origin_and_forwarding_boundary(hosted, business_seed):
    application = pilot.create_application(hosted)
    with connection(hosted) as database:
        secret = database.execute("SELECT secret FROM admin_mfa WHERE user_id='admin'").fetchone()[0]
    with TestClient(application, base_url=ORIGIN) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/healthz", headers={"Host": "alternate.onrender.com"}).status_code == 400
        assert client.get("/api/public/posts").status_code == 200
        assert client.get("/api/public/posts", headers={"Host": "alternate.onrender.com"}).status_code == 400
        payload = {"username": "admin", "password": business_seed.credentials["admin"], "otp": pyotp.TOTP(secret).now()}
        response = client.post("/api/login", json=payload, headers={
            "Origin": ORIGIN, "X-Forwarded-Proto": "http", "X-Forwarded-For": "192.0.2.123",
        })
        assert response.status_code == 200
        cookie = response.headers["set-cookie"].lower()
        assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        assert client.post("/api/logout", json={}, headers={
            "Origin": "https://alternate.onrender.com", "X-CSRF-Token": response.json()["csrf"],
            "X-Forwarded-Host": "business.example.com",
        }).status_code == 403


def test_health_failure_is_bounded_and_preserves_host_checks(hosted, monkeypatch):
    application = pilot.create_application(hosted)

    @contextmanager
    def broken_storage():
        raise sqlite3.OperationalError("PRIVATE_DIAGNOSTIC_CANARY")
        yield

    monkeypatch.setattr(application.state.database, "transaction", broken_storage)
    with TestClient(application, base_url=ORIGIN) as client:
        response = client.get("/healthz")
        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}
        assert "PRIVATE_DIAGNOSTIC_CANARY" not in response.text


@pytest.mark.parametrize("damage", ["missing-settings", "invalid-freeze", "invalid-revision", "missing-database"])
def test_health_does_not_report_ready_after_storage_damage(hosted, damage):
    application = pilot.create_application(hosted)
    if damage == "missing-database":
        (hosted.data_dir / "business.sqlite3").unlink()
    else:
        with connection(hosted) as database:
            database.execute("PRAGMA ignore_check_constraints=ON")
            database.execute({
                "missing-settings": "DELETE FROM settings",
                "invalid-freeze": "UPDATE settings SET frozen=2",
                "invalid-revision": "UPDATE settings SET freeze_revision=1.5",
            }[damage])
    with TestClient(application, base_url=ORIGIN) as client:
        response = client.get("/healthz")
        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}


@pytest.mark.parametrize("method,path", [
    ("GET", "/"), ("GET", "/healthz"), ("GET", "/ACCOUNTS.md"),
    ("POST", "/api/login"), ("PUT", "/api/admin/posts"),
    ("DELETE", "/api/logout"), ("PATCH", "/unknown"), ("OPTIONS", "/"), ("HEAD", "/"),
])
def test_bootstrap_exposes_only_fixed_maintenance_response(method, path):
    with TestClient(pilot.BootstrapApplication(), base_url=ORIGIN) as client:
        response = client.request(method, path, content=b"private input canary")
        assert response.status_code == 503
        assert response.headers["cache-control"] == "no-store"
        assert response.text == ("" if method == "HEAD" else "Service is being prepared.\n")


def test_bootstrap_never_requires_keys_reads_storage_or_activates_after_provision(hosted, monkeypatch):
    import uvicorn

    monkeypatch.delenv("BUSINESS_TURNSTILE_SITE_KEY")
    monkeypatch.delenv("BUSINESS_TURNSTILE_SECRET_KEY")
    absent = hosted.data_dir.parent / "absent"
    configuration = pilot.Configuration(ORIGIN, "business.example.com", absent, 10000)
    monkeypatch.setattr(pilot, "load_configuration", lambda: configuration)
    monkeypatch.setattr(pilot.os, "umask", lambda mode: None)
    monkeypatch.setattr(pilot, "create_application", lambda *args: pytest.fail("Bootstrap initialized an app"))
    monkeypatch.setattr(pilot, "inspect_existing_storage", lambda *args: pytest.fail("Bootstrap read storage"))
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda application, **kwargs: calls.append((application, kwargs)))
    pilot.main(["bootstrap"])
    assert len(calls) == 1
    assert not absent.exists()
    application, options = calls[0]
    assert options["proxy_headers"] is False and options["workers"] == 1
    assert options["access_log"] is False and options["server_header"] is False
    shutil.copytree(hosted.data_dir, absent)
    with TestClient(application, base_url=ORIGIN) as client:
        assert client.get("/").status_code == 503
        assert client.get("/api/public/posts").status_code == 503


def test_cli_serve_uses_single_worker_and_no_forwarding_trust(hosted, monkeypatch, capsys):
    import uvicorn

    monkeypatch.setattr(pilot, "load_configuration", lambda: hosted)
    monkeypatch.setattr(pilot.os, "umask", lambda mode: None)
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda application, **kwargs: calls.append(kwargs))
    pilot.main(["serve"])
    assert calls == [{"host": "0.0.0.0", "port": 10000, "workers": 1, "access_log": False,
                      "proxy_headers": False, "forwarded_allow_ips": "", "server_header": False}]
    output = capsys.readouterr()
    assert "synthetic-secret-key" not in output.out + output.err


def test_cli_failure_never_opens_a_listener_or_prints_os_details(hosted, monkeypatch, capsys):
    import uvicorn

    monkeypatch.setattr(pilot, "load_configuration", lambda: hosted)
    monkeypatch.setattr(pilot.os, "umask", lambda mode: None)
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: pytest.fail("Unexpected listener"))

    def inaccessible(configuration):
        raise OSError("PRIVATE_DIAGNOSTIC_CANARY")

    monkeypatch.setattr(pilot, "create_application", inaccessible)
    with pytest.raises(SystemExit) as result:
        pilot.main(["serve"])
    assert result.value.code == 1
    output = capsys.readouterr()
    assert "PRIVATE_DIAGNOSTIC_CANARY" not in output.out + output.err
