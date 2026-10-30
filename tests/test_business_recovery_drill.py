"""Recovery fixture isolation and evidence runners' assertion requirements."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")
pytest.importorskip("cryptography")
pytest.importorskip("webauthn")

from tools import business_recovery_drill as drill  # noqa: E402
from tools import business_dashboard_browser as browser  # noqa: E402


@pytest.mark.parametrize("runner", ["business_recovery_drill.py", "business_dashboard_browser.py"])
@pytest.mark.parametrize("flag,environment", [("-O", None), ("-OO", None), (None, "1"), (None, "2")])
def test_evidence_runners_reject_optimized_execution_before_creating_outputs(runner, flag, environment):
    env = os.environ.copy()
    env.pop("PYTHONOPTIMIZE", None)
    env.pop("BUSINESS_MFA_KEY_FILE", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if environment is not None:
        env["PYTHONOPTIMIZE"] = environment
    with tempfile.TemporaryDirectory(prefix="radt-optimized-runner-") as temporary:
        output = Path(temporary) / "evidence-must-not-be-created"
        command = [sys.executable, *([flag] if flag else []), str(drill.ROOT / "tools" / runner),
                   "--output-dir", str(output)]
        if runner == "business_recovery_drill.py":
            command += ["--release-archive", str(Path(temporary) / "archive-must-not-be-read.zip")]
        else:
            # A removed guard must not launch a real browser during this regression.
            command += ["--browser-channel", "radt-nonexistent-test-browser"]
        result = subprocess.run(command, cwd=temporary, env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode != 0
        assert "requires assertions" in result.stderr
        assert "PYTHONOPTIMIZE" in result.stderr
        assert not output.exists(), "Optimized execution created evidence or disposable fixtures"


@pytest.mark.parametrize("runner", ["business_recovery_drill.py", "business_dashboard_browser.py"])
def test_evidence_runners_keep_unoptimized_help_available(runner):
    env = os.environ.copy()
    env.pop("PYTHONOPTIMIZE", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run([sys.executable, str(drill.ROOT / "tools" / runner), "--help"],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert "--output-dir" in result.stdout


def test_fixture_never_reads_host_keys_configuration_or_storage(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="radt-drill-environment-") as temporary:
        output = Path(temporary).resolve()
        sentinel = output / "host-storage-must-not-be-read" / "missing.key"
        settings = {
            "BUSINESS_MFA_KEY_FILE": str(sentinel),
            "BUSINESS_DATA_DIR": str(sentinel.parent),
            "PUBLIC_ORIGIN": "https://host-must-not-be-contacted.invalid",
            "BUSINESS_TURNSTILE_SITE_KEY": "host-site-key-must-not-be-read",
            "BUSINESS_TURNSTILE_SECRET_KEY": "host-secret-must-not-be-read",
        }
        for name, value in settings.items():
            monkeypatch.setenv(name, value)
        original_get = os.environ.get

        def reject_host_configuration(name, default=None):
            assert name not in settings, "The disposable drill consulted hosted configuration"
            return original_get(name, default)

        monkeypatch.setattr(os.environ, "get", reject_host_configuration)
        fixture = drill.prepare_fixture(output)

        assert fixture.runtime == output / "fictional-current"
        assert fixture.key == output / "fictional-current.secrets" / "mfa.key"
        assert fixture.runtime not in fixture.key.parents
        assert fixture.key.stat().st_size == 32
        assert drill.digest(fixture.key) != drill.digest(fixture.runtime / "identity.key")
        assert drill.digest(fixture.key) == drill.digest(fixture.custody_key)
        assert fixture.plaintext_zip.stat().st_size > 1024 * 1024
        assert not sentinel.parent.exists()
        assert all(os.environ[name] == value for name, value in settings.items())


def test_browser_fixture_and_enrollment_ignore_host_key_and_configuration(monkeypatch):
    from fastapi.testclient import TestClient
    import pyotp

    monkeypatch.syspath_prepend(str(browser.EXAMPLE))
    with tempfile.TemporaryDirectory(prefix="radt-browser-environment-") as temporary:
        output = Path(temporary).resolve()
        runtime = output / "private"
        sentinel = output / "host-storage-must-not-be-read" / "missing.key"
        settings = {
            "BUSINESS_MFA_KEY_FILE": str(sentinel),
            "BUSINESS_DATA_DIR": str(sentinel.parent),
            "PUBLIC_ORIGIN": "https://host-must-not-be-contacted.invalid",
            "BUSINESS_TURNSTILE_SITE_KEY": "host-site-key-must-not-be-read",
            "BUSINESS_TURNSTILE_SECRET_KEY": "host-secret-must-not-be-read",
        }
        for name, value in settings.items():
            monkeypatch.setenv(name, value)
        original_get = os.environ.get

        def reject_host_configuration(name, default=None):
            assert name not in settings, "The disposable browser runner consulted hosted configuration"
            return original_get(name, default)

        monkeypatch.setattr(os.environ, "get", reject_host_configuration)
        credentials, application = browser.prepare_fixture(runtime, drill.ORIGIN)
        database = browser.synthetic_database(runtime)
        key = output / "private.secrets" / "mfa.key"
        assert database.mfa_secrets.path == application.state.database.mfa_secrets.path == key
        assert key.stat().st_size == 32
        assert drill.digest(key) != drill.digest(runtime / "identity.key")
        secret, counter = browser.synthetic_admin_enrollment(runtime)
        assert counter == -1
        with TestClient(application, base_url=drill.ORIGIN) as client:
            response = client.post("/api/login", json={
                "username": "admin", "password": credentials["admin"], "otp": pyotp.TOTP(secret).now(),
            }, headers={"Origin": drill.ORIGIN})
            assert response.status_code == 200
            assert client.get("/api/admin/overview").status_code == 200
        assert not sentinel.parent.exists()
        assert all(os.environ[name] == value for name, value in settings.items())
