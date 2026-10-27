"""Recovery fixture isolation from a real host's ambient configuration."""

import os
from pathlib import Path
import tempfile

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")
pytest.importorskip("cryptography")
pytest.importorskip("webauthn")

from tools import business_recovery_drill as drill  # noqa: E402


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
